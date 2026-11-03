// Command ja-loadgen is a constant-arrival-rate (open loop) HTTP load generator for the Arthas
// stage-0 measurements. Latency is measured from the time a request was *scheduled* to be sent, not
// from the time it was actually written, so a stall in the target shows up as latency for every
// request that was due during the stall (no coordinated omission).
//
// Output: one JSON line per flow and second:
//
//	{"t":1761219600,"flow":"hot","sent":1000,"ok":1000,"err":0,"drop":0,"h":{"1234":5,...}}
//
// where t is the scheduled second (Unix time) and h maps a histogram bucket to a count; the bucket
// index i covers latencies [1.01^i, 1.01^(i+1)) microseconds.
//
//	ja-loadgen -base http://172.20.0.2:8080 -flow ping=/ping@500 -flow hot=/hot?calls=1@1000 -duration 300s -out load.jsonl
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const bucketBase = 1.01

type flowSpec struct {
	name string
	path string
	rps  float64
}

type flowFlag []flowSpec

func (f *flowFlag) String() string { return fmt.Sprint(*f) }

// Set parses name=/path?query@rps.
func (f *flowFlag) Set(v string) error {
	name, rest, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("flow %q: want name=/path@rps", v)
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return fmt.Errorf("flow %q: want name=/path@rps", v)
	}
	rps, err := strconv.ParseFloat(rest[at+1:], 64)
	if err != nil || rps <= 0 {
		return fmt.Errorf("flow %q: bad rate", v)
	}
	*f = append(*f, flowSpec{name: name, path: rest[:at], rps: rps})
	return nil
}

type second struct {
	sent, ok, err, drop int64
	h                   map[int]int64
}

type flow struct {
	spec flowSpec
	mu   sync.Mutex
	secs map[int64]*second
}

func (f *flow) sec(t int64) *second {
	s := f.secs[t]
	if s == nil {
		s = &second{h: map[int]int64{}}
		f.secs[t] = s
	}
	return s
}

type job struct {
	sched time.Time
}

func main() {
	var flows flowFlag
	base := flag.String("base", "", "base URL, e.g. http://172.20.0.2:8080")
	flag.Var(&flows, "flow", "name=/path?query@rps (repeatable)")
	dur := flag.Duration("duration", 60*time.Second, "how long to run")
	out := flag.String("out", "load.jsonl", "output file")
	conns := flag.Int("conns", 64, "connections (workers) per flow")
	timeout := flag.Duration("timeout", 5*time.Second, "per-request timeout")
	queue := flag.Int("queue", 200000, "pending-request queue per flow; requests beyond it are counted as dropped")
	flag.Parse()
	if *base == "" || len(flows) == 0 {
		flag.Usage()
		os.Exit(64)
	}

	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		close(stop)
	}()
	time.AfterFunc(*dur, func() {
		select {
		case <-stop:
		default:
			close(stop)
		}
	})

	var wg sync.WaitGroup
	fl := make([]*flow, len(flows))
	for i, spec := range flows {
		fl[i] = &flow{spec: spec, secs: map[int64]*second{}}
		runFlow(fl[i], *base, *conns, *queue, *timeout, stop, &wg)
	}

	// Writer: flush seconds that no request can still complete into (older than the timeout + 2 s).
	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	enc := json.NewEncoder(w)
	flush := func(all bool) {
		cut := time.Now().Add(-*timeout - 2*time.Second).Unix()
		for _, fo := range fl {
			fo.mu.Lock()
			for t, s := range fo.secs {
				if !all && t >= cut {
					continue
				}
				h := make(map[string]int64, len(s.h))
				for b, c := range s.h {
					h[strconv.Itoa(b)] = c
				}
				_ = enc.Encode(map[string]any{"t": t, "flow": fo.spec.name, "sent": s.sent, "ok": s.ok, "err": s.err, "drop": s.drop, "h": h})
				delete(fo.secs, t)
			}
			fo.mu.Unlock()
		}
		_ = w.Flush()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			flush(false)
		case <-done:
			flush(true)
			f.Close()
			return
		}
	}
}

func runFlow(fo *flow, base string, conns, queue int, timeout time.Duration, stop <-chan struct{}, wg *sync.WaitGroup) {
	tr := &http.Transport{MaxIdleConnsPerHost: conns, MaxConnsPerHost: conns, DisableCompression: true, IdleConnTimeout: time.Minute}
	cl := &http.Client{Transport: tr, Timeout: timeout}
	url := base + fo.spec.path
	jobs := make(chan job, queue)
	var inflight atomic.Int64

	var workers sync.WaitGroup
	for i := 0; i < conns; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := range jobs {
				inflight.Add(1)
				ok := false
				resp, err := cl.Get(url)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					ok = resp.StatusCode >= 200 && resp.StatusCode < 300
				}
				lat := time.Since(j.sched)
				b := int(math.Log(float64(lat.Microseconds())+1) / math.Log(bucketBase))
				fo.mu.Lock()
				s := fo.sec(j.sched.Unix())
				s.h[b]++
				if ok {
					s.ok++
				} else {
					s.err++
				}
				fo.mu.Unlock()
				inflight.Add(-1)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		interval := time.Duration(float64(time.Second) / fo.spec.rps)
		next := time.Now()
		for {
			select {
			case <-stop:
				close(jobs)
				workers.Wait()
				tr.CloseIdleConnections()
				return
			default:
			}
			now := time.Now()
			for !next.After(now) {
				j := job{sched: next}
				fo.mu.Lock()
				fo.sec(next.Unix()).sent++
				fo.mu.Unlock()
				select {
				case jobs <- j:
				default:
					fo.mu.Lock()
					fo.sec(next.Unix()).drop++
					fo.mu.Unlock()
				}
				next = next.Add(interval)
			}
			sleep := time.Until(next)
			if sleep > 500*time.Microsecond {
				sleep = 500 * time.Microsecond
			}
			if sleep > 0 {
				time.Sleep(sleep)
			}
		}
	}()
}
