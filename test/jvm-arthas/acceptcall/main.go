// Command ja-call runs jvm_arthas calls against one JVM of the local Docker environment in
// test/jvm-arthas and records, for every call, the timings of its steps, the memory and the
// processes of the container, the hsperfdata counters of the JVM before and after the call,
// and the state the call left behind. It is the measurement tool of the stage-2 acceptance
// (docs/arthas-stage2-acceptance-report.md), not part of the product. It needs root, as the
// builtin does.
//
// The calls go through jvmarthas.RunWith with the environment of this host; ja-call only wraps
// the resolver, the JVM and the host functions to record when each step happened. Two options
// change what the checks see, and only for measurements the defaults would refuse:
//
//	-state fresh      every call gets a new state directory, so the attach count and interval checks pass
//	-threads-live N   the checks read N as java.threads.live (thread -b on JVMs with more than 500 threads)
//
// Usage:
//
//	ja-call -container jvm-arthas-accept-jdk17-1 -files run/arthas-minlog -kinds dashboard,jvm -out calls.jsonl
//	ja-call -container ... -snapshot      prints the counters, memory and Arthas state of the JVM once
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/builtin/jvmarthas"
	"github.com/liubing0806/allowops/internal/jvmtarget"
	"github.com/liubing0806/allowops/internal/jvmtarget/perfdata"
)

type options struct {
	container, mainClass, arthasDir, files string
	kinds                                  []arthas.Kind
	calls                                  int
	start                                  float64
	every, gap, sample                     time.Duration
	state, out, evidence, label            string
	threadsLive                            int64
	threadID                               int64
	maxOldGen                              int
	noFullGCWithin                         time.Duration
	snapshot                               bool
	diag                                   string
}

func main() {
	var o options
	var kinds string
	flag.StringVar(&o.container, "container", "", "container of the JVM")
	flag.StringVar(&o.mainClass, "main-class", "/app/app.jar", "main class or jar of the JVM")
	flag.StringVar(&o.arthasDir, "arthas-dir", "/opt/arthas-minlog", "directory of the Arthas files inside the container")
	flag.StringVar(&o.files, "files", "", "directory of the same Arthas files on the host, for their SHA-256")
	flag.StringVar(&kinds, "kinds", "version", "comma-separated command kinds, called in turn")
	flag.IntVar(&o.calls, "calls", 0, "number of calls, cycling through -kinds (default: one per kind)")
	flag.Float64Var(&o.start, "start", 0, "Unix time of the first call (default: now)")
	flag.DurationVar(&o.every, "every", 0, "time from the start of one call to the start of the next (0: -gap after each call)")
	flag.DurationVar(&o.gap, "gap", 0, "pause after each call when -every is 0")
	flag.DurationVar(&o.sample, "sample", 10*time.Millisecond, "interval of the memory and process samples during a call")
	flag.StringVar(&o.state, "state", "fresh", `"fresh" for a new state directory per call, or the path of one kept across calls`)
	flag.StringVar(&o.out, "out", "", "JSON lines file the records are appended to (default: stdout)")
	flag.StringVar(&o.evidence, "evidence", "", "directory for the output of every call")
	flag.StringVar(&o.label, "label", "", "label copied into every record")
	flag.Int64Var(&o.threadsLive, "threads-live", 0, "value of java.threads.live the checks see (0: the real one)")
	flag.Int64Var(&o.threadID, "thread-id", 2, "thread id for thread_info")
	flag.IntVar(&o.maxOldGen, "max-old-gen", 0, "checks.max_old_gen_percent (0: off)")
	flag.DurationVar(&o.noFullGCWithin, "no-full-gc-within", 0, "checks.no_full_gc_within (0: off)")
	flag.BoolVar(&o.snapshot, "snapshot", false, "print one snapshot of the JVM and exit")
	flag.StringVar(&o.diag, "diag", "", "URL of the /diag endpoint of the sample application, read before and after every call")
	flag.Parse()
	for _, k := range strings.Split(kinds, ",") {
		o.kinds = append(o.kinds, arthas.Kind(strings.TrimSpace(k)))
	}
	if o.calls == 0 {
		o.calls = len(o.kinds)
	}
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "ja-call:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	if o.container == "" {
		return errors.New("-container is required")
	}
	target := jvmtarget.Target{Name: "target", Container: o.container, MainClass: o.mainClass}
	ctx := context.Background()
	jvm, err := jvmtarget.NewResolver().Resolve(ctx, target)
	if err != nil {
		return err
	}
	cg, err := cgroupDir(jvm.PID)
	if err != nil {
		return err
	}
	if o.snapshot {
		snap := map[string]any{
			"t": unix(time.Now()), "pid": jvm.PID, "perf": readPerf(ctx, jvm), "memory_current": readInt(filepath.Join(cg, "memory.current")),
			"memory_max": strings.TrimSpace(readText(filepath.Join(cg, "memory.max"))), "memory_stat": memStat(cg), "post": inspectJVM(jvm.PID, nil),
		}
		return json.NewEncoder(os.Stdout).Encode(snap)
	}
	sums, err := fileSums(o.files)
	if err != nil {
		return err
	}
	out := os.Stdout
	if o.out != "" {
		f, err := os.OpenFile(o.out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	enc := json.NewEncoder(out)
	first := time.Now()
	if o.start > 0 {
		first = time.Unix(0, int64(o.start*1e9))
	}
	stateRoot, err := os.MkdirTemp("", "ja-call-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stateRoot)
	for i := 0; i < o.calls; i++ {
		at := first
		if o.every > 0 {
			at = first.Add(time.Duration(i) * o.every)
		}
		if d := time.Until(at); d > 0 {
			time.Sleep(d)
		}
		kind := o.kinds[i%len(o.kinds)]
		stateDir := o.state
		if o.state == "fresh" {
			stateDir = filepath.Join(stateRoot, strconv.Itoa(i), "arthas")
		}
		rec := oneCall(ctx, o, jvm, cg, kind, sums, stateDir, i)
		if err := enc.Encode(rec); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s call %d %s: %s %s attach=%s cleanup=%s %.0f ms, mem +%.1f MB (peak +%.1f), metaspace %+.1f MB\n",
			o.label, i, kind, rec.Status, rec.Check, rec.Attach, rec.Cleanup, rec.Ms,
			float64(rec.Memory.After-rec.Memory.Before)/1e6, float64(rec.Memory.Peak-rec.Memory.Before)/1e6,
			float64(rec.PerfAfter.MetaspaceUsed-rec.PerfBefore.MetaspaceUsed)/1e6)
		if o.every == 0 && o.gap > 0 && i+1 < o.calls {
			time.Sleep(o.gap)
		}
	}
	return nil
}

func fileSums(dir string) (map[string]string, error) {
	if dir == "" {
		return nil, errors.New("-files is required")
	}
	sums := map[string]string{}
	for _, name := range jvmarthas.FileNames {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		sums[name] = hex.EncodeToString(sum[:])
	}
	return sums, nil
}

func request(o options, kind arthas.Kind) arthas.Request {
	r := arthas.Request{Kind: kind}
	switch kind {
	case arthas.KindThreadTop:
		r.Top = 5
	case arthas.KindThreadInfo:
		r.ThreadID = o.threadID
	case arthas.KindClassInfo:
		r.Class = "demo.HotService"
	case arthas.KindMethodInfo:
		r.Class, r.Method = "demo.HotService", "work"
	case arthas.KindSysprop:
		r.Key = "java.version"
	}
	return r
}

// record is one line of the output. Times are Unix seconds; durations are milliseconds.
type record struct {
	Label string `json:"label,omitempty"`
	// Kind is "jvm_arthas" so that scripts/analyze.py counts the seconds from Start to End as seconds of a call.
	Kind    string  `json:"kind"`
	Seq     int     `json:"seq"`
	Command string  `json:"command"`
	Start   float64 `json:"start"`
	End     float64 `json:"end"`
	Ms      float64 `json:"ms"`

	Status   string `json:"status"`
	Check    string `json:"check,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Attach   string `json:"attach,omitempty"`
	Earlier  string `json:"earlier,omitempty"`
	Cleanup  string `json:"cleanup,omitempty"`
	ExitCode int    `json:"exit_code"`
	Err      string `json:"err,omitempty"`
	Stderr   string `json:"stderr,omitempty"`

	Steps steps `json:"steps"`

	Memory     memory    `json:"memory"`
	Procs      procs     `json:"procs"`
	PerfBefore perfShort `json:"perf_before"`
	PerfAfter  perfShort `json:"perf_after"`
	// DiagBefore and DiagAfter come from the MXBeans of the JVM; unlike hsperfdata, whose metaspace and
	// generation counters change only at a collection, they are current.
	DiagBefore map[string]any `json:"diag_before,omitempty"`
	DiagAfter  map[string]any `json:"diag_after,omitempty"`
	Post       post           `json:"post"`
}

type steps struct {
	// CheckAttach, Attach: the two calls to the JVM, as [start, end] relative to the start of the call.
	CheckAttach []float64 `json:"check_attach,omitempty"`
	Attach      []float64 `json:"attach,omitempty"`
	// PortOpen is the first poll that found the port listening.
	PortOpen *float64 `json:"port_open,omitempty"`
	// Requests are the HTTP requests to Arthas, one connection each.
	Requests []requestTrace `json:"requests,omitempty"`
	// StopSent is when the stop request was written; PortClosed and ThreadsZero are the first polls after it that found
	// the port closed and no arthas- thread.
	StopSent    *float64 `json:"stop_sent,omitempty"`
	PortClosed  *float64 `json:"port_closed,omitempty"`
	ThreadsZero *float64 `json:"threads_zero,omitempty"`
	// StopToPortClosed and StopToThreadsZero are the differences.
	StopToPortClosed  *float64 `json:"stop_to_port_closed,omitempty"`
	StopToThreadsZero *float64 `json:"stop_to_threads_zero,omitempty"`
}

type requestTrace struct {
	Action  string  `json:"action"`
	Command string  `json:"command,omitempty"`
	Open    float64 `json:"open"`
	Close   float64 `json:"close"`
}

type memory struct {
	// Before, Peak and After are memory.current of the container's cgroup, in bytes: just before the call,
	// the largest sample during it, and just after it.
	Before  int64 `json:"before"`
	Peak    int64 `json:"peak"`
	After   int64 `json:"after"`
	Samples int   `json:"samples"`
	// AnonBefore and AnonAfter are the anon field of memory.stat, FileBefore and FileAfter its file field.
	AnonBefore int64 `json:"anon_before"`
	AnonAfter  int64 `json:"anon_after"`
	FileBefore int64 `json:"file_before"`
	FileAfter  int64 `json:"file_after"`
}

type procs struct {
	Before []int `json:"before"`
	// New lists the processes that appeared in the container's cgroup during the call, with their names.
	New   []string `json:"new"`
	After []int    `json:"after"`
}

type post struct {
	Listening     []int `json:"listening"`
	ArthasThreads int   `json:"arthas_threads"`
	ProcsSame     bool  `json:"procs_same"`
}

func oneCall(ctx context.Context, o options, jvm *jvmtarget.JVM, cg string, kind arthas.Kind, sums map[string]string, stateDir string, seq int) record {
	cfg := jvmarthas.Config{
		Command: kind, Targets: map[string]jvmtarget.Target{"target": {Name: "target", Container: o.container, MainClass: o.mainClass}},
		ArthasDir: o.arthasDir, SHA256: sums,
		Checks: jvmarthas.Checks{MaxOldGenPercent: o.maxOldGen, NoFullGCWithin: o.noFullGCWithin},
	}
	if kind == arthas.KindSysprop {
		cfg.SyspropKeys = []string{"java.version", "user.timezone"}
	}
	tr := &trace{}
	env := jvmarthas.NewEnv()
	env.StateDir = stateDir
	env.Resolver = timedResolver{inner: env.Resolver, tr: tr, threadsLive: o.threadsLive}
	env.Host = timedHost{Host: env.Host, tr: tr}

	rec := record{Label: o.label, Kind: "jvm_arthas", Seq: seq, Command: string(kind)}
	rec.PerfBefore = readPerf(ctx, jvm)
	rec.DiagBefore = readDiag(o.diag)
	before := pidsOf(cg)
	rec.Procs.Before = before
	rec.Memory.AnonBefore, rec.Memory.FileBefore = anonFile(cg)
	rec.Memory.Before = readInt(filepath.Join(cg, "memory.current"))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	seen := map[int]string{}
	go func() {
		defer wg.Done()
		tick := time.NewTicker(o.sample)
		defer tick.Stop()
		for {
			if m := readInt(filepath.Join(cg, "memory.current")); m > rec.Memory.Peak {
				rec.Memory.Peak = m
			}
			rec.Memory.Samples++
			for _, pid := range pidsOf(cg) {
				if _, ok := seen[pid]; !ok && !contains(before, pid) {
					seen[pid] = strings.TrimSpace(readText(fmt.Sprintf("/proc/%d/comm", pid)))
				}
			}
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()

	start := time.Now()
	tr.start = start
	res, err := jvmarthas.RunWith(ctx, env, cfg, jvmarthas.Params{Target: "target", Request: request(o, kind)}, nil)
	end := time.Now()
	close(stop)
	wg.Wait()

	rec.Memory.After = readInt(filepath.Join(cg, "memory.current"))
	if rec.Memory.After > rec.Memory.Peak {
		rec.Memory.Peak = rec.Memory.After
	}
	rec.Memory.AnonAfter, rec.Memory.FileAfter = anonFile(cg)
	rec.Start, rec.End, rec.Ms = unix(start), unix(end), float64(end.Sub(start).Microseconds())/1000
	rec.Status, rec.Check, rec.Reason = row(res.Stdout, "status"), row(res.Stdout, "check"), row(res.Stdout, "reason")
	rec.Attach, rec.Earlier, rec.Cleanup = row(res.Stdout, "attach"), row(res.Stdout, "earlier_sessions"), row(res.Stdout, "cleanup")
	rec.ExitCode, rec.Stderr = res.ExitCode, strings.TrimSpace(res.Stderr)
	if err != nil {
		rec.Err = err.Error()
	}
	rec.Steps = tr.steps()
	for pid, comm := range seen {
		rec.Procs.New = append(rec.Procs.New, fmt.Sprintf("%d %s", pid, comm))
	}
	sort.Strings(rec.Procs.New)
	rec.PerfAfter = readPerf(ctx, jvm)
	rec.DiagAfter = readDiag(o.diag)
	rec.Post = inspectJVM(jvm.PID, before)
	rec.Procs.After = pidsOf(cg)
	if o.evidence != "" {
		if os.MkdirAll(o.evidence, 0o755) == nil {
			name := fmt.Sprintf("%s-%03d-%s.txt", strings.ReplaceAll(o.label, "/", "_"), seq, kind)
			text := fmt.Sprintf("err %v, exit %d, %.0f ms\n--- stdout\n%s--- stderr\n%s", err, res.ExitCode, rec.Ms, res.Stdout, res.Stderr)
			os.WriteFile(filepath.Join(o.evidence, name), []byte(text), 0o644)
		}
	}
	return rec
}

var diagClient = http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}

func readDiag(url string) map[string]any {
	if url == "" {
		return nil
	}
	resp, err := diagClient.Get(url)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return map[string]any{"error": err.Error()}
	}
	return m
}

func contains(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func unix(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

// row returns the value of a row of the call section of the output.
func row(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			return ""
		}
		if k, v, ok := strings.Cut(line, "\t"); ok && k == key {
			return v
		}
	}
	return ""
}

// trace collects what the wrappers saw during one call.
type trace struct {
	mu          sync.Mutex
	start       time.Time
	checkAttach [2]time.Time
	attach      [2]time.Time
	requests    []*connTrace
	listening   []poll
	threads     []poll
}

type poll struct {
	t     time.Time
	value int
	err   bool
}

type connTrace struct {
	open, firstWrite, close time.Time
	head                    []byte
}

func (tr *trace) rel(t time.Time) float64 { return float64(t.Sub(tr.start).Microseconds()) / 1000 }

func (tr *trace) relp(t time.Time) *float64 {
	if t.IsZero() {
		return nil
	}
	v := tr.rel(t)
	return &v
}

func (tr *trace) steps() steps {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	var s steps
	if !tr.checkAttach[0].IsZero() {
		s.CheckAttach = []float64{tr.rel(tr.checkAttach[0]), tr.rel(tr.checkAttach[1])}
	}
	if !tr.attach[0].IsZero() {
		s.Attach = []float64{tr.rel(tr.attach[0]), tr.rel(tr.attach[1])}
	}
	for _, p := range tr.listening {
		if !p.err && p.value == 1 {
			s.PortOpen = tr.relp(p.t)
			break
		}
	}
	var stopAt time.Time
	for _, c := range tr.requests {
		action, command := parseRequest(c.head)
		s.Requests = append(s.Requests, requestTrace{Action: action, Command: command, Open: tr.rel(c.open), Close: tr.rel(c.close)})
		if command == "stop" && !c.firstWrite.IsZero() {
			stopAt = c.firstWrite
		}
	}
	if stopAt.IsZero() {
		return s
	}
	s.StopSent = tr.relp(stopAt)
	for _, p := range tr.listening {
		if p.t.After(stopAt) && !p.err && p.value == 0 {
			s.PortClosed = tr.relp(p.t)
			d := tr.rel(p.t) - tr.rel(stopAt)
			s.StopToPortClosed = &d
			break
		}
	}
	for _, p := range tr.threads {
		if p.t.After(stopAt) && !p.err && p.value == 0 {
			s.ThreadsZero = tr.relp(p.t)
			d := tr.rel(p.t) - tr.rel(stopAt)
			s.StopToThreadsZero = &d
			break
		}
	}
	return s
}

// parseRequest reads the action and the command from the start of an HTTP request to the Arthas API.
// The headers, which hold the password, are not kept.
func parseRequest(head []byte) (action, command string) {
	i := bytes.Index(head, []byte("\r\n\r\n"))
	if i < 0 {
		return "?", ""
	}
	var body struct {
		Action  string `json:"action"`
		Command string `json:"command"`
	}
	if json.Unmarshal(head[i+4:], &body) != nil {
		return "?", ""
	}
	return body.Action, body.Command
}

type timedResolver struct {
	inner       jvmarthas.Resolver
	tr          *trace
	threadsLive int64
}

func (r timedResolver) wrap(p *jvmarthas.Process, err error) (*jvmarthas.Process, error) {
	if p != nil {
		p.JVM = timedJVM{inner: p.JVM, tr: r.tr, threadsLive: r.threadsLive}
	}
	return p, err
}

func (r timedResolver) Resolve(ctx context.Context, t jvmtarget.Target) (*jvmarthas.Process, error) {
	return r.wrap(r.inner.Resolve(ctx, t))
}

func (r timedResolver) Identify(pid int, startTime uint64) (*jvmarthas.Process, error) {
	return r.wrap(r.inner.Identify(pid, startTime))
}

type timedJVM struct {
	inner       jvmarthas.JVMOps
	tr          *trace
	threadsLive int64
}

func (j timedJVM) CheckAttach(ctx context.Context) (*jvmtarget.AttachCheck, error) {
	t0 := time.Now()
	c, err := j.inner.CheckAttach(ctx)
	j.tr.mu.Lock()
	j.tr.checkAttach = [2]time.Time{t0, time.Now()}
	j.tr.mu.Unlock()
	if err == nil && c != nil && c.PerfData != nil && j.threadsLive > 0 {
		e := c.PerfData.Entries["java.threads.live"]
		e.Long = j.threadsLive
		c.PerfData.Entries["java.threads.live"] = e
	}
	return c, err
}

func (j timedJVM) Attach(ctx context.Context, req jvmtarget.AttachRequest) (*jvmtarget.AttachResult, error) {
	t0 := time.Now()
	res, err := j.inner.Attach(ctx, req)
	j.tr.mu.Lock()
	j.tr.attach = [2]time.Time{t0, time.Now()}
	j.tr.mu.Unlock()
	return res, err
}

func (j timedJVM) DialTCP(ctx context.Context, port int) (net.Conn, error) {
	conn, err := j.inner.DialTCP(ctx, port)
	if err != nil {
		return nil, err
	}
	c := &connTrace{open: time.Now()}
	j.tr.mu.Lock()
	j.tr.requests = append(j.tr.requests, c)
	j.tr.mu.Unlock()
	return &timedConn{Conn: conn, tr: j.tr, c: c}, nil
}

func (j timedJVM) ReadPerfData(ctx context.Context) (*perfdata.PerfData, error) {
	return j.inner.ReadPerfData(ctx)
}

// maxHead bounds the bytes of a request that are kept to read its action.
const maxHead = 8 << 10

type timedConn struct {
	net.Conn
	tr *trace
	c  *connTrace
}

func (c *timedConn) Write(b []byte) (int, error) {
	c.tr.mu.Lock()
	if c.c.firstWrite.IsZero() {
		c.c.firstWrite = time.Now()
	}
	if room := maxHead - len(c.c.head); room > 0 {
		c.c.head = append(c.c.head, b[:min(room, len(b))]...)
	}
	c.tr.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *timedConn) Close() error {
	c.tr.mu.Lock()
	if c.c.close.IsZero() {
		c.c.close = time.Now()
	}
	c.tr.mu.Unlock()
	return c.Conn.Close()
}

type timedHost struct {
	jvmarthas.Host
	tr *trace
}

func (h timedHost) IsListening(pid, port int) (bool, error) {
	ok, err := h.Host.IsListening(pid, port)
	v := 0
	if ok {
		v = 1
	}
	h.tr.mu.Lock()
	h.tr.listening = append(h.tr.listening, poll{t: time.Now(), value: v, err: err != nil})
	h.tr.mu.Unlock()
	return ok, err
}

func (h timedHost) ArthasThreads(pid int) (int, error) {
	n, err := h.Host.ArthasThreads(pid)
	h.tr.mu.Lock()
	h.tr.threads = append(h.tr.threads, poll{t: time.Now(), value: n, err: err != nil})
	h.tr.mu.Unlock()
	return n, err
}

// cgroupDir returns the cgroup v2 directory of the process.
func cgroupDir(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join("/sys/fs/cgroup", rest), nil
		}
	}
	return "", fmt.Errorf("process %d has no cgroup v2 entry", pid)
}

func readText(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

func readInt(path string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(readText(path)), 10, 64)
	return n
}

func memStat(cg string) map[string]int64 {
	out := map[string]int64{}
	for _, line := range strings.Split(readText(filepath.Join(cg, "memory.stat")), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok {
			n, _ := strconv.ParseInt(v, 10, 64)
			out[k] = n
		}
	}
	return out
}

func anonFile(cg string) (int64, int64) {
	m := memStat(cg)
	return m["anon"], m["file"]
}

func pidsOf(cg string) []int {
	var pids []int
	for _, f := range strings.Fields(readText(filepath.Join(cg, "cgroup.procs"))) {
		if n, err := strconv.Atoi(f); err == nil {
			pids = append(pids, n)
		}
	}
	sort.Ints(pids)
	return pids
}

// inspectJVM reads the Arthas state of the process the way the post-checks of test/jvm-arthas/real do.
func inspectJVM(pid int, before []int) post {
	p := post{Listening: []int{}}
	tasks, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	for _, task := range tasks {
		if strings.HasPrefix(readText(fmt.Sprintf("/proc/%d/task/%s/comm", pid, task.Name())), "arthas-") {
			p.ArthasThreads++
		}
	}
	for _, file := range []string{"tcp", "tcp6"} {
		for _, line := range strings.Split(readText(fmt.Sprintf("/proc/%d/net/%s", pid, file)), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != "0A" {
				continue
			}
			i := strings.LastIndex(f[1], ":")
			port, err := strconv.ParseUint(f[1][i+1:], 16, 32)
			if err == nil && port >= jvmarthas.DefaultHTTPPortMin && port <= jvmarthas.DefaultHTTPPortMax {
				p.Listening = append(p.Listening, int(port))
			}
		}
	}
	if before != nil {
		cg, err := cgroupDir(pid)
		after := pidsOf(cg)
		p.ProcsSame = err == nil && len(after) == len(before)
		for i := range after {
			if p.ProcsSame && after[i] != before[i] {
				p.ProcsSame = false
			}
		}
	}
	return p
}

// perfShort holds the hsperfdata counters the report uses. Sizes are bytes, times milliseconds.
type perfShort struct {
	OK                bool                 `json:"ok"`
	MetaspaceUsed     int64                `json:"metaspace_used"`
	MetaspaceCapacity int64                `json:"metaspace_capacity"`
	MetaspaceMax      int64                `json:"metaspace_max_capacity"`
	ClassSpaceUsed    int64                `json:"class_space_used"`
	ThreadsLive       int64                `json:"threads_live"`
	HeapUsed          int64                `json:"heap_used"`
	YoungUsed         int64                `json:"young_used"`
	OldUsed           int64                `json:"old_used"`
	OldCapacity       int64                `json:"old_capacity"`
	OldMax            int64                `json:"old_max_capacity"`
	ClassesLoaded     int64                `json:"classes_loaded"`
	ClassesUnloaded   int64                `json:"classes_unloaded"`
	Collectors        map[string]collector `json:"collectors"`
	UptimeMs          int64                `json:"uptime_ms"`
}

type collector struct {
	Count int64   `json:"count"`
	Ms    float64 `json:"ms"`
	// LastExitAgoMs is the time since the last collection of this kind ended.
	LastExitAgoMs float64 `json:"last_exit_ago_ms"`
}

func readPerf(ctx context.Context, jvm *jvmtarget.JVM) perfShort {
	pd, err := jvm.ReadPerfData(ctx)
	if err != nil {
		return perfShort{}
	}
	long := func(name string) int64 { v, _ := pd.Long(name); return v }
	s := perfShort{OK: true, Collectors: map[string]collector{}}
	s.MetaspaceUsed, s.MetaspaceCapacity, s.MetaspaceMax = long("sun.gc.metaspace.used"), long("sun.gc.metaspace.capacity"), long("sun.gc.metaspace.maxCapacity")
	s.ClassSpaceUsed = long("sun.gc.compressedclassspace.used")
	s.ThreadsLive = long("java.threads.live")
	s.ClassesLoaded, s.ClassesUnloaded = long("java.cls.loadedClasses"), long("java.cls.unloadedClasses")
	freq, ticks := float64(long("sun.os.hrt.frequency")), long("sun.os.hrt.ticks")
	if freq > 0 {
		s.UptimeMs = int64(float64(ticks) / freq * 1000)
	}
	for g := 0; g < 4; g++ {
		prefix := fmt.Sprintf("sun.gc.generation.%d.", g)
		name, ok := pd.Text(prefix + "name")
		if !ok {
			continue
		}
		var used int64
		for sp := 0; sp < 8; sp++ {
			used += long(fmt.Sprintf("%sspace.%d.used", prefix, sp))
		}
		s.HeapUsed += used
		switch name {
		case "new", "young":
			s.YoungUsed = used
		case "old":
			s.OldUsed, s.OldCapacity, s.OldMax = used, long(prefix+"capacity"), long(prefix+"maxCapacity")
		}
	}
	for c := 0; c < 8; c++ {
		prefix := fmt.Sprintf("sun.gc.collector.%d.", c)
		name, ok := pd.Text(prefix + "name")
		if !ok {
			continue
		}
		col := collector{Count: long(prefix + "invocations")}
		if freq > 0 {
			col.Ms = float64(long(prefix+"time")) / freq * 1000
			if last := long(prefix + "lastExitTime"); last > 0 {
				col.LastExitAgoMs = float64(ticks-last) / freq * 1000
			}
		}
		s.Collectors[name] = col
	}
	return s
}
