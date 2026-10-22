//go:build perfprofile

// Package perfprofile is linked only by the local profiling overlay.
package perfprofile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type sample struct {
	Calls          int
	TotalNS, MaxNS int64
}

var mu sync.Mutex
var queries map[string]sample
var active bool
var cpu *os.File

type Tracer struct{}
type queryKey struct{}
type acquireKey struct{}

func (Tracer) TraceAcquireStart(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireStartData) context.Context {
	mu.Lock()
	enabled := active
	mu.Unlock()
	if !enabled {
		return ctx
	}
	return context.WithValue(ctx, acquireKey{}, time.Now())
}
func (Tracer) TraceAcquireEnd(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireEndData) {
	start, ok := ctx.Value(acquireKey{}).(time.Time)
	if !ok {
		return
	}
	elapsed := time.Since(start).Nanoseconds()
	mu.Lock()
	defer mu.Unlock()
	s := queries["POOL ACQUIRE"]
	s.Calls++
	s.TotalNS += elapsed
	s.MaxNS = max(s.MaxNS, elapsed)
	queries["POOL ACQUIRE"] = s
}

type query struct {
	sql   string
	start time.Time
}

func (Tracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	mu.Lock()
	enabled := active
	mu.Unlock()
	if !enabled {
		return ctx
	}
	return context.WithValue(ctx, queryKey{}, query{d.SQL, time.Now()})
}
func (Tracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	q, ok := ctx.Value(queryKey{}).(query)
	if !ok {
		return
	}
	elapsed := time.Since(q.start).Nanoseconds()
	mu.Lock()
	defer mu.Unlock()
	s := queries[q.sql]
	s.Calls++
	s.TotalNS += elapsed
	s.MaxNS = max(s.MaxNS, elapsed)
	queries[q.sql] = s
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func writeJSON(dir, name string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(dir, name), b, 0600))
}
func snapshot(dir, name string) {
	b, err := os.ReadFile("/proc/loadavg")
	must(err)
	must(os.WriteFile(filepath.Join(dir, name+".loadavg"), b, 0600))
	runtime.GC()
	f, err := os.Create(filepath.Join(dir, name+".heap"))
	must(err)
	must(pprof.WriteHeapProfile(f))
	must(f.Close())
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	writeJSON(dir, name+".memory.json", m)
	b, err = os.ReadFile("/proc/self/status")
	must(err)
	must(os.WriteFile(filepath.Join(dir, name+".status"), b, 0600))
}

// Serve uses files in a private directory, without a network listener or signals.
func Serve() {
	dir := os.Getenv("ALLOWOPS_PROFILE_DIR")
	if dir == "" {
		panic("profile directory required")
	}
	go func() {
		for {
			time.Sleep(10 * time.Millisecond)
			b, err := os.ReadFile(filepath.Join(dir, "command"))
			if os.IsNotExist(err) {
				continue
			}
			must(err)
			must(os.Remove(filepath.Join(dir, "command")))
			switch string(b) {
			case "start":
				snapshot(dir, "online")
				mu.Lock()
				queries = map[string]sample{}
				active = true
				mu.Unlock()
				runtime.SetBlockProfileRate(1)
				runtime.SetMutexProfileFraction(1)
				cpu, err = os.Create(filepath.Join(dir, "job.cpu"))
				must(err)
				must(pprof.StartCPUProfile(cpu))
			case "stop":
				pprof.StopCPUProfile()
				must(cpu.Close())
				mu.Lock()
				active = false
				writeJSON(dir, "job.sql.json", queries)
				mu.Unlock()
				for _, name := range []string{"block", "mutex"} {
					f, err := os.Create(filepath.Join(dir, "job."+name))
					must(err)
					must(pprof.Lookup(name).WriteTo(f, 0))
					must(f.Close())
				}
				runtime.SetBlockProfileRate(0)
				runtime.SetMutexProfileFraction(0)
				snapshot(dir, "finished")
			}
			must(os.WriteFile(filepath.Join(dir, "done"), b, 0600))
		}
	}()
}
func Command(name string) {
	dir := os.Getenv("ALLOWOPS_PROFILE_DIR")
	must(os.WriteFile(filepath.Join(dir, "pending"), []byte(name), 0600))
	must(os.Rename(filepath.Join(dir, "pending"), filepath.Join(dir, "command")))
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(filepath.Join(dir, "done"))
		if err == nil && string(b) == name {
			must(os.Remove(filepath.Join(dir, "done")))
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	panic("profile command timed out")
}
