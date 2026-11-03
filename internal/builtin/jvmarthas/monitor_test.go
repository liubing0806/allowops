package jvmarthas

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var guardStart = time.Unix(1_700_000_000, 0).UTC()

// at returns the time of the n-th second after the start of the command.
func at(n float64) time.Time { return guardStart.Add(time.Duration(n * float64(time.Second))) }

func TestGuardCPU(t *testing.T) {
	cfg := Guard{MaxCPUPercent: 150}
	tests := []struct {
		name    string
		samples []sample
		// tripAt is the index of the sample at which the guard must trip; -1 for never.
		tripAt int
	}{
		{"below the limit", []sample{{At: at(0), CPUTicks: 0}, {At: at(6), CPUTicks: 100}, {At: at(7), CPUTicks: 250}}, -1},
		{"exactly the limit", []sample{{At: at(5), CPUTicks: 0}, {At: at(6), CPUTicks: 150}}, -1},
		{"above the limit", []sample{{At: at(5), CPUTicks: 0}, {At: at(6), CPUTicks: 151}}, 1},
		{"four CPUs busy", []sample{{At: at(5), CPUTicks: 1000}, {At: at(6), CPUTicks: 1380}}, 1},
		{"the first sample has no predecessor", []sample{{At: at(6), CPUTicks: 1 << 40}}, -1},
		{"inside the settle time", []sample{{At: at(0), CPUTicks: 0}, {At: at(1), CPUTicks: 378}, {At: at(4.9), CPUTicks: 2000}}, -1},
		{"the first interval after the settle time counts", []sample{{At: at(4), CPUTicks: 0}, {At: at(5), CPUTicks: 400}}, 1},
		{"a longer interval is averaged", []sample{{At: at(5), CPUTicks: 0}, {At: at(7), CPUTicks: 290}}, -1},
		{"time that did not advance", []sample{{At: at(6), CPUTicks: 0}, {At: at(6), CPUTicks: 5000}}, -1},
		{"ticks that went back", []sample{{At: at(6), CPUTicks: 5000}, {At: at(7), CPUTicks: 10}}, -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := newGuard(cfg, guardStart)
			tripped := -1
			for i, s := range tc.samples {
				if a := g.Evaluate(s); a != nil {
					if a.Check != GuardCPU {
						t.Fatalf("sample %d: check = %s, want %s", i, a.Check, GuardCPU)
					}
					if !strings.Contains(a.Detail, "150") {
						t.Errorf("detail %q does not name the limit", a.Detail)
					}
					tripped = i
					break
				}
			}
			if tripped != tc.tripAt {
				t.Errorf("tripped at sample %d, want %d", tripped, tc.tripAt)
			}
		})
	}
}

func TestGuardCPUOffWithoutAThreshold(t *testing.T) {
	g := newGuard(Guard{}, guardStart)
	g.Evaluate(sample{At: at(6), CPUTicks: 0})
	if a := g.Evaluate(sample{At: at(7), CPUTicks: 100000}); a != nil {
		t.Errorf("tripped without a threshold: %v", a)
	}
}

func TestGuardSettleTimeIsConfigurable(t *testing.T) {
	g := newGuard(Guard{MaxCPUPercent: 100, Settle: 20 * time.Second}, guardStart)
	g.Evaluate(sample{At: at(10), CPUTicks: 0})
	if a := g.Evaluate(sample{At: at(11), CPUTicks: 500}); a != nil {
		t.Errorf("tripped inside the configured settle time: %v", a)
	}
	g.Evaluate(sample{At: at(20), CPUTicks: 500})
	if a := g.Evaluate(sample{At: at(21), CPUTicks: 1000}); a == nil {
		t.Error("did not trip after the configured settle time")
	}
}

func TestGuardGC(t *testing.T) {
	cfg := Guard{MaxGCTimePercent: 30, MaxGCPerSecond: 3}
	tests := []struct {
		name  string
		first sample
		next  sample
		want  string
	}{
		{"quiet", sample{At: at(0)}, sample{At: at(1), GCCount: 2, GCTime: 50 * time.Millisecond}, ""},
		{"exactly the limits", sample{At: at(0)}, sample{At: at(1), GCCount: 3, GCTime: 300 * time.Millisecond}, ""},
		{"too many collections", sample{At: at(0), GCCount: 10}, sample{At: at(1), GCCount: 14, GCTime: time.Millisecond}, GuardGCRate},
		{"too much time in the collector", sample{At: at(0)}, sample{At: at(1), GCCount: 1, GCTime: 310 * time.Millisecond}, GuardGCTime},
		{"rate over a longer interval", sample{At: at(0)}, sample{At: at(2), GCCount: 6, GCTime: time.Millisecond}, ""},
		{"counted inside the settle time", sample{At: at(0)}, sample{At: at(1), GCCount: 9, GCTime: time.Millisecond}, GuardGCRate},
		{"counters that went back", sample{At: at(0), GCCount: 50, GCTime: time.Hour}, sample{At: at(1), GCCount: 1}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := newGuard(cfg, guardStart)
			g.Evaluate(tc.first)
			a := g.Evaluate(tc.next)
			switch {
			case tc.want == "" && a != nil:
				t.Errorf("tripped: %v", a)
			case tc.want != "" && a == nil:
				t.Errorf("did not trip; want %s", tc.want)
			case a != nil && a.Check != tc.want:
				t.Errorf("check = %s, want %s", a.Check, tc.want)
			}
		})
	}
}

func TestGuardHealth(t *testing.T) {
	failed := errors.New("HTTP 503")
	health := &HealthCheck{URL: "http://127.0.0.1:8080/health", AllowedPrefixes: []string{"http://127.0.0.1:8080/"}, MaxFailures: 3}
	g := newGuard(Guard{Health: health}, guardStart)
	// Failures inside the settle time are ignored and do not count.
	for i := 0; i < 5; i++ {
		if a := g.Health(at(float64(i)), failed); a != nil {
			t.Fatalf("tripped inside the settle time: %v", a)
		}
	}
	if a := g.Health(at(6), failed); a != nil {
		t.Fatalf("tripped on the first failure: %v", a)
	}
	if a := g.Health(at(7), failed); a != nil {
		t.Fatalf("tripped on the second failure: %v", a)
	}
	// A success resets the count.
	if a := g.Health(at(8), nil); a != nil {
		t.Fatalf("tripped on a success: %v", a)
	}
	g.Health(at(9), failed)
	g.Health(at(10), failed)
	a := g.Health(at(11), failed)
	if a == nil || a.Check != GuardHealth {
		t.Fatalf("abort = %v, want health_check after 3 failures in a row", a)
	}
	if !strings.Contains(a.Detail, "3") || !strings.Contains(a.Detail, "HTTP 503") {
		t.Errorf("detail %q", a.Detail)
	}
}

func TestGuardHealthDefaultsToTwoFailures(t *testing.T) {
	health := &HealthCheck{URL: "http://127.0.0.1:8080/health", AllowedPrefixes: []string{"http://127.0.0.1:8080/"}}
	g := newGuard(Guard{Health: health}, guardStart)
	if a := g.Health(at(6), errors.New("x")); a != nil {
		t.Fatalf("tripped on the first failure: %v", a)
	}
	if a := g.Health(at(7), errors.New("x")); a == nil {
		t.Error("did not trip on the second failure in a row")
	}
}

func TestGuardHealthOffWithoutACheck(t *testing.T) {
	g := newGuard(Guard{}, guardStart)
	for i := 6; i < 20; i++ {
		if a := g.Health(at(float64(i)), errors.New("x")); a != nil {
			t.Fatalf("tripped without a health check: %v", a)
		}
	}
}

func TestReadSampleReadsOnlyWhatIsConfigured(t *testing.T) {
	jvm := &fakeJVM{perf: perf(setLong("sun.gc.collector.0.invocations", 7), setLong("sun.gc.collector.0.time", 2_000_000_000))}
	proc := &Process{PID: 4242, JVM: jvm}
	host := &fakeHost{cpu: map[int]uint64{4242: 1234}}
	s, abort := readSample(context.Background(), host, proc, Guard{MaxCPUPercent: 100}, at(1))
	if abort != nil {
		t.Fatal(abort)
	}
	if s.CPUTicks != 1234 || s.GCCount != 0 || !s.At.Equal(at(1)) {
		t.Errorf("sample = %+v, want the CPU ticks only", s)
	}
	if jvm.perfReads != 0 {
		t.Errorf("hsperfdata was read %d times without a GC threshold", jvm.perfReads)
	}
	s, abort = readSample(context.Background(), host, proc, Guard{MaxGCPerSecond: 3}, at(2))
	if abort != nil {
		t.Fatal(abort)
	}
	// perf() has a young and a full collector with 40 and 1 invocations; the test adds none, so
	// the counters of the first one are replaced: 7 + 1 invocations, 2 s of time.
	if s.GCCount != 8 || s.GCTime != 2*time.Second || s.CPUTicks != 0 {
		t.Errorf("sample = %+v, want GC counters only", s)
	}
}

func TestReadSampleFailsClosed(t *testing.T) {
	proc := func(jvm *fakeJVM) *Process { return &Process{PID: 4242, JVM: jvm} }
	t.Run("cpu cannot be read", func(t *testing.T) {
		host := &fakeHost{cpuErr: errors.New("no such process")}
		_, abort := readSample(context.Background(), host, proc(&fakeJVM{perf: perf()}), Guard{MaxCPUPercent: 100}, at(1))
		if abort == nil || abort.Check != GuardSampling || !strings.Contains(abort.Detail, "no such process") {
			t.Errorf("abort = %v", abort)
		}
	})
	t.Run("hsperfdata cannot be read", func(t *testing.T) {
		jvm := &fakeJVM{perfErr: errors.New("process changed")}
		_, abort := readSample(context.Background(), &fakeHost{}, proc(jvm), Guard{MaxGCTimePercent: 50}, at(1))
		if abort == nil || abort.Check != GuardSampling || !strings.Contains(abort.Detail, "process changed") {
			t.Errorf("abort = %v", abort)
		}
	})
	t.Run("no collector counters", func(t *testing.T) {
		jvm := &fakeJVM{perf: perf(
			dropPrefix("sun.gc.collector."))}
		_, abort := readSample(context.Background(), &fakeHost{}, proc(jvm), Guard{MaxGCPerSecond: 5}, at(1))
		if abort == nil || abort.Check != GuardSampling {
			t.Errorf("abort = %v", abort)
		}
	})
	t.Run("nothing configured reads nothing", func(t *testing.T) {
		host := &fakeHost{cpuErr: errors.New("x")}
		jvm := &fakeJVM{perfErr: errors.New("y")}
		if _, abort := readSample(context.Background(), host, proc(jvm), Guard{}, at(1)); abort != nil {
			t.Errorf("abort = %v", abort)
		}
	})
}
