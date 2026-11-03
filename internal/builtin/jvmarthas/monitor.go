package jvmarthas

import (
	"context"
	"fmt"
	"time"
)

// Names of the run-time checks, as they appear in an Abort.
const (
	GuardCPU      = "cpu"
	GuardGCTime   = "gc_time"
	GuardGCRate   = "gc_rate"
	GuardHealth   = "health_check"
	GuardSampling = "sampling"
)

// DefaultSettle is the time after the start of the command in which the CPU and health
// thresholds are not evaluated: the first seconds of an Arthas session load classes and
// raise the CPU use of every JVM.
const DefaultSettle = 5 * time.Second

// defaultHealthFailures applies when HealthCheck.MaxFailures is zero.
const defaultHealthFailures = 2

// ticksPerSecond is the unit of /proc/<pid>/stat on Linux (USER_HZ), so that 100 ticks per
// second are 100 percent of one CPU.
const ticksPerSecond = 100

// Abort says why the guard ended a call.
type Abort struct {
	// Check is the name of the check that tripped.
	Check  string
	Detail string
}

func (a *Abort) Error() string { return a.Check + ": " + a.Detail }

// sample is one reading of the target process.
type sample struct {
	At       time.Time
	CPUTicks uint64
	GCCount  int64
	GCTime   time.Duration
}

// guard evaluates the samples of one call against the thresholds of the configuration.
type guard struct {
	cfg     Guard
	started time.Time
	settle  time.Duration
	prev    *sample
	// failures counts the health requests that failed in a row.
	failures int
}

func newGuard(cfg Guard, started time.Time) *guard {
	settle := cfg.Settle
	if settle == 0 {
		settle = DefaultSettle
	}
	return &guard{cfg: cfg, started: started, settle: settle}
}

// settled reports whether the settle time is over at now.
func (g *guard) settled(now time.Time) bool { return !now.Before(g.started.Add(g.settle)) }

// exceeds reports whether value is above limit. The tolerance absorbs the rounding of a ratio
// that is exactly at the limit.
func exceeds(value float64, limit int) bool { return value > float64(limit)+1e-9 }

// Evaluate compares a sample with the previous one. The first sample only becomes the
// baseline. A counter that went back, or time that did not advance, skips the interval.
func (g *guard) Evaluate(cur sample) *Abort {
	prev := g.prev
	g.prev = &cur
	if prev == nil {
		return nil
	}
	elapsed := cur.At.Sub(prev.At)
	if elapsed <= 0 {
		return nil
	}
	seconds := elapsed.Seconds()
	if limit := g.cfg.MaxCPUPercent; limit > 0 && g.settled(cur.At) && cur.CPUTicks >= prev.CPUTicks {
		percent := float64(cur.CPUTicks-prev.CPUTicks) / seconds * 100 / ticksPerSecond
		if exceeds(percent, limit) {
			return &Abort{GuardCPU, fmt.Sprintf("the process used %.0f%% of one CPU in %s, the limit is %d%%", percent, elapsed.Round(10*time.Millisecond), limit)}
		}
	}
	if limit := g.cfg.MaxGCPerSecond; limit > 0 && cur.GCCount >= prev.GCCount {
		rate := float64(cur.GCCount-prev.GCCount) / seconds
		if exceeds(rate, limit) {
			return &Abort{GuardGCRate, fmt.Sprintf("%d collections in %s, the limit is %d per second", cur.GCCount-prev.GCCount, elapsed.Round(10*time.Millisecond), limit)}
		}
	}
	if limit := g.cfg.MaxGCTimePercent; limit > 0 && cur.GCTime >= prev.GCTime {
		percent := float64(cur.GCTime-prev.GCTime) / float64(elapsed) * 100
		if exceeds(percent, limit) {
			return &Abort{GuardGCTime, fmt.Sprintf("the collectors ran %.0f%% of %s, the limit is %d%%", percent, elapsed.Round(10*time.Millisecond), limit)}
		}
	}
	return nil
}

// Health records the result of one health request; err is nil when the request succeeded.
// Results inside the settle time are ignored.
func (g *guard) Health(now time.Time, err error) *Abort {
	h := g.cfg.Health
	if h == nil || !g.settled(now) {
		return nil
	}
	if err == nil {
		g.failures = 0
		return nil
	}
	g.failures++
	limit := h.MaxFailures
	if limit == 0 {
		limit = defaultHealthFailures
	}
	if g.failures >= limit {
		return &Abort{GuardHealth, fmt.Sprintf("%d health requests in a row failed, the last with: %v", g.failures, err)}
	}
	return nil
}

// readSample reads what the configured thresholds need. A reading that fails is an Abort of
// its own: a threshold that cannot be evaluated protects nothing.
func readSample(ctx context.Context, host Host, proc *Process, cfg Guard, now time.Time) (sample, *Abort) {
	s := sample{At: now}
	if cfg.MaxCPUPercent > 0 {
		ticks, err := host.CPUTicks(proc.PID)
		if err != nil {
			return s, &Abort{GuardSampling, fmt.Sprintf("cannot read the CPU time: %v", err)}
		}
		s.CPUTicks = ticks
	}
	if cfg.MaxGCTimePercent > 0 || cfg.MaxGCPerSecond > 0 {
		data, err := proc.JVM.ReadPerfData(ctx)
		if err != nil {
			return s, &Abort{GuardSampling, fmt.Sprintf("cannot read the hsperfdata: %v", err)}
		}
		summary, err := data.Summary()
		if err != nil {
			return s, &Abort{GuardSampling, fmt.Sprintf("cannot read the GC counters: %v", err)}
		}
		if len(summary.GC.Collectors) == 0 {
			return s, &Abort{GuardSampling, "the hsperfdata has no GC collector counters"}
		}
		for _, c := range summary.GC.Collectors {
			s.GCCount += c.Invocations
			s.GCTime += time.Duration(c.TimeMS * float64(time.Millisecond))
		}
	}
	return s, nil
}

// enabled reports whether any threshold is set.
func (g Guard) enabled() bool {
	return g.MaxCPUPercent > 0 || g.MaxGCTimePercent > 0 || g.MaxGCPerSecond > 0 || g.Health != nil
}

// watch samples the process every env.SampleEvery until ctx ends. It returns the first
// violation, or nil when ctx ended first or no threshold is set. A violation does not end
// ctx; the caller does that.
func watch(ctx context.Context, env Env, cfg Guard, proc *Process, started time.Time) *Abort {
	if !cfg.enabled() {
		return nil
	}
	g := newGuard(cfg, started)
	base, abort := readSample(ctx, env.Host, proc, cfg, env.Now())
	if abort != nil {
		return abortUnlessEnded(ctx, abort)
	}
	g.Evaluate(base)
	every := env.SampleEvery
	if every <= 0 {
		every = time.Second
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		now := env.Now()
		s, abort := readSample(ctx, env.Host, proc, cfg, now)
		if abort != nil {
			return abortUnlessEnded(ctx, abort)
		}
		if abort := g.Evaluate(s); abort != nil {
			return abort
		}
		if cfg.Health != nil && g.settled(now) {
			err := env.Probe(ctx, *cfg.Health)
			if ctx.Err() != nil {
				return nil
			}
			if abort := g.Health(now, err); abort != nil {
				return abort
			}
		}
	}
}

// abortUnlessEnded drops an abort that only a cancelled context caused.
func abortUnlessEnded(ctx context.Context, a *Abort) *Abort {
	if ctx.Err() != nil {
		return nil
	}
	return a
}
