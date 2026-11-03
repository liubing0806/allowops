package jvmarthas

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/jvmtarget/perfdata"
)

// Names of the checks, as they appear in a Refusal.
const (
	CheckJVMVersion       = "jvm_version"
	CheckArchitecture     = "architecture"
	CheckAttachState      = "attach_state"
	CheckMemoryHeadroom   = "memory_headroom"
	CheckMetaspace        = "metaspace_headroom"
	CheckAttachCount      = "attach_count"
	CheckAttachInterval   = "attach_interval"
	CheckThreadCount      = "thread_count"
	CheckOldGenUsage      = "old_gen_usage"
	CheckRecentFullGC     = "recent_full_gc"
	CheckArthasFiles      = "arthas_files"
	CheckTargetLocked     = "target_locked"
	CheckPortRange        = "http_port"
	supportedArchitecture = "amd64"
)

// Checks of the L2 commands: CheckCPUUsage refuses a call before the attach; CheckAffect and
// CheckEnhancedClasses fail a call after the enhancement.
const (
	CheckCPUUsage        = "cpu_usage"
	CheckAffect          = "affect"
	CheckEnhancedClasses = "enhanced_classes"
)

// Refusal says why a call stopped before it attached to the JVM.
type Refusal struct {
	// Check is the name of the check that failed.
	Check  string
	Reason string
}

func (r *Refusal) Error() string { return r.Check + ": " + r.Reason }

// checkInput is what the checks before the attach look at. Config must be effective.
type checkInput struct {
	Config  Config
	Command arthas.Command
	PID     int
	Perf    *perfdata.PerfData
	Counter Counter
	Now     time.Time
	Host    Host
	// Arch is the architecture of this host as GOARCH names it.
	Arch string
}

// runChecks returns the first check that fails, or nil. The checks read the hsperfdata of the
// JVM, the counters of the state directory and the cgroup of the process; none of them
// touches the JVM.
func runChecks(in checkInput) *Refusal {
	for _, check := range []func(checkInput) *Refusal{
		checkVersion, checkArch, checkMemory, checkMetaspace, checkCount, checkInterval,
		checkThreads, checkOldGen, checkFullGC,
	} {
		if r := check(in); r != nil {
			return r
		}
	}
	return nil
}

func refuse(check, format string, args ...any) *Refusal {
	return &Refusal{Check: check, Reason: fmt.Sprintf(format, args...)}
}

func mib(n int64) int64 { return n >> 20 }

// supportedMajors are the feature releases of Java that Arthas 4.3.5 was tested with: Temurin
// 8u504, 11.0.32, 17.0.20 and 21.0.12. Other updates of the same releases are accepted.
var supportedMajors = []int{8, 11, 17, 21}

// javaMajor returns the feature release of a java.version value: 8 for 1.8.0_504, 17 for 17.0.20.
func javaMajor(version string) (int, bool) {
	rest := strings.TrimPrefix(version, "1.")
	end := 0
	for end < len(rest) && end < 4 && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(rest[:end])
	return n, err == nil
}

func checkVersion(in checkInput) *Refusal {
	version, ok := in.Perf.Text("java.property.java.version")
	if !ok {
		return refuse(CheckJVMVersion, "hsperfdata has no java.version, so the release of the JVM is unknown")
	}
	major, ok := javaMajor(version)
	if !ok || !slices.Contains(supportedMajors, major) {
		return refuse(CheckJVMVersion, "java.version %q is not one of the tested releases (Java 8, 11, 17 and 21)", clipText(version))
	}
	return nil
}

func checkArch(in checkInput) *Refusal {
	if in.Arch != supportedArchitecture {
		return refuse(CheckArchitecture, "Arthas was tested on x86_64 only, this host is %s", in.Arch)
	}
	return nil
}

func checkMemory(in checkInput) *Refusal {
	room, err := in.Host.MemoryHeadroom(in.PID)
	if err != nil {
		return refuse(CheckMemoryHeadroom, "cannot read the memory limit and usage of process %d: %v", in.PID, err)
	}
	if min := in.Config.Checks.MinMemoryHeadroom; room < min {
		return refuse(CheckMemoryHeadroom, "%d MiB of memory are left in the cgroup of the JVM, at least %d MiB are required", mib(room), mib(min))
	}
	return nil
}

// maxMetaspaceSize returns the value of the last -XX:MaxMetaspaceSize option in the flags and
// arguments of the JVM. The text is read here and never shown: it can hold secrets.
func maxMetaspaceSize(p *perfdata.PerfData) (int64, bool) {
	var size int64
	found := false
	for _, counter := range []string{"java.rt.vmFlags", "java.rt.vmArgs"} {
		text, _ := p.Text(counter)
		for _, word := range strings.Fields(text) {
			value, ok := strings.CutPrefix(word, "-XX:MaxMetaspaceSize=")
			if !ok {
				continue
			}
			if n, ok := parseJVMSize(value); ok {
				size, found = n, true
			}
		}
	}
	return size, found
}

// parseJVMSize reads a size as the JVM does: digits and an optional k, m or g.
func parseJVMSize(s string) (int64, bool) {
	unit := int64(1)
	if s != "" {
		switch s[len(s)-1] {
		case 'k', 'K':
			unit, s = 1<<10, s[:len(s)-1]
		case 'm', 'M':
			unit, s = 1<<20, s[:len(s)-1]
		case 'g', 'G':
			unit, s = 1<<30, s[:len(s)-1]
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || n > math.MaxInt64/unit {
		return 0, false
	}
	return n * unit, true
}

// metaspacePerAttach is the metaspace counted for each attach that hsperfdata does not show yet
// (decision A69). One call added at most 19.4 MiB in the stage-2 acceptance.
const metaspacePerAttach int64 = 20 << 20

// gcCount returns the sum of the invocations of all collectors.
func gcCount(p *perfdata.PerfData) int64 {
	var n int64
	for i := 0; i < maxCounterGroups; i++ {
		v, _ := p.Long(fmt.Sprintf("sun.gc.collector.%d.invocations", i))
		n += v
	}
	return n
}

func checkMetaspace(in checkInput) *Refusal {
	limit, ok := maxMetaspaceSize(in.Perf)
	if !ok {
		return nil // without MaxMetaspaceSize the container's memory is the limit, which checkMemory covers
	}
	used, ok := in.Perf.Long("sun.gc.metaspace.used")
	if !ok {
		return refuse(CheckMetaspace, "MaxMetaspaceSize is set but hsperfdata has no sun.gc.metaspace.used")
	}
	// The counter changes at a collection only: what the attaches since the last one loaded is not in it.
	unseen := in.Counter.unseenAttaches(gcCount(in.Perf))
	pending := int64(unseen) * metaspacePerAttach
	if room, min := limit-used-pending, in.Config.Checks.MinMetaspaceHeadroom; room < min {
		reason := fmt.Sprintf("%d MiB of metaspace are left below MaxMetaspaceSize, at least %d MiB are required", mib(room), mib(min))
		if unseen > 0 {
			reason += fmt.Sprintf(" (attaches since the last garbage collection: %d, counted as %d MiB)", unseen, mib(pending))
		}
		return refuse(CheckMetaspace, "%s", reason)
	}
	return nil
}

func checkCount(in checkInput) *Refusal {
	if max := in.Config.Checks.MaxAttaches; in.Counter.Attaches >= max {
		return refuse(CheckAttachCount, "the JVM had %d attaches since it started, at most %d are allowed; restart the JVM to attach again", in.Counter.Attaches, max)
	}
	return nil
}

func checkInterval(in checkInput) *Refusal {
	if in.Counter.Attaches == 0 {
		return nil
	}
	min := in.Config.Checks.MinAttachInterval
	elapsed := in.Now.Sub(in.Counter.LastAttach)
	switch {
	case elapsed < 0:
		return refuse(CheckAttachInterval, "the last attach is dated %s in the future", (-elapsed).Round(time.Second))
	case elapsed < min:
		return refuse(CheckAttachInterval, "the last attach to this JVM was %s ago; wait %s", elapsed.Round(time.Second), (min - elapsed).Round(time.Second))
	}
	return nil
}

func checkThreads(in checkInput) *Refusal {
	if !slices.Contains(in.Command.PreChecks, arthas.PreCheckThreadCount) {
		return nil
	}
	live, ok := in.Perf.Long("java.threads.live")
	if !ok {
		return refuse(CheckThreadCount, "hsperfdata has no java.threads.live")
	}
	if max := int64(in.Config.Checks.MaxBlockingThreads); live > max {
		return refuse(CheckThreadCount, "the JVM has %d live threads, %s accepts at most %d", live, in.Command.Text, max)
	}
	return nil
}

// oldGeneration returns the bytes used in the old generation and its limit.
func oldGeneration(p *perfdata.PerfData) (used, limit int64, ok bool) {
	for i := 0; i < maxCounterGroups; i++ {
		prefix := fmt.Sprintf("sun.gc.generation.%d.", i)
		if name, _ := p.Text(prefix + "name"); name != "old" {
			continue
		}
		for j := 0; j < maxCounterGroups; j++ {
			n, _ := p.Long(fmt.Sprintf("%sspace.%d.used", prefix, j))
			used += n
		}
		limit, _ = p.Long(prefix + "maxCapacity")
		return used, limit, true
	}
	return 0, 0, false
}

// maxCounterGroups bounds the numbered counter groups (generations, spaces, collectors) that are scanned.
const maxCounterGroups = 16

// checkOldGen does not apply to a JVM without an old generation, such as one with Shenandoah.
func checkOldGen(in checkInput) *Refusal {
	percent := in.Config.Checks.MaxOldGenPercent
	used, limit, ok := oldGeneration(in.Perf)
	if !ok {
		return nil
	}
	if limit <= 0 || used < 0 {
		return refuse(CheckOldGenUsage, "the old generation has no usable limit (used %d, limit %d)", used, limit)
	}
	if float64(used)*100 > float64(percent)*float64(limit) {
		return refuse(CheckOldGenUsage, "the old generation is %.0f%% full, the limit is %d%%", float64(used)*100/float64(limit), percent)
	}
	return nil
}

// oldCollectors are the old generation collectors of JDK 8 and 11 whose names do not say so:
// Parallel, Serial and CMS. A CMS cycle counts as a full collection, which errs on the safe side.
var oldCollectors = []string{"PSParallelCompact", "MSC", "CMS"}

func isFullCollector(name string) bool {
	if slices.Contains(oldCollectors, name) {
		return true
	}
	name = strings.ToLower(name)
	return strings.Contains(name, "full") || strings.Contains(name, "marksweep")
}

// isConcurrentCollector reports the collectors of ZGC ("Z ", and "ZGC " when generational)
// and Shenandoah. They collect the old generation concurrently, so there is no stop-the-world
// full collection to wait for. On JDK 17 the invocations of "Shenandoah full" also grew with
// concurrent cycles, so that counter is not read as one of full collections.
func isConcurrentCollector(name string) bool {
	return strings.HasPrefix(name, "Z ") || strings.HasPrefix(name, "ZGC ") || strings.HasPrefix(name, "Shenandoah")
}

func checkFullGC(in checkInput) *Refusal {
	window := in.Config.Checks.NoFullGCWithin
	frequency, okF := in.Perf.Long("sun.os.hrt.frequency")
	ticks, okT := in.Perf.Long("sun.os.hrt.ticks")
	if !okF || !okT || frequency <= 0 {
		return refuse(CheckRecentFullGC, "hsperfdata has no clock counters, so the age of the last full collection is unknown")
	}
	found, concurrent := false, false
	for i := 0; i < maxCounterGroups; i++ {
		prefix := fmt.Sprintf("sun.gc.collector.%d.", i)
		name, _ := in.Perf.Text(prefix + "name")
		if isConcurrentCollector(name) {
			concurrent = true
			continue
		}
		if !isFullCollector(name) {
			continue
		}
		found = true
		if n, _ := in.Perf.Long(prefix + "invocations"); n == 0 {
			continue
		}
		last, ok := in.Perf.Long(prefix + "lastExitTime")
		if !ok || last > ticks {
			return refuse(CheckRecentFullGC, "the time of the last full collection is not usable")
		}
		age := time.Duration(float64(ticks-last) / float64(frequency) * float64(time.Second))
		if age < window {
			return refuse(CheckRecentFullGC, "a full collection ended %s ago, within the last %s", age.Round(time.Second), window)
		}
	}
	if !found && !concurrent {
		return refuse(CheckRecentFullGC, "this garbage collector publishes no full collection counter, so the check cannot be evaluated")
	}
	return nil
}

// checkCPU measures the CPU use of the process over env.CPUWindow, relative to its CPU limit. It
// returns the text of the cpu_before row, the refusal when the use reached
// Checks.MaxCPUPercent or cannot be measured, and the error of ctx when it ended the wait.
func checkCPU(ctx context.Context, env Env, cfg Config, pid int) (string, *Refusal, error) {
	limit, err := env.Host.CPULimit(pid)
	if err != nil {
		return "", refuse(CheckCPUUsage, "cannot read the CPU limit of process %d: %v", pid, err), nil
	}
	if limit <= 0 {
		return "", refuse(CheckCPUUsage, "process %d has no usable CPU limit (%.2f CPUs)", pid, limit), nil
	}
	before, err := env.Host.CPUTicks(pid)
	if err != nil {
		return "", refuse(CheckCPUUsage, "cannot read the CPU time of process %d: %v", pid, err), nil
	}
	from := env.Now()
	sleep(ctx, env.CPUWindow)
	if err := ctxErr(ctx); err != nil {
		return "", nil, err
	}
	after, err := env.Host.CPUTicks(pid)
	if err != nil {
		return "", refuse(CheckCPUUsage, "cannot read the CPU time of process %d: %v", pid, err), nil
	}
	elapsed := env.Now().Sub(from)
	if after < before || elapsed <= 0 {
		return "", refuse(CheckCPUUsage, "the CPU time of process %d did not advance in order", pid), nil
	}
	percent := float64(after-before) / ticksPerSecond / elapsed.Seconds() / limit * 100
	window := elapsed.Round(100 * time.Millisecond)
	row := fmt.Sprintf("%.0f%% of the CPU limit (%.2f CPUs) over %s", percent, limit, window)
	if max := cfg.Checks.MaxCPUPercent; percent >= float64(max) {
		return row, refuse(CheckCPUUsage, "the JVM used %.0f%% of its CPU limit (%.2f CPUs) over %s, an L2 command needs it below %d%%", percent, limit, window, max), nil
	}
	return row, nil, nil
}

// clipText shortens text from a JVM for a message.
func clipText(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
