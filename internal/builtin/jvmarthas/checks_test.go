package jvmarthas

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/jvmtarget/perfdata"
)

var checkNow = time.Unix(1_700_000_000, 0).UTC()

// perf builds the counters of a healthy JDK 17 with G1: 100 threads, an old generation of
// 100 of 512 MB, 50 MB of metaspace, no MaxMetaspaceSize and one full collection long ago.
func perf(mutate ...func(e map[string]perfdata.Entry)) *perfdata.PerfData {
	e := map[string]perfdata.Entry{}
	text := func(name, v string) { e[name] = perfdata.Entry{Name: name, Kind: perfdata.KindText, Text: v} }
	long := func(name string, v int64) { e[name] = perfdata.Entry{Name: name, Kind: perfdata.KindLong, Long: v} }
	text("java.property.java.version", "17.0.20")
	text("java.rt.vmArgs", "-Xmx512m -Dpassword=hunter2")
	text("java.rt.vmFlags", "")
	long("java.threads.live", 100)
	long("sun.gc.metaspace.used", 50<<20)
	long("sun.gc.metaspace.capacity", 52<<20)
	long("sun.os.hrt.frequency", 1_000_000_000)
	long("sun.os.hrt.ticks", 1_000_000_000_000)
	text("sun.gc.generation.1.name", "old")
	long("sun.gc.generation.1.capacity", 256<<20)
	long("sun.gc.generation.1.maxCapacity", 512<<20)
	text("sun.gc.generation.1.space.0.name", "space")
	long("sun.gc.generation.1.space.0.used", 100<<20)
	text("sun.gc.collector.0.name", "G1 young collection pauses")
	long("sun.gc.collector.0.invocations", 40)
	long("sun.gc.collector.0.lastExitTime", 999_000_000_000)
	text("sun.gc.collector.1.name", "G1 full collection pauses")
	long("sun.gc.collector.1.invocations", 1)
	long("sun.gc.collector.1.lastExitTime", 500_000_000_000)
	for _, m := range mutate {
		m(e)
	}
	return &perfdata.PerfData{Major: 2, Minor: 0, Entries: e}
}

func setText(name, v string) func(map[string]perfdata.Entry) {
	return func(e map[string]perfdata.Entry) {
		e[name] = perfdata.Entry{Name: name, Kind: perfdata.KindText, Text: v}
	}
}

func setLong(name string, v int64) func(map[string]perfdata.Entry) {
	return func(e map[string]perfdata.Entry) {
		e[name] = perfdata.Entry{Name: name, Kind: perfdata.KindLong, Long: v}
	}
}

func drop(names ...string) func(map[string]perfdata.Entry) {
	return func(e map[string]perfdata.Entry) {
		for _, n := range names {
			delete(e, n)
		}
	}
}

// checkCase is one run of the checks; change adjusts the passing input.
type checkCase struct {
	name   string
	change func(*checkInput)
	// want is the check that must refuse the call; empty when the call passes.
	want string
	// mention is a text the reason must contain.
	mention string
}

func passingInput(t *testing.T) checkInput {
	t.Helper()
	cmd, err := arthas.Build(arthas.Request{Kind: arthas.KindDashboard}, arthas.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	return checkInput{
		Config: goodConfig().Effective(), Command: cmd, PID: 4242, Perf: perf(),
		Counter: Counter{}, Now: checkNow, Host: &fakeHost{headroom: 1 << 30}, Arch: "amd64",
	}
}

func runCheckCases(t *testing.T, cases []checkCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := passingInput(t)
			tc.change(&in)
			got := runChecks(in)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("refused: %v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("passed; want a refusal by %s", tc.want)
			}
			if got.Check != tc.want {
				t.Errorf("refused by %s (%s), want %s", got.Check, got.Reason, tc.want)
			}
			if tc.mention != "" && !strings.Contains(got.Reason, tc.mention) {
				t.Errorf("reason %q does not mention %q", got.Reason, tc.mention)
			}
			if strings.Contains(got.Reason, "hunter2") {
				t.Errorf("reason %q repeats the JVM arguments", got.Reason)
			}
		})
	}
}

func TestChecksPassForAHealthyJVM(t *testing.T) {
	if r := runChecks(passingInput(t)); r != nil {
		t.Fatalf("refused: %v", r)
	}
}

func TestCheckJVMVersion(t *testing.T) {
	version := func(v string) func(*checkInput) {
		return func(in *checkInput) { in.Perf = perf(setText("java.property.java.version", v)) }
	}
	runCheckCases(t, []checkCase{
		{"jdk 8", version("1.8.0_504"), "", ""},
		{"jdk 8 other update", version("1.8.0_999"), "", ""},
		{"jdk 11", version("11.0.32"), "", ""},
		{"jdk 17", version("17.0.20"), "", ""},
		{"jdk 21", version("21.0.12"), "", ""},
		{"jdk 21 early access", version("21-ea"), "", ""},
		{"jdk 7", version("1.7.0_80"), CheckJVMVersion, "1.7.0_80"},
		{"jdk 9", version("9.0.4"), CheckJVMVersion, ""},
		{"jdk 10", version("10.0.2"), CheckJVMVersion, ""},
		{"jdk 22", version("22.0.1"), CheckJVMVersion, ""},
		{"not a version", version("banana"), CheckJVMVersion, ""},
		{"empty version", version(""), CheckJVMVersion, ""},
		{"no version counter", func(in *checkInput) { in.Perf = perf(drop("java.property.java.version")) }, CheckJVMVersion, ""},
	})
}

func TestCheckArchitecture(t *testing.T) {
	runCheckCases(t, []checkCase{
		{"amd64", func(in *checkInput) { in.Arch = "amd64" }, "", ""},
		{"arm64", func(in *checkInput) { in.Arch = "arm64" }, CheckArchitecture, "arm64"},
	})
}

func TestCheckMemoryHeadroom(t *testing.T) {
	headroom := func(n int64) func(*checkInput) {
		return func(in *checkInput) { in.Host = &fakeHost{headroom: n} }
	}
	runCheckCases(t, []checkCase{
		{"exactly the default", headroom(256 << 20), "", ""},
		{"one byte below the default", headroom(256<<20 - 1), CheckMemoryHeadroom, "256"},
		{"no memory left", headroom(0), CheckMemoryHeadroom, ""},
		{"raised threshold", func(in *checkInput) {
			in.Config.Checks.MinMemoryHeadroom = 512 << 20
			in.Host = &fakeHost{headroom: 400 << 20}
		}, CheckMemoryHeadroom, "512"},
		{"cgroup cannot be read", func(in *checkInput) { in.Host = &fakeHost{headroomErr: errors.New("no cgroup")} }, CheckMemoryHeadroom, "no cgroup"},
	})
}

func TestCheckMetaspaceHeadroom(t *testing.T) {
	limit := func(args, flags string, used int64) func(*checkInput) {
		return func(in *checkInput) {
			in.Perf = perf(setText("java.rt.vmArgs", args), setText("java.rt.vmFlags", flags), setLong("sun.gc.metaspace.used", used))
		}
	}
	runCheckCases(t, []checkCase{
		{"no MaxMetaspaceSize skips the check", limit("-Xmx512m", "", 900<<20), "", ""},
		{"enough room", limit("-XX:MaxMetaspaceSize=256m", "", 100<<20), "", ""},
		{"exactly the default", limit("-XX:MaxMetaspaceSize=256m", "", 192<<20), "", ""},
		{"one byte below the default", limit("-XX:MaxMetaspaceSize=256m", "", 192<<20+1), CheckMetaspace, "64"},
		{"limit given in bytes in the flags", limit("", "-XX:MaxMetaspaceSize=268435456", 200<<20), CheckMetaspace, ""},
		{"limit in kilobytes", limit("-XX:MaxMetaspaceSize=262144k", "", 200<<20), CheckMetaspace, ""},
		{"limit in gigabytes", limit("-XX:MaxMetaspaceSize=1g", "", 200<<20), "", ""},
		{"the last occurrence wins", limit("-XX:MaxMetaspaceSize=64m -Xmx1g -XX:MaxMetaspaceSize=1g", "", 200<<20), "", ""},
		{"other options with the same prefix are not it", limit("-XX:MaxMetaspaceFreeRatio=70 -XX:MetaspaceSize=21m", "", 900<<20), "", ""},
		{"used counter is missing", func(in *checkInput) {
			in.Perf = perf(setText("java.rt.vmArgs", "-XX:MaxMetaspaceSize=256m"), drop("sun.gc.metaspace.used"))
		}, CheckMetaspace, "sun.gc.metaspace.used"},
		{"raised threshold", func(in *checkInput) {
			in.Config.Checks.MinMetaspaceHeadroom = 128 << 20
			in.Perf = perf(setText("java.rt.vmArgs", "-XX:MaxMetaspaceSize=256m"), setLong("sun.gc.metaspace.used", 150<<20))
		}, CheckMetaspace, "128"},
	})
}

func TestCheckAttachCount(t *testing.T) {
	count := func(n int) func(*checkInput) {
		return func(in *checkInput) { in.Counter = Counter{Attaches: n, LastAttach: checkNow.Add(-time.Hour)} }
	}
	runCheckCases(t, []checkCase{
		{"first attach", count(0), "", ""},
		{"fourth attach", count(3), "", ""},
		{"fifth attach", count(4), "", ""},
		{"sixth attach", count(5), CheckAttachCount, "5"},
		{"many attaches", count(50), CheckAttachCount, ""},
		{"lowered limit", func(in *checkInput) {
			in.Config.Checks.MaxAttaches = 2
			in.Counter = Counter{Attaches: 2, LastAttach: checkNow.Add(-time.Hour)}
		}, CheckAttachCount, "2"},
	})
}

func TestCheckAttachInterval(t *testing.T) {
	last := func(ago time.Duration) func(*checkInput) {
		return func(in *checkInput) { in.Counter = Counter{Attaches: 1, LastAttach: checkNow.Add(-ago)} }
	}
	runCheckCases(t, []checkCase{
		{"never attached", func(in *checkInput) { in.Counter = Counter{} }, "", ""},
		{"exactly the interval ago", last(60 * time.Second), "", ""},
		{"one second too early", last(59 * time.Second), CheckAttachInterval, "1s"},
		{"just now", last(0), CheckAttachInterval, "1m0s"},
		{"a clock that went back", last(-time.Hour), CheckAttachInterval, ""},
		{"raised interval", func(in *checkInput) {
			in.Config.Checks.MinAttachInterval = 5 * time.Minute
			last(2 * time.Minute)(in)
		}, CheckAttachInterval, "3m0s"},
	})
}

func TestCheckThreadCountOnlyForThreadBlocking(t *testing.T) {
	blocking := func(in *checkInput, live int64) {
		cmd, err := arthas.Build(arthas.Request{Kind: arthas.KindThreadBlocking}, arthas.Policy{})
		if err != nil {
			t.Fatal(err)
		}
		in.Command = cmd
		in.Perf = perf(setLong("java.threads.live", live))
	}
	runCheckCases(t, []checkCase{
		{"500 threads", func(in *checkInput) { blocking(in, 500) }, "", ""},
		{"501 threads", func(in *checkInput) { blocking(in, 501) }, CheckThreadCount, "501"},
		{"lowered limit", func(in *checkInput) { in.Config.Checks.MaxBlockingThreads = 50; blocking(in, 51) }, CheckThreadCount, "50"},
		{"no thread counter", func(in *checkInput) { blocking(in, 0); in.Perf = perf(drop("java.threads.live")) }, CheckThreadCount, "java.threads.live"},
		{"another command is not limited", func(in *checkInput) { in.Perf = perf(setLong("java.threads.live", 5000)) }, "", ""},
	})
}

func TestCheckOldGeneration(t *testing.T) {
	old := func(used int64) func(*checkInput) {
		return func(in *checkInput) {
			in.Config.Checks.MaxOldGenPercent = 80
			in.Perf = perf(setLong("sun.gc.generation.1.space.0.used", used))
		}
	}
	runCheckCases(t, []checkCase{
		{"not configured, nearly full", func(in *checkInput) { in.Perf = perf(setLong("sun.gc.generation.1.space.0.used", 510<<20)) }, "", ""},
		{"below the threshold", old(400 << 20), "", ""},
		{"at the threshold", old((512 << 20) * 8 / 10), "", ""},
		{"above the threshold", old(420 << 20), CheckOldGenUsage, "80"},
		{"full", old(512 << 20), CheckOldGenUsage, ""},
		{"no old generation counters", func(in *checkInput) {
			in.Config.Checks.MaxOldGenPercent = 80
			in.Perf = perf(drop("sun.gc.generation.1.name"))
		}, CheckOldGenUsage, "old generation"},
		{"old generation without a limit", func(in *checkInput) {
			in.Config.Checks.MaxOldGenPercent = 80
			in.Perf = perf(setLong("sun.gc.generation.1.maxCapacity", 0))
		}, CheckOldGenUsage, "limit"},
	})
}

func TestCheckRecentFullGC(t *testing.T) {
	ended := func(ago time.Duration) func(*checkInput) {
		return func(in *checkInput) {
			in.Config.Checks.NoFullGCWithin = 30 * time.Second
			in.Perf = perf(setLong("sun.gc.collector.1.lastExitTime", 1_000_000_000_000-int64(ago)))
		}
	}
	runCheckCases(t, []checkCase{
		{"not configured, just ended", func(in *checkInput) { in.Perf = perf(setLong("sun.gc.collector.1.lastExitTime", 1_000_000_000_000)) }, "", ""},
		{"ended long ago", ended(10 * time.Minute), "", ""},
		{"ended exactly the window ago", ended(30 * time.Second), "", ""},
		{"ended inside the window", ended(10 * time.Second), CheckRecentFullGC, "10s"},
		{"never happened", func(in *checkInput) {
			ended(time.Second)(in)
			in.Perf = perf(setLong("sun.gc.collector.1.invocations", 0), setLong("sun.gc.collector.1.lastExitTime", 1_000_000_000_000))
		}, "", ""},
		{"parallel collector names", func(in *checkInput) {
			in.Config.Checks.NoFullGCWithin = 30 * time.Second
			in.Perf = perf(setText("sun.gc.collector.1.name", "Parallel full collection pauses"), setLong("sun.gc.collector.1.lastExitTime", 1_000_000_000_000-int64(5*time.Second)))
		}, CheckRecentFullGC, ""},
		{"mark sweep names of JDK 8", func(in *checkInput) {
			in.Config.Checks.NoFullGCWithin = 30 * time.Second
			in.Perf = perf(setText("sun.gc.collector.1.name", "PSMarkSweep"), setLong("sun.gc.collector.1.lastExitTime", 1_000_000_000_000-int64(5*time.Second)))
		}, CheckRecentFullGC, ""},
		{"a collector without full collections", func(in *checkInput) {
			in.Config.Checks.NoFullGCWithin = 30 * time.Second
			in.Perf = perf(drop("sun.gc.collector.1.name", "sun.gc.collector.1.invocations", "sun.gc.collector.1.lastExitTime"),
				setText("sun.gc.collector.2.name", "Z concurrent cycle pauses"))
		}, CheckRecentFullGC, "full collection"},
	})
}

func TestCheckOrderPutsTheCheapAndDefiniteChecksFirst(t *testing.T) {
	in := passingInput(t)
	in.Perf = perf(setText("java.property.java.version", "1.7.0_80"), setLong("java.threads.live", 9999))
	in.Counter = Counter{Attaches: 9, LastAttach: checkNow}
	in.Host = &fakeHost{headroom: 0}
	r := runChecks(in)
	if r == nil || r.Check != CheckJVMVersion {
		t.Errorf("refusal = %v, want the version check first", r)
	}
}
