package perfdata

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

func summarize(t *testing.T, name string) Summary {
	t.Helper()
	p, err := Parse(sample(t, name))
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Summary()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestSummaryG1(t *testing.T) {
	s := summarize(t, "jdk17-g1")
	if s.JVM.Version != "17.0.20.1" || s.JVM.VMVersion != "17.0.20.1+1" || s.JVM.VMName == "" {
		t.Errorf("jvm = %+v", s.JVM)
	}
	if s.UptimeSeconds == nil || !near(*s.UptimeSeconds, 18.702695806) {
		t.Errorf("uptime = %v", s.UptimeSeconds)
	}
	h := s.Heap
	if h == nil || h.Used != 3619120 || h.Capacity != 26214408+40894488 {
		t.Fatalf("heap = %+v", h)
	}
	// G1 reports the whole heap limit in every generation; the limit is that value, not the sum.
	if h.MaxCapacity != 268435480 {
		t.Errorf("heap max = %d; want 268435480", h.MaxCapacity)
	}
	if len(h.Generations) != 2 || h.Generations[0].Name != "young" || h.Generations[1].Name != "old" {
		t.Fatalf("generations = %+v", h.Generations)
	}
	young := h.Generations[0]
	if young.Capacity != 40894488 || young.MaxCapacity != 268435480 || len(young.Spaces) != 3 {
		t.Errorf("young = %+v", young)
	}
	if got := young.Spaces[0]; got.Name != "eden" || got.Capacity != 40894472 || got.Used != 0 {
		t.Errorf("eden = %+v", got)
	}
	if old := h.Generations[1]; len(old.Spaces) != 1 || old.Spaces[0].Used != 3619120 {
		t.Errorf("old = %+v", old)
	}
	if m := s.Metaspace; m == nil || m.Used != 78872 || m.Capacity != 327680 || m.MaxCapacity != 1140850688 {
		t.Errorf("metaspace = %+v", m)
	}
	if s.CompressedClassSpace == nil {
		t.Error("compressed class space missing")
	}
	if s.GC.Policy != "GarbageFirst" || len(s.GC.Collectors) != 3 {
		t.Fatalf("gc = %+v", s.GC)
	}
	if c := s.GC.Collectors[0]; c.Name != "G1 young collection pauses" || c.Invocations != 1 || !near(c.TimeMS, 1.54283) {
		t.Errorf("collector 0 = %+v", c)
	}
	if c := s.GC.Collectors[1]; c.Name != "G1 full collection pauses" || c.Invocations != 1 || !near(c.TimeMS, 2.188617) {
		t.Errorf("collector 1 = %+v", c)
	}
	if c := s.GC.Collectors[2]; c.Invocations != 0 || c.TimeMS != 0 {
		t.Errorf("collector 2 = %+v", c)
	}
	// java.cls.loadedClasses (7) leaves out the classes read from the CDS archive
	// (java.cls.sharedLoadedClasses, 493), as ClassLoadingMXBean and jstat -class count them.
	if s.Classes != (Classes{Loaded: 7 + 493}) {
		t.Errorf("classes = %+v", s.Classes)
	}
	if s.Threads != (Threads{Live: 8, Daemon: 6, Peak: 8, Started: 8}) {
		t.Errorf("threads = %+v", s.Threads)
	}
}

func TestSummaryParallelSumsGenerationLimits(t *testing.T) {
	s := summarize(t, "jdk8-parallel")
	h := s.Heap
	if h == nil || h.Used != 4322088+2893352 || h.Capacity != 38797312+45088768 || h.MaxCapacity != 89128960+179306496 {
		t.Fatalf("heap = %+v", h)
	}
	if len(h.Generations) != 2 || h.Generations[0].Name != "new" || len(h.Generations[0].Spaces) != 3 {
		t.Errorf("generations = %+v", h.Generations)
	}
	if len(s.GC.Collectors) != 2 || s.GC.Collectors[0].Name != "PSScavenge" || s.GC.Collectors[0].Invocations != 2 || !near(s.GC.Collectors[0].TimeMS, 14.499061) {
		t.Errorf("collectors = %+v", s.GC.Collectors)
	}
	if s.Classes.Loaded != 584 {
		t.Errorf("classes = %+v", s.Classes)
	}
	if s.UptimeSeconds == nil || !near(*s.UptimeSeconds, 19.713062448) {
		t.Errorf("uptime = %v", s.UptimeSeconds)
	}
}

// ZGC publishes no young generation and only some collector slots.
func TestSummaryZGCHasSparseCounters(t *testing.T) {
	s := summarize(t, "jdk21-zgc")
	if s.Heap == nil || s.Heap.Used != 6291456 || s.Heap.Capacity != 67108864 || s.Heap.MaxCapacity != 268435456 {
		t.Errorf("heap = %+v", s.Heap)
	}
	if len(s.GC.Collectors) != 1 || s.GC.Collectors[0].Name != "Z concurrent cycle pauses" || s.GC.Collectors[0].Invocations != 3 {
		t.Errorf("collectors = %+v", s.GC.Collectors)
	}
}

func TestSummaryAllSamples(t *testing.T) {
	for _, smp := range samples {
		t.Run(smp.name, func(t *testing.T) {
			s := summarize(t, smp.name)
			if !strings.HasPrefix(s.JVM.Version, smp.version) {
				t.Errorf("version = %q", s.JVM.Version)
			}
			found := false
			for _, c := range s.GC.Collectors {
				found = found || c.Name == smp.collector
			}
			if !found {
				t.Errorf("collector %q missing from %+v", smp.collector, s.GC.Collectors)
			}
			if s.Heap == nil || s.Heap.Used <= 0 || s.Heap.Capacity <= 0 || s.Heap.MaxCapacity < s.Heap.Capacity {
				t.Errorf("heap = %+v", s.Heap)
			}
			if s.Metaspace == nil || s.Metaspace.Used <= 0 || s.Metaspace.Capacity < s.Metaspace.Used {
				t.Errorf("metaspace = %+v", s.Metaspace)
			}
			if s.Threads.Live < s.Threads.Daemon || s.Threads.Peak < s.Threads.Live || s.Threads.Daemon < 1 {
				t.Errorf("threads = %+v", s.Threads)
			}
			if s.Classes.Loaded < 400 {
				t.Errorf("classes = %+v", s.Classes)
			}
			if s.UptimeSeconds == nil || *s.UptimeSeconds <= 0 || *s.UptimeSeconds > 600 {
				t.Errorf("uptime = %v", s.UptimeSeconds)
			}
		})
	}
}

// The summary is what callers see. None of the values that may hold secrets or
// reveal the application may appear in it.
func TestSummaryJSONOmitsSensitiveCounters(t *testing.T) {
	for _, smp := range samples {
		s := summarize(t, smp.name)
		out, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"--note", "hello", "com.example", "Sample", "-Xmx", "-Xms", "UseG1GC", "/opt/java", "/app", "javaCommand", "vmArgs", "vmFlags", "class.path", "library.path"} {
			if strings.Contains(string(out), forbidden) {
				t.Errorf("%s: summary contains %q: %s", smp.name, forbidden, out)
			}
		}
	}
}

func TestSummaryDoesNotCarryInjectedSecrets(t *testing.T) {
	b := newBuilder(binary.LittleEndian)
	b.long("java.threads.live", 3).long("java.threads.daemon", 1).long("java.threads.livePeak", 3).long("java.threads.started", 3)
	b.long("java.cls.loadedClasses", 10)
	b.text("java.property.java.version", "17.0.1")
	b.text("java.rt.vmArgs", "-Ddb.password=CANARY-vmargs")
	b.text("java.rt.vmFlags", "-XX:Flag=CANARY-vmflags")
	b.text("sun.rt.javaCommand", "app.Main --token=CANARY-command")
	b.text("java.property.java.class.path", "/srv/CANARY-classpath.jar")
	b.text("java.property.user.name", "CANARY-user")
	p, err := Parse(b.bytes())
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Summary()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(s)
	if strings.Contains(string(out), "CANARY") || strings.Contains(p.String(), "CANARY") {
		t.Errorf("secret leaked: %s / %s", out, p)
	}
}

func TestSummaryOmitsUptimeWithoutFrequency(t *testing.T) {
	b := newBuilder(binary.LittleEndian)
	b.long("java.threads.live", 3).long("java.threads.daemon", 1).long("java.threads.livePeak", 3).long("java.cls.loadedClasses", 10)
	b.long("sun.os.hrt.ticks", 5e9).long("sun.os.hrt.frequency", 0)
	b.text("java.property.java.version", "17.0.1")
	p, err := Parse(b.bytes())
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Summary()
	if err != nil {
		t.Fatal(err)
	}
	if s.UptimeSeconds != nil {
		t.Errorf("uptime = %v; want none", *s.UptimeSeconds)
	}
	if s.Heap != nil || s.Metaspace != nil {
		t.Errorf("absent counters were invented: %+v %+v", s.Heap, s.Metaspace)
	}
}

func TestSummaryRejectsFilesWithoutThreadCounters(t *testing.T) {
	p, err := Parse(newBuilder(binary.LittleEndian).long("something.else", 1).bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Summary(); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v; want ErrIncomplete", err)
	}
}

// Classes loaded from the CDS archive are counted apart; the figures are the sum.
func TestSummaryCountsSharedClasses(t *testing.T) {
	build := func(extra func(*builder)) Summary {
		b := newBuilder(binary.LittleEndian)
		b.long("java.threads.live", 3)
		extra(b)
		p, err := Parse(b.bytes())
		if err != nil {
			t.Fatal(err)
		}
		s, err := p.Summary()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := build(func(b *builder) {
		b.long("java.cls.loadedClasses", 10).long("java.cls.unloadedClasses", 2)
		b.long("java.cls.sharedLoadedClasses", 5).long("java.cls.sharedUnloadedClasses", 1)
	})
	if s.Classes != (Classes{Loaded: 15, Unloaded: 3}) {
		t.Errorf("classes = %+v; want loaded 15, unloaded 3", s.Classes)
	}
	// A JVM without the shared counters, and a shared counter alone.
	if s := build(func(b *builder) { b.long("java.cls.loadedClasses", 10) }); s.Classes != (Classes{Loaded: 10}) {
		t.Errorf("no shared counters: classes = %+v", s.Classes)
	}
	if s := build(func(b *builder) { b.long("java.cls.sharedLoadedClasses", 5) }); s.Classes != (Classes{Loaded: 5}) {
		t.Errorf("only shared counter: classes = %+v", s.Classes)
	}
	// Forged values do not overflow.
	s = build(func(b *builder) {
		b.long("java.cls.loadedClasses", math.MaxInt64).long("java.cls.sharedLoadedClasses", 7)
	})
	if s.Classes.Loaded != math.MaxInt64 {
		t.Errorf("forged counters: loaded = %d; want saturation at MaxInt64", s.Classes.Loaded)
	}
}
