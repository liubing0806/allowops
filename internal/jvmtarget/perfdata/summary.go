package perfdata

import (
	"fmt"
	"math"
)

// Summary is the operator-facing view of a PerfData file. It contains no JVM
// arguments, no sun.rt.javaCommand and no system property values except the
// three version properties.
type Summary struct {
	JVM           VersionInfo `json:"jvm"`
	UptimeSeconds *float64    `json:"uptime_seconds,omitempty"`
	Heap          *Heap       `json:"heap,omitempty"`
	Metaspace     *Memory     `json:"metaspace,omitempty"`
	// CompressedClassSpace is absent when compressed class pointers are off.
	CompressedClassSpace *Memory `json:"compressed_class_space,omitempty"`
	GC                   GC      `json:"gc"`
	Classes              Classes `json:"classes"`
	Threads              Threads `json:"threads"`
}

// VersionInfo carries java.version, java.vm.name and java.vm.version.
type VersionInfo struct {
	Version   string `json:"version,omitempty"`
	VMName    string `json:"vm_name,omitempty"`
	VMVersion string `json:"vm_version,omitempty"`
}

// Memory values are bytes.
type Memory struct {
	Used        int64 `json:"used"`
	Capacity    int64 `json:"capacity"`
	MaxCapacity int64 `json:"max_capacity"`
}

// Heap sums the spaces of all generations. MaxCapacity is the heap limit.
type Heap struct {
	Used        int64        `json:"used"`
	Capacity    int64        `json:"capacity"`
	MaxCapacity int64        `json:"max_capacity"`
	Generations []Generation `json:"generations"`
}

type Generation struct {
	Name        string  `json:"name"`
	Capacity    int64   `json:"capacity"`
	MaxCapacity int64   `json:"max_capacity"`
	Spaces      []Space `json:"spaces"`
}

type Space struct {
	Name        string `json:"name"`
	Used        int64  `json:"used"`
	Capacity    int64  `json:"capacity"`
	MaxCapacity int64  `json:"max_capacity"`
}

type GC struct {
	Policy     string      `json:"policy,omitempty"`
	Collectors []Collector `json:"collectors"`
}

type Collector struct {
	Name        string  `json:"name"`
	Invocations int64   `json:"invocations"`
	TimeMS      float64 `json:"time_ms"`
}

type Classes struct {
	Loaded   int64 `json:"loaded"`
	Unloaded int64 `json:"unloaded"`
}

type Threads struct {
	Live    int64 `json:"live"`
	Daemon  int64 `json:"daemon"`
	Peak    int64 `json:"peak"`
	Started int64 `json:"started"`
}

// The counters come in numbered groups (generations, spaces, collectors). The
// group numbers are small; the scan stops at these bounds.
const (
	maxGenerations = 16
	maxSpaces      = 16
	maxCollectors  = 16
)

// Summary extracts the summary. It fails when the file lacks the thread
// counters every supported JVM publishes. Counters that only some JVMs publish
// (a young generation under ZGC, compressed class space without compressed
// class pointers) are left out.
func (p *PerfData) Summary() (Summary, error) {
	live, ok := p.Long("java.threads.live")
	if !ok {
		return Summary{}, ErrIncomplete
	}
	var s Summary
	s.Threads.Live = live
	s.Threads.Daemon, _ = p.Long("java.threads.daemon")
	s.Threads.Peak, _ = p.Long("java.threads.livePeak")
	s.Threads.Started, _ = p.Long("java.threads.started")
	// Classes read from the CDS archive are counted apart (JDK 11 and later load most
	// startup classes that way); ClassLoadingMXBean and jstat -class add them.
	loaded, _ := p.Long("java.cls.loadedClasses")
	shared, _ := p.Long("java.cls.sharedLoadedClasses")
	s.Classes.Loaded = addSaturating(loaded, shared)
	unloaded, _ := p.Long("java.cls.unloadedClasses")
	sharedUnloaded, _ := p.Long("java.cls.sharedUnloadedClasses")
	s.Classes.Unloaded = addSaturating(unloaded, sharedUnloaded)
	s.JVM.Version, _ = p.Text("java.property.java.version")
	s.JVM.VMName, _ = p.Text("java.property.java.vm.name")
	s.JVM.VMVersion, _ = p.Text("java.property.java.vm.version")

	frequency, _ := p.Long("sun.os.hrt.frequency")
	if ticks, ok := p.Long("sun.os.hrt.ticks"); ok && frequency > 0 && ticks >= 0 {
		uptime := float64(ticks) / float64(frequency)
		s.UptimeSeconds = &uptime
	}
	s.GC.Policy, _ = p.Text("sun.gc.policy.name")
	s.GC.Collectors = p.collectors(frequency)
	s.Heap = p.heap(s.GC.Policy)
	s.Metaspace = p.memory("sun.gc.metaspace.")
	s.CompressedClassSpace = p.memory("sun.gc.compressedclassspace.")
	return s, nil
}

func (p *PerfData) memory(prefix string) *Memory {
	capacity, ok := p.Long(prefix + "capacity")
	if !ok {
		return nil
	}
	m := &Memory{Capacity: capacity}
	m.Used, _ = p.Long(prefix + "used")
	m.MaxCapacity, _ = p.Long(prefix + "maxCapacity")
	return m
}

func (p *PerfData) collectors(frequency int64) []Collector {
	collectors := []Collector{}
	for i := 0; i < maxCollectors; i++ {
		prefix := fmt.Sprintf("sun.gc.collector.%d.", i)
		name, ok := p.Text(prefix + "name")
		if !ok {
			continue
		}
		c := Collector{Name: name}
		c.Invocations, _ = p.Long(prefix + "invocations")
		if ticks, ok := p.Long(prefix + "time"); ok && frequency > 0 {
			c.TimeMS = float64(ticks) * 1000 / float64(frequency)
		}
		collectors = append(collectors, c)
	}
	return collectors
}

// heap sums the generations. G1 reports the limit of the whole heap in each
// generation, so for it the limit is that value; for the other collectors the
// generation limits add up to the heap limit.
func (p *PerfData) heap(policy string) *Heap {
	h := &Heap{Generations: []Generation{}}
	for i := 0; i < maxGenerations; i++ {
		prefix := fmt.Sprintf("sun.gc.generation.%d.", i)
		name, ok := p.Text(prefix + "name")
		if !ok {
			continue
		}
		g := Generation{Name: name, Spaces: []Space{}}
		g.Capacity, _ = p.Long(prefix + "capacity")
		g.MaxCapacity, _ = p.Long(prefix + "maxCapacity")
		for j := 0; j < maxSpaces; j++ {
			sp := fmt.Sprintf("%sspace.%d.", prefix, j)
			spaceName, ok := p.Text(sp + "name")
			if !ok {
				continue
			}
			space := Space{Name: spaceName}
			space.Used, _ = p.Long(sp + "used")
			space.Capacity, _ = p.Long(sp + "capacity")
			space.MaxCapacity, _ = p.Long(sp + "maxCapacity")
			g.Spaces = append(g.Spaces, space)
			h.Used = addSaturating(h.Used, space.Used)
		}
		h.Capacity = addSaturating(h.Capacity, g.Capacity)
		if policy == "GarbageFirst" {
			h.MaxCapacity = max(h.MaxCapacity, g.MaxCapacity)
		} else {
			h.MaxCapacity = addSaturating(h.MaxCapacity, g.MaxCapacity)
		}
		h.Generations = append(h.Generations, g)
	}
	if len(h.Generations) == 0 {
		return nil
	}
	return h
}

// addSaturating adds counters from a file that may be forged, so the sum cannot wrap around.
func addSaturating(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	if b < 0 && a < math.MinInt64-b {
		return math.MinInt64
	}
	return a + b
}
