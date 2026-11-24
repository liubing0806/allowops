package cluster

import (
	"math"
	"slices"
	"strings"
)

// MetricVariance describes the numeric distribution of a single normalized
// slot across hosts within a cluster. All float64 fields are guaranteed finite.
type MetricVariance struct {
	Label        string
	Unit         string
	Min          float64
	P50          float64
	P95          float64
	Max          float64
	MinHost      string
	MaxHost      string
	OutlierHosts []string
}

type metricSample struct {
	host  string
	value float64
}

type slotBucket struct {
	label   string
	unit    string
	samples []metricSample
}

type clusterMetrics struct {
	byLabel map[string]*slotBucket
	order   []string
}

func newClusterMetrics() *clusterMetrics {
	return &clusterMetrics{
		byLabel: make(map[string]*slotBucket, 8),
	}
}

func (m *clusterMetrics) addHostSlots(hostname string, slots []MetricSlot) {
	if len(slots) == 0 {
		return
	}
	for _, sl := range slots {
		if sl.Label == "" || !isFiniteFloat(sl.Value) {
			continue
		}
		b, ok := m.byLabel[sl.Label]
		if !ok {
			if len(m.order) >= MaxSlotsPerCluster {
				continue
			}
			b = &slotBucket{
				label: sl.Label,
				unit:  sl.Unit,
			}
			m.byLabel[sl.Label] = b
			m.order = append(m.order, sl.Label)
		}
		if len(b.samples) < MaxSamplesPerSlot {
			b.samples = append(b.samples, metricSample{
				host:  hostname,
				value: sl.Value,
			})
		}
	}
}

type computedVariance struct {
	variance    MetricVariance
	relSpan     float64
	typicalHost string
	extremeHost string
}

// summarize computes up to MaxReportedVariances sorted by outlier presence,
// relative span descending, and label ascending. It also returns smart concise
// sample hosts (typicalHost, extremeHost) if any outlier was detected.
func (m *clusterMetrics) summarize() ([]MetricVariance, string, string) {
	if m == nil || len(m.order) == 0 {
		return nil, "", ""
	}

	var candidates []computedVariance
	for _, lbl := range m.order {
		b := m.byLabel[lbl]
		if len(b.samples) < 2 {
			continue
		}
		cv, ok := computeSlotVariance(b)
		if !ok {
			continue
		}
		candidates = append(candidates, cv)
	}
	if len(candidates) == 0 {
		return nil, "", ""
	}

	slices.SortFunc(candidates, func(a, b computedVariance) int {
		aOut := len(a.variance.OutlierHosts) > 0
		bOut := len(b.variance.OutlierHosts) > 0
		if aOut != bOut {
			if aOut {
				return -1
			}
			return 1
		}
		if a.relSpan != b.relSpan {
			if a.relSpan > b.relSpan {
				return -1
			}
			return 1
		}
		return strings.Compare(a.variance.Label, b.variance.Label)
	})

	if len(candidates) > MaxReportedVariances {
		candidates = candidates[:MaxReportedVariances]
	}

	out := make([]MetricVariance, len(candidates))
	for i, c := range candidates {
		out[i] = c.variance
	}
	var typicalHost, extremeHost string
	if len(candidates[0].variance.OutlierHosts) > 0 {
		typicalHost = candidates[0].typicalHost
		extremeHost = candidates[0].extremeHost
	}
	return out, typicalHost, extremeHost
}

func computeSlotVariance(b *slotBucket) (computedVariance, bool) {
	n := len(b.samples)
	sorted := make([]metricSample, n)
	copy(sorted, b.samples)
	slices.SortFunc(sorted, func(a, c metricSample) int {
		if a.value < c.value {
			return -1
		}
		if a.value > c.value {
			return 1
		}
		return strings.Compare(a.host, c.host)
	})

	minS := sorted[0]
	maxS := sorted[n-1]
	if minS.value == maxS.value {
		return computedVariance{}, false
	}

	p50 := medianSamples(sorted)
	p95Idx := int(math.Ceil(0.95*float64(n))) - 1
	if p95Idx < 0 {
		p95Idx = 0
	}
	if p95Idx >= n {
		p95Idx = n - 1
	}
	p95 := sorted[p95Idx].value

	if !isFiniteFloat(minS.value) || !isFiniteFloat(p50) || !isFiniteFloat(p95) || !isFiniteFloat(maxS.value) {
		return computedVariance{}, false
	}

	var outliers []string
	var typicalHost, extremeHost string
	if n >= 5 {
		devs := make([]float64, n)
		for i, s := range sorted {
			devs[i] = math.Abs(s.value - p50)
		}
		slices.Sort(devs)
		mad := medianFloat64(devs)

		type outlierCand struct {
			host string
			dev  float64
		}
		var cands []outlierCand
		for _, s := range sorted {
			dev := math.Abs(s.value - p50)
			if !isFiniteFloat(dev) {
				continue
			}
			isOutlier := false
			if mad == 0 {
				isOutlier = s.value != p50
			} else {
				isOutlier = dev > 4.5*mad && relDiff(s.value, p50) >= 0.25
			}
			if isOutlier {
				cands = append(cands, outlierCand{host: s.host, dev: dev})
			}
		}

		if len(cands) > 0 {
			slices.SortFunc(cands, func(a, c outlierCand) int {
				if a.dev > c.dev {
					return -1
				}
				if a.dev < c.dev {
					return 1
				}
				return strings.Compare(a.host, c.host)
			})
			seen := make(map[string]struct{}, MaxOutlierHosts)
			for _, oc := range cands {
				if _, dup := seen[oc.host]; dup {
					continue
				}
				seen[oc.host] = struct{}{}
				outliers = append(outliers, oc.host)
				if len(outliers) >= MaxOutlierHosts {
					break
				}
			}
			extremeHost = outliers[0]
			// Pick typicalHost closest to p50 (excluding extremeHost).
			bestDev := math.Inf(1)
			for _, s := range sorted {
				if s.host == extremeHost {
					continue
				}
				d := math.Abs(s.value - p50)
				if d < bestDev || (d == bestDev && (typicalHost == "" || s.host < typicalHost)) {
					bestDev = d
					typicalHost = s.host
				}
			}
		}
	}

	span := (maxS.value - minS.value) / math.Max(math.Abs(p50), 1.0)
	if !isFiniteFloat(span) {
		span = 0
	}

	return computedVariance{
		variance: MetricVariance{
			Label:        SanitizeLabel(b.label),
			Unit:         SanitizeLabel(b.unit),
			Min:          minS.value,
			P50:          p50,
			P95:          p95,
			Max:          maxS.value,
			MinHost:      minS.host,
			MaxHost:      maxS.host,
			OutlierHosts: outliers,
		},
		relSpan:     span,
		typicalHost: typicalHost,
		extremeHost: extremeHost,
	}, true
}

func relDiff(x, med float64) float64 {
	d := math.Abs(x-med) / math.Max(math.Abs(med), 1.0)
	if !isFiniteFloat(d) {
		return 0
	}
	return d
}

func medianSamples(sorted []metricSample) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2].value
	}
	lo := sorted[n/2-1].value
	hi := sorted[n/2].value
	return lo + (hi-lo)/2.0
}

func medianFloat64(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	lo := sorted[n/2-1]
	hi := sorted[n/2]
	return lo + (hi-lo)/2.0
}
