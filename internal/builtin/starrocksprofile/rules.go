package starrocksprofile

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Thresholds are the rule limits. The defaults are the plan's initial values
// where the plan gave one; see docs/builtin-starrocks.md for the calibration.
type Thresholds struct {
	// Time shares are fractions of the summed operator time.
	ScanTimeShare    float64
	ScanRows         int64
	ScanBytes        int64
	ProjectTimeShare float64
	SortTimeShare    float64
	// MinOperatorTime is the least operator time for the share rules to fire.
	MinOperatorTime time.Duration
	// AggMemoryShare is the hash table size as a fraction of the query peak memory.
	AggMemoryShare float64
	AggMinMemory   int64
	JoinExpansion  float64
	// JoinMinOutputRows is the least probe output for SR-JOIN-2.
	JoinMinOutputRows int64
	ExchangeBytes     int64
	SkewRatio         float64
	SkewMinTime       time.Duration
	// MemLimitShare is the fraction of query_mem_limit that counts as "near the limit".
	MemLimitShare float64
}

// DefaultThresholds returns the thresholds starrocks_diag uses.
func DefaultThresholds() Thresholds {
	return Thresholds{
		ScanTimeShare: 0.30, ScanRows: 100_000_000, ScanBytes: 10 << 30,
		ProjectTimeShare: 0.30, SortTimeShare: 0.30, MinOperatorTime: 10 * time.Millisecond,
		AggMemoryShare: 0.5, AggMinMemory: 128 << 20,
		JoinExpansion: 10, JoinMinOutputRows: 100_000,
		ExchangeBytes: 10 << 30,
		SkewRatio:     3, SkewMinTime: 10 * time.Millisecond,
		MemLimitShare: 0.9,
	}
}

// Evidence is one metric value that supports a finding.
type Evidence struct {
	Metric string  `json:"metric"`
	Value  float64 `json:"value"`
	Unit   string  `json:"unit"`
}

// Finding is a rule hit.
type Finding struct {
	Rule       string     `json:"rule"`
	Operator   string     `json:"operator,omitempty"`
	PlanNodeID *int       `json:"plan_node_id,omitempty"`
	Evidence   []Evidence `json:"evidence"`
	Cause      string     `json:"cause"`
	Advice     string     `json:"advice"`
}

// maxFindingsPerRule keeps one noisy rule from filling the summary.
const maxFindingsPerRule = 5

type rule struct {
	id     string
	cause  string
	advice string
	check  func(p *Profile, t Thresholds, share func(*Operator) float64) []hit
}

type hit struct {
	op       *Operator
	evidence []Evidence
	score    float64
}

func ev(metric string, value float64, unit string) Evidence {
	return Evidence{Metric: metric, Value: value, Unit: unit}
}

func percent(v float64) float64 { return round1(v * 100) }

// memoryLimit returns the per-query memory limit: the exact session variable
// when it is set, otherwise the QueryMemoryLimit of the fragments (printed
// rounded, so it is approximate).
func (p *Profile) memoryLimit() int64 {
	if v, err := strconv.ParseInt(p.SessionVariables["query_mem_limit"], 10, 64); err == nil && v > 0 {
		return v
	}
	return p.QueryMemoryLimit
}

var aggregateOperators = []string{"AGGREGATE_BLOCKING_SINK", "AGGREGATE_BLOCKING_SOURCE", "AGGREGATE_STREAMING_SINK", "AGGREGATE_STREAMING_SOURCE", "AGGREGATE_DISTINCT_BLOCKING_SINK", "AGGREGATE_DISTINCT_BLOCKING_SOURCE", "AGGREGATE_DISTINCT_STREAMING_SINK", "AGGREGATE_DISTINCT_STREAMING_SOURCE"}

func isAggregate(name string) bool {
	return slices.Contains(aggregateOperators, name) || strings.HasPrefix(name, "AGGREGATE_") || strings.HasPrefix(name, "SPILLABLE_AGGREGATE_")
}

func isSortOrWindow(name string) bool {
	switch name {
	case "LOCAL_SORT_SINK", "SPILLABLE_LOCAL_SORT_SINK", "LOCAL_PARTITION_TOPN_SINK", "ANALYTIC_SINK", "ANALYTIC_SOURCE":
		return true
	}
	return false
}

// shareHits returns the operators accepted by match whose share of the total
// operator time reaches limit and whose time reaches the floor.
func shareHits(p *Profile, t Thresholds, share func(*Operator) float64, limit float64, match func(*Operator) bool) []hit {
	var hits []hit
	for _, o := range p.Operators {
		if !match(o) {
			continue
		}
		d, ok := o.effectiveTime()
		if s := share(o); ok && s >= limit && d >= t.MinOperatorTime {
			hits = append(hits, hit{o, []Evidence{ev("OperatorTotalTime", ms(d), "ms"), ev("time_share", percent(s), "percent")}, s})
		}
	}
	return hits
}

var rules = []rule{
	{
		id:     "SR-SCAN-1",
		cause:  "The scan reads a large amount of data and takes a large share of the query time: a full table scan over too much data, or a saturated disk.",
		advice: "Add a partition or bucket filter on the table; select only the needed columns.",
		check: func(p *Profile, t Thresholds, share func(*Operator) float64) []hit {
			var hits []hit
			for _, h := range shareHits(p, t, share, t.ScanTimeShare, func(o *Operator) bool { return o.Name == "OLAP_SCAN" }) {
				rows, _ := h.op.Count("RawRowsRead")
				bytes, _ := h.op.Bytes("BytesRead")
				if rows >= t.ScanRows || bytes >= t.ScanBytes {
					h.evidence = append(h.evidence, ev("RawRowsRead", float64(rows), "rows"), ev("BytesRead", float64(bytes), "bytes"))
					hits = append(hits, h)
				}
			}
			return hits
		},
	},
	{
		id:     "SR-PROJ-1",
		cause:  "Expressions in the projection take a large share of the query time: JSON extraction, nested CASE WHEN, or LIKE and regular expressions on wide columns.",
		advice: "Extract the needed fields once in a subquery; avoid expressions on wide columns.",
		check: func(p *Profile, t Thresholds, share func(*Operator) float64) []hit {
			return shareHits(p, t, share, t.ProjectTimeShare, func(o *Operator) bool { return o.Name == "PROJECT" })
		},
	},
	{
		id:     "SR-AGG-1",
		cause:  "The aggregation spilled to disk, or its hash table holds a large part of the query memory: wide columns in the aggregate, a skewed or high-cardinality key, or too little spill disk.",
		advice: "Remove wide columns from the aggregation; check the distribution of the grouping key.",
		check: func(p *Profile, t Thresholds, _ func(*Operator) float64) []hit {
			var hits []hit
			peak, _ := ParseBytes(p.Execution["QueryPeakMemoryUsagePerNode"])
			for _, o := range p.Operators {
				if !isAggregate(o.Name) {
					continue
				}
				if spill := o.SpillBytes(); spill > 0 {
					hits = append(hits, hit{o, []Evidence{ev("SpillBytes", float64(spill), "bytes")}, float64(spill)})
					continue
				}
				mem, ok := o.Bytes("HashTableMemoryUsage")
				if ok && peak > 0 && mem >= t.AggMinMemory && float64(mem) >= t.AggMemoryShare*float64(peak) {
					hits = append(hits, hit{o, []Evidence{ev("HashTableMemoryUsage", float64(mem), "bytes"), ev("QueryPeakMemoryUsagePerNode", float64(peak), "bytes")}, float64(mem)})
				}
			}
			return hits
		},
	},
	{
		id:     "SR-SORT-1",
		cause:  "Sorting and window computation take a large share of the query time: columns were not pruned before the window, or there are too many window functions.",
		advice: "Prune columns before the window; split the window computation into separate steps.",
		check: func(p *Profile, t Thresholds, share func(*Operator) float64) []hit {
			// The sort and the window operators of a query are one cost: a query with
			// several window functions spreads it over many operators, each below the limit.
			var ops []*Operator
			var sum time.Duration
			var top *Operator
			var topTime time.Duration
			for _, o := range p.Operators {
				d, ok := o.effectiveTime()
				if !ok || !isSortOrWindow(o.Name) {
					continue
				}
				ops, sum = append(ops, o), sum+d
				if d > topTime {
					top, topTime = o, d
				}
			}
			var combined float64
			for _, o := range ops {
				combined += share(o)
			}
			if top == nil || combined < t.SortTimeShare || sum < t.MinOperatorTime {
				return nil
			}
			return []hit{{top, []Evidence{ev("OperatorTotalTime", ms(sum), "ms"), ev("time_share", percent(combined), "percent"), ev("operators", float64(len(ops)), "count")}, combined}}
		},
	},
	{
		id:     "SR-JOIN-1",
		cause:  "The query uses a nested loop join: the join condition cannot be used for a hash join, or the join is a Cartesian product.",
		advice: "Rewrite the join condition as an equality; limit the data volume of a Cartesian product.",
		check: func(p *Profile, t Thresholds, share func(*Operator) float64) []hit {
			var hits []hit
			for _, o := range p.Operators {
				if o.Name != "NESTLOOP_JOIN_PROBE" {
					continue
				}
				d, _ := o.effectiveTime()
				e := []Evidence{ev("OperatorTotalTime", ms(d), "ms"), ev("time_share", percent(share(o)), "percent")}
				if v, ok := o.Count("PullRowNum"); ok {
					e = append(e, ev("PullRowNum", float64(v), "rows"))
				}
				hits = append(hits, hit{o, e, float64(d)})
			}
			return hits
		},
	},
	{
		id:     "SR-JOIN-2",
		cause:  "The hash join produces many more rows than it reads from the probe side: the join key is not unique on the build side.",
		advice: "Check the uniqueness of the join key on both sides.",
		check: func(p *Profile, t Thresholds, _ func(*Operator) float64) []hit {
			var hits []hit
			for _, o := range p.Operators {
				if o.Name != "HASH_JOIN_PROBE" {
					continue
				}
				in, okIn := o.Count("PushRowNum")
				out, okOut := o.Count("PullRowNum")
				if okIn && okOut && in > 0 && out >= t.JoinMinOutputRows && float64(out) >= t.JoinExpansion*float64(in) {
					hits = append(hits, hit{o, []Evidence{ev("PushRowNum", float64(in), "rows"), ev("PullRowNum", float64(out), "rows"), ev("output_input_ratio", round1(float64(out)/float64(in)), "ratio")}, float64(out) / float64(in)})
				}
			}
			return hits
		},
	},
	{
		id:     "SR-XCHG-1",
		cause:  "A large amount of data is sent between nodes.",
		advice: "Filter and aggregate earlier; consider a Broadcast or Bucket Join hint.",
		check: func(p *Profile, t Thresholds, _ func(*Operator) float64) []hit {
			var hits []hit
			for _, o := range p.Operators {
				if o.Name != "EXCHANGE_SINK" {
					continue
				}
				if sent, ok := o.Bytes("BytesSent"); ok && sent >= t.ExchangeBytes {
					hits = append(hits, hit{o, []Evidence{ev("BytesSent", float64(sent), "bytes")}, float64(sent)})
				}
			}
			return hits
		},
	},
	{
		id:     "SR-SKEW-1",
		cause:  "The slowest instance of the operator takes much longer than the average: data skew. Scan operators are not checked: the instance times of a scan follow the tablet sizes and the I/O schedule.",
		advice: "Check the key distribution of the GROUP BY, JOIN and PARTITION BY columns.",
		check: func(p *Profile, t Thresholds, _ func(*Operator) float64) []hit {
			var hits []hit
			for _, o := range p.Operators {
				if strings.HasSuffix(o.Name, "_SCAN") {
					continue
				}
				avg, _ := o.Duration("OperatorTotalTime")
				max, _ := o.MaxDuration("OperatorTotalTime")
				if r, ok := o.skew(); ok && r >= t.SkewRatio && max >= t.SkewMinTime {
					hits = append(hits, hit{o, []Evidence{ev("OperatorTotalTime", ms(avg), "ms"), ev("MAX_OF_OperatorTotalTime", ms(max), "ms"), ev("max_avg_ratio", round1(r), "ratio")}, r})
				}
			}
			return hits
		},
	},
}

// Evaluate applies the rules of the plan's section 5.2 (SR-MEM-1 is applied at
// query level) and returns the findings ordered by rule number.
func Evaluate(p *Profile, t Thresholds) []Finding {
	total := p.totalOperatorTime()
	share := func(o *Operator) float64 {
		d, ok := o.effectiveTime()
		if !ok || total <= 0 {
			return 0
		}
		return float64(d) / float64(total)
	}
	findings := []Finding{}
	for _, r := range rules {
		hits := r.check(p, t, share)
		slices.SortStableFunc(hits, func(a, b hit) int { return cmp.Compare(b.score, a.score) })
		if len(hits) > maxFindingsPerRule {
			hits = hits[:maxFindingsPerRule]
		}
		for _, h := range hits {
			id := h.op.PlanNodeID
			findings = append(findings, Finding{Rule: r.id, Operator: h.op.Name, PlanNodeID: &id, Evidence: h.evidence, Cause: r.cause, Advice: r.advice})
		}
	}
	findings = append(findings, memoryFindings(p, t)...)
	slices.SortStableFunc(findings, func(a, b Finding) int { return cmp.Compare(a.Rule, b.Rule) })
	return findings
}

func memoryFindings(p *Profile, t Thresholds) []Finding {
	peak, havePeak := ParseBytes(p.Execution["QueryPeakMemoryUsagePerNode"])
	limit := p.memoryLimit()
	var evidence []Evidence
	if p.MemLimitExceeded {
		evidence = append(evidence, ev("MemLimitExceeded", 1, "flag"))
	}
	if havePeak && limit > 0 && float64(peak) >= t.MemLimitShare*float64(limit) {
		evidence = append(evidence, ev("QueryPeakMemoryUsagePerNode", float64(peak), "bytes"), ev("query_mem_limit", float64(limit), "bytes"), ev("peak_limit_ratio", round1(float64(peak)/float64(limit)), "ratio"))
	}
	if evidence == nil {
		return nil
	}
	return []Finding{{
		Rule: "SR-MEM-1", Evidence: evidence,
		Cause:  "The query used (nearly) all of its memory limit, or failed with a memory limit error: high query complexity, high parallelism, or wide columns such as origin_data.",
		Advice: "Split the SQL; tune pipeline_dop, chunk_size and enable_phased_scheduler; drop wide columns early.",
	}}
}
