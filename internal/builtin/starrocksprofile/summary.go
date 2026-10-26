package starrocksprofile

import (
	"cmp"
	"slices"
	"strings"
	"time"
)

// DefaultTopN is the number of operators in a summary unless the caller asks otherwise.
const DefaultTopN = 10

// MaxTopN is the largest accepted number of operators.
const MaxTopN = 50

// QuerySummary holds the query-level numbers. A field that the profile does
// not report is omitted.
type QuerySummary struct {
	QueryID          string   `json:"query_id,omitempty"`
	State            string   `json:"state,omitempty"`
	QueryType        string   `json:"query_type,omitempty"`
	TotalMs          *float64 `json:"total_ms,omitempty"`
	ExecutionMs      *float64 `json:"execution_wall_ms,omitempty"`
	CPUMs            *float64 `json:"cumulative_cpu_ms,omitempty"`
	PeakMemoryBytes  *int64   `json:"peak_memory_per_node_bytes,omitempty"`
	QueryMemoryLimit *int64   `json:"query_mem_limit_bytes,omitempty"`
	SpillBytes       *int64   `json:"spill_bytes,omitempty"`
	ScanRows         *int64   `json:"scan_rows,omitempty"`
	ScanBytes        *int64   `json:"scan_bytes,omitempty"`
}

// OperatorSummary describes one operator. Time is the mean over the instances
// of the operator's pipeline; SkewRatio is the slowest instance divided by that mean.
type OperatorSummary struct {
	Fragment       int      `json:"fragment"`
	PlanNodeID     int      `json:"plan_node_id"`
	Operator       string   `json:"operator"`
	NodeType       string   `json:"node_type,omitempty"`
	TimeMs         float64  `json:"time_ms"`
	TimePercent    float64  `json:"time_percent"`
	RowsIn         *int64   `json:"rows_in,omitempty"`
	RowsOut        *int64   `json:"rows_out,omitempty"`
	HashTableBytes *int64   `json:"hash_table_memory_bytes,omitempty"`
	SpillBytes     *int64   `json:"spill_bytes,omitempty"`
	BytesSent      *int64   `json:"bytes_sent,omitempty"`
	SkewRatio      *float64 `json:"skew_ratio,omitempty"`
	timeNs         time.Duration
}

// Summary is the output of profile_summary and profile_run.
type Summary struct {
	Query        QuerySummary      `json:"query"`
	TopOperators []OperatorSummary `json:"top_operators"`
	Findings     []Finding         `json:"findings"`
	// OperatorCount is the number of operator sections in the profile.
	OperatorCount int `json:"operator_count"`
	// OperatorsOmitted is the number of slowest operators dropped to fit the output limit.
	OperatorsOmitted int `json:"operators_omitted,omitempty"`
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func ptr[T any](v T) *T { return &v }

func executionDuration(p *Profile, name string) *float64 {
	if d, ok := ParseDuration(p.Execution[name]); ok && p.Execution[name] != "" {
		return ptr(ms(d))
	}
	return nil
}

// effectiveTime is OperatorTotalTime plus, for scans, ScanTime: the I/O tasks
// run outside the operator and StarRocks' own ANALYZE PROFILE counts them with it.
func (o *Operator) effectiveTime() (time.Duration, bool) {
	t, ok := o.Duration("OperatorTotalTime")
	if !ok {
		return 0, false
	}
	if strings.HasSuffix(o.Name, "_SCAN") {
		if scan, ok := o.Duration("ScanTime"); ok {
			t += scan
		}
	}
	return t, true
}

func (o *Operator) skew() (float64, bool) {
	avg, ok := o.Duration("OperatorTotalTime")
	if !ok || avg <= 0 {
		return 0, false
	}
	max, ok := o.MaxDuration("OperatorTotalTime")
	if !ok {
		return 0, false
	}
	return float64(max) / float64(avg), true
}

func optCount(o *Operator, name string) *int64 {
	if v, ok := o.Count(name); ok {
		return &v
	}
	return nil
}

func optBytes(o *Operator, name string) *int64 {
	if v, ok := o.Bytes(name); ok {
		return &v
	}
	return nil
}

func (p *Profile) totalOperatorTime() time.Duration {
	var total time.Duration
	for _, o := range p.Operators {
		if t, ok := o.effectiveTime(); ok {
			total += t
		}
	}
	return total
}

func (p *Profile) querySummary() QuerySummary {
	q := QuerySummary{QueryID: p.Summary["Query ID"], State: p.Summary["Query State"], QueryType: p.Summary["Query Type"]}
	if d, ok := ParseDuration(p.Summary["Total"]); ok {
		q.TotalMs = ptr(ms(d))
	}
	q.ExecutionMs = executionDuration(p, "QueryExecutionWallTime")
	q.CPUMs = executionDuration(p, "QueryCumulativeCpuTime")
	if b, ok := ParseBytes(p.Execution["QueryPeakMemoryUsagePerNode"]); ok {
		q.PeakMemoryBytes = &b
	}
	if b, ok := ParseBytes(p.Execution["QuerySpillBytes"]); ok {
		q.SpillBytes = &b
	}
	if limit := p.memoryLimit(); limit > 0 {
		q.QueryMemoryLimit = &limit
	}
	var rows, bytes int64
	var haveRows, haveBytes bool
	for _, o := range p.Operators {
		if !strings.HasSuffix(o.Name, "_SCAN") {
			continue
		}
		if v, ok := o.Count("RawRowsRead"); ok {
			rows, haveRows = rows+v, true
		}
		if v, ok := o.Bytes("BytesRead"); ok {
			bytes, haveBytes = bytes+v, true
		}
	}
	if haveRows {
		q.ScanRows = &rows
	}
	if haveBytes {
		q.ScanBytes = &bytes
	}
	return q
}

// Summarize returns the query numbers, the topN slowest operators and the rule findings.
func Summarize(p *Profile, topN int, t Thresholds) Summary {
	if topN < 1 {
		topN = DefaultTopN
	}
	total := p.totalOperatorTime()
	ops := make([]OperatorSummary, 0, len(p.Operators))
	for _, o := range p.Operators {
		time, ok := o.effectiveTime()
		if !ok {
			continue
		}
		s := OperatorSummary{
			Fragment: o.Fragment, PlanNodeID: o.PlanNodeID, Operator: o.Name, NodeType: o.NodeType,
			TimeMs: ms(time), RowsIn: optCount(o, "PushRowNum"), RowsOut: optCount(o, "PullRowNum"),
			HashTableBytes: optBytes(o, "HashTableMemoryUsage"), BytesSent: optBytes(o, "BytesSent"),
			timeNs: time,
		}
		if total > 0 {
			s.TimePercent = round1(100 * float64(time) / float64(total))
		}
		if spill := o.SpillBytes(); spill > 0 {
			s.SpillBytes = &spill
		}
		if r, ok := o.skew(); ok {
			s.SkewRatio = ptr(round1(r))
		}
		ops = append(ops, s)
	}
	slices.SortStableFunc(ops, func(a, b OperatorSummary) int { return cmp.Compare(b.timeNs, a.timeNs) })
	if len(ops) > topN {
		ops = ops[:topN]
	}
	return Summary{Query: p.querySummary(), TopOperators: ops, Findings: Evaluate(p, t), OperatorCount: len(p.Operators)}
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// Redact applies mask to every string of the summary. The strings come from
// fixed vocabularies and profile identifiers, so the mask rarely changes
// them; it is applied so that a redaction policy covers this output as well.
func (s *Summary) Redact(mask func(string) string) {
	q := &s.Query
	q.QueryID, q.State, q.QueryType = mask(q.QueryID), mask(q.State), mask(q.QueryType)
	for i := range s.TopOperators {
		o := &s.TopOperators[i]
		o.Operator, o.NodeType = mask(o.Operator), mask(o.NodeType)
	}
	for i := range s.Findings {
		f := &s.Findings[i]
		f.Rule, f.Operator, f.Cause, f.Advice = mask(f.Rule), mask(f.Operator), mask(f.Cause), mask(f.Advice)
		for j := range f.Evidence {
			f.Evidence[j].Metric, f.Evidence[j].Unit = mask(f.Evidence[j].Metric), mask(f.Evidence[j].Unit)
		}
	}
}
