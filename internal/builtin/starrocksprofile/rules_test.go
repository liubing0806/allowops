package starrocksprofile

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

func findings(t *testing.T, text string, th Thresholds) []Finding {
	t.Helper()
	p, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return Evaluate(p, th)
}

func rulesOf(fs []Finding) []string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.Rule)
	}
	return ids
}

func has(fs []Finding, rule string) *Finding {
	for i := range fs {
		if fs[i].Rule == rule {
			return &fs[i]
		}
	}
	return nil
}

// Real profiles. Each rule has at least one profile that hits it and one that
// does not; rules that the synthetic data volume cannot trigger are tested
// with rewritten profiles further below.
var realHits = map[string][]string{
	"SR-PROJ-1": {"project_expr", "mem_limit_ok"},
	"SR-AGG-1":  {"agg_memory", "mem_limit_ok"},
	"SR-SORT-1": {"window_multi", "window_topn"},
	"SR-JOIN-1": {"nestloop_join"},
	"SR-JOIN-2": {"join_expand"},
	"SR-SKEW-1": {"skew_window"},
	"SR-MEM-1":  {"mem_limit_exceeded"},
}

var allSamples = []string{
	"scan_agg", "hash_join", "window", "nestloop_join", "project_json", "project_expr", "join_expand", "skew_window",
	"window_topn", "window_multi", "agg_memory", "mem_limit_exceeded", "mem_limit_ok", "scan_heavy",
}

// TestRulesOnRealProfiles pins the complete result for every real profile, so
// that a threshold change shows up as a difference in this table.
func TestRulesOnRealProfiles(t *testing.T) {
	want := map[string][]string{
		"scan_agg": nil, "hash_join": nil, "window": nil, "project_json": nil, "scan_heavy": nil,
		"nestloop_join":      {"SR-JOIN-1"},
		"project_expr":       {"SR-PROJ-1"},
		"join_expand":        {"SR-JOIN-2"},
		"skew_window":        {"SR-SKEW-1"},
		"window_topn":        {"SR-SORT-1"},
		"window_multi":       {"SR-SORT-1"},
		"agg_memory":         {"SR-AGG-1"},
		"mem_limit_exceeded": {"SR-MEM-1"},
		"mem_limit_ok":       {"SR-AGG-1", "SR-PROJ-1"},
	}
	for _, name := range allSamples {
		got := rulesOf(findings(t, sample(t, name), DefaultThresholds()))
		if strings.Join(got, ",") != strings.Join(want[name], ",") {
			t.Errorf("%s: rules %v, want %v", name, got, want[name])
		}
	}
	// Every rule of the plan hits at least one real profile except those that the synthetic data cannot trigger.
	for rule, names := range realHits {
		for _, name := range names {
			if has(findings(t, sample(t, name), DefaultThresholds()), rule) == nil {
				t.Errorf("%s does not hit %s", name, rule)
			}
		}
	}
}

func TestRuleEvidence(t *testing.T) {
	f := has(findings(t, sample(t, "join_expand"), DefaultThresholds()), "SR-JOIN-2")
	if f == nil || f.Operator != "HASH_JOIN_PROBE" || f.PlanNodeID == nil || *f.PlanNodeID != 5 {
		t.Fatalf("finding: %+v", f)
	}
	evidence := map[string]float64{}
	for _, e := range f.Evidence {
		evidence[e.Metric] = e.Value
	}
	if evidence["PushRowNum"] != 500000 || evidence["PullRowNum"] != 19990000 || evidence["output_input_ratio"] != 40 {
		t.Errorf("evidence: %+v", f.Evidence)
	}
	if f.Cause == "" || f.Advice == "" {
		t.Error("a finding needs a cause and advice")
	}
	m := has(findings(t, sample(t, "mem_limit_exceeded"), DefaultThresholds()), "SR-MEM-1")
	if m == nil || m.Operator != "" || m.PlanNodeID != nil {
		t.Fatalf("SR-MEM-1 is a query-level finding: %+v", m)
	}
	kinds := map[string]bool{}
	for _, e := range m.Evidence {
		kinds[e.Metric] = true
	}
	if !kinds["MemLimitExceeded"] || !kinds["query_mem_limit"] {
		t.Errorf("evidence: %+v", m.Evidence)
	}
	skew := has(findings(t, sample(t, "skew_window"), DefaultThresholds()), "SR-SKEW-1")
	if skew == nil || skew.Operator != "LOCAL_SORT_SINK" {
		t.Errorf("skew finding: %+v", skew)
	}
}

// The scan operators are exempt from SR-SKEW-1: the instance times of a scan
// follow the tablet sizes. scan_heavy has a scan whose slowest instance is
// four times the mean and takes more than the floor.
func TestSkewIgnoresScans(t *testing.T) {
	p := parsed(t, "scan_heavy")
	var scan *Operator
	for _, o := range p.Operators {
		if o.Name == "OLAP_SCAN" {
			scan = o
		}
	}
	if r, ok := scan.skew(); !ok || r < 3 {
		t.Fatalf("the sample no longer has a skewed scan: %v %v", r, ok)
	}
	if max, _ := scan.MaxDuration("OperatorTotalTime"); max < DefaultThresholds().SkewMinTime {
		t.Fatalf("the skewed scan is below the floor: %v", max)
	}
	if has(Evaluate(p, DefaultThresholds()), "SR-SKEW-1") != nil {
		t.Error("a scan was reported as skewed")
	}
}

func TestSortFloorAndCombinedShare(t *testing.T) {
	// window: the sort takes 50% of the operator time but only 5 ms.
	if has(findings(t, sample(t, "window"), DefaultThresholds()), "SR-SORT-1") != nil {
		t.Error("an operator below the time floor was reported")
	}
	th := DefaultThresholds()
	th.MinOperatorTime = time.Millisecond
	if has(findings(t, sample(t, "window"), th), "SR-SORT-1") == nil {
		t.Error("not reported with a lower floor")
	}
	// window_multi: no single operator reaches 30%, together they take 63%.
	p := parsed(t, "window_multi")
	for _, o := range p.Operators {
		if !isSortOrWindow(o.Name) {
			continue
		}
		d, _ := o.effectiveTime()
		if share := float64(d) / float64(p.totalOperatorTime()); share >= 0.30 {
			t.Fatalf("%s alone takes %.0f%%; the sample no longer shows the combined rule", o.Name, share*100)
		}
	}
	th = DefaultThresholds()
	th.SortTimeShare = 0.7
	if has(findings(t, sample(t, "window_multi"), th), "SR-SORT-1") != nil {
		t.Error("reported below the share limit")
	}
}

func TestThresholdsAreConfigurable(t *testing.T) {
	th := DefaultThresholds()
	th.ProjectTimeShare = 0.7
	if has(findings(t, sample(t, "project_expr"), th), "SR-PROJ-1") != nil {
		t.Error("PROJECT at 59.6% reported with a 70% limit")
	}
	th = DefaultThresholds()
	th.JoinExpansion = 100
	if has(findings(t, sample(t, "join_expand"), th), "SR-JOIN-2") != nil {
		t.Error("expansion 40 reported with a limit of 100")
	}
	th = DefaultThresholds()
	th.SkewRatio = 20
	if has(findings(t, sample(t, "skew_window"), th), "SR-SKEW-1") != nil {
		t.Error("skew 9.6 reported with a limit of 20")
	}
	th = DefaultThresholds()
	th.AggMinMemory = 512 << 20
	if has(findings(t, sample(t, "agg_memory"), th), "SR-AGG-1") != nil {
		t.Error("a 201 MB hash table reported with a 512 MB floor")
	}
}

// ---- rewritten profiles: not real, see docs/builtin-starrocks.md ----

var operatorHeaderLine = regexp.MustCompile(`^\s+([A-Z][A-Z0-9_]*) \(plan_node_id=(-?\d+)\):$`)

// editOperator rewrites the first operator section called name with the
// given plan node id: each line of that section is passed to edit, which
// returns the replacement lines.
func editOperator(t *testing.T, text, name string, planID int, edit func(line string) []string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	var out []string
	inside, done := false, false
	for _, line := range lines {
		if m := operatorHeaderLine.FindStringSubmatch(line); m != nil {
			inside = !done && m[1] == name && m[2] == fmt.Sprint(planID)
			if inside {
				done = true
			}
			out = append(out, line)
			continue
		}
		if inside && strings.HasPrefix(strings.TrimSpace(line), "Pipeline (id=") {
			inside = false
		}
		if inside {
			out = append(out, edit(line)...)
			continue
		}
		out = append(out, line)
	}
	if !done {
		t.Fatalf("operator %s (plan_node_id=%d) not found", name, planID)
	}
	return strings.Join(out, "\n")
}

// setMetric replaces the value of the first line "- metric: ..." of the operator.
func setMetric(t *testing.T, text, name string, planID int, metric, value string) string {
	t.Helper()
	changed := false
	prefix := "- " + metric + ": "
	out := editOperator(t, text, name, planID, func(line string) []string {
		if !changed && strings.HasPrefix(strings.TrimSpace(line), prefix) {
			changed = true
			return []string{line[:strings.Index(line, "- ")] + prefix + value}
		}
		return []string{line}
	})
	if !changed {
		t.Fatalf("metric %s of %s not found", metric, name)
	}
	return out
}

// addUniqueMetric adds "- metric: value" at the head of the operator's UniqueMetrics.
func addUniqueMetric(t *testing.T, text, name string, planID int, metric, value string) string {
	t.Helper()
	added := false
	out := editOperator(t, text, name, planID, func(line string) []string {
		if !added && strings.TrimSpace(line) == "UniqueMetrics:" {
			added = true
			return []string{line, strings.Repeat(" ", len(line)-len(strings.TrimLeft(line, " "))+3) + "- " + metric + ": " + value}
		}
		return []string{line}
	})
	if !added {
		t.Fatalf("UniqueMetrics of %s not found", name)
	}
	return out
}

func TestRewriteHelpersChangeOnlyTheTarget(t *testing.T) {
	text := sample(t, "scan_heavy")
	rewritten := setMetric(t, text, "OLAP_SCAN", 0, "RawRowsRead", "1.500B (1500000000)")
	if rewritten == text || len(strings.Split(rewritten, "\n")) != len(strings.Split(text, "\n")) {
		t.Fatal("setMetric must change one line")
	}
	p, _ := Parse(rewritten)
	q := p.querySummary()
	if q.ScanRows == nil || *q.ScanRows != 1500000000 {
		t.Errorf("scan rows %v", q.ScanRows)
	}
	added := addUniqueMetric(t, text, "AGGREGATE_BLOCKING_SINK", 2, "SpillBytes", "2.000 GB")
	p, _ = Parse(added)
	for _, o := range p.Operators {
		want := int64(0)
		if o.Name == "AGGREGATE_BLOCKING_SINK" && o.PlanNodeID == 2 {
			want = 2 << 30
		}
		if o.SpillBytes() != want {
			t.Errorf("%s %d spill %d, want %d", o.Name, o.PlanNodeID, o.SpillBytes(), want)
		}
	}
}

func TestScanRuleOnRewrittenProfiles(t *testing.T) {
	base := sample(t, "scan_heavy") // the scan takes 88% of 21 ms and reads 500000 rows
	if has(findings(t, base, DefaultThresholds()), "SR-SCAN-1") != nil {
		t.Fatal("the real profile hits SR-SCAN-1")
	}
	rows := setMetric(t, base, "OLAP_SCAN", 0, "RawRowsRead", "100.000M (100000000)")
	f := has(findings(t, rows, DefaultThresholds()), "SR-SCAN-1")
	if f == nil || f.Operator != "OLAP_SCAN" {
		t.Fatalf("100 million rows: %+v", f)
	}
	if has(findings(t, setMetric(t, base, "OLAP_SCAN", 0, "RawRowsRead", "99.999M (99999999)"), DefaultThresholds()), "SR-SCAN-1") != nil {
		t.Error("99,999,999 rows reported")
	}
	if has(findings(t, setMetric(t, base, "OLAP_SCAN", 0, "BytesRead", "10.000 GB"), DefaultThresholds()), "SR-SCAN-1") == nil {
		t.Error("10 GB not reported")
	}
	if has(findings(t, setMetric(t, base, "OLAP_SCAN", 0, "BytesRead", "9.990 GB"), DefaultThresholds()), "SR-SCAN-1") != nil {
		t.Error("9.99 GB reported")
	}
	// A large scan that takes a small share of the time is not reported.
	small := setMetric(t, sample(t, "hash_join"), "OLAP_SCAN", 6, "RawRowsRead", "1.500B (1500000000)")
	if has(findings(t, small, DefaultThresholds()), "SR-SCAN-1") != nil {
		t.Error("a scan with a small time share was reported")
	}
	// A scan below the time floor is not reported even with a large volume.
	short := setMetric(t, sample(t, "scan_agg"), "OLAP_SCAN", 0, "RawRowsRead", "1.500B (1500000000)")
	if has(findings(t, short, DefaultThresholds()), "SR-SCAN-1") != nil {
		t.Error("a scan below the time floor was reported")
	}
}

func TestAggregateSpillOnRewrittenProfile(t *testing.T) {
	base := sample(t, "scan_agg")
	if has(findings(t, base, DefaultThresholds()), "SR-AGG-1") != nil {
		t.Fatal("the real profile hits SR-AGG-1")
	}
	f := has(findings(t, addUniqueMetric(t, base, "AGGREGATE_BLOCKING_SINK", 3, "SpillBytes", "1.000 GB"), DefaultThresholds()), "SR-AGG-1")
	if f == nil || f.Operator != "AGGREGATE_BLOCKING_SINK" || f.Evidence[0].Metric != "SpillBytes" || f.Evidence[0].Value != 1<<30 {
		t.Fatalf("finding: %+v", f)
	}
	if has(findings(t, addUniqueMetric(t, base, "AGGREGATE_BLOCKING_SINK", 3, "SpillBytes", "0.000 B"), DefaultThresholds()), "SR-AGG-1") != nil {
		t.Error("zero spill reported")
	}
	// Spill on a non-aggregate operator is not an aggregate finding.
	if has(findings(t, addUniqueMetric(t, base, "EXCHANGE_SINK", 4, "SpillBytes", "1.000 GB"), DefaultThresholds()), "SR-AGG-1") != nil {
		t.Error("spill of an exchange reported as SR-AGG-1")
	}
	// A small hash table that holds most of the query memory is below the floor.
	small := setMetric(t, base, "AGGREGATE_STREAMING_SINK", 1, "HashTableMemoryUsage", "11.000 MB")
	if has(findings(t, small, DefaultThresholds()), "SR-AGG-1") != nil {
		t.Error("an 11 MB hash table reported")
	}
}

func TestExchangeRuleOnRewrittenProfile(t *testing.T) {
	base := sample(t, "project_expr") // EXCHANGE_SINK 3 sent 4.236 MB
	if has(findings(t, base, DefaultThresholds()), "SR-XCHG-1") != nil {
		t.Fatal("the real profile hits SR-XCHG-1")
	}
	f := has(findings(t, setMetric(t, base, "EXCHANGE_SINK", 3, "BytesSent", "10.000 GB"), DefaultThresholds()), "SR-XCHG-1")
	if f == nil || f.Operator != "EXCHANGE_SINK" || f.Evidence[0].Value != 10<<30 {
		t.Fatalf("finding: %+v", f)
	}
	if has(findings(t, setMetric(t, base, "EXCHANGE_SINK", 3, "BytesSent", "9.990 GB"), DefaultThresholds()), "SR-XCHG-1") != nil {
		t.Error("9.99 GB reported")
	}
	// Only the sending side counts: BytesReceived of the receiving operator is the same data.
	if has(findings(t, setMetric(t, base, "GLOBAL_PARALLEL_MERGE_SOURCE", 3, "BytesReceived", "50.000 GB"), DefaultThresholds()), "SR-XCHG-1") != nil {
		t.Error("BytesReceived reported")
	}
}

func TestMemoryRuleOnRewrittenProfile(t *testing.T) {
	base := sample(t, "mem_limit_ok") // peak 382 MiB of a 1,000,000,000 byte limit
	withLimit := func(limit string) string {
		return strings.Replace(base, `"query_mem_limit":{"defaultValue":0,"actualValue":1000000000}`, `"query_mem_limit":{"defaultValue":0,"actualValue":`+limit+`}`, 1)
	}
	if has(findings(t, base, DefaultThresholds()), "SR-MEM-1") != nil {
		t.Fatal("40% of the limit reported")
	}
	// peak 400371482
	if has(findings(t, withLimit("440000000"), DefaultThresholds()), "SR-MEM-1") == nil {
		t.Error("91% of the limit not reported")
	}
	if has(findings(t, withLimit("450000000"), DefaultThresholds()), "SR-MEM-1") != nil {
		t.Error("89% of the limit reported")
	}
	// Without a limit there is nothing to compare, and without an error message nothing is reported.
	if has(findings(t, sample(t, "scan_agg"), DefaultThresholds()), "SR-MEM-1") != nil {
		t.Error("reported without a limit")
	}
}

func TestMemLimitMessageDetection(t *testing.T) {
	for msg, want := range map[string]bool{
		"- ErrorMsg: Memory of Queryabc exceed limit. Used: 1, Limit: 2":     true,
		"- ErrorMsg__DUP(0): Mem usage has exceed the limit of single query": true,
		"- ErrorMsg: MEM_LIMIT_EXCEEDED":                                     true,
		"- ErrorMsg: Unknown table":                                          false,
		"- Other: exceed limit":                                              false,
	} {
		text := sample(t, "scan_agg") + "\n         " + msg + "\n"
		p, err := Parse(text)
		if err != nil {
			t.Fatal(err)
		}
		if p.MemLimitExceeded != want {
			t.Errorf("%q: MemLimitExceeded = %v, want %v", msg, p.MemLimitExceeded, want)
		}
	}
}
