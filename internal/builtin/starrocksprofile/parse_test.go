package starrocksprofile

import (
	"os"
	"strings"
	"testing"
	"time"
)

func sample(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func parsed(t *testing.T, name string) *Profile {
	t.Helper()
	p, err := Parse(sample(t, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return p
}

func TestParseDuration(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"0", 0}, {"0ns", 0}, {"786ns", 786}, {"1.119us", 1119}, {"17ms", 17 * time.Millisecond},
		{"2.381ms", 2381 * time.Microsecond}, {"1s234ms", 1234 * time.Millisecond},
		{"1m2s", 62 * time.Second}, {"1h2m3s", 3723 * time.Second}, {"1h1ms", time.Hour + time.Millisecond},
	} {
		got, ok := ParseDuration(tc.in)
		if !ok || got != tc.want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", tc.in, got, ok, tc.want)
		}
	}
	for _, in := range []string{"", "ms", "5", "5 ms", "1x", "1ms2", "-1ms", "NaN", "1e3ms"} {
		if got, ok := ParseDuration(in); ok {
			t.Errorf("ParseDuration(%q) = %v, want failure", in, got)
		}
	}
}

func TestParseBytes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"0.000 B", 0}, {"1.000 KB", 1024}, {"11.424 MB", 11978932}, {"1.500 GB", 1610612736}, {"2.000 TB", 2 << 40},
	} {
		got, ok := ParseBytes(tc.in)
		if !ok || got != tc.want {
			t.Errorf("ParseBytes(%q) = %d, %v; want %d", tc.in, got, ok, tc.want)
		}
	}
	for _, in := range []string{"", "11.424", "MB", "11.424MB", "-1.000 B", "1 XB", "99999999999.000 PB"} {
		if got, ok := ParseBytes(in); ok {
			t.Errorf("ParseBytes(%q) = %d, want failure", in, got)
		}
	}
}

func TestParseCount(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"0", 0}, {"50", 50}, {"500.000K (500000)", 500000}, {"413.883K (413883)", 413883}, {"1.5M", 1500000}, {"2B", 2000000000},
		{"1.234M (1234567)", 1234567}, {"-3", -3},
	} {
		got, ok := ParseCount(tc.in)
		if !ok || got != tc.want {
			t.Errorf("ParseCount(%q) = %d, %v; want %d", tc.in, got, ok, tc.want)
		}
	}
	for _, in := range []string{"", "K", "1.5 MB", "abc", "1,000", "12 (13"} {
		if got, ok := ParseCount(in); ok {
			t.Errorf("ParseCount(%q) = %d, want failure", in, got)
		}
	}
}

func TestParseRejectsTextWithoutSummary(t *testing.T) {
	for _, in := range []string{"", "\n\n", "hello", "Query:\n  Planner:\n     - -- Parser[1] 0\n"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) succeeded", in)
		}
	}
}

func TestParseSample(t *testing.T) {
	p := parsed(t, "scan_agg")
	if p.Summary["Query State"] != "Finished" || p.Summary["Query Type"] != "Query" || p.Summary["Total"] != "17ms" {
		t.Fatalf("summary: %v", p.Summary)
	}
	if p.Execution["QueryPeakMemoryUsagePerNode"] != "11.424 MB" || p.Execution["QuerySpillBytes"] != "0.000 B" {
		t.Fatalf("execution: %v", p.Execution)
	}
	if got := p.SessionVariables["enable_profile"]; got != "true" {
		t.Fatalf("non-default session variables: %v", p.SessionVariables)
	}
	names := map[string]int{}
	for _, o := range p.Operators {
		names[o.Name]++
	}
	for _, name := range []string{"OLAP_SCAN", "AGGREGATE_STREAMING_SINK", "AGGREGATE_BLOCKING_SINK", "EXCHANGE_SINK", "EXCHANGE_SOURCE", "RESULT_SINK"} {
		if names[name] == 0 {
			t.Errorf("operator %s not found in %v", name, names)
		}
	}
	var scan *Operator
	for _, o := range p.Operators {
		if o.Name == "OLAP_SCAN" {
			scan = o
		}
	}
	if scan.PlanNodeID != 0 || scan.Fragment != 2 || scan.NodeType != "OLAP_SCAN" {
		t.Errorf("scan operator: %+v", scan)
	}
	if rows, ok := scan.Count("RawRowsRead"); !ok || rows != 500000 {
		t.Errorf("RawRowsRead = %d, %v", rows, ok)
	}
	if d, ok := scan.Duration("OperatorTotalTime"); !ok || d != 2381*time.Microsecond {
		t.Errorf("OperatorTotalTime = %v, %v", d, ok)
	}
	if d, ok := scan.MaxDuration("IOTaskExecTime"); !ok || d != 1022*time.Microsecond {
		t.Errorf("MAX_OF_IOTaskExecTime = %v, %v", d, ok)
	}
	if _, ok := scan.Count("NoSuchMetric"); ok {
		t.Error("an absent metric is reported")
	}
}

func TestParseTruncatedAndMangledInputNeverPanics(t *testing.T) {
	text := sample(t, "hash_join")
	for cut := 0; cut < len(text); cut += 997 {
		_, _ = Parse(text[:cut])
	}
	for _, mangle := range []func(string) string{
		func(s string) string { return strings.ReplaceAll(s, ": ", ":") },
		func(s string) string { return strings.ReplaceAll(s, "plan_node_id=", "plan_node_id=x") },
		func(s string) string { return strings.ReplaceAll(s, "ms", "") },
		func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") },
		func(s string) string { return strings.ReplaceAll(s, "  ", "\t") },
	} {
		if p, err := Parse(mangle(text)); err == nil {
			Summarize(p, 5, DefaultThresholds())
		}
	}
}

func TestParseLimitsLines(t *testing.T) {
	text := "Query:\n  Summary:\n" + strings.Repeat("     - X: 1\n", MaxLines)
	if _, err := Parse(text); err == nil {
		t.Fatal("accepted a profile over the line limit")
	}
}
