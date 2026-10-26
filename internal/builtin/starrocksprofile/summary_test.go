package starrocksprofile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSummarizeScanAgg(t *testing.T) {
	p := parsed(t, "scan_agg")
	s := Summarize(p, 3, DefaultThresholds())
	q := s.Query
	if q.QueryID != "b6e3e384-ced5-11f1-b155-5ee444682bc1" || q.State != "Finished" || q.QueryType != "Query" {
		t.Errorf("query: %+v", q)
	}
	if q.TotalMs == nil || *q.TotalMs != 17 || q.PeakMemoryBytes == nil || *q.PeakMemoryBytes != 11978932 || q.SpillBytes == nil || *q.SpillBytes != 0 {
		t.Errorf("query numbers: %+v", q)
	}
	if q.ScanRows == nil || *q.ScanRows != 500000 || q.ScanBytes == nil || *q.ScanBytes <= 0 {
		t.Errorf("scan numbers: %+v", q)
	}
	if q.QueryMemoryLimit != nil {
		t.Errorf("query_mem_limit reported for an unlimited query: %d", *q.QueryMemoryLimit)
	}
	if len(s.TopOperators) != 3 || s.OperatorCount != len(p.Operators) {
		t.Fatalf("operators: %d of %d", len(s.TopOperators), s.OperatorCount)
	}
	top := s.TopOperators[0]
	if top.Operator != "OLAP_SCAN" || top.PlanNodeID != 0 || top.NodeType != "OLAP_SCAN" || top.TimePercent < 50 {
		t.Errorf("top operator: %+v", top)
	}
	for i := 1; i < len(s.TopOperators); i++ {
		if s.TopOperators[i].TimeMs > s.TopOperators[i-1].TimeMs {
			t.Errorf("operators not sorted by time: %+v", s.TopOperators)
		}
	}
	if s.Findings == nil {
		t.Error("findings must be an empty list, not null")
	}
}

func TestSummarizeJSONDoesNotContainSQL(t *testing.T) {
	for _, name := range []string{"scan_agg", "hash_join", "window", "nestloop_join", "project_json"} {
		data, err := json.Marshal(Summarize(parsed(t, name), MaxTopN, DefaultThresholds()))
		if err != nil {
			t.Fatal(err)
		}
		for _, leak := range []string{"demo_dw", "fact_orders", "allowops_query", "Sql Statement"} {
			if strings.Contains(string(data), leak) {
				t.Errorf("%s: summary contains %q", name, leak)
			}
		}
	}
}

func TestSummarizeTopNBounds(t *testing.T) {
	p := parsed(t, "hash_join")
	if got := len(Summarize(p, 0, DefaultThresholds()).TopOperators); got != DefaultTopN {
		t.Errorf("default top = %d, want %d", got, DefaultTopN)
	}
	if got := len(Summarize(p, 1, DefaultThresholds()).TopOperators); got != 1 {
		t.Errorf("top 1 = %d", got)
	}
	if got := len(Summarize(p, 100000, DefaultThresholds()).TopOperators); got != len(p.Operators) {
		t.Errorf("large top = %d, want all %d operators", got, len(p.Operators))
	}
}

func TestSummaryRedactMasksEveryString(t *testing.T) {
	s := Summarize(parsed(t, "nestloop_join"), 5, DefaultThresholds())
	s.Redact(func(v string) string { return strings.ReplaceAll(v, "NESTLOOP", "XXXX") })
	data, _ := json.Marshal(s)
	if strings.Contains(string(data), "NESTLOOP") || !strings.Contains(string(data), "XXXX_JOIN_PROBE") {
		t.Errorf("not masked: %s", data)
	}
}
