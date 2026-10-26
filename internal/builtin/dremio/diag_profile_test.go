package dremio

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func sampleZip(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "profiles", name+".zip"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sampleSummary(t *testing.T, name string, topN int, mask func(string) string) Summary {
	t.Helper()
	profile, err := extractProfile(sampleZip(t, name), DefaultMaxProfileBytes)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if mask == nil {
		mask = identity
	}
	s, err := summarize("0123abcd-0123-4abc-8def-0123456789ab", profile, topN, mask)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return s
}

func hitIDs(s Summary) []string {
	ids := []string{}
	for _, h := range s.Hits {
		ids = append(ids, h.Rule)
	}
	slices.Sort(ids)
	return ids
}

func makeZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The numbers come from UserBitShared.CoreOperatorType of dremio-protocol 24.1.0
// and from the operators of the samples.
func TestOperatorTypeNames(t *testing.T) {
	if len(coreOperatorTypes) != 68 {
		t.Fatalf("CoreOperatorType has 68 values (0 to 67), got %d", len(coreOperatorTypes))
	}
	seen := map[string]int{}
	for n, name := range coreOperatorTypes {
		if name == "" || name != strings.ToUpper(name) {
			t.Errorf("operator %d has no upper-case name: %q", n, name)
		}
		if other, dup := seen[name]; dup {
			t.Errorf("%q is used for %d and %d", name, other, n)
		}
		seen[name] = n
	}
	for n, want := range map[int]string{0: "SINGLE_SENDER", 3: "HASH_AGGREGATE", 4: "HASH_JOIN", 10: "PROJECT", 13: "SCREEN", 35: "NESTED_LOOP_JOIN", 43: "ARROW_WRITER", 47: "JDBC_SUB_SCAN", 49: "WRITER_COMMITTER", 67: "ICEBERG_SIMPLE_WRITER"} {
		if got := operatorTypeName(n); got != want {
			t.Errorf("operatorTypeName(%d)=%s; want %s", n, got, want)
		}
	}
	if got := operatorTypeName(68); got != "OPERATOR_68" {
		t.Errorf("unknown operator: %s", got)
	}
	if got := operatorTypeName(-1); got != "OPERATOR_-1" {
		t.Errorf("negative operator: %s", got)
	}
}

// The expected rules of each sample are listed in testdata/README.md.
var sampleRules = map[string][]string{
	"pushdown_scan":        {},
	"pushdown_join_agg":    {},
	"cross_join_small":     {},
	"cross_join_large":     {"DR-JOIN-1", "DR-SCAN-1"},
	"scan_large":           {"DR-SCAN-1"},
	"join_explosion":       {"DR-JOIN-3"},
	"nested_loop":          {"DR-JOIN-2"},
	"many_branches":        {"DR-MEM-1", "DR-PLAN-1", "DR-SCAN-1"},
	"failed_unknown_table": {"DR-FAIL-1"},
	"canceled":             {"DR-FAIL-1"},
}

func TestRulesOnSamples(t *testing.T) {
	for name, want := range sampleRules {
		t.Run(name, func(t *testing.T) {
			s := sampleSummary(t, name, 5, nil)
			if got := hitIDs(s); !slices.Equal(got, want) {
				t.Fatalf("rules=%v; want %v\nsummary: %+v", got, want, s)
			}
			for _, h := range s.Hits {
				if len(h.Evidence) == 0 || h.Cause == "" || h.Advice == "" {
					t.Errorf("%s: a hit needs evidence, cause and advice: %+v", h.Rule, h)
				}
			}
		})
	}
}

// Every rule has a sample that it matches and a sample that it does not match.
func TestEveryRuleHasHitAndMissSample(t *testing.T) {
	all := []string{"DR-FAIL-1", "DR-PLAN-1", "DR-SCAN-1", "DR-JOIN-1", "DR-JOIN-2", "DR-JOIN-3", "DR-MEM-1"}
	for _, id := range all {
		hit, miss := 0, 0
		for _, rules := range sampleRules {
			if slices.Contains(rules, id) {
				hit++
			} else {
				miss++
			}
		}
		if hit == 0 || miss == 0 {
			t.Errorf("%s: %d hit samples, %d miss samples", id, hit, miss)
		}
	}
	for _, s := range []string{"pushdown_scan", "many_branches"} {
		for _, h := range sampleSummary(t, s, 5, nil).Hits {
			if !slices.Contains(all, h.Rule) {
				t.Errorf("rule %s is not in the list of this test", h.Rule)
			}
		}
	}
	if got := len(rules); got != len(all) {
		t.Errorf("%d rules are registered; this test lists %d", got, len(all))
	}
}

func TestSummaryOfPushdownJoin(t *testing.T) {
	s := sampleSummary(t, "pushdown_join_agg", 3, nil)
	if s.State != "COMPLETED" || s.User != "allowops_reader" || s.Queue == "" {
		t.Errorf("identity: %+v", s)
	}
	if s.TotalMs <= 0 || s.PlanningMs <= 0 || s.PlanningMs > s.TotalMs {
		t.Errorf("times: total=%d planning=%d", s.TotalMs, s.PlanningMs)
	}
	names := []string{}
	for _, p := range s.Phases {
		names = append(names, p.Name)
	}
	if !slices.Contains(names, "PLANNING") || !slices.Contains(names, "RUNNING") || slices.Contains(names, "COMPLETED") {
		t.Errorf("phases: %v", names)
	}
	if len(s.PushdownSQL) != 1 || !strings.HasPrefix(s.PushdownSQL[0], "SELECT `dim_product`.`category`, COUNT(*) AS `c`") || !strings.Contains(s.PushdownSQL[0], "INNER JOIN") || strings.Contains(s.PushdownSQL[0], "]) : rowType") {
		t.Errorf("pushdown SQL: %q", s.PushdownSQL)
	}
	if s.Acceleration.Accelerated || s.Acceleration.Substitutions != 0 || len(s.Acceleration.Reflections) != 0 {
		t.Errorf("acceleration: %+v", s.Acceleration)
	}
	if s.PeakMemory <= 0 || s.DirectMemory != 2<<30 {
		t.Errorf("memory: peak=%d direct=%d", s.PeakMemory, s.DirectMemory)
	}
	if len(s.Operators) != 3 || s.OperatorsOmitted <= 0 {
		t.Errorf("top 3 of %d operators: %+v", len(s.Operators)+s.OperatorsOmitted, s.Operators)
	}
	for i := 1; i < len(s.Operators); i++ {
		a, b := s.Operators[i-1], s.Operators[i]
		if a.processNanos+a.waitNanos < b.processNanos+b.waitNanos {
			t.Errorf("operators are not ordered by process and wait time: %+v", s.Operators)
		}
	}
	// The statement of the user is not part of the summary.
	data, _ := json.Marshal(s)
	if strings.Contains(string(data), "FROM \"demo_src\"") {
		t.Errorf("the original statement is in the summary: %s", data)
	}
}

func TestSummaryOfCrossSourceJoin(t *testing.T) {
	s := sampleSummary(t, "cross_join_large", 20, nil)
	byType := map[string]Operator{}
	for _, op := range s.Operators {
		byType[op.Type] = op
	}
	join, ok := byType["HASH_JOIN"]
	if !ok || join.RecordsIn != 510000 || join.RecordsOut != 500000 {
		t.Errorf("HASH_JOIN: %+v", join)
	}
	if s.ScanRecords != 510000 {
		t.Errorf("scan records: %d", s.ScanRecords)
	}
	if len(s.PushdownSQL) != 2 {
		t.Errorf("each source gets its own statement: %q", s.PushdownSQL)
	}
	for _, op := range s.Operators {
		if op.Instances != 1 || op.SkewRatio != "" {
			t.Errorf("one instance has no skew: %+v", op)
		}
	}
}

func TestSummaryOfFailedAndCanceledJobs(t *testing.T) {
	failed := sampleSummary(t, "failed_unknown_table", 5, nil)
	if failed.State != "FAILED" || !strings.Contains(failed.Error, "no_such_table") || strings.Contains(failed.Error, "\n") {
		t.Errorf("failed: %+v", failed)
	}
	if failed.PlanningMs != 0 || failed.Hits[0].Evidence["category"] != "object not found" {
		t.Errorf("failed: planning=%d hit=%+v", failed.PlanningMs, failed.Hits)
	}
	canceled := sampleSummary(t, "canceled", 5, nil)
	if canceled.State != "CANCELED" || canceled.Hits[0].Evidence["state"] != "CANCELED" {
		t.Errorf("canceled: %+v", canceled)
	}
}

func TestSummaryAppliesMaskToServerStrings(t *testing.T) {
	mask := func(s string) string {
		return strings.NewReplacer("demo_dw", "[SCHEMA]", "allowops_reader", "[USER]", "SMALL", "[QUEUE]", "no_such_table", "[TABLE]").Replace(s)
	}
	for _, name := range []string{"pushdown_join_agg", "failed_unknown_table"} {
		s := sampleSummary(t, name, 5, mask)
		data, _ := json.Marshal(s)
		for _, secret := range []string{"demo_dw", "allowops_reader", "SMALL", "no_such_table"} {
			if strings.Contains(string(data), secret) {
				t.Errorf("%s: %q is not masked in %s", name, secret, data)
			}
		}
	}
	if s := sampleSummary(t, "pushdown_join_agg", 5, mask); !strings.Contains(s.PushdownSQL[0], "[SCHEMA]") || s.User != "[USER]" {
		t.Errorf("mask: %+v", s)
	}
}

func TestPushdownStatementsAreBounded(t *testing.T) {
	var plan strings.Builder
	for i := 0; i < 15; i++ {
		fmt.Fprintf(&plan, "00-%02d  Jdbc(sql=[SELECT %d]) : rowType = RecordType(INTEGER a)\n", i, i)
	}
	fmt.Fprintf(&plan, "00-20  Jdbc(sql=[SELECT '%s']) : rowType = RecordType(INTEGER a)\n", strings.Repeat("x", 5000))
	profile, _ := json.Marshal(map[string]any{"plan": plan.String(), "state": 2})
	s, err := summarize("id", profile, 5, identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.PushdownSQL) != maxPushdownStatements {
		t.Errorf("%d statements; want %d", len(s.PushdownSQL), maxPushdownStatements)
	}
	profile, _ = json.Marshal(map[string]any{"plan": fmt.Sprintf("Jdbc(sql=[SELECT '%s']) : rowType = RecordType(INTEGER a)\n", strings.Repeat("x", 5000)), "state": 2})
	s, _ = summarize("id", profile, 5, identity)
	if len(s.PushdownSQL) != 1 || len([]rune(s.PushdownSQL[0])) > maxPushdownRunes+3 || !strings.HasSuffix(s.PushdownSQL[0], "...") {
		t.Errorf("a long statement is cut: %d runes", len([]rune(s.PushdownSQL[0])))
	}
}

// No local profile has an operator with several instances (a data source over
// JDBC scans with width 1), so this profile is written by hand. It checks the
// arithmetic only: the largest process time of an instance divided by the mean.
func TestSkewAndReflectionFieldsFromWrittenProfile(t *testing.T) {
	op := func(id, nanos int64) map[string]any {
		return map[string]any{"operatorId": 4, "operatorType": 3, "processNanos": nanos, "waitNanos": 0, "outputRecords": id, "peakLocalMemoryAllocated": 1000}
	}
	minor := func(nanos int64) map[string]any {
		return map[string]any{"minorFragmentId": 0, "operatorProfile": []any{op(1, nanos)}}
	}
	profile, _ := json.Marshal(map[string]any{
		"state": 2, "start": 1000, "end": 3000,
		"fragmentProfile": []any{map[string]any{"majorFragmentId": 1, "minorFragmentProfile": []any{minor(900e6), minor(50e6), minor(30e6), minor(20e6)}}},
		"accelerationProfile": map[string]any{
			"accelerated": false, "numSubstitutions": 1,
			"layoutProfiles": []any{map[string]any{"layoutId": "id-1", "name": "raw_sales", "numUsed": 1}, map[string]any{"layoutId": "id-2", "name": "agg_sales", "numUsed": 0}},
		},
	})
	s, err := summarize("id", profile, 5, identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Operators) != 1 {
		t.Fatalf("operators: %+v", s.Operators)
	}
	got := s.Operators[0]
	if got.Type != "HASH_AGGREGATE" || got.Instances != 4 || got.ProcessMs != 1000 || got.SkewRatio != "3.60" {
		t.Errorf("operator: %+v", got)
	}
	if !s.Acceleration.Accelerated || s.Acceleration.Substitutions != 1 || s.Acceleration.Considered != 2 || !slices.Equal(s.Acceleration.Reflections, []string{"raw_sales"}) {
		t.Errorf("acceleration: %+v", s.Acceleration)
	}
}

func TestSummaryRejectsInvalidJSON(t *testing.T) {
	for _, data := range []string{"", "not json", "[]", `{"state": "x"}`, `{"fragmentProfile": 3}`} {
		if _, err := summarize("id", []byte(data), 5, identity); err == nil {
			t.Errorf("accepted %q", data)
		}
	}
}

func TestFitSummaryKeepsHits(t *testing.T) {
	s := sampleSummary(t, "many_branches", 50, nil)
	full, truncated := fitSummary(s, 1<<20)
	if truncated || len(full) < 2000 {
		t.Fatalf("full summary: truncated=%v len=%d", truncated, len(full))
	}
	hitsOnly, _ := fitSummary(Summary{Hits: s.Hits}, 1<<20)
	limit := int64(len(hitsOnly)) + 600
	small, truncated := fitSummary(s, limit)
	if !truncated || int64(len(small)) > limit {
		t.Fatalf("limited summary: truncated=%v len=%d", truncated, len(small))
	}
	var parsed Summary
	if err := json.Unmarshal(small, &parsed); err != nil || len(parsed.Hits) != len(s.Hits) {
		t.Fatalf("hits are dropped: %v %s", err, small)
	}
	if parsed.OperatorsOmitted <= s.OperatorsOmitted || len(parsed.PushdownSQL) >= len(s.PushdownSQL) {
		t.Errorf("operators and statements are cut first: %+v", parsed)
	}
	tiny, truncated := fitSummary(s, 10)
	if !truncated || !strings.Contains(string(tiny), "max_bytes") {
		t.Errorf("a limit below the hits: %s", tiny)
	}
}

func TestExtractProfile(t *testing.T) {
	good := sampleZip(t, "pushdown_scan")
	if data, err := extractProfile(good, DefaultMaxProfileBytes); err != nil || !json.Valid(data) {
		t.Fatalf("sample: %v", err)
	}
	// The last attempt is read, and only entries with the fixed name.
	profile := func(marker string) []byte { return []byte(`{"state":2,"user":"` + marker + `"}`) }
	zipped := makeZip(t, map[string][]byte{
		"header.json": []byte(`{}`), "profile_attempt_0.json": profile("first"), "profile_attempt_1.json": profile("second"), "profile_attempt_10.json": profile("third"),
		"profile_attempt_2.json.bak": profile("backup"), "../profile_attempt_99.json": profile("path"), "dir/profile_attempt_50.json": profile("dir"),
	})
	data, err := extractProfile(zipped, 1<<20)
	if err != nil || !strings.Contains(string(data), "third") {
		t.Fatalf("attempt 10 is the last: %s %v", data, err)
	}
	for name, zipped := range map[string][]byte{
		"empty":         makeZip(t, nil),
		"no profile":    makeZip(t, map[string][]byte{"header.json": []byte(`{}`)}),
		"other names":   makeZip(t, map[string][]byte{"profile_attempt_x.json": []byte(`{}`), "profile_attempt_0.txt": []byte(`{}`)}),
		"not a zip":     []byte("<html>login</html>"),
		"truncated zip": good[:len(good)/2],
		"empty input":   nil,
	} {
		if _, err := extractProfile(zipped, 1<<20); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExtractProfileEntryCountIsBounded(t *testing.T) {
	files := map[string][]byte{"profile_attempt_0.json": []byte(`{}`)}
	for i := 0; i < maxZipEntries; i++ {
		files[fmt.Sprintf("log_%d.json", i)] = []byte("x")
	}
	if _, err := extractProfile(makeZip(t, files), 1<<20); err == nil {
		t.Fatal("accepted a zip with more than the allowed number of entries")
	}
}

// A zip that expands far beyond the limit is refused without being unpacked,
// both when the central directory states the real size and when it understates it.
func TestExtractProfileRefusesZipBomb(t *testing.T) {
	const limit = 1 << 20
	zeros := bytes.Repeat([]byte{0}, 64<<20)
	bomb := makeZip(t, map[string][]byte{"profile_attempt_0.json": zeros})
	if len(bomb) > 1<<20 {
		t.Fatalf("test bomb is %d bytes; it should be tiny", len(bomb))
	}
	_, err := extractProfile(bomb, limit)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("declared size: %v", err)
	}
	// Understate the size in the central directory (offset 24 of the entry).
	lying := bytes.Clone(bomb)
	at := bytes.Index(lying, []byte("PK\x01\x02"))
	if at < 0 {
		t.Fatal("central directory not found")
	}
	binary.LittleEndian.PutUint32(lying[at+24:], 100)
	// The reader of the standard library stops at the stated size, so this is
	// an error of another kind, but it is an error and the 64 MiB are not read.
	if _, err = extractProfile(lying, limit); err == nil {
		t.Fatal("understated size accepted")
	}
	// A profile at exactly the limit is accepted.
	exact := bytes.Repeat([]byte(" "), limit-2)
	exact = append(append([]byte("{"), exact...), '}')
	if data, err := extractProfile(makeZip(t, map[string][]byte{"profile_attempt_0.json": exact}), limit); err != nil || len(data) != limit {
		t.Fatalf("at the limit: %d %v", len(data), err)
	}
	if _, err := extractProfile(makeZip(t, map[string][]byte{"profile_attempt_0.json": append(exact, ' ')}), limit); err == nil {
		t.Fatal("one byte over the limit")
	}
}
