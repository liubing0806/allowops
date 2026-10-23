package logquery

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const levelRegex = `^\S+ \S+ \[[^\]]*\] (?P<level>[A-Z]+)`

func levelLine(at time.Time, level, message string) string {
	return at.In(shanghai).Format(logback) + " [main] " + level + " c.y.App - " + message + "\n"
}

func withLevel(cfg Config) Config {
	s := cfg.Sources["app"]
	s.Level = &Level{Regex: levelRegex}
	cfg.Sources["app"] = s
	return cfg
}

// leveled writes 60 records one minute apart over three rotated files. Every
// fifth record is ERROR with a stack trace, every third (not fifth) is WARN,
// the rest INFO. INFO stack lines mention "ERROR" to check that the level is
// taken from the first line only.
func leveled(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for i, name := range []string{"app.log.2.gz", "app.log.1", "app.log"} {
		var content strings.Builder
		for j := 0; j < 20; j++ {
			n := i*20 + j
			at := base.Add(time.Duration(n) * time.Minute)
			switch {
			case n%5 == 0:
				content.WriteString(levelLine(at, "ERROR", fmt.Sprintf("order %d failed for user %d", n, 1000+n)))
				content.WriteString("java.lang.IllegalStateException: boom\n\tat com.example.Foo.bar(Foo.java:10)\n")
			case n%3 == 0:
				content.WriteString(levelLine(at, "WARN", fmt.Sprintf("slow query took %d ms", 300+n)))
			default:
				content.WriteString(levelLine(at, "INFO", fmt.Sprintf("request %d handled", n)))
				content.WriteString("\tcontext: no ERROR here\n")
			}
		}
		writeLog(t, filepath.Join(root, name), content.String(), base.Add(time.Duration(i*20+19)*time.Minute))
	}
	setNow(t, base.Add(2*time.Hour))
	return root
}

func stats(t *testing.T, cfg Config, p Params) (StatsOutput, string, error) {
	t.Helper()
	cfg.Mode = ModeStats
	r, err := Run(context.Background(), cfg, p, nil, 0)
	var out StatsOutput
	if err != nil {
		return out, "", err
	}
	if err := json.Unmarshal([]byte(r.Stdout), &out); err != nil {
		t.Fatalf("invalid JSON %q: %v", r.Stdout, err)
	}
	return out, r.Stdout, nil
}

func patterns(t *testing.T, cfg Config, p Params, redact func(string) string, maxOutput int64) (PatternsOutput, string, error) {
	t.Helper()
	cfg.Mode = ModePatterns
	r, err := Run(context.Background(), cfg, p, redact, maxOutput)
	var out PatternsOutput
	if err != nil {
		return out, "", err
	}
	if maxOutput > 0 && int64(len(r.Stdout)) > maxOutput {
		t.Fatalf("output %d bytes exceeds max_output %d", len(r.Stdout), maxOutput)
	}
	if err := json.Unmarshal([]byte(r.Stdout), &out); err != nil {
		t.Fatalf("invalid JSON %q: %v", r.Stdout, err)
	}
	return out, r.Stdout, nil
}

func TestLevelConfigValidate(t *testing.T) {
	root := t.TempDir()
	if err := withLevel(testConfig(root)).Validate(); err != nil {
		t.Fatalf("valid level: %v", err)
	}
	for name, regex := range map[string]string{
		"no group":      `^\S+ \S+ \[[^\]]*\] ([A-Z]+)`,
		"other name":    `^\S+ \S+ \[[^\]]*\] (?P<severity>[A-Z]+)`,
		"invalid regex": `(?P<level>[A-Z]+`,
		"empty":         ``,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(root)
			s := cfg.Sources["app"]
			s.Level = &Level{Regex: regex}
			cfg.Sources["app"] = s
			if err := cfg.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, mode := range []string{ModeStats, ModePatterns} {
		cfg := testConfig(root)
		cfg.Mode = mode
		if err := cfg.Validate(); err != nil {
			t.Fatalf("mode %s: %v", mode, err)
		}
	}
}

func TestSearchLevelFilter(t *testing.T) {
	root := leveled(t)
	cfg := withLevel(testConfig(root))
	window := Params{Source: "app", Since: "2026-10-23T09:59:00+08:00", Until: "2026-10-23T11:00:00+08:00", Limit: 200}
	cases := []struct {
		levels []string
		want   int
	}{
		{nil, 60},
		{[]string{"ERROR"}, 12},
		{[]string{"WARN"}, 16},
		{[]string{"ERROR", "WARN"}, 28},
		{[]string{"INFO"}, 32},
		{[]string{"DEBUG"}, 0},
	}
	for _, tc := range cases {
		p := window
		p.Level = tc.levels
		out, err := search(t, cfg, p)
		if err != nil || out.Matched != tc.want {
			t.Fatalf("level %v: matched=%d err=%v, want %d", tc.levels, out.Matched, err, tc.want)
		}
	}
	p := window
	p.Level, p.Pattern = []string{"ERROR"}, "order 1[05] "
	if out, err := search(t, cfg, p); err != nil || out.Matched != 2 {
		t.Fatalf("level and pattern: matched=%d err=%v", out.Matched, err)
	}
	// A cursor carries the level in its parameter hash.
	p = window
	p.Level, p.Limit = []string{"ERROR"}, 5
	first, err := search(t, cfg, p)
	if err != nil || !first.HasMore {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	p.Cursor, p.Level = first.NextCursor, []string{"WARN"}
	if _, err := search(t, cfg, p); reasonOf(err) != CodeCursorInvalid {
		t.Fatalf("changed level with cursor: err=%v", err)
	}
	// A source without a level rule rejects the parameter.
	p = window
	p.Level = []string{"ERROR"}
	if _, err := search(t, testConfig(root), p); reasonOf(err) != CodeLevelUnsupported {
		t.Fatalf("err=%v, want %s", err, CodeLevelUnsupported)
	}
	p.Level = []string{"FATAL"}
	if _, err := search(t, cfg, p); err == nil {
		t.Fatal("accepted unknown level")
	}
}

func histogramTotal(out StatsOutput) int {
	total := 0
	for _, b := range out.Histogram {
		total += b.Count
	}
	return total
}

// Design 7.4 item 1: the histogram total equals log_search matched for the
// same parameters.
func TestStatsHistogramEqualsSearchMatched(t *testing.T) {
	root := leveled(t)
	cfg := withLevel(testConfig(root))
	window := Params{Source: "app", Since: "2026-10-23T10:07:30+08:00", Until: "2026-10-23T10:52:10+08:00"}
	variants := []Params{
		{},
		{Pattern: "order"},
		{Pattern: "Foo.java", Fixed: true},
		{Pattern: "REQUEST", IgnoreCase: true, Exclude: "request 2"},
		{Level: []string{"ERROR", "WARN"}},
		{Level: []string{"INFO"}, Pattern: "ERROR"},
		{Pattern: "absent"},
	}
	for i, v := range variants {
		p := v
		p.Source, p.Since, p.Until = window.Source, window.Since, window.Until
		st, _, err := stats(t, cfg, p)
		if err != nil {
			t.Fatalf("variant %d: %v", i, err)
		}
		for _, order := range []string{"desc", "asc"} {
			sp := p
			sp.Order, sp.Limit = order, 1
			found, err := search(t, cfg, sp)
			if err != nil {
				t.Fatalf("variant %d %s: %v", i, order, err)
			}
			if histogramTotal(st) != found.Matched || st.Matched != found.Matched {
				t.Fatalf("variant %d %s: histogram total %d, stats matched %d, search matched %d", i, order, histogramTotal(st), st.Matched, found.Matched)
			}
		}
		files := 0
		for _, f := range st.ByFile {
			files += f.Count
		}
		levels := 0
		for _, n := range st.ByLevel {
			levels += n
		}
		if files != st.Matched || levels != st.Matched {
			t.Fatalf("variant %d: by_file %d, by_level %d, matched %d", i, files, levels, st.Matched)
		}
	}
}

func TestStatsOutput(t *testing.T) {
	root := leveled(t)
	cfg := withLevel(testConfig(root))
	out, raw, err := stats(t, cfg, Params{Source: "app", Since: "2026-10-23T10:00:00+08:00", Until: "2026-10-23T11:00:00+08:00", Bucket: "10m"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Bucket != "10m0s" || out.Matched != 60 || out.FirstMatch != "2026-10-23T10:00:00+08:00" || out.LastMatch != "2026-10-23T10:59:00+08:00" || out.ScanLimitReached {
		t.Fatalf("out=%+v", out)
	}
	want := []HistogramBucket{}
	for i := 0; i < 6; i++ {
		want = append(want, HistogramBucket{Start: base.Add(time.Duration(i) * 10 * time.Minute).Format(time.RFC3339Nano), Count: 10})
	}
	if fmt.Sprint(out.Histogram) != fmt.Sprint(want) {
		t.Fatalf("histogram=%v\nwant      %v", out.Histogram, want)
	}
	if fmt.Sprint(out.ByLevel) != fmt.Sprint(map[string]int{"ERROR": 12, "INFO": 32, "WARN": 16}) {
		t.Fatalf("by_level=%v", out.ByLevel)
	}
	wantFiles := []FileCount{{filepath.Join(root, "app.log.2.gz"), 20}, {filepath.Join(root, "app.log.1"), 20}, {filepath.Join(root, "app.log"), 20}}
	if fmt.Sprint(out.ByFile) != fmt.Sprint(wantFiles) {
		t.Fatalf("by_file=%v", out.ByFile)
	}
	for _, text := range []string{"order", "request", "IllegalStateException", "slow query"} {
		if strings.Contains(raw, text) {
			t.Fatalf("stats output contains log text %q: %s", text, raw)
		}
	}
	// Without a level rule there is no by_level.
	plain, raw, err := stats(t, testConfig(root), Params{Source: "app", Since: "2026-10-23T10:00:00+08:00", Until: "2026-10-23T11:00:00+08:00"})
	if err != nil || plain.ByLevel != nil || strings.Contains(raw, "by_level") || plain.Matched != 60 {
		t.Fatalf("plain=%s err=%v", raw, err)
	}
}

func TestStatsAutoBucket(t *testing.T) {
	root := leveled(t)
	cfg := testConfig(root)
	cases := []struct {
		since, until, want string
	}{
		{"2026-10-23T10:00:00+08:00", "2026-10-23T11:00:00+08:00", "1m0s"},
		{"2026-10-23T10:00:00+08:00", "2026-10-23T10:00:30+08:00", "1s"},
		{"2026-10-23T10:00:00+08:00", "2026-10-23T16:00:00+08:00", "10m0s"},
		{"2026-10-22T11:00:00+08:00", "2026-10-23T11:00:00+08:00", "30m0s"},
	}
	for _, tc := range cases {
		out, _, err := stats(t, cfg, Params{Source: "app", Since: tc.since, Until: tc.until})
		if err != nil || out.Bucket != tc.want {
			t.Fatalf("%s..%s: bucket=%q err=%v, want %s", tc.since, tc.until, out.Bucket, err, tc.want)
		}
		width, _ := time.ParseDuration(out.Bucket)
		since, _ := time.Parse(time.RFC3339, tc.since)
		until, _ := time.Parse(time.RFC3339, tc.until)
		if buckets := (until.Sub(since) + width - 1) / width; buckets > 60 {
			t.Fatalf("%s: %d buckets", out.Bucket, buckets)
		}
	}
	// Bucket starts are aligned to the bucket width in the source time zone.
	out, _, err := stats(t, cfg, Params{Source: "app", Since: "2026-10-23T10:07:30+08:00", Until: "2026-10-23T10:30:00+08:00", Bucket: "5m"})
	if err != nil || len(out.Histogram) == 0 || out.Histogram[0].Start != "2026-10-23T10:05:00+08:00" || out.Histogram[0].Count != 2 {
		t.Fatalf("aligned=%+v err=%v", out, err)
	}
	// A bucket that yields too many buckets falls back to the automatic width.
	out, _, err = stats(t, cfg, Params{Source: "app", Since: "2026-10-22T11:00:00+08:00", Until: "2026-10-23T11:00:00+08:00", Bucket: "1s"})
	if err != nil || out.Bucket != "30m0s" {
		t.Fatalf("too many buckets: bucket=%q err=%v", out.Bucket, err)
	}
}

func TestStatsScanLimit(t *testing.T) {
	root := leveled(t)
	cfg := testConfig(root)
	cfg.MaxScan = 2000
	out, _, err := stats(t, cfg, Params{Source: "app", Since: "2026-10-23T10:00:00+08:00", Until: "2026-10-23T11:00:00+08:00"})
	if err != nil || !out.ScanLimitReached || out.Matched == 0 || out.Matched >= 60 || histogramTotal(out) != out.Matched || out.ScannedUntil == out.Until {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestStatsLevelUnsupported(t *testing.T) {
	root := leveled(t)
	_, _, err := stats(t, testConfig(root), Params{Source: "app", Level: []string{"ERROR"}})
	if reasonOf(err) != CodeLevelUnsupported {
		t.Fatalf("err=%v, want %s", err, CodeLevelUnsupported)
	}
}

// Design 7.4 item 2: the same input yields the same output.
func TestPatternsDeterministic(t *testing.T) {
	root := leveled(t)
	cfg := withLevel(testConfig(root))
	p := Params{Source: "app", Since: "2026-10-23T09:00:00+08:00", Until: "2026-10-23T11:00:00+08:00"}
	_, first, err := patterns(t, cfg, p, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, again, err := patterns(t, cfg, p, nil, 0)
		if err != nil || again != first {
			t.Fatalf("run %d differs:\n%s\n%s err=%v", i, first, again, err)
		}
	}
	out, _, _ := patterns(t, cfg, p, nil, 0)
	want := []struct {
		template string
		count    int
	}{
		{"<_> [main] INFO c.y.App - request <_> handled", 32},
		{"<_> [main] WARN c.y.App - slow query took <_> ms", 16},
		{"<_> [main] ERROR c.y.App - order <_> failed for user <_>", 12},
	}
	if out.Records != 60 || len(out.Patterns) != len(want) {
		t.Fatalf("out=%+v", out)
	}
	for i, w := range want {
		got := out.Patterns[i]
		if got.Template != w.template || got.Count != w.count {
			t.Fatalf("pattern %d=%+v, want %q x%d", i, got, w.template, w.count)
		}
	}
	if e := out.Patterns[2]; e.First != "2026-10-23T10:00:00+08:00" || e.Last != "2026-10-23T10:55:00+08:00" ||
		e.Sample != "2026-10-23 10:00:00.000 [main] ERROR c.y.App - order 0 failed for user 1000" {
		t.Fatalf("error pattern=%+v", e)
	}
}

func TestPatternsFiltersAndTop(t *testing.T) {
	root := leveled(t)
	cfg := withLevel(testConfig(root))
	p := Params{Source: "app", Since: "2026-10-23T09:00:00+08:00", Until: "2026-10-23T11:00:00+08:00"}
	p.Level = []string{"ERROR", "WARN"}
	out, _, err := patterns(t, cfg, p, nil, 0)
	if err != nil || out.Records != 28 || len(out.Patterns) != 2 {
		t.Fatalf("level out=%+v err=%v", out, err)
	}
	p.Level, p.Exclude = nil, "slow query"
	out, _, err = patterns(t, cfg, p, nil, 0)
	if err != nil || out.Records != 44 || len(out.Patterns) != 2 {
		t.Fatalf("exclude out=%+v err=%v", out, err)
	}
	p.Exclude, p.Top = "", 1
	out, _, err = patterns(t, cfg, p, nil, 0)
	if err != nil || len(out.Patterns) != 1 || out.Patterns[0].Count != 32 || out.Clusters != 3 {
		t.Fatalf("top out=%+v err=%v", out, err)
	}
	p.Top = MaxPatternsTop + 1
	if _, _, err := patterns(t, cfg, p, nil, 0); err == nil {
		t.Fatal("accepted top above maximum")
	}
	p.Top, p.Pattern = 0, "order"
	if _, _, err := patterns(t, cfg, p, nil, 0); err == nil {
		t.Fatal("patterns accepted pattern")
	}
	p.Pattern, p.Level = "", []string{"ERROR"}
	if _, _, err := patterns(t, testConfig(root), p, nil, 0); reasonOf(err) != CodeLevelUnsupported {
		t.Fatalf("err=%v, want %s", err, CodeLevelUnsupported)
	}
}

func TestPatternsMaskAndRedact(t *testing.T) {
	root := t.TempDir()
	var content strings.Builder
	ids := []string{"1f0e8c1a-6a4b-4c1e-9d0b-2a3b4c5d6e7f", "0b8d9a2c-1111-4222-8333-944455566677"}
	for i := 0; i < 6; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		content.WriteString(line(at, fmt.Sprintf("trace %s from 10.0.%d.7:8080 at 2026-10-23T10:0%d:00Z token=0x%x hash deadbeef%02d password=hunter2", ids[i%2], i, i, 0xabc0+i, i)))
	}
	writeLog(t, filepath.Join(root, "app.log"), content.String(), base.Add(6*time.Minute))
	setNow(t, base.Add(10*time.Minute))
	redact := func(s string) string {
		if i := strings.Index(s, "password="); i >= 0 {
			return s[:i] + "password=[REDACTED:credential]"
		}
		return s
	}
	out, _, err := patterns(t, testConfig(root), Params{Source: "app"}, redact, 0)
	if err != nil || len(out.Patterns) != 1 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	got := out.Patterns[0]
	want := "<_> [main] INFO c.y.App - trace <_> from <_> at <_> token=<_> hash <_> password=[REDACTED:credential]"
	if got.Template != want || got.Count != 6 {
		t.Fatalf("template=%q count=%d\nwant     %q", got.Template, got.Count, want)
	}
	if strings.Contains(got.Sample, "hunter") || !strings.Contains(got.Sample, "[REDACTED:credential]") {
		t.Fatalf("sample=%q", got.Sample)
	}
}

func TestPatternsOutputBudget(t *testing.T) {
	root := t.TempDir()
	var content strings.Builder
	for i := 0; i < 40; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		// A different token count per record gives one template each.
		content.WriteString(line(at, strings.Repeat("x", 200)+strings.Repeat(" y", i)))
	}
	writeLog(t, filepath.Join(root, "app.log"), content.String(), base.Add(time.Minute))
	setNow(t, base.Add(10*time.Minute))
	full, _, err := patterns(t, testConfig(root), Params{Source: "app", Top: 100}, nil, 0)
	if err != nil || len(full.Patterns) < 10 {
		t.Fatalf("full=%+v err=%v", full, err)
	}
	limited, _, err := patterns(t, testConfig(root), Params{Source: "app", Top: 100}, nil, 4096)
	if err != nil || len(limited.Patterns) == 0 || len(limited.Patterns) >= len(full.Patterns) || limited.Omitted != len(full.Patterns)-len(limited.Patterns) {
		t.Fatalf("limited=%d omitted=%d full=%d err=%v", len(limited.Patterns), limited.Omitted, len(full.Patterns), err)
	}
}

func TestPatternsScanLimit(t *testing.T) {
	root := leveled(t)
	cfg := testConfig(root)
	cfg.MaxScan = 2000
	out, _, err := patterns(t, cfg, Params{Source: "app", Since: "2026-10-23T10:00:00+08:00", Until: "2026-10-23T11:00:00+08:00"}, nil, 0)
	if err != nil || !out.ScanLimitReached || out.Records == 0 || out.Records >= 60 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestPhase2Parameters(t *testing.T) {
	root := t.TempDir()
	keys := func(cfg Config) string {
		var names []string
		for name := range Parameters(cfg) {
			names = append(names, name)
		}
		slices.Sort(names)
		return fmt.Sprint(names)
	}
	cfg := testConfig(root)
	if got := keys(cfg); got != "[cursor exclude fixed ignore_case limit order pattern since source until]" {
		t.Fatalf("search without level rule: %s", got)
	}
	cfg = withLevel(testConfig(root))
	if got := keys(cfg); got != "[cursor exclude fixed ignore_case level limit order pattern since source until]" {
		t.Fatalf("search: %s", got)
	}
	cfg.Mode = ModeStats
	if got := keys(cfg); got != "[bucket exclude fixed ignore_case level pattern since source until]" {
		t.Fatalf("stats: %s", got)
	}
	cfg.Mode = ModePatterns
	if got := keys(cfg); got != "[exclude level since source top until]" {
		t.Fatalf("patterns: %s", got)
	}
}
