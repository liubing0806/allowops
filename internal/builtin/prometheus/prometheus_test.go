package prometheus

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/builtin/apiclient"
	"github.com/liubing0806/allowops/internal/params"
)

// fixedNow is 2026-10-23T03:12:00Z; the unix value below is the same instant.
var fixedNow = time.Date(2026, 10, 23, 3, 12, 0, 0, time.UTC)

const fixedUnix = 1792725120

func useFixedClock(t *testing.T) {
	t.Helper()
	previous := now
	now = func() time.Time { return fixedNow }
	t.Cleanup(func() { now = previous })
}

type fakeServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
}

func (f *fakeServer) last(t *testing.T) *http.Request {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		t.Fatal("server received no request")
	}
	return f.requests[len(f.requests)-1]
}

func (f *fakeServer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func serve(t *testing.T, status int, body string) *fakeServer {
	t.Helper()
	f := &fakeServer{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Clone(context.Background()))
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(f.Close)
	return f
}

func config(api string, f *fakeServer) Config {
	return Config{API: api, Config: apiclient.Config{Address: f.URL}}
}

func success(data string) string { return `{"status":"success","data":` + data + `}` }

func vector(results ...string) string {
	return success(`{"resultType":"vector","result":[` + strings.Join(results, ",") + `]}`)
}

func lines(s string) []string { return strings.Split(strings.TrimSuffix(s, "\n"), "\n") }

func mustRun(t *testing.T, cfg Config, p Params) Result {
	t.Helper()
	r, err := Run(context.Background(), cfg, p)
	if err != nil {
		t.Fatalf("Run: %v (stderr %q)", err, r.Stderr)
	}
	return r
}

func TestDefinitionsPerAPI(t *testing.T) {
	cases := []struct {
		api      string
		names    []string
		required []string
	}{
		{"query", []string{"query", "time"}, []string{"query"}},
		{"query_range", []string{"end", "query", "start", "step", "summary"}, []string{"query", "start"}},
		{"series", []string{"end", "match", "start"}, []string{"match"}},
		{"labels", []string{"end", "match", "start"}, nil},
		{"label_values", []string{"end", "label", "match", "start"}, []string{"label"}},
		{"alerts", nil, nil},
		{"rules", []string{"rule_type"}, nil},
		{"targets", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.api, func(t *testing.T) {
			defs, err := Definitions(tc.api)
			if err != nil {
				t.Fatal(err)
			}
			if err := params.ValidateDefinitions(defs); err != nil {
				t.Fatalf("invalid definitions: %v", err)
			}
			var names, required []string
			for name, d := range defs {
				names = append(names, name)
				if !d.Optional && d.Default == nil {
					required = append(required, name)
				}
			}
			slices.Sort(names)
			slices.Sort(required)
			if !slices.Equal(names, tc.names) && !(len(names) == 0 && len(tc.names) == 0) {
				t.Errorf("names = %v; want %v", names, tc.names)
			}
			if !slices.Equal(required, tc.required) && !(len(required) == 0 && len(tc.required) == 0) {
				t.Errorf("required = %v; want %v", required, tc.required)
			}
		})
	}
	if _, err := Definitions("status_config"); err == nil {
		t.Error("unsupported api accepted")
	}
}

func TestDefinitionConstraints(t *testing.T) {
	defs, _ := Definitions("query_range")
	if d := defs["query"]; d.Type != params.String || d.MaxLen != 2000 {
		t.Errorf("query = %+v", d)
	}
	if d := defs["step"]; d.Type != params.Duration || !d.Optional {
		t.Errorf("step = %+v", d)
	}
	if d := defs["summary"]; d.Type != params.Bool || d.Default != false {
		t.Errorf("summary = %+v", d)
	}
	series, _ := Definitions("series")
	if d := series["match"]; d.Type != params.StringArray || d.MaxItems != 10 || d.MaxLen != 500 {
		t.Errorf("match = %+v", d)
	}
	values, _ := Definitions("label_values")
	if d := values["label"]; d.Regex != `^[a-zA-Z_][a-zA-Z0-9_]*$` {
		t.Errorf("label regex = %q", d.Regex)
	}
	rules, _ := Definitions("rules")
	if d := rules["rule_type"]; d.Type != params.Enum || !slices.Equal(d.Values, []string{"alert", "record"}) || !d.Optional {
		t.Errorf("rule_type = %+v", d)
	}
	// The definitions must accept what the handler accepts.
	if _, err := params.Parse(defs, map[string]any{"query": "up", "start": "now-1h"}); err != nil {
		t.Errorf("parse valid input: %v", err)
	}
	for _, bad := range []string{"1h", "now+1h", "yesterday", "2026-10-23 03:12:00", "2026-10-23T03:12:00+08:00", "now-1w"} {
		if _, err := params.Parse(defs, map[string]any{"query": "up", "start": bad}); err == nil {
			t.Errorf("start %q accepted by definitions", bad)
		}
	}
}

func TestParseTime(t *testing.T) {
	cases := []struct {
		in   string
		want time.Time
	}{
		{"now", fixedNow},
		{"now-30s", fixedNow.Add(-30 * time.Second)},
		{"now-5m", fixedNow.Add(-5 * time.Minute)},
		{"now-2h", fixedNow.Add(-2 * time.Hour)},
		{"now-7d", fixedNow.Add(-7 * 24 * time.Hour)},
		{"2026-10-23T03:12:00Z", fixedNow},
		{"2026-10-22T00:00:00Z", time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		got, err := ParseTime(tc.in, fixedNow)
		if err != nil || !got.Equal(tc.want) || got.Location() != time.UTC {
			t.Errorf("ParseTime(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "NOW", "now-", "now-5", "now-5w", "now+5m", "now-0.5h", "now- 5m", "now-1h30m",
		"now-99999999999d", "2026-10-23", "2026-10-23T03:12:00", "2026-10-23T11:12:00+08:00", "2026-10-23T03:12:00.5Z",
		"2026-13-23T03:12:00Z", "1792725120", "2026-10-23T03:12:00Z\n"} {
		if got, err := ParseTime(bad, fixedNow); err == nil {
			t.Errorf("ParseTime(%q) = %v; want error", bad, got)
		}
	}
}

func TestConfigDefaultsAndLimits(t *testing.T) {
	base := Config{API: "query_range", Config: apiclient.Config{Address: "http://127.0.0.1:9090"}}
	if err := base.Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	valid := base
	valid.Timeout, valid.MaxRange, valid.MinStep = 30*time.Second, 7*24*time.Hour, time.Minute
	valid.MaxPoints, valid.MaxSeries, valid.MaxResponseBytes = 11000, 1000, 16<<20
	if err := valid.Validate(); err != nil {
		t.Fatalf("upper limits: %v", err)
	}
	mutations := map[string]func(*Config){
		"missing api":       func(c *Config) { c.API = "" },
		"unknown api":       func(c *Config) { c.API = "status_config" },
		"missing address":   func(c *Config) { c.Address = "" },
		"address query":     func(c *Config) { c.Address = "http://127.0.0.1:9090/?a=b" },
		"address userinfo":  func(c *Config) { c.Address = "http://u:p@127.0.0.1:9090" },
		"timeout over":      func(c *Config) { c.Timeout = 31 * time.Second },
		"timeout negative":  func(c *Config) { c.Timeout = -time.Second },
		"max_range over":    func(c *Config) { c.MaxRange = 7*24*time.Hour + time.Second },
		"min_step under":    func(c *Config) { c.MinStep = 14 * time.Second },
		"max_points over":   func(c *Config) { c.MaxPoints = 11001 },
		"max_points one":    func(c *Config) { c.MaxPoints = 1 },
		"max_points neg":    func(c *Config) { c.MaxPoints = -1 },
		"max_series over":   func(c *Config) { c.MaxSeries = 1001 },
		"max_response over": func(c *Config) { c.MaxResponseBytes = 16<<20 + 1 },
		"relative cred":     func(c *Config) { c.Credential = "cred.json" },
		"ca without https":  func(c *Config) { c.CAFile = "/etc/ca.pem" },
	}
	for name, mutate := range mutations {
		c := base
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestQueryVector(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, vector(
		fmt.Sprintf(`{"metric":{"__name__":"up","job":"node","instance":"10.0.0.5:9100"},"value":[%d.123,"1"]}`, fixedUnix),
		fmt.Sprintf(`{"metric":{},"value":[%d,"NaN"]}`, fixedUnix),
		fmt.Sprintf(`{"metric":{"__name__":"x","a":"+Inf"},"value":[%d,"+Inf"]}`, fixedUnix),
	))
	r := mustRun(t, config("query", f), Params{Query: "up"})
	want := []string{
		"# api=query time=2026-10-23T03:12:00Z",
		`up{instance="10.0.0.5:9100",job="node"}` + "\t2026-10-23T03:12:00Z\t1",
		"{}\t2026-10-23T03:12:00Z\tNaN",
		`x{a="+Inf"}` + "\t2026-10-23T03:12:00Z\t+Inf",
	}
	if !reflect.DeepEqual(lines(r.Stdout), want) || r.ExitCode != 0 || r.Truncated || r.Stderr != "" {
		t.Fatalf("result = %+v\nwant stdout %q", r, want)
	}
	req := f.last(t)
	if req.Method != http.MethodGet || req.URL.Path != "/api/v1/query" {
		t.Errorf("request = %s %s", req.Method, req.URL.Path)
	}
	q := req.URL.Query()
	if q.Get("query") != "up" || q.Get("time") != "2026-10-23T03:12:00Z" || q.Get("timeout") != "10" {
		t.Errorf("query = %v", q)
	}
}

func TestQueryExplicitTimeAndTimeout(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, vector())
	cfg := config("query", f)
	cfg.Timeout = 2500 * time.Millisecond
	r := mustRun(t, cfg, Params{Query: "up", Time: "now-1h"})
	if lines(r.Stdout)[0] != "# api=query time=2026-10-23T02:12:00Z" {
		t.Errorf("header = %q", r.Stdout)
	}
	q := f.last(t).URL.Query()
	if q.Get("time") != "2026-10-23T02:12:00Z" || q.Get("timeout") != "2.5" {
		t.Errorf("query = %v", q)
	}
}

func TestQueryScalarStringAndMatrix(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, success(fmt.Sprintf(`{"resultType":"scalar","result":[%d,"3"]}`, fixedUnix)))
	r := mustRun(t, config("query", f), Params{Query: "1+2"})
	if got := lines(r.Stdout); len(got) != 2 || got[1] != "2026-10-23T03:12:00Z\t3" {
		t.Errorf("scalar = %q", r.Stdout)
	}
	f = serve(t, 200, success(fmt.Sprintf(`{"resultType":"string","result":[%d,"a\tb"]}`, fixedUnix)))
	r = mustRun(t, config("query", f), Params{Query: `"a"`})
	if got := lines(r.Stdout); len(got) != 2 || got[1] != `2026-10-23T03:12:00Z`+"\t"+`a\tb` {
		t.Errorf("string = %q", r.Stdout)
	}
	f = serve(t, 200, success(fmt.Sprintf(`{"resultType":"matrix","result":[{"metric":{"__name__":"up","job":"a"},"values":[[%d,"1"],[%d,"0"]]}]}`, fixedUnix-60, fixedUnix)))
	r = mustRun(t, config("query", f), Params{Query: "up[1m]"})
	want := []string{
		"# api=query time=2026-10-23T03:12:00Z",
		`up{job="a"}` + "\t2026-10-23T03:11:00Z\t1",
		`up{job="a"}` + "\t2026-10-23T03:12:00Z\t0",
	}
	if !reflect.DeepEqual(lines(r.Stdout), want) {
		t.Errorf("matrix = %q", r.Stdout)
	}
}

func TestNativeHistogramOutputsCountAndSum(t *testing.T) {
	useFixedClock(t)
	hist := `{"count":"12","sum":"3.5","buckets":[[1,"0","1","7"],[1,"1","2","5"]]}`
	f := serve(t, 200, vector(fmt.Sprintf(`{"metric":{"__name__":"latency"},"histogram":[%d,%s]}`, fixedUnix, hist)))
	r := mustRun(t, config("query", f), Params{Query: "latency"})
	want := "latency\t2026-10-23T03:12:00Z\tcount=12 sum=3.5"
	if got := lines(r.Stdout); len(got) != 2 || got[1] != want || strings.Contains(r.Stdout, "buckets") {
		t.Errorf("histogram = %q; want line %q", r.Stdout, want)
	}
	f = serve(t, 200, success(fmt.Sprintf(`{"resultType":"matrix","result":[{"metric":{"__name__":"latency"},"histograms":[[%d,%s]]}]}`, fixedUnix, hist)))
	r = mustRun(t, config("query", f), Params{Query: "latency[1m]"})
	if got := lines(r.Stdout); len(got) != 2 || got[1] != want {
		t.Errorf("histogram matrix = %q", r.Stdout)
	}
}

func TestLabelSetsAreSortedAndEscaped(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, vector(fmt.Sprintf(`{"metric":{"z":"1","__name__":"m","a":"x\"y\\z\nw\tv"},"value":[%d,"1"]}`, fixedUnix)))
	r := mustRun(t, config("query", f), Params{Query: "m"})
	// Prometheus label quoting first, then TSV escaping of the whole field.
	want := `m{a="x\\"y\\\\z\\nw\tv",z="1"}` + "\t2026-10-23T03:12:00Z\t1"
	if got := lines(r.Stdout); len(got) != 2 || got[1] != want {
		t.Errorf("line = %q\nwant   %q", got[1], want)
	}
	if strings.Count(r.Stdout, "\n") != 2 || strings.Contains(strings.Split(r.Stdout, "\n")[1], "\t\t") {
		t.Errorf("unescaped separators in %q", r.Stdout)
	}
}

func TestMaskRunsBeforeEncoding(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, vector(fmt.Sprintf(`{"metric":{"__name__":"m","token":"abc"},"value":[%d,"1"]}`, fixedUnix)))
	mask := func(s string) string { return strings.ReplaceAll(s, "abc", "***\t***") }
	r, err := RunRedacted(context.Background(), config("query", f), Params{Query: "m"}, mask)
	if err != nil {
		t.Fatal(err)
	}
	// A tab introduced by the mask is escaped, not emitted as a field separator.
	want := `m{token="***\t***"}` + "\t2026-10-23T03:12:00Z\t1"
	if got := lines(r.Stdout); len(got) != 2 || got[1] != want {
		t.Errorf("stdout = %q", r.Stdout)
	}
	if strings.Contains(r.Stdout, "abc") {
		t.Error("unmasked value in stdout")
	}
}

func TestQueryRange(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, success(fmt.Sprintf(`{"resultType":"matrix","result":[{"metric":{"__name__":"up","job":"a"},"values":[[%d,"1"],[%d,"0"]]}]}`, fixedUnix-60, fixedUnix)))
	r := mustRun(t, config("query_range", f), Params{Query: "up", Start: "now-1h", End: "now", Step: time.Minute})
	want := []string{
		"# api=query_range start=2026-10-23T02:12:00Z end=2026-10-23T03:12:00Z step=60s",
		`up{job="a"}` + "\t2026-10-23T03:11:00Z\t1",
		`up{job="a"}` + "\t2026-10-23T03:12:00Z\t0",
	}
	if !reflect.DeepEqual(lines(r.Stdout), want) {
		t.Errorf("stdout = %q", r.Stdout)
	}
	req := f.last(t)
	q := req.URL.Query()
	if req.URL.Path != "/api/v1/query_range" || q.Get("start") != "2026-10-23T02:12:00Z" || q.Get("end") != "2026-10-23T03:12:00Z" || q.Get("step") != "60" || q.Get("timeout") != "10" || q.Get("query") != "up" {
		t.Errorf("request = %s ?%s", req.URL.Path, req.URL.RawQuery)
	}
}

func TestQueryRangeDefaultStepFromMaxPoints(t *testing.T) {
	useFixedClock(t)
	// step = max(min_step, ceil(range / (max_points-1))) in whole seconds.
	table := []struct {
		start      string
		maxPoints  int
		wantSecond string
	}{
		{"now-1h", 0, "15"}, // 3600/299 = 12.04 is raised to min_step
		{"now-12h", 0, "145"},
		{"now-5m", 0, "15"},
		{"now-24h", 0, "289"},
		{"now-1h", 61, "60"},
		{"now-1h", 301, "15"},
		{"now-1h", 2, "3600"},
		{"now-1h", 3, "1800"},
	}
	for _, tc := range table {
		f := serve(t, 200, success(`{"resultType":"matrix","result":[]}`))
		cfg := config("query_range", f)
		cfg.MaxPoints = tc.maxPoints
		r := mustRun(t, cfg, Params{Query: "up", Start: tc.start})
		step := f.last(t).URL.Query().Get("step")
		if step != tc.wantSecond {
			t.Errorf("start=%s max_points=%d: step = %q; want %s", tc.start, tc.maxPoints, step, tc.wantSecond)
		}
		if !strings.HasSuffix(lines(r.Stdout)[0], " step="+tc.wantSecond+"s") {
			t.Errorf("header = %q", lines(r.Stdout)[0])
		}
	}
}

func TestQueryRangeSummary(t *testing.T) {
	useFixedClock(t)
	body := success(fmt.Sprintf(`{"resultType":"matrix","result":[
		{"metric":{"__name__":"cpu","job":"a"},"values":[[%d,"1"],[%d,"3"],[%d,"NaN"],[%d,"2"]]},
		{"metric":{"__name__":"cpu","job":"b"},"values":[[%d,"NaN"]]},
		{"metric":{"__name__":"cpu","job":"c"},"values":[[%d,"0.5"],[%d,"+Inf"]]}]}`,
		fixedUnix-180, fixedUnix-120, fixedUnix-60, fixedUnix, fixedUnix, fixedUnix-60, fixedUnix))
	f := serve(t, 200, body)
	r := mustRun(t, config("query_range", f), Params{Query: "cpu", Start: "now-1h", Step: time.Minute, Summary: true})
	want := []string{
		"# api=query_range start=2026-10-23T02:12:00Z end=2026-10-23T03:12:00Z step=60s",
		`cpu{job="a"}` + "\t1\t2\t3\t2",
		`cpu{job="b"}` + "\tNaN\tNaN\tNaN\tNaN",
		`cpu{job="c"}` + "\t0.5\t+Inf\t+Inf\t+Inf",
	}
	if !reflect.DeepEqual(lines(r.Stdout), want) {
		t.Errorf("stdout = %q", strings.Join(lines(r.Stdout), "\n"))
	}
}

func TestQueryRangeRejectsBadRanges(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, success(`{"resultType":"matrix","result":[]}`))
	cfg := config("query_range", f)
	cfg.MaxRange, cfg.MaxPoints = 2*time.Hour, 100
	cases := map[string]Params{
		"missing query":        {Start: "now-1h", Step: time.Minute},
		"missing start":        {Query: "up", Step: time.Minute},
		"start equals":         {Query: "up", Start: "now", End: "now", Step: time.Minute},
		"start after":          {Query: "up", Start: "now-5m", End: "now-10m", Step: time.Minute},
		"range too long":       {Query: "up", Start: "now-3h", Step: time.Minute},
		"step too small":       {Query: "up", Start: "now-1h", Step: 14 * time.Second},
		"bad end default step": {Query: "up", Start: "now-1h", End: "bad"},
		"too many":             {Query: "up", Start: "now-2h", Step: time.Minute},
		"bad start":            {Query: "up", Start: "yesterday", Step: time.Minute},
		"bad end":              {Query: "up", Start: "now-1h", End: "tomorrow", Step: time.Minute},
	}
	for name, p := range cases {
		if r, err := Run(context.Background(), cfg, p); err == nil {
			t.Errorf("%s accepted: %+v", name, r)
		}
	}
	if f.count() != 0 {
		t.Errorf("%d requests sent for rejected parameters", f.count())
	}
	// Exactly max_points points and exactly max_range are allowed.
	ok := Params{Query: "up", Start: "now-99m", Step: time.Minute}
	mustRun(t, cfg, ok)
	ok = Params{Query: "up", Start: "now-2h", Step: 2 * time.Minute}
	mustRun(t, cfg, ok)
}

func TestSeriesLabelsAndLabelValues(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, success(`[{"__name__":"up","job":"a"},{"__name__":"up","job":"b"}]`))
	r := mustRun(t, config("series", f), Params{Match: []string{`up{job=~"a|b"}`, "node_load1"}})
	want := []string{"# api=series start=2026-10-23T02:12:00Z end=2026-10-23T03:12:00Z", `up{job="a"}`, `up{job="b"}`}
	if !reflect.DeepEqual(lines(r.Stdout), want) {
		t.Errorf("series = %q", r.Stdout)
	}
	req := f.last(t)
	q := req.URL.Query()
	if req.URL.Path != "/api/v1/series" || !slices.Equal(q["match[]"], []string{`up{job=~"a|b"}`, "node_load1"}) ||
		q.Get("start") != "2026-10-23T02:12:00Z" || q.Get("end") != "2026-10-23T03:12:00Z" || q.Get("limit") != "51" {
		t.Errorf("request = %s ?%s", req.URL.Path, req.URL.RawQuery)
	}

	f = serve(t, 200, success(`["__name__","instance","job"]`))
	r = mustRun(t, config("labels", f), Params{Start: "now-2h", End: "now-1h"})
	want = []string{"# api=labels start=2026-10-23T01:12:00Z end=2026-10-23T02:12:00Z", "__name__", "instance", "job"}
	if !reflect.DeepEqual(lines(r.Stdout), want) {
		t.Errorf("labels = %q", r.Stdout)
	}
	req = f.last(t)
	if req.URL.Path != "/api/v1/labels" || len(req.URL.Query()["match[]"]) != 0 || req.URL.Query().Get("limit") != "51" {
		t.Errorf("request = %s ?%s", req.URL.Path, req.URL.RawQuery)
	}

	f = serve(t, 200, success("[\"a\\tb\",\"c\"]"))
	r = mustRun(t, config("label_values", f), Params{Label: "__name__", Match: []string{"up"}})
	want = []string{"# api=label_values start=2026-10-23T02:12:00Z end=2026-10-23T03:12:00Z", `a\tb`, "c"}
	if !reflect.DeepEqual(lines(r.Stdout), want) {
		t.Errorf("label_values = %q", r.Stdout)
	}
	req = f.last(t)
	if req.URL.Path != "/api/v1/label/__name__/values" || req.URL.Query().Get("limit") != "51" || !slices.Equal(req.URL.Query()["match[]"], []string{"up"}) {
		t.Errorf("request = %s ?%s", req.URL.Path, req.URL.RawQuery)
	}
}

func TestSeriesRejectsBadParameters(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, success(`[]`))
	cases := []struct {
		api string
		p   Params
	}{
		{"series", Params{}},
		{"series", Params{Match: []string{"up"}, Start: "now", End: "now"}},
		{"series", Params{Match: []string{"up"}, Start: "now-8d"}},
		{"label_values", Params{}},
		{"label_values", Params{Label: "a/b"}},
		{"label_values", Params{Label: "../status/config"}},
		{"label_values", Params{Label: "9a"}},
		{"label_values", Params{Label: "job\n"}},
		{"rules", Params{RuleType: "all"}},
	}
	for _, tc := range cases {
		if _, err := Run(context.Background(), config(tc.api, f), tc.p); err == nil {
			t.Errorf("%s accepted %+v", tc.api, tc.p)
		}
	}
	if f.count() != 0 {
		t.Errorf("%d requests sent for rejected parameters", f.count())
	}
}

func TestDefaultStartClampsToMaxRange(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, success(`[]`))
	cfg := config("labels", f)
	cfg.MaxRange = 15 * time.Minute
	r := mustRun(t, cfg, Params{})
	if lines(r.Stdout)[0] != "# api=labels start=2026-10-23T02:57:00Z end=2026-10-23T03:12:00Z" {
		t.Errorf("header = %q", lines(r.Stdout)[0])
	}
}

func TestSeriesTruncation(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, success(`[{"__name__":"a"},{"__name__":"b"},{"__name__":"c"}]`))
	cfg := config("series", f)
	cfg.MaxSeries = 2
	r := mustRun(t, cfg, Params{Match: []string{"{__name__=~\".+\"}"}})
	if got := lines(r.Stdout); len(got) != 3 || got[1] != "a" || got[2] != "b" {
		t.Errorf("stdout = %q", r.Stdout)
	}
	if !r.Truncated || r.ExitCode != 0 || f.last(t).URL.Query().Get("limit") != "3" {
		t.Errorf("result = %+v limit=%s", r, f.last(t).URL.Query().Get("limit"))
	}
	if !strings.Contains(r.Stderr, "returned 2") || !strings.Contains(r.Stderr, "3") {
		t.Errorf("stderr = %q", r.Stderr)
	}
	// Exactly max_series items is not truncated.
	f = serve(t, 200, success(`["a","b"]`))
	cfg = config("labels", f)
	cfg.MaxSeries = 2
	if r := mustRun(t, cfg, Params{}); r.Truncated || r.Stderr != "" {
		t.Errorf("result = %+v", r)
	}
}

func TestQueryTruncationByMaxSeries(t *testing.T) {
	useFixedClock(t)
	var results []string
	for _, job := range []string{"a", "b", "c", "d"} {
		results = append(results, fmt.Sprintf(`{"metric":{"__name__":"up","job":"%s"},"value":[%d,"1"]}`, job, fixedUnix))
	}
	f := serve(t, 200, vector(results...))
	cfg := config("query", f)
	cfg.MaxSeries = 3
	r := mustRun(t, cfg, Params{Query: "up"})
	if got := lines(r.Stdout); len(got) != 4 || !strings.HasPrefix(got[3], `up{job="c"}`) {
		t.Errorf("stdout = %q", r.Stdout)
	}
	if !r.Truncated || !strings.Contains(r.Stderr, "4") || !strings.Contains(r.Stderr, "3") {
		t.Errorf("result = %+v", r)
	}
	f = serve(t, 200, success(fmt.Sprintf(`{"resultType":"matrix","result":[{"metric":{"job":"a"},"values":[[%d,"1"]]},{"metric":{"job":"b"},"values":[[%d,"1"]]}]}`, fixedUnix, fixedUnix)))
	cfg = config("query_range", f)
	cfg.MaxSeries = 1
	r = mustRun(t, cfg, Params{Query: "up", Start: "now-1h", Step: time.Minute, Summary: true})
	if got := lines(r.Stdout); len(got) != 2 || !r.Truncated {
		t.Errorf("summary result = %+v", r)
	}
}

func TestAlerts(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, success(`{"alerts":[
		{"labels":{"alertname":"HighLatency","severity":"critical","instance":"10.0.0.5:9100"},"annotations":{"summary":"p99\tover 1s","description":"d"},"state":"firing","activeAt":"2026-10-23T03:00:00.123456789+08:00","value":"1.5e+00"},
		{"labels":{"alertname":"Pending"},"annotations":{},"state":"pending","activeAt":"2026-10-23T03:10:00Z","value":"1"}]}`))
	r := mustRun(t, config("alerts", f), Params{})
	got := lines(r.Stdout)
	if len(got) != 3 || got[0] != "# api=alerts" {
		t.Fatalf("stdout = %q", r.Stdout)
	}
	first := strings.Split(got[1], "\t")
	wantFirst := []string{"HighLatency", "firing", "2026-10-22T19:00:00Z", "1.5e+00", `{alertname="HighLatency",instance="10.0.0.5:9100",severity="critical"}`, `p99\tover 1s`}
	if !slices.Equal(first, wantFirst) {
		t.Errorf("first = %q\nwant    %q", first, wantFirst)
	}
	second := strings.Split(got[2], "\t")
	if !slices.Equal(second, []string{"Pending", "pending", "2026-10-23T03:10:00Z", "1", `{alertname="Pending"}`, ""}) {
		t.Errorf("second = %q", second)
	}
	if f.last(t).URL.Path != "/api/v1/alerts" {
		t.Errorf("path = %s", f.last(t).URL.Path)
	}
}

func TestRules(t *testing.T) {
	useFixedClock(t)
	body := success(`{"groups":[
		{"name":"g1","file":"/etc/prometheus/rules.yml","rules":[
			{"name":"HighLatency","query":"histogram_quantile(0.99, rate(x[5m])) > 1","type":"alerting","health":"ok","state":"firing","lastError":"","labels":{}},
			{"name":"job:up:sum","query":"sum(up) by (job)","type":"recording","health":"err","lastError":"bad\ttab"}]},
		{"name":"g2","rules":[{"name":"Down","query":"up == 0","type":"alerting","health":"ok","state":"inactive"}]}]}`)
	f := serve(t, 200, body)
	r := mustRun(t, config("rules", f), Params{RuleType: "alert"})
	want := []string{
		"# api=rules",
		"g1\talerting\tHighLatency\tok\tfiring\t\thistogram_quantile(0.99, rate(x[5m])) > 1",
		`g1` + "\trecording\tjob:up:sum\terr\t\t" + `bad\ttab` + "\tsum(up) by (job)",
		"g2\talerting\tDown\tok\tinactive\t\tup == 0",
	}
	if !reflect.DeepEqual(lines(r.Stdout), want) {
		t.Errorf("stdout = %q", strings.Join(lines(r.Stdout), "\n"))
	}
	q := f.last(t).URL.Query()
	if f.last(t).URL.Path != "/api/v1/rules" || q.Get("type") != "alert" {
		t.Errorf("request = %s ?%s", f.last(t).URL.Path, f.last(t).URL.RawQuery)
	}
	f = serve(t, 200, body)
	mustRun(t, config("rules", f), Params{})
	if f.last(t).URL.Query().Has("type") {
		t.Error("type sent without rule_type")
	}
	f = serve(t, 200, body)
	cfg := config("rules", f)
	cfg.MaxSeries = 2
	if r := mustRun(t, cfg, Params{}); !r.Truncated || len(lines(r.Stdout)) != 3 || !strings.Contains(r.Stderr, "3") {
		t.Errorf("truncated rules = %+v", r)
	}
}

func TestTargets(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, success(`{"activeTargets":[
		{"labels":{"instance":"10.0.0.5:9100","job":"node"},"scrapePool":"node","scrapeUrl":"http://10.0.0.5:9100/metrics","lastError":"","lastScrape":"2026-10-23T11:11:50.5+08:00","health":"up"},
		{"labels":{"instance":"10.0.0.6:9100","job":"node"},"scrapePool":"node","scrapeUrl":"http://10.0.0.6:9100/metrics","lastError":"connection refused","lastScrape":"2026-10-23T03:11:51Z","health":"down"}],
		"droppedTargets":[{"discoveredLabels":{"job":"x"},"scrapePool":"x"}]}`))
	r := mustRun(t, config("targets", f), Params{})
	want := []string{
		"# api=targets",
		"node\t10.0.0.5:9100\tup\t2026-10-23T03:11:50Z\t\thttp://10.0.0.5:9100/metrics",
		"node\t10.0.0.6:9100\tdown\t2026-10-23T03:11:51Z\tconnection refused\thttp://10.0.0.6:9100/metrics",
	}
	if !reflect.DeepEqual(lines(r.Stdout), want) {
		t.Errorf("stdout = %q", strings.Join(lines(r.Stdout), "\n"))
	}
	req := f.last(t)
	if req.URL.Path != "/api/v1/targets" || req.URL.Query().Get("state") != "active" {
		t.Errorf("request = %s ?%s", req.URL.Path, req.URL.RawQuery)
	}
}

func TestWarningsGoToStderr(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, `{"status":"success","warnings":["first\nsecond","third"],"data":{"resultType":"vector","result":[]}}`)
	r := mustRun(t, config("query", f), Params{Query: "up"})
	if r.ExitCode != 0 || r.Truncated {
		t.Errorf("result = %+v", r)
	}
	if want := "warning: first second\nwarning: third\n"; r.Stderr != want {
		t.Errorf("stderr = %q; want %q", r.Stderr, want)
	}
	if strings.Contains(r.Stdout, "warning") {
		t.Errorf("warning on stdout: %q", r.Stdout)
	}
}

func TestPrometheusErrors(t *testing.T) {
	useFixedClock(t)
	cases := []struct {
		name   string
		status int
		body   string
		want   []string
	}{
		{"bad query", 400, `{"status":"error","errorType":"bad_data","error":"1:3: parse error: unexpected end of input"}`, []string{"bad_data", "unexpected end of input"}},
		{"timeout", 503, `{"status":"error","errorType":"timeout","error":"query timed out in expression evaluation"}`, []string{"timeout", "query timed out"}},
		{"error with 200", 200, `{"status":"error","errorType":"execution","error":"boom"}`, []string{"execution", "boom"}},
		{"not json", 502, `<html>Bad Gateway</html>`, []string{"502"}},
		{"empty error", 500, `{"status":"error"}`, []string{"500"}},
		{"unauthorized", 401, `Unauthorized`, []string{"401"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := serve(t, tc.status, tc.body)
			r, err := Run(context.Background(), config("query", f), Params{Query: "up"})
			if err != nil {
				t.Fatalf("Run error %v; Prometheus errors are reported through stderr", err)
			}
			if r.ExitCode != 1 || r.Stdout != "" || r.StatusCode != tc.status {
				t.Errorf("result = %+v", r)
			}
			for _, w := range tc.want {
				if !strings.Contains(r.Stderr, w) {
					t.Errorf("stderr %q lacks %q", r.Stderr, w)
				}
			}
			if strings.Contains(r.Stderr, "<html>") {
				t.Errorf("stderr copies a non-JSON body: %q", r.Stderr)
			}
		})
	}
}

func TestTransportFailures(t *testing.T) {
	useFixedClock(t)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
	}))
	defer redirect.Close()
	r, err := Run(context.Background(), Config{API: "query", Config: apiclient.Config{Address: redirect.URL}}, Params{Query: "up"})
	if err == nil || r.ExitCode != 1 {
		t.Errorf("redirect: %+v %v", r, err)
	}

	f := serve(t, 200, vector(strings.Repeat(" ", 4096)))
	cfg := config("query", f)
	cfg.MaxResponseBytes = 1024
	r, err = Run(context.Background(), cfg, Params{Query: "up"})
	if err == nil || r.ExitCode != 1 || !strings.Contains(err.Error(), "max_response_bytes") {
		t.Errorf("large body: %+v %v", r, err)
	}

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer slow.Close()
	cfg = Config{API: "query", Config: apiclient.Config{Address: slow.URL, Timeout: 100 * time.Millisecond}}
	started := time.Now()
	r, err = Run(context.Background(), cfg, Params{Query: "up"})
	if err == nil || r.ExitCode != 1 || time.Since(started) > 3*time.Second {
		t.Errorf("timeout: %+v %v after %v", r, err, time.Since(started))
	}

	r, err = Run(context.Background(), Config{API: "query", Config: apiclient.Config{Address: "http://127.0.0.1:1"}}, Params{Query: "up"})
	if err == nil || r.ExitCode != 1 {
		t.Errorf("refused: %+v %v", r, err)
	}
}

func TestAddressPathPrefixAndOnlyAllowedPaths(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, success(`[]`))
	cfg := Config{API: "labels", Config: apiclient.Config{Address: f.URL + "/prometheus/"}}
	mustRun(t, cfg, Params{})
	if got := f.last(t).URL.Path; got != "/prometheus/api/v1/labels" {
		t.Errorf("path = %s", got)
	}
	allowed := map[string]string{
		"query": "/api/v1/query", "query_range": "/api/v1/query_range", "series": "/api/v1/series", "labels": "/api/v1/labels",
		"label_values": "/api/v1/label/job/values", "alerts": "/api/v1/alerts", "rules": "/api/v1/rules", "targets": "/api/v1/targets",
	}
	sample := Params{Query: "up", Start: "now-1h", Step: time.Minute, Match: []string{"up"}, Label: "job"}
	for api, path := range allowed {
		f := serve(t, 200, success(`{"resultType":"vector","result":[]}`))
		if _, err := Run(context.Background(), config(api, f), sample); err != nil {
			// Shape errors are fine for this probe; the path is what is asserted.
			_ = err
		}
		if f.count() != 1 || f.last(t).URL.Path != path || f.last(t).Method != http.MethodGet {
			t.Errorf("%s requested %d times, %s %s; want one GET %s", api, f.count(), f.last(t).Method, f.last(t).URL.Path, path)
		}
		if f.last(t).URL.Query().Has("query") != (api == "query" || api == "query_range") {
			t.Errorf("%s sends query=%q", api, f.last(t).URL.Query().Get("query"))
		}
	}
}

func TestRejectsUnexpectedDataShapes(t *testing.T) {
	useFixedClock(t)
	for api, body := range map[string]string{
		"query":       success(`{"resultType":"vector","result":"x"}`),
		"series":      success(`{"a":1}`),
		"labels":      success(`[1,2]`),
		"alerts":      success(`[]`),
		"rules":       success(`{"groups":"x"}`),
		"targets":     success(`[]`),
		"query_range": success(`{"resultType":"vector","result":[]}`),
	} {
		f := serve(t, 200, body)
		r, err := Run(context.Background(), config(api, f), Params{Query: "up", Start: "now-1h", Step: time.Minute, Match: []string{"up"}})
		if err == nil || r.ExitCode != 1 {
			t.Errorf("%s accepted malformed response: %+v", api, r)
		}
	}
	f := serve(t, 200, `not json`)
	if r, err := Run(context.Background(), config("labels", f), Params{}); err != nil || r.ExitCode != 1 || r.Stdout != "" || !strings.Contains(r.Stderr, "200") {
		t.Errorf("non-JSON 200 response: %+v %v", r, err)
	}
}

func TestQueryParameterEncoding(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, vector())
	query := `sum by (job) (rate(http_requests_total{code=~"5.."}[5m])) & "x y"`
	mustRun(t, config("query", f), Params{Query: query})
	got, err := url.ParseQuery(f.last(t).URL.RawQuery)
	if err != nil || got.Get("query") != query {
		t.Errorf("query = %q, %v", got.Get("query"), err)
	}
}
