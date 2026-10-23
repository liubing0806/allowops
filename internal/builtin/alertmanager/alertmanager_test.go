package alertmanager

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/builtin/apiclient"
	"github.com/liubing0806/allowops/internal/redact"
)

type recorder struct {
	mu       sync.Mutex
	requests []*http.Request
}

func (r *recorder) add(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req.Clone(context.Background()))
}

// serve answers every request with status and body and records it.
func serve(t *testing.T, status int, body string) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func run(t *testing.T, cfg Config, p Params, mask func(string) string) Result {
	t.Helper()
	r, err := Run(context.Background(), cfg, p, mask)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r
}

func lines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func TestRequestMapping(t *testing.T) {
	cases := []struct {
		name string
		p    Params
		want url.Values
	}{
		{"defaults", Params{Active: true}, url.Values{"active": {"true"}, "silenced": {"false"}, "inhibited": {"false"}}},
		{"all states", Params{Active: true, Silenced: true, Inhibited: true}, url.Values{"active": {"true"}, "silenced": {"true"}, "inhibited": {"true"}}},
		{"only silenced", Params{Silenced: true}, url.Values{"active": {"false"}, "silenced": {"true"}, "inhibited": {"false"}}},
		{"filters", Params{Active: true, Filter: []string{`alertname="HighLatency"`, `severity=~"critical|warning"`}},
			url.Values{"active": {"true"}, "silenced": {"false"}, "inhibited": {"false"}, "filter": {`alertname="HighLatency"`, `severity=~"critical|warning"`}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, rec := serve(t, 200, `[]`)
			run(t, Config{Address: srv.URL}, tc.p, nil)
			if len(rec.requests) != 1 {
				t.Fatalf("requests = %d, want 1", len(rec.requests))
			}
			req := rec.requests[0]
			if req.Method != http.MethodGet || req.URL.Path != "/api/v2/alerts" {
				t.Fatalf("request = %s %s", req.Method, req.URL.Path)
			}
			got := req.URL.Query()
			if len(got) != len(tc.want) {
				t.Fatalf("query = %v, want %v", got, tc.want)
			}
			for k, want := range tc.want {
				if strings.Join(got[k], "\x00") != strings.Join(want, "\x00") {
					t.Errorf("query %s = %q, want %q", k, got[k], want)
				}
			}
		})
	}
}

func TestAddressPathPrefix(t *testing.T) {
	srv, rec := serve(t, 200, `[]`)
	run(t, Config{Address: srv.URL + "/am/"}, Params{Active: true}, nil)
	if got := rec.requests[0].URL.Path; got != "/am/api/v2/alerts" {
		t.Fatalf("path = %q", got)
	}
}

const alertsJSON = `[
 {"startsAt":"2026-10-23T11:00:00.5+08:00","fingerprint":"b","status":{"state":"active","silencedBy":[],"inhibitedBy":[]},
  "labels":{"alertname":"HighLatency","severity":"critical","job":"api","instance":"10.0.0.5:9100"},
  "annotations":{"summary":"p99 above 1s","description":"api slow"},
  "generatorURL":"http://prom:9090/graph?g0.expr=histogram_quantile%280.99%2C+rate%28x%5B5m%5D%29%29+%3E+1&g0.tab=1"},
 {"startsAt":"2026-10-23T02:00:00Z","fingerprint":"a","status":{"state":"suppressed","silencedBy":["s1","s2"],"inhibitedBy":["i1"]},
  "labels":{"alertname":"DiskFull"},
  "annotations":{}}
]`

func TestSortOutputAndFields(t *testing.T) {
	srv, _ := serve(t, 200, alertsJSON)
	r := run(t, Config{Address: srv.URL}, Params{Active: true}, nil)
	if r.ExitCode != 0 || r.Truncated || r.Stderr != "" {
		t.Fatalf("result = %+v", r)
	}
	want := []string{
		// 2026-10-23T02:00:00Z sorts before 11:00:00.5+08:00 (= 03:00:00.5Z).
		"2026-10-23T02:00:00Z\tsuppressed\tDiskFull\t\t{}\t\t\ts1,s2\ti1\t",
		"2026-10-23T03:00:00Z\tactive\tHighLatency\tcritical\t" + `{instance="10.0.0.5:9100",job="api"}` + "\tp99 above 1s\tapi slow\t\t\thistogram_quantile(0.99, rate(x[5m])) > 1",
	}
	got := lines(r.Stdout)
	if len(got) != len(want) {
		t.Fatalf("stdout = %q", r.Stdout)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d:\n got %q\nwant %q", i, got[i], want[i])
		}
	}
}

func TestSortIsStableForEqualStart(t *testing.T) {
	srv, _ := serve(t, 200, `[
 {"startsAt":"2026-10-23T02:00:00Z","fingerprint":"b","labels":{"alertname":"B"},"status":{"state":"active"}},
 {"startsAt":"2026-10-23T02:00:00Z","fingerprint":"a","labels":{"alertname":"A"},"status":{"state":"active"}}]`)
	r := run(t, Config{Address: srv.URL}, Params{Active: true}, nil)
	got := lines(r.Stdout)
	if len(got) != 2 || !strings.Contains(got[0], "\tA\t") || !strings.Contains(got[1], "\tB\t") {
		t.Fatalf("equal start times must order by fingerprint: %q", r.Stdout)
	}
}

func TestEscaping(t *testing.T) {
	srv, _ := serve(t, 200, `[{"startsAt":"2026-10-23T02:00:00Z","status":{"state":"active"},
 "labels":{"alertname":"A\tB","path":"C:\\x\n\"q\""},
 "annotations":{"summary":"a\tb\nc\rd\\e","description":"x\u0000y"}}]`)
	r := run(t, Config{Address: srv.URL}, Params{Active: true}, nil)
	got := lines(r.Stdout)
	if len(got) != 1 {
		t.Fatalf("an alert must stay on one line: %q", r.Stdout)
	}
	fields := strings.Split(got[0], "\t")
	if len(fields) != 10 {
		t.Fatalf("fields = %d: %q", len(fields), got[0])
	}
	// Prometheus label-value escaping (\\, \n, \") comes first; the TSV rule then doubles each backslash.
	checks := map[int]string{
		2: `A\tB`,
		4: `{path="C:\\\\x\\n\\"q\\""}`,
		5: `a\tb\nc\rd\\e`,
		6: `x\0y`,
	}
	for i, want := range checks {
		if fields[i] != want {
			t.Errorf("field %d = %q, want %q", i, fields[i], want)
		}
	}
}

func TestLabelSetQuotesUnusualNames(t *testing.T) {
	srv, _ := serve(t, 200, `[{"startsAt":"2026-10-23T02:00:00Z","status":{"state":"active"},"labels":{"alertname":"A","b":"2","a":"1","9x":"3"}}]`)
	r := run(t, Config{Address: srv.URL}, Params{Active: true}, nil)
	fields := strings.Split(lines(r.Stdout)[0], "\t")
	if want := `{"9x"="3",a="1",b="2"}`; fields[4] != want {
		t.Fatalf("labels = %q, want %q", fields[4], want)
	}
}

func TestExprDecoding(t *testing.T) {
	cases := []struct {
		name, generator, want string
	}{
		{"no generatorURL", ``, ""},
		{"no query", `http://prom:9090/graph`, ""},
		{"no g0.expr", `http://prom:9090/graph?g0.tab=1`, ""},
		{"empty g0.expr", `http://prom:9090/graph?g0.expr=&g0.tab=1`, ""},
		{"simple", `http://prom:9090/graph?g0.expr=up%3D%3D0`, "up==0"},
		{"plus is space", `http://prom:9090/graph?g0.expr=a+%2B+b`, "a + b"},
		{"after other params", `http://prom:9090/graph?g0.tab=1&g0.expr=rate%28x%5B1m%5D%29`, "rate(x[1m])"},
		{"first wins", `http://prom:9090/graph?g0.expr=a&g0.expr=b`, "a"},
		{"prometheus 3 path", `http://prom:9090/query?g0.expr=up&g0.tab=0`, "up"},
		{"bad escape in expr", `http://prom:9090/graph?g0.expr=up%zz`, ""},
		{"truncated escape", `http://prom:9090/graph?g0.expr=up%`, ""},
		{"bad escape elsewhere", `http://prom:9090/graph?g0.tab=%zz&g0.expr=up`, "up"},
		{"unparsable URL", "http://prom:9090/graph?g0.expr=up\x7f", ""},
		{"not a URL", `::::`, ""},
		{"similar key", `http://prom:9090/graph?xg0.expr=a&g0.expr2=b`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `[{"startsAt":"2026-10-23T02:00:00Z","status":{"state":"active"},"labels":{"alertname":"A"},"generatorURL":` + jsonString(tc.generator) + `}]`
			srv, _ := serve(t, 200, body)
			r := run(t, Config{Address: srv.URL}, Params{Active: true}, nil)
			fields := strings.Split(lines(r.Stdout)[0], "\t")
			if got := fields[len(fields)-1]; got != tc.want {
				t.Fatalf("expr = %q, want %q", got, tc.want)
			}
		})
	}
}

func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			b.WriteString(`\u00`)
			b.WriteString(string("0123456789abcdef"[r>>4]))
			b.WriteString(string("0123456789abcdef"[r&15]))
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func TestMissingGeneratorURLField(t *testing.T) {
	srv, _ := serve(t, 200, `[{"startsAt":"2026-10-23T02:00:00Z","status":{"state":"active"},"labels":{"alertname":"A"}}]`)
	r := run(t, Config{Address: srv.URL}, Params{Active: true}, nil)
	if !strings.HasSuffix(lines(r.Stdout)[0], "\t") {
		t.Fatalf("expr must be the empty last field: %q", r.Stdout)
	}
}

func TestMaxAlertsTruncation(t *testing.T) {
	var items []string
	for _, h := range []string{"05", "01", "04", "02", "03"} {
		items = append(items, `{"startsAt":"2026-10-23T`+h+`:00:00Z","status":{"state":"active"},"labels":{"alertname":"A`+h+`"}}`)
	}
	srv, _ := serve(t, 200, "["+strings.Join(items, ",")+"]")
	r := run(t, Config{Address: srv.URL, MaxAlerts: 3}, Params{Active: true}, nil)
	if !r.Truncated || r.ExitCode != 0 {
		t.Fatalf("result = %+v", r)
	}
	got := lines(r.Stdout)
	if len(got) != 3 || !strings.Contains(got[0], "A01") || !strings.Contains(got[2], "A03") {
		t.Fatalf("the earliest 3 alerts must be kept: %q", r.Stdout)
	}
	if !strings.Contains(r.Stderr, "3 of 5") {
		t.Fatalf("stderr = %q, want total and returned counts", r.Stderr)
	}
	exact := run(t, Config{Address: srv.URL, MaxAlerts: 5}, Params{Active: true}, nil)
	if exact.Truncated || exact.Stderr != "" || len(lines(exact.Stdout)) != 5 {
		t.Fatalf("a result at the limit is not truncated: %+v", exact)
	}
}

func TestEmptyResult(t *testing.T) {
	for _, body := range []string{`[]`, `null`} {
		srv, _ := serve(t, 200, body)
		r := run(t, Config{Address: srv.URL}, Params{Active: true}, nil)
		if r.Stdout != "" || r.ExitCode != 0 || r.Truncated {
			t.Fatalf("body %s: result = %+v", body, r)
		}
	}
}

func TestMaskRunsBeforeEscaping(t *testing.T) {
	srv, _ := serve(t, 200, `[{"startsAt":"2026-10-23T02:00:00Z","status":{"state":"active"},
 "labels":{"alertname":"A","token":"secret-1"},"annotations":{"summary":"leak secret-2\there"},
 "generatorURL":"http://p/graph?g0.expr=up%7Btoken%3D%22secret-3%22%7D"}]`)
	mask := func(s string) string {
		return strings.NewReplacer("secret-1", "[R1]", "secret-2\there", "[R2]", "secret-3", "[R3]").Replace(s)
	}
	r := run(t, Config{Address: srv.URL}, Params{Active: true}, mask)
	for _, leaked := range []string{"secret-1", "secret-2", "secret-3"} {
		if strings.Contains(r.Stdout, leaked) {
			t.Fatalf("%s leaked: %q", leaked, r.Stdout)
		}
	}
	for _, want := range []string{"[R1]", "[R2]", "[R3]"} {
		if !strings.Contains(r.Stdout, want) {
			t.Fatalf("%s missing: %q", want, r.Stdout)
		}
	}
}

func TestErrorStatus(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 500, 503} {
		srv, _ := serve(t, status, "bad filter: unexpected token\n")
		r, err := Run(context.Background(), Config{Address: srv.URL}, Params{Active: true}, nil)
		if err != nil {
			t.Fatalf("status %d: %v", status, err)
		}
		if r.ExitCode != 1 || r.Stdout != "" {
			t.Fatalf("status %d: result = %+v", status, r)
		}
		if !strings.Contains(r.Stderr, http.StatusText(status)) && !strings.Contains(r.Stderr, "HTTP "+strconv.Itoa(status)) {
			t.Fatalf("status %d: stderr = %q", status, r.Stderr)
		}
		if !strings.Contains(r.Stderr, "bad filter: unexpected token") {
			t.Fatalf("status %d: stderr must carry the server message: %q", status, r.Stderr)
		}
	}
}

func TestErrorBodyIsBoundedAndSingleLine(t *testing.T) {
	srv, _ := serve(t, 500, strings.Repeat("x\n\x1b[31m", 5000))
	r := run(t, Config{Address: srv.URL}, Params{Active: true}, nil)
	if r.ExitCode != 1 {
		t.Fatalf("exit = %d", r.ExitCode)
	}
	if len(r.Stderr) > 1024 {
		t.Fatalf("stderr = %d bytes", len(r.Stderr))
	}
	if strings.Contains(r.Stderr, "\x1b") || strings.Count(strings.TrimSuffix(r.Stderr, "\n"), "\n") != 0 {
		t.Fatalf("stderr must be one sanitized line: %q", r.Stderr)
	}
}

func TestTransportFailures(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
		}))
		defer srv.Close()
		_, err := Run(context.Background(), Config{Address: srv.URL}, Params{Active: true}, nil)
		if !errors.Is(err, apiclient.ErrRedirect) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("response too large", func(t *testing.T) {
		srv, _ := serve(t, 200, "["+strings.Repeat(" ", 4096)+"]")
		_, err := Run(context.Background(), Config{Address: srv.URL, MaxResponseBytes: 1024}, Params{Active: true}, nil)
		if !errors.Is(err, apiclient.ErrResponseTooLarge) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("invalid JSON", func(t *testing.T) {
		srv, _ := serve(t, 200, `{"not":"an array"}`)
		if _, err := Run(context.Background(), Config{Address: srv.URL}, Params{Active: true}, nil); err == nil {
			t.Fatal("a non-array body must fail")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}))
		defer srv.Close()
		start := time.Now()
		_, err := Run(context.Background(), Config{Address: srv.URL, Timeout: 100 * time.Millisecond}, Params{Active: true}, nil)
		if err == nil || time.Since(start) > 3*time.Second {
			t.Fatalf("err = %v after %s", err, time.Since(start))
		}
	})
	t.Run("connection refused", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		addr := srv.URL
		srv.Close()
		if _, err := Run(context.Background(), Config{Address: addr}, Params{Active: true}, nil); err == nil {
			t.Fatal("a closed port must fail")
		}
	})
	t.Run("invalid config", func(t *testing.T) {
		if _, err := Run(context.Background(), Config{Address: "not a url"}, Params{Active: true}, nil); err == nil {
			t.Fatal("an invalid address must fail")
		}
	})
}

func TestConfigValidate(t *testing.T) {
	ok := Config{Address: "http://127.0.0.1:9093"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	full := Config{Address: "https://am.example.com/prefix", Credential: "/etc/allowops/credentials/am.json", CAFile: "/etc/ssl/ca.pem",
		Timeout: MaxTimeout, MaxAlerts: MaxAlerts, MaxResponseBytes: MaxResponseBytes}
	if err := full.Validate(); err != nil {
		t.Fatalf("limits at the maximum: %v", err)
	}
	bad := map[string]Config{
		"no address":           {},
		"query in address":     {Address: "http://127.0.0.1:9093/?a=b"},
		"userinfo":             {Address: "http://u:p@127.0.0.1:9093"},
		"relative credential":  {Address: ok.Address, Credential: "am.json"},
		"relative ca_file":     {Address: "https://am.example.com", CAFile: "ca.pem"},
		"ca_file over http":    {Address: ok.Address, CAFile: "/etc/ssl/ca.pem"},
		"timeout above max":    {Address: ok.Address, Timeout: MaxTimeout + time.Second},
		"negative timeout":     {Address: ok.Address, Timeout: -time.Second},
		"max_alerts above max": {Address: ok.Address, MaxAlerts: MaxAlerts + 1},
		"negative max_alerts":  {Address: ok.Address, MaxAlerts: -1},
		"response above max":   {Address: ok.Address, MaxResponseBytes: MaxResponseBytes + 1},
		"negative response":    {Address: ok.Address, MaxResponseBytes: -1},
	}
	for name, cfg := range bad {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestUsesCredential(t *testing.T) {
	if (Config{Address: "http://127.0.0.1:9093"}).UsesCredential() {
		t.Error("no credential configured")
	}
	if !(Config{Address: "http://127.0.0.1:9093", Credential: "/etc/allowops/credentials/am.json"}).UsesCredential() {
		t.Error("credential configured")
	}
}

func TestDefaultLimitsApplied(t *testing.T) {
	var items []string
	for i := 0; i < DefaultMaxAlerts+5; i++ {
		items = append(items, `{"startsAt":"2026-10-23T02:00:00Z","status":{"state":"active"},"labels":{"alertname":"A"}}`)
	}
	srv, _ := serve(t, 200, "["+strings.Join(items, ",")+"]")
	r := run(t, Config{Address: srv.URL}, Params{Active: true}, nil)
	if !r.Truncated || len(lines(r.Stdout)) != DefaultMaxAlerts {
		t.Fatalf("default max_alerts must apply: truncated=%v lines=%d", r.Truncated, len(lines(r.Stdout)))
	}
}

// A rule that matches to the end of the line must not swallow the labels that
// follow the one it redacts.
func TestMaskAppliesToEachLabel(t *testing.T) {
	r, err := redact.New(&redact.Config{Builtin: []string{"secrets", "pii"}})
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := serve(t, 200, `[{"startsAt":"2026-10-23T02:00:00Z","status":{"state":"active"},
 "labels":{"alertname":"A","msg":"password=hunter2","zone":"z"}}]`)
	out := run(t, Config{Address: srv.URL}, Params{Active: true}, r.Line)
	fields := strings.Split(lines(out.Stdout)[0], "\t")
	if strings.Contains(out.Stdout, "hunter2") {
		t.Fatalf("secret leaked: %q", out.Stdout)
	}
	if !strings.HasPrefix(fields[4], "{") || !strings.HasSuffix(fields[4], "}") || !strings.Contains(fields[4], `zone="z"`) {
		t.Fatalf("labels = %q, want zone and the closing brace kept", fields[4])
	}
}

// Alerts whose startsAt cannot be parsed sort after every valid time, so a
// max_alerts cut drops them first. Their text is kept as received.
func TestUnparsableStartsAtSortsLast(t *testing.T) {
	srv, _ := serve(t, 200, `[
 {"startsAt":"not a time","fingerprint":"a","status":{"state":"active"},"labels":{"alertname":"Bad1"}},
 {"fingerprint":"b","status":{"state":"active"},"labels":{"alertname":"Missing"}},
 {"startsAt":"2026-10-23T05:00:00Z","fingerprint":"c","status":{"state":"active"},"labels":{"alertname":"Late"}},
 {"startsAt":"2026-10-23T01:00:00Z","fingerprint":"d","status":{"state":"active"},"labels":{"alertname":"Early"}}]`)
	r := run(t, Config{Address: srv.URL}, Params{Active: true}, nil)
	got := lines(r.Stdout)
	if len(got) != 4 {
		t.Fatalf("stdout = %q", r.Stdout)
	}
	for i, want := range []string{"Early", "Late", "Bad1", "Missing"} {
		if f := strings.Split(got[i], "\t"); f[2] != want {
			t.Errorf("row %d = %s, want %s", i, f[2], want)
		}
	}
	if !strings.HasPrefix(got[2], "not a time\t") || !strings.HasPrefix(got[3], "\t") {
		t.Errorf("unparsable text must be kept: %q %q", got[2], got[3])
	}
	cut := run(t, Config{Address: srv.URL, MaxAlerts: 2}, Params{Active: true}, nil)
	if !cut.Truncated || strings.Contains(cut.Stdout, "Bad1") || strings.Contains(cut.Stdout, "Missing") || !strings.Contains(cut.Stderr, "2 of 4") {
		t.Fatalf("a cut must drop unparsable alerts first: %+v", cut)
	}
}
