package dremio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/builtin/credfile"
	"github.com/liubing0806/allowops/internal/builtin/sqlguard"
)

const (
	testToken    = "TOKEN-9f3a7c51d2e84b6a"
	testPassword = "PASSWORD-77c1e0b2"
	testSQL      = "SELECT 'marker-3f9c' AS c FROM src.t"
	testCredPath = "/etc/allowops/credentials/dremio.json"
)

var testCred = credfile.Credential{Username: "reader", Password: testPassword}

type recorded struct {
	Method, Path, Query, Auth, ContentType, Body string
}

// fakeDremio mimics the parts of the Dremio REST API that the handler uses.
// Like the real server it answers a result request for an unfinished job with
// 400 and refuses a limit above 500.
type fakeDremio struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	requests []recorded
	polls    int

	loginStatus  int      // default 200
	jobStates    []string // returned by successive status requests; the last one repeats
	errorMessage string
	columns      []string
	rows         []string // raw JSON objects
	showStyle    bool     // report rowCount 0, as SHOW, DESCRIBE and EXPLAIN do
	// override sees every request first and returns true when it answered.
	override func(w http.ResponseWriter, r *http.Request) bool
}

func newFake(t *testing.T) *fakeDremio {
	t.Helper()
	f := &fakeDremio{t: t, jobStates: []string{"COMPLETED"}, columns: []string{"c"}, rows: []string{`{"c": "v"}`}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	original := readCredential
	readCredential = func(string) (credfile.Credential, error) { return testCred, nil }
	t.Cleanup(func() { readCredential = original })
	return f
}

func (f *fakeDremio) config() Config {
	return Config{Credential: testCredPath, URL: f.srv.URL, Timeout: 5 * time.Second}
}

func (f *fakeDremio) run(cfg Config, sql string, mask func(string) string) (Result, error) {
	f.t.Helper()
	return RunRedacted(context.Background(), cfg, Params{SQL: sql}, mask)
}

func (f *fakeDremio) record(r *http.Request) recorded {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	rec := recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), string(body)}
	f.mu.Lock()
	f.requests = append(f.requests, rec)
	f.mu.Unlock()
	return rec
}

func (f *fakeDremio) all() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

func (f *fakeDremio) find(method, path string) []recorded {
	var out []recorded
	for _, r := range f.all() {
		if r.Method == method && r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeDremio) results() []recorded {
	var out []recorded
	for _, r := range f.all() {
		if r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/results") {
			out = append(out, r)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (f *fakeDremio) serve(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	if f.override != nil && f.override(w, r) {
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/apiv2/login":
		status := f.loginStatus
		if status == 0 {
			status = 200
		}
		if status != 200 {
			writeJSON(w, status, `{"errorMessage":"Login failed: Invalid username or password, user reader password `+testPassword+`"}`)
			return
		}
		writeJSON(w, 200, `{"token":"`+testToken+`","userName":"reader","admin":true,"expires":1}`)
	case r.Method == http.MethodDelete && r.URL.Path == "/apiv2/login":
		w.WriteHeader(204)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v3/sql":
		writeJSON(w, 200, `{"id":"job-1"}`)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v3/job/job-1":
		f.mu.Lock()
		state := f.jobStates[min(f.polls, len(f.jobStates)-1)]
		f.polls++
		f.mu.Unlock()
		body := map[string]any{"jobState": state, "errorMessage": ""}
		if state == "FAILED" {
			body["errorMessage"] = f.errorMessage
		}
		data, _ := json.Marshal(body)
		writeJSON(w, 200, string(data))
	case r.Method == http.MethodGet && r.URL.Path == "/api/v3/job/job-1/results":
		f.mu.Lock()
		state := f.jobStates[min(max(f.polls-1, 0), len(f.jobStates)-1)]
		f.mu.Unlock()
		if state != "COMPLETED" {
			writeJSON(w, 400, `{"errorMessage":"Can not fetch details for a job that is in [`+state+`] state."}`)
			return
		}
		q, _ := url.ParseQuery(r.URL.RawQuery)
		offset, _ := strconv.Atoi(q.Get("offset"))
		limit, err := strconv.Atoi(q.Get("limit"))
		if err != nil {
			limit = 100
		}
		if limit > 500 {
			writeJSON(w, 400, `{"errorMessage":"limit can not exceed 500 rows"}`)
			return
		}
		page := []string{}
		if offset < len(f.rows) {
			page = f.rows[offset:min(offset+limit, len(f.rows))]
		}
		var schema []string
		for _, c := range f.columns {
			schema = append(schema, fmt.Sprintf(`{"name":%q,"type":{"name":"VARCHAR"}}`, c))
		}
		rowCount := len(f.rows)
		if f.showStyle {
			rowCount = 0
		}
		writeJSON(w, 200, fmt.Sprintf(`{"rowCount":%d,"schema":[%s],"rows":[%s]}`, rowCount, strings.Join(schema, ","), strings.Join(page, ",")))
	case r.Method == http.MethodPost && r.URL.Path == "/api/v3/job/job-1/cancel":
		w.WriteHeader(204)
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		writeJSON(w, 404, `{"errorMessage":"not found"}`)
	}
}

func rowsOf(n int) []string {
	rows := make([]string, n)
	for i := range rows {
		rows[i] = fmt.Sprintf(`{"c": "v%d"}`, i)
	}
	return rows
}

func mustRun(t *testing.T, f *fakeDremio, cfg Config, sql string) Result {
	t.Helper()
	result, err := f.run(cfg, sql, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return result
}

func TestConfigValidate(t *testing.T) {
	valid := Config{Credential: testCredPath, URL: "http://127.0.0.1:9047"}
	for _, u := range []string{"http://127.0.0.1:9047", "https://dremio.example.com:9047", "http://[::1]:9047", "http://localhost:80"} {
		c := valid
		c.URL = u
		if err := c.Validate(); err != nil {
			t.Errorf("url %q: %v", u, err)
		}
	}
	for _, u := range []string{
		"", "127.0.0.1:9047", "ftp://h:9047", "http://h", "http://h:", "http://h:0", "http://h:65536", "http://h:abc",
		"http://h:9047/", "http://h:9047/api", "http://h:9047?x=1", "http://h:9047?", "http://h:9047#f",
		"http://user:pass@h:9047", "http://:9047", "http://h:9047 ", "unix:///var/run/x.sock", "tcp://h:9047",
	} {
		c := valid
		c.URL = u
		if err := c.Validate(); err == nil {
			t.Errorf("accepted url %q", u)
		}
	}
	for name, mutate := range map[string]func(*Config){
		"relative credential":   func(c *Config) { c.Credential = "dremio.json" },
		"empty credential":      func(c *Config) { c.Credential = "" },
		"negative max_rows":     func(c *Config) { c.MaxRows = -1 },
		"max_rows above 500":    func(c *Config) { c.MaxRows = 501 },
		"negative max_bytes":    func(c *Config) { c.MaxBytes = -1 },
		"max_bytes above 1MiB":  func(c *Config) { c.MaxBytes = 1<<20 + 1 },
		"negative timeout":      func(c *Config) { c.Timeout = -time.Second },
		"timeout above 10s":     func(c *Config) { c.Timeout = 10*time.Second + time.Millisecond },
		"timeout below 1ms":     func(c *Config) { c.Timeout = time.Microsecond },
		"empty statement_types": func(c *Config) { c.StatementTypes = []string{} },
		"unknown statement":     func(c *Config) { c.StatementTypes = []string{"SELECT", "INSERT"} },
		"empty show_types":      func(c *Config) { c.ShowTypes = []string{} },
		"unknown show type":     func(c *Config) { c.ShowTypes = []string{"TABLES", "PROFILELIST"} },
		"starrocks show type":   func(c *Config) { c.ShowTypes = []string{"DATABASES"} },
	} {
		c := valid
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, mutate := range map[string]func(*Config){
		"limits at the maximum": func(c *Config) { c.MaxRows, c.MaxBytes, c.Timeout = 500, 1<<20, 10*time.Second },
		"limits at the minimum": func(c *Config) { c.MaxRows, c.MaxBytes, c.Timeout = 1, 1, time.Millisecond },
		"statement types":       func(c *Config) { c.StatementTypes = []string{"select", "Show", "DESCRIBE", "EXPLAIN"} },
		"show types": func(c *Config) {
			c.ShowTypes = []string{"schemas", "TABLES", "VIEWS", "PARTITIONS", "FILES", "CREATE TABLE", "FUNCTIONS"}
		},
	} {
		c := valid
		mutate(&c)
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDefaultsAreTheMaximum(t *testing.T) {
	if builtin.DefaultDremioMaxRows != 500 || builtin.DefaultDremioMaxBytes != 1<<20 {
		t.Fatalf("defaults: rows=%d bytes=%d", builtin.DefaultDremioMaxRows, builtin.DefaultDremioMaxBytes)
	}
	c := Config{}.normalized()
	if c.MaxRows != 500 || c.MaxBytes != 1<<20 || c.Timeout != 10*time.Second {
		t.Fatalf("normalized zero config: %+v", c)
	}
	c = Config{MaxRows: 7, MaxBytes: 99, Timeout: time.Second}.normalized()
	if c.MaxRows != 7 || c.MaxBytes != 99 || c.Timeout != time.Second {
		t.Fatalf("normalized explicit config: %+v", c)
	}
}

func TestRunRequestSequence(t *testing.T) {
	f := newFake(t)
	f.jobStates = []string{"PLANNING", "RUNNING", "COMPLETED"}
	f.columns, f.rows = []string{"a", "b"}, []string{`{"a": 1, "b": "x"}`, `{"a": 2, "b": "y"}`}
	result := mustRun(t, f, f.config(), testSQL)
	if result.Output != "a\tb\n1\tx\n2\ty\n" || result.Rows != 2 || result.Truncated {
		t.Fatalf("result %+v", result)
	}
	var steps []string
	for _, r := range f.all() {
		steps = append(steps, r.Method+" "+r.Path)
	}
	want := []string{
		"POST /apiv2/login", "POST /api/v3/sql",
		"GET /api/v3/job/job-1", "GET /api/v3/job/job-1", "GET /api/v3/job/job-1",
		"GET /api/v3/job/job-1/results", "DELETE /apiv2/login",
	}
	if !slices.Equal(steps, want) {
		t.Fatalf("requests\n got %v\nwant %v", steps, want)
	}
	login := f.find("POST", "/apiv2/login")[0]
	var credentials map[string]string
	if err := json.Unmarshal([]byte(login.Body), &credentials); err != nil || credentials["userName"] != "reader" || credentials["password"] != testPassword || len(credentials) != 2 {
		t.Errorf("login body %q: %v", login.Body, err)
	}
	if login.Auth != "" {
		t.Errorf("login carries Authorization %q", login.Auth)
	}
	submit := f.find("POST", "/api/v3/sql")[0]
	var sent map[string]any
	if err := json.Unmarshal([]byte(submit.Body), &sent); err != nil || sent["sql"] != testSQL || len(sent) != 1 {
		t.Errorf("submit body %q: %v", submit.Body, err)
	}
	for _, r := range f.all() {
		if r.Path != "/apiv2/login" || r.Method == http.MethodDelete {
			if r.Auth != "_dremio"+testToken {
				t.Errorf("%s %s Authorization %q; want the session token with the _dremio prefix", r.Method, r.Path, r.Auth)
			}
		}
		if r.Method == http.MethodPost && r.ContentType != "application/json" {
			t.Errorf("%s %s Content-Type %q", r.Method, r.Path, r.ContentType)
		}
	}
	if q := f.results()[0].Query; q != "offset=0&limit=500" {
		t.Errorf("results query %q; the default max_rows is 500 and Dremio caps a page at 500", q)
	}
}

func TestLoginFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		override func(http.ResponseWriter, *http.Request) bool
		want     string
	}{
		{"wrong password", 401, nil, "dremio login failed (status 401)"},
		{"server error", 500, nil, "dremio login failed (status 500)"},
		{"no token", 200, func(w http.ResponseWriter, r *http.Request) bool {
			writeJSON(w, 200, `{"userName":"reader"}`)
			return true
		}, "dremio login failed (invalid response)"},
		{"empty token", 200, func(w http.ResponseWriter, r *http.Request) bool {
			writeJSON(w, 200, `{"token":""}`)
			return true
		}, "dremio login failed (invalid response)"},
		{"not json", 200, func(w http.ResponseWriter, r *http.Request) bool {
			writeJSON(w, 200, `<html>`+testPassword)
			return true
		}, "dremio login failed (invalid response)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.loginStatus, f.override = tc.status, tc.override
			result, err := f.run(f.config(), testSQL, nil)
			if err == nil || err.Error() != tc.want || result != (Result{}) {
				t.Fatalf("got %+v, %v; want error %q", result, err, tc.want)
			}
			if n := len(f.all()); n != 1 {
				t.Errorf("%d requests after a failed login; want only the login", n)
			}
			for _, secret := range []string{testPassword, testToken, "marker-3f9c"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error contains %q", secret)
				}
			}
		})
	}
}

func TestJobFailureReturnsStateAndCategory(t *testing.T) {
	for _, tc := range []struct{ message, want string }{
		{"Non-query expression encountered in illegal context", "dremio job FAILED (syntax or validation error)"},
		{"Encountered \"<EOF>\" at line 0, column 0. Was expecting one of:", "dremio job FAILED (syntax or validation error)"},
		{"Dremio only supports single statement execution. Unable to execute the given query with 2 statements: " + testSQL, "dremio job FAILED (syntax or validation error)"},
		{"VALIDATION ERROR: From line 1, column 8: Object 'nonexist' not found within 'src'", "dremio job FAILED (object not found)"},
		{"Object 'nosuch.t' not found. Please check that it exists", "dremio job FAILED (object not found)"},
		{"Access denied; you need (at least one of) the INSERT privilege(s) on TABLE t for this operation", "dremio job FAILED (access denied)"},
		{"Query was cancelled because it exceeded the memory limits set by the administrator", "dremio job FAILED (resource limit)"},
		{"Connection refused to jdbc:mysql://db.internal:9030 user=" + testPassword + " " + testToken, "dremio job FAILED (execution error)"},
		{"", "dremio job FAILED (execution error)"},
	} {
		t.Run(tc.message, func(t *testing.T) {
			f := newFake(t)
			f.jobStates, f.errorMessage = []string{"RUNNING", "FAILED"}, tc.message
			result, err := f.run(f.config(), testSQL, nil)
			if err == nil || err.Error() != tc.want || result != (Result{}) {
				t.Fatalf("got %+v, %v; want error %q", result, err, tc.want)
			}
			if len(f.results()) != 0 {
				t.Error("results requested for a failed job")
			}
			if n := len(f.find("POST", "/api/v3/job/job-1/cancel")); n != 0 {
				t.Errorf("%d cancel requests for a job that already failed", n)
			}
			if n := len(f.find("DELETE", "/apiv2/login")); n != 1 {
				t.Errorf("%d logout requests; want 1", n)
			}
		})
	}
}

func TestJobCanceledByServer(t *testing.T) {
	f := newFake(t)
	f.jobStates = []string{"RUNNING", "CANCELED"}
	_, err := f.run(f.config(), testSQL, nil)
	if err == nil || err.Error() != "dremio job CANCELED" {
		t.Fatalf("got %v", err)
	}
	if n := len(f.find("POST", "/api/v3/job/job-1/cancel")); n != 0 {
		t.Errorf("%d cancel requests for an already canceled job", n)
	}
}

func TestPollTimeoutCancelsJob(t *testing.T) {
	f := newFake(t)
	f.jobStates = []string{"RUNNING"}
	cfg := f.config()
	cfg.Timeout = 300 * time.Millisecond
	start := time.Now()
	_, err := f.run(cfg, testSQL, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v; want the deadline error", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %v for a 300ms timeout", elapsed)
	}
	// Run has returned, so the cleanup requests have been sent already.
	cancels := f.find("POST", "/api/v3/job/job-1/cancel")
	if len(cancels) != 1 || cancels[0].Auth != "_dremio"+testToken {
		t.Fatalf("cancel requests after the timeout: %+v", cancels)
	}
	if n := len(f.find("DELETE", "/apiv2/login")); n != 1 {
		t.Errorf("%d logout requests; want 1", n)
	}
	if len(f.results()) != 0 {
		t.Error("results requested for an unfinished job")
	}
}

func TestContextCancelCancelsJob(t *testing.T) {
	f := newFake(t)
	f.jobStates = []string{"RUNNING"}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/v3/job/job-1" {
			stop() // the caller gives up while the job is running
		}
		return false
	}
	_, err := RunRedacted(ctx, f.config(), Params{SQL: testSQL}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v; want context.Canceled", err)
	}
	if n := len(f.find("POST", "/api/v3/job/job-1/cancel")); n != 1 {
		t.Errorf("%d cancel requests after the caller cancelled; want 1", n)
	}
	if n := len(f.find("DELETE", "/apiv2/login")); n != 1 {
		t.Errorf("%d logout requests; want 1", n)
	}
}

func TestHungStatusRequestStillCancelsJob(t *testing.T) {
	f := newFake(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v3/job/job-1" {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return true
		}
		return false
	}
	cfg := f.config()
	cfg.Timeout = 300 * time.Millisecond
	start := time.Now()
	_, err := f.run(cfg, testSQL, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %v for a 300ms timeout", elapsed)
	}
	if n := len(f.find("POST", "/api/v3/job/job-1/cancel")); n != 1 {
		t.Errorf("%d cancel requests; the expired context must not prevent the cancel", n)
	}
}

func TestCancelledContextSendsNothing(t *testing.T) {
	f := newFake(t)
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := RunRedacted(ctx, f.config(), Params{SQL: testSQL}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if n := len(f.all()); n != 0 {
		t.Errorf("%d requests with a cancelled context", n)
	}
}

func TestTruncation(t *testing.T) {
	for _, tc := range []struct {
		name         string
		maxRows      int // 0 selects the default of 500
		total        int
		wantRows     int
		wantTrunc    bool
		wantLimits   []string // limit of each results request
		wantOffsets  []string
		showStyleRow bool
	}{
		{"more rows than max_rows", 3, 10, 3, true, []string{"4"}, []string{"0"}, false},
		{"exactly max_rows", 3, 3, 3, false, []string{"4"}, []string{"0"}, false},
		{"fewer rows than max_rows", 3, 2, 2, false, []string{"4"}, []string{"0"}, false},
		{"one row limit", 1, 2, 1, true, []string{"2"}, []string{"0"}, false},
		{"default, fewer than a page", 0, 499, 499, false, []string{"500"}, []string{"0"}, false},
		{"default, exactly a page", 0, 500, 500, false, []string{"500", "1"}, []string{"0", "500"}, false},
		{"default, one more than a page", 0, 501, 500, true, []string{"500", "1"}, []string{"0", "500"}, false},
		{"default, many more", 0, 900, 500, true, []string{"500", "1"}, []string{"0", "500"}, false},
		{"max_rows 499 uses one extra row", 499, 500, 499, true, []string{"500"}, []string{"0"}, false},
		// SHOW, DESCRIBE and EXPLAIN report rowCount 0 whatever they return, so a full page is checked by reading past it.
		{"show style, exactly a page", 0, 500, 500, false, []string{"500", "1"}, []string{"0", "500"}, true},
		{"show style, more than a page", 0, 520, 500, true, []string{"500", "1"}, []string{"0", "500"}, true},
		{"show style, fewer than a page", 0, 12, 12, false, []string{"500"}, []string{"0"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.rows, f.showStyle = rowsOf(tc.total), tc.showStyleRow
			cfg := f.config()
			cfg.MaxRows = tc.maxRows
			result := mustRun(t, f, cfg, testSQL)
			if result.Rows != tc.wantRows || result.Truncated != tc.wantTrunc {
				t.Fatalf("rows=%d truncated=%v; want %d, %v", result.Rows, result.Truncated, tc.wantRows, tc.wantTrunc)
			}
			if lines := strings.Count(result.Output, "\n"); lines != tc.wantRows+1 {
				t.Errorf("%d output lines; want %d plus the header", lines, tc.wantRows)
			}
			if !strings.HasPrefix(result.Output, "c\nv0\n") {
				t.Errorf("output %.20q", result.Output)
			}
			var limits, offsets []string
			for _, r := range f.results() {
				q, _ := url.ParseQuery(r.Query)
				limits, offsets = append(limits, q.Get("limit")), append(offsets, q.Get("offset"))
			}
			if !slices.Equal(limits, tc.wantLimits) || !slices.Equal(offsets, tc.wantOffsets) {
				t.Errorf("result requests limit=%v offset=%v; want limit=%v offset=%v", limits, offsets, tc.wantLimits, tc.wantOffsets)
			}
		})
	}
}

func TestEmptyResultKeepsHeader(t *testing.T) {
	f := newFake(t)
	f.columns, f.rows = []string{"id", "name"}, nil
	result := mustRun(t, f, f.config(), testSQL)
	if result.Output != "id\tname\n" || result.Rows != 0 || result.Truncated {
		t.Fatalf("result %+v", result)
	}
}

func TestCellValues(t *testing.T) {
	f := newFake(t)
	f.columns = []string{"big", "huge", "dbl", "exp", "flag", "nested", "nothing", "absent", "text", "a\tb"}
	f.rows = []string{`{"big": 9223372036854775807, "huge": 12345678901234567890123, "dbl": 1.0, "exp": 1e+300, "flag": true,` +
		` "nested": {"a": 1.0, "b": [1, 2], "s": "x\ty"}, "nothing": null, "text": "a\tb\nc\\d", "a\tb": "k"}`}
	result := mustRun(t, f, f.config(), testSQL)
	want := "big\thuge\tdbl\texp\tflag\tnested\tnothing\tabsent\ttext\ta\\tb\n" +
		`9223372036854775807` + "\t" + `12345678901234567890123` + "\t" + `1.0` + "\t" + `1e+300` + "\t" + `true` + "\t" +
		`{"a":1.0,"b":[1,2],"s":"x\\ty"}` + "\t" + `\N` + "\t" + `\N` + "\t" + `a\tb\nc\\d` + "\t" + `k` + "\n"
	if result.Output != want {
		t.Fatalf("output\n got %q\nwant %q", result.Output, want)
	}
}

func TestCellText(t *testing.T) {
	for _, tc := range []struct {
		raw, want string
		valid     bool
	}{
		{`"text"`, "text", true},
		{`"é\n"`, "é\n", true},
		{`""`, "", true},
		{`0`, "0", true},
		{`-12345678901234567890`, "-12345678901234567890", true},
		{`1.50`, "1.50", true},
		{`1E5`, "1E5", true},
		{`true`, "true", true},
		{`false`, "false", true},
		{`null`, "", false},
		{`[]`, "[]", true},
		{`[ 1 , {"a" : null} ]`, `[1,{"a":null}]`, true},
		{`{ "k" : "v" }`, `{"k":"v"}`, true},
	} {
		got, err := cellText(json.RawMessage(tc.raw))
		if err != nil || got.Valid != tc.valid || got.String != tc.want {
			t.Errorf("cellText(%s) = %+v, %v; want %q valid=%v", tc.raw, got, err, tc.want, tc.valid)
		}
	}
	for _, raw := range []string{``, `{`, `"unterminated`, `nul`, `{"a":}`} {
		if got, err := cellText(json.RawMessage(raw)); err == nil {
			t.Errorf("cellText(%q) = %+v; want an error", raw, got)
		}
	}
}

func TestMaskAppliesToHeaderAndCells(t *testing.T) {
	f := newFake(t)
	f.columns = []string{"secret_col", "n", "j"}
	f.rows = []string{`{"secret_col": "keep secret-value keep", "n": 42, "j": {"k": "secret-value"}}`, `{"secret_col": null, "n": 7, "j": []}`}
	mask := func(s string) string { return strings.ReplaceAll(s, "secret", "***") }
	result, err := f.run(f.config(), testSQL, mask)
	if err != nil {
		t.Fatal(err)
	}
	want := "***_col\tn\tj\n" + `keep ***-value keep` + "\t42\t" + `{"k":"***-value"}` + "\n" + `\N` + "\t7\t[]\n"
	if result.Output != want || strings.Contains(result.Output, "secret") {
		t.Fatalf("output\n got %q\nwant %q", result.Output, want)
	}
}

func TestMaxBytes(t *testing.T) {
	f := newFake(t)
	f.rows = []string{`{"c": "aaaaaaaaaa"}`, `{"c": "bbbbbbbbbb"}`, `{"c": "cccccccccc"}`}
	cfg := f.config()
	// "c\n" is 2 bytes and every row 11 bytes.
	cfg.MaxBytes = 2 + 11 + 11
	result := mustRun(t, f, cfg, testSQL)
	if result.Output != "c\naaaaaaaaaa\nbbbbbbbbbb\n" || result.Rows != 2 || !result.Truncated {
		t.Fatalf("result %+v", result)
	}
	cfg.MaxBytes = 2 + 11 + 11 + 11
	result = mustRun(t, f, cfg, testSQL)
	if result.Rows != 3 || result.Truncated || int64(len(result.Output)) != cfg.MaxBytes {
		t.Fatalf("result at the exact limit %+v", result)
	}
	cfg.MaxBytes = 5
	result = mustRun(t, f, cfg, testSQL)
	if result.Output != "c\n" || result.Rows != 0 || !result.Truncated {
		t.Fatalf("no row fits: %+v", result)
	}
	// The limit counts the header too.
	f.columns = []string{"a_long_column_name"}
	f.rows = []string{`{"a_long_column_name": "x"}`}
	cfg.MaxBytes = 10
	if result, err := f.run(cfg, testSQL, nil); err == nil || result != (Result{}) || !strings.Contains(err.Error(), "max_bytes") {
		t.Fatalf("header over the limit: %+v, %v", result, err)
	}
}

func TestShowStyleRowCountIsNotUsed(t *testing.T) {
	f := newFake(t)
	f.rows, f.showStyle = rowsOf(12), true
	result := mustRun(t, f, f.config(), "SHOW SCHEMAS")
	if result.Rows != 12 || result.Truncated {
		t.Fatalf("result %+v; rows must be counted from the returned rows, not from rowCount 0", result)
	}
}

func TestResponseTooLarge(t *testing.T) {
	big := func(n int) func(http.ResponseWriter, *http.Request) bool {
		return func(w http.ResponseWriter, r *http.Request) bool {
			w.WriteHeader(200)
			_, _ = w.Write(bytes.Repeat([]byte(" "), n))
			return true
		}
	}
	match := func(path string, inner func(http.ResponseWriter, *http.Request) bool) func(http.ResponseWriter, *http.Request) bool {
		return func(w http.ResponseWriter, r *http.Request) bool {
			return r.URL.Path == path && inner(w, r)
		}
	}
	for _, tc := range []struct {
		name, path string
		size       int
		canceled   bool // the job was still running when the response was refused
	}{
		{"login", "/apiv2/login", maxControlBody + 1, false},
		{"submit", "/api/v3/sql", maxControlBody + 1, false},
		{"status", "/api/v3/job/job-1", maxControlBody + 1, true},
		{"results", "/api/v3/job/job-1/results", maxResultBody + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.override = match(tc.path, big(tc.size))
			result, err := f.run(f.config(), testSQL, nil)
			if err == nil || !strings.Contains(err.Error(), "exceeds") || result != (Result{}) {
				t.Fatalf("got %+v, %v; want a byte limit error", result, err)
			}
			if got := len(f.find("POST", "/api/v3/job/job-1/cancel")) == 1; got != tc.canceled {
				t.Errorf("cancel sent=%v; want %v", got, tc.canceled)
			}
		})
	}
	// A response of exactly the limit is accepted up to the parser.
	f := newFake(t)
	f.override = match("/api/v3/job/job-1/results", func(w http.ResponseWriter, r *http.Request) bool {
		pad := strings.Repeat(" ", maxResultBody-len(`{"schema":[{"name":"c"}],"rows":[]}`))
		writeJSON(w, 200, `{"schema":[{"name":"c"}],"rows":[]}`+pad)
		return true
	})
	if result := mustRun(t, f, f.config(), testSQL); result.Output != "c\n" {
		t.Fatalf("result at the exact response limit: %+v", result)
	}
}

func TestMalformedResults(t *testing.T) {
	for name, body := range map[string]string{
		"not json":         `{"rows": [`,
		"rows not objects": `{"schema":[{"name":"c"}],"rows":["v"]}`,
		"schema missing":   `{"rows":[{"c":"v"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.override = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v3/job/job-1/results" {
					return false
				}
				writeJSON(w, 200, body)
				return true
			}
			result, err := f.run(f.config(), testSQL, nil)
			if err == nil || err.Error() != "dremio results failed (invalid response)" || result != (Result{}) {
				t.Fatalf("got %+v, %v", result, err)
			}
		})
	}
}

func TestInvalidJobID(t *testing.T) {
	for _, body := range []string{`{"id":"../../apiv2/login"}`, `{"id":"a/b"}`, `{"id":""}`, `{}`, `{"id":"x y"}`, `{"id":"` + strings.Repeat("a", 129) + `"}`, `{"id":12}`} {
		t.Run(body, func(t *testing.T) {
			f := newFake(t)
			f.override = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v3/sql" {
					return false
				}
				writeJSON(w, 200, body)
				return true
			}
			_, err := f.run(f.config(), testSQL, nil)
			if err == nil || err.Error() != "dremio submit failed (invalid response)" {
				t.Fatalf("got %v", err)
			}
			for _, r := range f.all() {
				if strings.Contains(r.Path, "..") || strings.HasPrefix(r.Path, "/api/v3/job") {
					t.Errorf("request to %s after an invalid job id", r.Path)
				}
			}
		})
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	for _, tc := range []struct{ name, path, want string }{
		{"login", "/apiv2/login", "dremio login failed (status 302)"},
		{"submit", "/api/v3/sql", "dremio submit failed (status 302)"},
		{"status", "/api/v3/job/job-1", "dremio status failed (status 302)"},
		{"results", "/api/v3/job/job-1/results", "dremio results failed (status 302)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var seen []recorded
			elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				mu.Lock()
				seen = append(seen, recorded{r.Method, r.URL.Path, "", r.Header.Get("Authorization"), "", string(body)})
				mu.Unlock()
				writeJSON(w, 200, `{"token":"other","id":"job-1","jobState":"COMPLETED"}`)
			}))
			defer elsewhere.Close()
			f := newFake(t)
			f.override = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodDelete || r.URL.Path != tc.path {
					return false
				}
				http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusFound)
				return true
			}
			_, err := f.run(f.config(), testSQL, nil)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v; want %q", err, tc.want)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(seen) != 0 {
				t.Fatalf("the redirect target received %+v", seen)
			}
		})
	}
}

func TestSelfSignedTLSIsRejected(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		writeJSON(w, 200, `{"token":"x"}`)
	}))
	defer srv.Close()
	f := newFake(t)
	cfg := f.config()
	cfg.URL = srv.URL
	_, err := f.run(cfg, testSQL, nil)
	if err == nil || err.Error() != "dremio login request failed" {
		t.Fatalf("got %v; the system roots must not trust the test server", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("%d requests reached a server with an untrusted certificate", hits)
	}
}

func TestHTTPClientSettings(t *testing.T) {
	c := newHTTPClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport %T", c.Transport)
	}
	if tr.Proxy != nil {
		t.Error("the transport may use a proxy: credentials and the token would pass through it")
	}
	if tr.TLSClientConfig != nil && (tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.RootCAs != nil) {
		t.Errorf("TLS config %+v; only the system roots are supported", tr.TLSClientConfig)
	}
	if err := c.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect returned %v", err)
	}
	if c.Timeout != 0 {
		t.Errorf("client timeout %v; the context bounds every request", c.Timeout)
	}
}

func TestSecretsNeverReachErrors(t *testing.T) {
	secrets := []string{testToken, testPassword, "marker-3f9c", "db.internal"}
	leak := func(w http.ResponseWriter, status int) {
		writeJSON(w, status, `{"errorMessage":"token `+testToken+` password `+testPassword+` sql `+testSQL+` host db.internal"}`)
	}
	for _, tc := range []struct {
		name, method, path string
		status             int
	}{
		{"login", "POST", "/apiv2/login", 500},
		{"submit", "POST", "/api/v3/sql", 400},
		{"status", "GET", "/api/v3/job/job-1", 500},
		{"results", "GET", "/api/v3/job/job-1/results", 500},
		{"results garbage", "GET", "/api/v3/job/job-1/results", 200},
		{"status not found", "GET", "/api/v3/job/job-1", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.override = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == tc.method && r.URL.Path == tc.path {
					leak(w, tc.status)
					return true
				}
				return false
			}
			result, err := f.run(f.config(), testSQL, func(s string) string { return s })
			if err == nil || result != (Result{}) {
				t.Fatalf("got %+v, %v", result, err)
			}
			for _, secret := range secrets {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error %q contains %q", err, secret)
				}
			}
			if n := len(f.find("DELETE", "/apiv2/login")); n != map[bool]int{true: 0, false: 1}[tc.name == "login"] {
				t.Errorf("%d logout requests", n)
			}
		})
	}
	// A failing job and a successful run: neither error nor output contains the token or the password.
	f := newFake(t)
	f.jobStates, f.errorMessage = []string{"FAILED"}, "user "+testCred.Username+" "+testPassword+" "+testToken+" "+testSQL
	_, err := f.run(f.config(), testSQL, nil)
	for _, secret := range secrets {
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Errorf("job failure %v contains %q", err, secret)
		}
	}
	f = newFake(t)
	result := mustRun(t, f, f.config(), testSQL)
	for _, secret := range []string{testToken, testPassword} {
		if strings.Contains(result.Output, secret) {
			t.Errorf("output contains %q", secret)
		}
	}
}

func TestRejectedSQLSendsNoRequest(t *testing.T) {
	for _, sql := range []string{
		`SELECT * FROM TABLE("src".external_query('INSERT INTO t VALUES (1)'))`,
		`EXPLAIN PLAN FOR SELECT * FROM TABLE("src".external_query('INSERT INTO t VALUES (1)'))`,
		`SELECT * FROM TABLE ( "src" . "EXTERNAL_QUERY" ('SELECT 1'))`,
		`CREATE VIEW v AS SELECT 1`,
		`CREATE OR REPLACE VIEW "@u".v AS SELECT 1`,
		`TRUNCATE TABLE src.t`,
		`ALTER SYSTEM SET "planner.slice_target" = 1`,
		`ALTER SESSION SET "planner.slice_target" = 1`,
		`SELECT 1; SELECT 2`,
		`SELECT 1; TRUNCATE TABLE src.t`,
		`INSERT INTO src.t VALUES (1)`,
		`DROP TABLE src.t`,
		`ALTER PDS src.t REFRESH METADATA`,
		`/* set_var.pipeline_dop='9' */ SELECT 1`,
		`SELECT 1 -- ` + "\n; DROP TABLE t",
		``,
		strings.Repeat("x", 4001),
		"SELECT 1\x00",
	} {
		t.Run(fmt.Sprintf("%.40q", sql), func(t *testing.T) {
			f := newFake(t)
			result, err := f.run(f.config(), sql, nil)
			if !errors.Is(err, sqlguard.ErrRejected) || result != (Result{}) {
				t.Fatalf("got %+v, %v; want a guard rejection", result, err)
			}
			if n := len(f.all()); n != 0 {
				t.Errorf("%d HTTP requests before the rejection: %+v", n, f.all())
			}
		})
	}
}

func TestRestrictionsApplyBeforeAnyRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*Config)
		sql   string
		want  string
	}{
		{"select not allowed", func(c *Config) { c.StatementTypes = []string{"SHOW"} }, "SELECT 1", "statement_types"},
		{"show not allowed", func(c *Config) { c.StatementTypes = []string{"SELECT"} }, "SHOW SCHEMAS", "statement_types"},
		{"describe not allowed", func(c *Config) { c.StatementTypes = []string{"SELECT", "SHOW"} }, "DESCRIBE src.t", "statement_types"},
		{"explain not allowed", func(c *Config) { c.StatementTypes = []string{"SELECT"} }, "EXPLAIN PLAN FOR SELECT 1", "statement_types"},
		{"explain target not allowed", func(c *Config) { c.StatementTypes = []string{"EXPLAIN"} }, "EXPLAIN PLAN FOR SELECT 1", "statement_types"},
		{"show type not allowed", func(c *Config) { c.ShowTypes = []string{"TABLES"} }, "SHOW SCHEMAS", "show_types"},
		{"show type not allowed, create table", func(c *Config) { c.ShowTypes = []string{"SCHEMAS", "TABLES"} }, "SHOW CREATE TABLE src.t", "show_types"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			cfg := f.config()
			tc.apply(&cfg)
			result, err := f.run(cfg, tc.sql, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) || result != (Result{}) {
				t.Fatalf("got %+v, %v; want a %s error", result, err, tc.want)
			}
			if n := len(f.all()); n != 0 {
				t.Errorf("%d HTTP requests before the rejection", n)
			}
		})
	}
	f := newFake(t)
	cfg := f.config()
	cfg.StatementTypes, cfg.ShowTypes = []string{"SELECT", "EXPLAIN", "SHOW"}, []string{"schemas"}
	for _, sql := range []string{"SELECT 1", "EXPLAIN PLAN FOR SELECT 1", "SHOW SCHEMAS"} {
		if _, err := f.run(cfg, sql, nil); err != nil {
			t.Errorf("%s: %v", sql, err)
		}
	}
}

func TestInvalidConfigSendsNothing(t *testing.T) {
	f := newFake(t)
	cfg := f.config()
	cfg.MaxRows = 501
	if _, err := f.run(cfg, testSQL, nil); err == nil {
		t.Fatal("accepted max_rows 501")
	}
	if n := len(f.all()); n != 0 {
		t.Errorf("%d requests with an invalid config", n)
	}
}

func TestCredentialIsReadBeforeAnyRequest(t *testing.T) {
	f := newFake(t)
	readCredential = credfile.Read
	cfg := f.config()
	cfg.Credential = "/nonexistent/dremio-credential.json"
	_, err := f.run(cfg, testSQL, nil)
	if err == nil || err.Error() != "cannot open credential file" {
		t.Fatalf("got %v", err)
	}
	if n := len(f.all()); n != 0 {
		t.Errorf("%d requests without a credential", n)
	}
	// A rejected statement fails before the credential file is touched.
	called := false
	readCredential = func(string) (credfile.Credential, error) { called = true; return testCred, nil }
	if _, err := f.run(f.config(), "TRUNCATE TABLE t", nil); !errors.Is(err, sqlguard.ErrRejected) || called {
		t.Fatalf("got %v, credential read=%v", err, called)
	}
}

func TestGuardPanicIsRejected(t *testing.T) {
	f := newFake(t)
	original := validate
	t.Cleanup(func() { validate = original })
	validate = func(sqlguard.Dialect, string, sqlguard.Options) (sqlguard.Statement, error) {
		panic("SQL password=must-not-leak")
	}
	_, err := f.run(f.config(), testSQL, nil)
	if !errors.Is(err, sqlguard.ErrRejected) || strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("got %v", err)
	}
	if n := len(f.all()); n != 0 {
		t.Errorf("%d requests after a guard panic", n)
	}
}

func TestGuardUsesDremioDialect(t *testing.T) {
	f := newFake(t)
	original := validate
	t.Cleanup(func() { validate = original })
	var dialect sqlguard.Dialect
	var options sqlguard.Options
	validate = func(d sqlguard.Dialect, sql string, o sqlguard.Options) (sqlguard.Statement, error) {
		dialect, options = d, o
		return original(d, sql, o)
	}
	mustRun(t, f, f.config(), testSQL)
	if dialect != sqlguard.Dremio || options != (sqlguard.Options{}) {
		t.Fatalf("dialect=%v options=%+v", dialect, options)
	}
}

func TestParallelRunsDoNotShareState(t *testing.T) {
	f := newFake(t)
	f.rows = rowsOf(3)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := RunRedacted(context.Background(), f.config(), Params{SQL: testSQL}, nil)
			if err == nil && (result.Rows != 3 || result.Truncated) {
				err = fmt.Errorf("result %+v", result)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if n := len(f.find("DELETE", "/apiv2/login")); n != 8 {
		t.Errorf("%d logouts for 8 runs", n)
	}
}

// sql is imported for the NullString type used by cellText.
