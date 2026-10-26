package dremio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/builtin/credfile"
)

const diagJobID = "152329ab-6312-f9a2-7240-1e8469e7bd00"

func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// diagServer mimics the requests that dremio_diag sends. SQL jobs are answered
// from the sys fixtures, the job list and the job status from the job
// fixtures, and the support download from a zip chosen by the test.
type diagServer struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	requests []recorded
	sqlOf    map[string]string // job id -> statement

	listing  []byte // body of the job list; nil serves testdata/jobs/listing.json
	status   []byte // body of GET /api/v3/job/{id}; nil serves a completed job
	download []byte // body of the support download
	// override sees every request first and returns true when it answered.
	override func(w http.ResponseWriter, r *http.Request) bool
}

func newDiagServer(t *testing.T) *diagServer {
	t.Helper()
	d := &diagServer{t: t, sqlOf: map[string]string{}, download: sampleZip(t, "pushdown_join_agg")}
	d.srv = httptest.NewServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.srv.Close)
	original := readCredential
	readCredential = func(string) (credfile.Credential, error) { return testCred, nil }
	t.Cleanup(func() { readCredential = original })
	return d
}

func (d *diagServer) config() DiagConfig {
	return DiagConfig{Credential: testCredPath, URL: d.srv.URL, Timeout: 5 * time.Second}
}

func (d *diagServer) run(p DiagParams, mask func(string) string) (Result, error) {
	d.t.Helper()
	return RunDiagRedacted(context.Background(), d.config(), p, mask)
}

func (d *diagServer) all() []recorded {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.requests)
}

func (d *diagServer) find(method, path string) []recorded {
	var out []recorded
	for _, r := range d.all() {
		if r.Method == method && r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

func (d *diagServer) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	d.mu.Lock()
	d.requests = append(d.requests, recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), string(body)})
	d.mu.Unlock()
	if d.override != nil && d.override(w, r) {
		return
	}
	path := r.URL.Path
	switch {
	case r.Method == http.MethodPost && path == "/apiv2/login":
		writeJSON(w, 200, `{"token":"`+testToken+`"}`)
	case r.Method == http.MethodDelete && path == "/apiv2/login":
		w.WriteHeader(204)
	case r.Method == http.MethodPost && path == "/api/v3/sql":
		var req struct{ SQL string }
		_ = json.Unmarshal(body, &req)
		id := "0000000" + strconv.Itoa(len(d.sqlOf)+1) + "-0000-4000-8000-000000000000"
		d.mu.Lock()
		d.sqlOf[id] = req.SQL
		d.mu.Unlock()
		writeJSON(w, 200, `{"id":"`+id+`"}`)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v3/job/") && strings.HasSuffix(path, "/results"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v3/job/"), "/results")
		d.mu.Lock()
		statement := d.sqlOf[id]
		d.mu.Unlock()
		fixtureName := map[string]string{"SELECT * FROM sys.nodes": "sys/nodes.json", "SELECT * FROM sys.memory": "sys/memory.json", "SELECT * FROM sys.reflections": "sys/reflections.json"}[statement]
		if fixtureName == "" {
			writeJSON(w, 400, `{"errorMessage":"unexpected statement"}`)
			return
		}
		writeJSON(w, 200, string(fixture(d.t, fixtureName)))
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v3/job/"):
		if strings.HasPrefix(strings.TrimPrefix(path, "/api/v3/job/"), "0000000") || d.status == nil && path == "/api/v3/job/"+diagJobID {
			if d.status != nil {
				writeJSON(w, 200, string(d.status))
				return
			}
			writeJSON(w, 200, `{"jobState":"COMPLETED"}`)
			return
		}
		if d.status != nil {
			writeJSON(w, 200, string(d.status))
			return
		}
		writeJSON(w, 404, `{"errorMessage":"Could not find a job with id [x] secret-detail"}`)
	case r.Method == http.MethodGet && path == "/apiv2/jobs-listing/v1.0":
		body := d.listing
		if body == nil {
			body = fixture(d.t, "jobs/listing.json")
		}
		var listing struct {
			Jobs []json.RawMessage `json:"jobs"`
		}
		_ = json.Unmarshal(body, &listing)
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit < len(listing.Jobs) {
			listing.Jobs = listing.Jobs[:limit]
		}
		out, _ := json.Marshal(listing)
		writeJSON(w, 200, string(out))
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/apiv2/support/") && strings.HasSuffix(path, "/download"):
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(d.download)
	default:
		writeJSON(w, 404, `{"errorMessage":"no route"}`)
	}
}

func ptr[T any](v T) *T { return &v }

func TestDiagConfigValidate(t *testing.T) {
	valid := DiagConfig{Credential: testCredPath, URL: "http://127.0.0.1:9047"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*DiagConfig){
		"relative credential":       func(c *DiagConfig) { c.Credential = "dremio.json" },
		"url with path":             func(c *DiagConfig) { c.URL = "http://127.0.0.1:9047/api" },
		"max_rows above default":    func(c *DiagConfig) { c.MaxRows = 501 },
		"negative max_rows":         func(c *DiagConfig) { c.MaxRows = -1 },
		"max_bytes above default":   func(c *DiagConfig) { c.MaxBytes = 1<<20 + 1 },
		"timeout above default":     func(c *DiagConfig) { c.Timeout = 11 * time.Second },
		"max_profile_bytes above":   func(c *DiagConfig) { c.MaxProfileBytes = DefaultMaxProfileBytes + 1 },
		"negative max_profile_size": func(c *DiagConfig) { c.MaxProfileBytes = -1 },
	} {
		c := valid
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	c := valid
	c.MaxProfileBytes = 1 << 20
	if err := c.Validate(); err != nil {
		t.Errorf("a smaller profile limit: %v", err)
	}
	n := valid.normalized()
	if n.MaxRows != 500 || n.MaxBytes != 1<<20 || n.Timeout != 10*time.Second || n.MaxProfileBytes != DefaultMaxProfileBytes {
		t.Errorf("defaults are the maximum: %+v", n)
	}
}

func TestDiagConfigOps(t *testing.T) {
	valid := DiagConfig{Credential: testCredPath, URL: "http://127.0.0.1:9047"}
	for ops, ok := range map[string]bool{"nodes": true, "nodes,jobs": true, "nodes,jobs,job,job_profile,reflections": true, "kill": false, "nodes,kill": false} {
		c := valid
		c.Ops = strings.Split(ops, ",")
		if err := c.Validate(); (err == nil) != ok {
			t.Errorf("ops %s: %v", ops, err)
		}
	}
	c := valid
	c.Ops = []string{}
	if err := c.Validate(); err == nil {
		t.Error("an empty ops list")
	}
	// An op outside the list is refused before the credential is read and before any request.
	d := newDiagServer(t)
	cfg := d.config()
	cfg.Ops = []string{OpNodes}
	if _, err := RunDiag(context.Background(), cfg, DiagParams{Op: OpJobs}); err == nil || !strings.Contains(err.Error(), "ops allows only") {
		t.Fatalf("jobs with ops=[nodes]: %v", err)
	}
	if _, err := RunDiag(context.Background(), cfg, DiagParams{Op: OpJob, JobID: diagJobID}); err == nil {
		t.Fatal("job with ops=[nodes]")
	}
	if got := d.all(); len(got) != 0 {
		t.Fatalf("requests were sent: %+v", got)
	}
	if _, err := RunDiag(context.Background(), cfg, DiagParams{Op: OpNodes}); err != nil {
		t.Fatalf("nodes with ops=[nodes]: %v", err)
	}
}

func TestDiagParamsPerOp(t *testing.T) {
	id := diagJobID
	for _, tc := range []struct {
		name string
		p    DiagParams
		ok   bool
	}{
		{"nodes", DiagParams{Op: OpNodes}, true},
		{"reflections", DiagParams{Op: OpReflection}, true},
		{"jobs without filters", DiagParams{Op: OpJobs}, true},
		{"jobs with all filters", DiagParams{Op: OpJobs, Since: ptr(2 * time.Hour), MinDuration: ptr(time.Second), State: "failed", User: "alice@example.com", Limit: ptr(5)}, true},
		{"job", DiagParams{Op: OpJob, JobID: id}, true},
		{"job upper case id", DiagParams{Op: OpJob, JobID: strings.ToUpper(id)}, true},
		{"job_profile", DiagParams{Op: OpJobProfile, JobID: id, TopN: ptr(5)}, true},
		{"unknown op", DiagParams{Op: "kill"}, false},
		{"empty op", DiagParams{}, false},
		{"nodes with job_id", DiagParams{Op: OpNodes, JobID: id}, false},
		{"nodes with limit", DiagParams{Op: OpNodes, Limit: ptr(1)}, false},
		{"reflections with user", DiagParams{Op: OpReflection, User: "a"}, false},
		{"jobs with job_id", DiagParams{Op: OpJobs, JobID: id}, false},
		{"jobs with top_n", DiagParams{Op: OpJobs, TopN: ptr(1)}, false},
		{"job without job_id", DiagParams{Op: OpJob}, false},
		{"job with since", DiagParams{Op: OpJob, JobID: id, Since: ptr(time.Hour)}, false},
		{"job with top_n", DiagParams{Op: OpJob, JobID: id, TopN: ptr(1)}, false},
		{"job_profile without job_id", DiagParams{Op: OpJobProfile}, false},
		{"job_profile with state", DiagParams{Op: OpJobProfile, JobID: id, State: "FAILED"}, false},
		{"top_n 0", DiagParams{Op: OpJobProfile, JobID: id, TopN: ptr(0)}, false},
		{"top_n 51", DiagParams{Op: OpJobProfile, JobID: id, TopN: ptr(51)}, false},
		{"top_n 50", DiagParams{Op: OpJobProfile, JobID: id, TopN: ptr(50)}, true},
		{"limit 0", DiagParams{Op: OpJobs, Limit: ptr(0)}, false},
		{"limit 500", DiagParams{Op: OpJobs, Limit: ptr(500)}, true},
		{"limit 501", DiagParams{Op: OpJobs, Limit: ptr(501)}, false},
		{"since 0", DiagParams{Op: OpJobs, Since: ptr(time.Duration(0))}, false},
		{"since negative", DiagParams{Op: OpJobs, Since: ptr(-time.Hour)}, false},
		{"since 168h", DiagParams{Op: OpJobs, Since: ptr(MaxSince)}, true},
		{"since above 168h", DiagParams{Op: OpJobs, Since: ptr(MaxSince + time.Second)}, false},
		{"min_duration 0", DiagParams{Op: OpJobs, MinDuration: ptr(time.Duration(0))}, true},
		{"min_duration negative", DiagParams{Op: OpJobs, MinDuration: ptr(-time.Second)}, false},
		{"min_duration above 168h", DiagParams{Op: OpJobs, MinDuration: ptr(MaxSince + time.Second)}, false},
		{"state QUEUED", DiagParams{Op: OpJobs, State: "QUEUED"}, false},
		{"state lower case", DiagParams{Op: OpJobs, State: "completed"}, true},
		{"state injection", DiagParams{Op: OpJobs, State: `FAILED")`}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate(500)
			if (err == nil) != tc.ok {
				t.Fatalf("error=%v; want ok=%v", err, tc.ok)
			}
		})
	}
	// The limit follows max_rows of the configuration.
	if err := (DiagParams{Op: OpJobs, Limit: ptr(11)}).Validate(10); err == nil {
		t.Error("limit above max_rows accepted")
	}
}

// Values that reach a path or a filter are checked against a fixed pattern
// first, so nothing is sent for a value that does not match.
func TestDiagRefusesBadValuesBeforeAnyRequest(t *testing.T) {
	d := newDiagServer(t)
	readCredential = func(string) (credfile.Credential, error) {
		t.Error("the credential file is read for an invalid call")
		return testCred, nil
	}
	for _, id := range []string{
		"", "..", "../etc/passwd", diagJobID + "/cancel", diagJobID + "?x=1", diagJobID + "#", diagJobID + "\n", " " + diagJobID,
		"152329ab-6312-f9a2-7240-1e8469e7bd0", "152329ab-6312-f9a2-7240-1e8469e7bd000", "152329ab63124f9a72401e8469e7bd00", "152329ab-6312-f9a2-7240-1e8469e7bdzz",
		"%2e%2e%2f", "152329ab-6312-f9a2-7240-1e8469e7bd00%2fcancel", strings.Repeat("a", 1000),
	} {
		for _, op := range []string{OpJob, OpJobProfile} {
			if _, err := d.run(DiagParams{Op: op, JobID: id}, nil); err == nil {
				t.Errorf("%s accepted job_id %q", op, id)
			}
		}
	}
	for _, user := range []string{`a"b`, `a;b`, `a)(b`, `a=b`, `a b`, "a\nb", "-a", "a/b", "a*", "a%22", strings.Repeat("a", 129), `a==b`} {
		if _, err := d.run(DiagParams{Op: OpJobs, User: user}, nil); err == nil {
			t.Errorf("accepted user %q", user)
		}
	}
	if got := d.all(); len(got) != 0 {
		t.Fatalf("requests were sent: %+v", got)
	}
}

func TestDiagNodes(t *testing.T) {
	d := newDiagServer(t)
	r, err := d.run(DiagParams{Op: OpNodes}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sql := []string{}
	for _, req := range d.find(http.MethodPost, "/api/v3/sql") {
		var body struct{ SQL string }
		_ = json.Unmarshal([]byte(req.Body), &body)
		sql = append(sql, body.SQL)
	}
	if !slices.Equal(sql, []string{"SELECT * FROM sys.nodes", "SELECT * FROM sys.memory"}) {
		t.Fatalf("statements: %q", sql)
	}
	if !strings.HasPrefix(r.Output, "# sys.nodes\nname\thostname\tip\t") || !strings.Contains(r.Output, "\n# sys.memory\nnode_id\thostname\t") || r.Rows != 2 || r.Truncated {
		t.Fatalf("output (%d rows, truncated=%v):\n%s", r.Rows, r.Truncated, r.Output)
	}
	for _, req := range d.all() {
		if req.Path != "/apiv2/login" && req.Auth != "_dremio"+testToken {
			t.Errorf("%s %s: authorization %q", req.Method, req.Path, req.Auth)
		}
	}
	if got := d.find(http.MethodDelete, "/apiv2/login"); len(got) != 1 {
		t.Errorf("the session is closed once: %d logout requests", len(got))
	}
}

func TestDiagNodesByteLimitIsShared(t *testing.T) {
	d := newDiagServer(t)
	cfg := d.config()
	full, err := RunDiag(context.Background(), cfg, DiagParams{Op: OpNodes})
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int64{int64(len(full.Output)) - 1, 300} {
		cfg.MaxBytes = limit
		r, err := RunDiag(context.Background(), cfg, DiagParams{Op: OpNodes})
		if err != nil {
			t.Fatalf("limit %d: %v", limit, err)
		}
		if int64(len(r.Output)) > limit || !r.Truncated || !strings.HasPrefix(r.Output, "# sys.nodes\n") {
			t.Errorf("limit %d: len=%d truncated=%v\n%s", limit, len(r.Output), r.Truncated, r.Output)
		}
	}
}

func TestDiagReflections(t *testing.T) {
	d := newDiagServer(t)
	r, err := d.run(DiagParams{Op: OpReflection}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.Output, "reflection_id\treflection_name\ttype\tstatus\t") || r.Rows != 0 || r.Truncated {
		t.Fatalf("an empty table keeps its header:\n%s", r.Output)
	}
}

func TestDiagJobsFilter(t *testing.T) {
	now := time.UnixMilli(1_792_860_000_000)
	for _, tc := range []struct {
		p    DiagParams
		want string
	}{
		{DiagParams{Op: OpJobs}, `(st=ge=1792856400000)`},
		{DiagParams{Op: OpJobs, Since: ptr(24 * time.Hour)}, `(st=ge=1792773600000)`},
		{DiagParams{Op: OpJobs, State: "failed"}, `(st=ge=1792856400000;jst=="FAILED")`},
		{DiagParams{Op: OpJobs, User: "alice@example.com"}, `(st=ge=1792856400000;usr=="alice@example.com")`},
		{DiagParams{Op: OpJobs, MinDuration: ptr(2500 * time.Millisecond)}, `(st=ge=1792856400000;dur=ge=2500)`},
		{DiagParams{Op: OpJobs, MinDuration: ptr(time.Duration(0))}, `(st=ge=1792856400000)`},
		{DiagParams{Op: OpJobs, Since: ptr(time.Minute), State: "COMPLETED", User: "bob", MinDuration: ptr(time.Second)}, `(st=ge=1792859940000;jst=="COMPLETED";usr=="bob";dur=ge=1000)`},
	} {
		if got := jobsFilter(tc.p, now); got != tc.want {
			t.Errorf("%+v:\n got %s\nwant %s", tc.p, got, tc.want)
		}
	}
}

func TestDiagJobs(t *testing.T) {
	d := newDiagServer(t)
	r, err := d.run(DiagParams{Op: OpJobs, State: "FAILED", Limit: ptr(5), MinDuration: ptr(time.Second)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	reqs := d.find(http.MethodGet, "/apiv2/jobs-listing/v1.0")
	if len(reqs) != 1 || reqs[0].Auth != "_dremio"+testToken {
		t.Fatalf("list requests: %+v", reqs)
	}
	q, _ := url.ParseQuery(reqs[0].Query)
	if q.Get("limit") != "6" || q.Get("offset") != "0" || q.Get("sort") != "dur" || q.Get("order") != "DESCENDING" || !strings.Contains(q.Get("filter"), `jst=="FAILED"`) || !strings.Contains(q.Get("filter"), "dur=ge=1000") {
		t.Errorf("query: %v", q)
	}
	lines := strings.Split(strings.TrimSuffix(r.Output, "\n"), "\n")
	if lines[0] != strings.Join(jobColumns, "\t") || len(lines) != 6 || r.Rows != 5 || !r.Truncated {
		t.Fatalf("5 of more rows, truncated=%v rows=%d:\n%s", r.Truncated, r.Rows, r.Output)
	}
	var listing struct {
		Jobs []struct {
			ID, State, User string
			StartTime       int64
			Duration        int64
			RowsScanned     int64
		}
	}
	if err := json.Unmarshal(fixture(t, "jobs/listing.json"), &listing); err != nil {
		t.Fatal(err)
	}
	want, first := listing.Jobs[0], strings.Split(lines[1], "\t")
	if len(first) != len(jobColumns) || first[0] != want.ID || first[1] != want.State || first[2] != want.User || first[5] != time.UnixMilli(want.StartTime).UTC().Format(time.RFC3339) || first[6] != strconv.FormatInt(want.Duration, 10) || first[7] != strconv.FormatInt(want.RowsScanned, 10) {
		t.Errorf("first row: %q; want job %+v", first, want)
	}
	for _, line := range lines[1:] {
		if cells := strings.Split(line, "\t"); len(cells) != len(jobColumns) || len([]rune(cells[len(cells)-1])) > maxQueryRunes+3 {
			t.Errorf("row: %q", line)
		}
	}
	// Default: start time order, the default limit, no truncation when the list is shorter.
	d2 := newDiagServer(t)
	r, err = d2.run(DiagParams{Op: OpJobs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	q, _ = url.ParseQuery(d2.find(http.MethodGet, "/apiv2/jobs-listing/v1.0")[0].Query)
	if q.Get("limit") != "21" || q.Get("sort") != "st" || r.Rows != DefaultJobsLimit || !r.Truncated {
		t.Errorf("defaults: %v rows=%d truncated=%v", q, r.Rows, r.Truncated)
	}
	d2.listing = []byte(`{"jobs":[]}`)
	if r, err = d2.run(DiagParams{Op: OpJobs}, nil); err != nil || r.Rows != 0 || r.Truncated || r.Output != strings.Join(jobColumns, "\t")+"\n" {
		t.Errorf("no jobs: %+v %v", r, err)
	}
}

func TestDiagJobsLimitFollowsMaxRows(t *testing.T) {
	d := newDiagServer(t)
	cfg := d.config()
	cfg.MaxRows = 3
	r, err := RunDiag(context.Background(), cfg, DiagParams{Op: OpJobs})
	if err != nil || r.Rows != 3 || !r.Truncated {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := RunDiag(context.Background(), cfg, DiagParams{Op: OpJobs, Limit: ptr(4)}); err == nil {
		t.Error("a limit above max_rows")
	}
}

func TestDiagJobsFlattensAndMasksStatements(t *testing.T) {
	d := newDiagServer(t)
	d.listing = []byte(`{"jobs":[{"id":"` + diagJobID + `","state":"FAILED","user":"carol","queryText":"SELECT 1\n\tFROM secret_table\nWHERE x = '` + strings.Repeat("y", 400) + `'","startTime":1792860000000,"duration":12}]}`)
	mask := func(s string) string { return strings.ReplaceAll(s, "secret_table", "[T]") }
	r, err := d.run(DiagParams{Op: OpJobs}, mask)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.Output, "secret_table") || !strings.Contains(r.Output, "SELECT 1 FROM [T] WHERE x = ") || strings.Count(r.Output, "\n") != 2 {
		t.Fatalf("one line per job, masked:\n%s", r.Output)
	}
	if !strings.HasSuffix(strings.TrimSuffix(r.Output, "\n"), "...") {
		t.Errorf("the statement is cut: %s", r.Output)
	}
}

func TestDiagJob(t *testing.T) {
	d := newDiagServer(t)
	d.status = fixture(t, "jobs/status_failed_unknown_table.json")
	r, err := d.run(DiagParams{Op: OpJob, JobID: diagJobID}, func(s string) string { return strings.ReplaceAll(s, "no_such_table", "[T]") })
	if err != nil {
		t.Fatal(err)
	}
	if got := d.find(http.MethodGet, "/api/v3/job/"+diagJobID); len(got) != 1 {
		t.Fatalf("status requests: %+v", d.all())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(r.Output), &out); err != nil {
		t.Fatalf("%v: %s", err, r.Output)
	}
	if out["job_id"] != diagJobID || out["state"] != "FAILED" || out["error_category"] != "object not found" || out["query_type"] != "REST" || out["duration_ms"] != float64(8) {
		t.Errorf("fields: %v", out)
	}
	if e, _ := out["error"].(string); !strings.Contains(e, "[T]") || strings.Contains(e, "no_such_table") {
		t.Errorf("error is masked: %v", out["error"])
	}
	if !strings.HasSuffix(r.Output, "\n") || strings.Count(r.Output, "\n") != 1 || r.Rows != 1 {
		t.Errorf("one line: %q", r.Output)
	}

	d.status = fixture(t, "jobs/status_canceled.json")
	r, err = d.run(DiagParams{Op: OpJob, JobID: diagJobID}, nil)
	if err != nil || !strings.Contains(r.Output, `"state":"CANCELED"`) || !strings.Contains(r.Output, "cancellation_reason") {
		t.Fatalf("canceled: %v\n%s", err, r.Output)
	}
	d.status = fixture(t, "jobs/status_pushdown_scan.json")
	r, _ = d.run(DiagParams{Op: OpJob, JobID: diagJobID}, nil)
	if strings.Contains(r.Output, `"error`) || !strings.Contains(r.Output, `"row_count":2500`) {
		t.Errorf("completed: %s", r.Output)
	}
}

func TestDiagJobUnknownIDAndBadResponse(t *testing.T) {
	d := newDiagServer(t)
	other := "ffffffff-6312-f9a2-7240-1e8469e7bd00"
	_, err := d.run(DiagParams{Op: OpJob, JobID: other}, nil)
	if err == nil || !strings.Contains(err.Error(), "status 404") || strings.Contains(err.Error(), "secret-detail") {
		t.Fatalf("not found: %v", err)
	}
	d.status = []byte(`{"unexpected":true}`)
	if _, err = d.run(DiagParams{Op: OpJob, JobID: diagJobID}, nil); err == nil || !strings.Contains(err.Error(), "invalid response") {
		t.Fatalf("bad body: %v", err)
	}
}

func TestDiagJobProfile(t *testing.T) {
	d := newDiagServer(t)
	d.download = sampleZip(t, "cross_join_large")
	r, err := d.run(DiagParams{Op: OpJobProfile, JobID: diagJobID, TopN: ptr(4)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	reqs := d.find(http.MethodPost, "/apiv2/support/"+diagJobID+"/download")
	if len(reqs) != 1 || reqs[0].Body != "{}" || reqs[0].Auth != "_dremio"+testToken {
		t.Fatalf("download requests: %+v", reqs)
	}
	var s Summary
	if err := json.Unmarshal([]byte(r.Output), &s); err != nil {
		t.Fatalf("%v: %s", err, r.Output)
	}
	if s.JobID != diagJobID || s.State != "COMPLETED" || len(s.Operators) != 4 || s.OperatorsOmitted <= 0 || s.ScanRecords != 510000 || len(s.PushdownSQL) != 2 {
		t.Errorf("summary: %+v", s)
	}
	if got := hitIDs(s); !slices.Equal(got, []string{"DR-JOIN-1", "DR-SCAN-1"}) {
		t.Errorf("hits: %v", got)
	}
	if r.Rows != 1 || r.Truncated || !strings.HasSuffix(r.Output, "\n") {
		t.Errorf("result: rows=%d truncated=%v", r.Rows, r.Truncated)
	}
	// The default is the ten longest operators.
	r, _ = d.run(DiagParams{Op: OpJobProfile, JobID: diagJobID}, nil)
	_ = json.Unmarshal([]byte(r.Output), &s)
	if len(s.Operators) != DefaultTopOperators {
		t.Errorf("default top_n: %d operators", len(s.Operators))
	}
}

func TestDiagJobProfileTruncatesToMaxBytes(t *testing.T) {
	d := newDiagServer(t)
	d.download = sampleZip(t, "many_branches")
	cfg := d.config()
	cfg.MaxBytes = 3000
	r, err := RunDiag(context.Background(), cfg, DiagParams{Op: OpJobProfile, JobID: diagJobID, TopN: ptr(50)})
	if err != nil || int64(len(r.Output)) > cfg.MaxBytes || !r.Truncated {
		t.Fatalf("len=%d truncated=%v err=%v", len(r.Output), r.Truncated, err)
	}
	if !strings.Contains(r.Output, "DR-PLAN-1") {
		t.Errorf("hits are kept: %s", r.Output)
	}
}

func TestDiagJobProfileRefusesBadDownloads(t *testing.T) {
	bomb := makeZip(t, map[string][]byte{"profile_attempt_0.json": bytes.Repeat([]byte{0}, 64<<20)})
	for name, tc := range map[string]struct {
		body []byte
		want string
	}{
		"zip bomb":          {bomb, "exceeds"},
		"login page":        {[]byte("<html><body>Sign in</body></html>"), "not valid"},
		"no profile":        {makeZip(t, map[string][]byte{"header.json": []byte("{}")}), "not valid"},
		"profile not json":  {makeZip(t, map[string][]byte{"profile_attempt_0.json": []byte("{{{")}), "not valid"},
		"profile is a list": {makeZip(t, map[string][]byte{"profile_attempt_0.json": []byte("[1,2]")}), "not valid"},
	} {
		t.Run(name, func(t *testing.T) {
			d := newDiagServer(t)
			d.download = tc.body
			cfg := d.config()
			cfg.MaxProfileBytes = 1 << 20
			start := time.Now()
			_, err := RunDiag(context.Background(), cfg, DiagParams{Op: OpJobProfile, JobID: diagJobID})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v; want %q", err, tc.want)
			}
			if time.Since(start) > 3*time.Second {
				t.Errorf("took %s", time.Since(start))
			}
			if got := d.find(http.MethodDelete, "/apiv2/login"); len(got) != 1 {
				t.Errorf("the session is closed on this path: %d", len(got))
			}
		})
	}
}

// A response larger than the limit is cut off while it is read.
func TestDiagJobProfileBoundsTheDownload(t *testing.T) {
	d := newDiagServer(t)
	d.download = bytes.Repeat([]byte{'x'}, 2<<20)
	cfg := d.config()
	cfg.MaxProfileBytes = 1 << 20
	_, err := RunDiag(context.Background(), cfg, DiagParams{Op: OpJobProfile, JobID: diagJobID})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("download over the limit: %v", err)
	}
}

func TestDiagMasksEverySecretAndLeaksNoError(t *testing.T) {
	d := newDiagServer(t)
	mask := func(s string) string {
		return strings.NewReplacer("allowops_reader", "[USER]", "demo_dw", "[SCHEMA]").Replace(s)
	}
	for _, p := range []DiagParams{{Op: OpNodes}, {Op: OpReflection}, {Op: OpJobs}, {Op: OpJob, JobID: diagJobID}, {Op: OpJobProfile, JobID: diagJobID}} {
		r, err := d.run(p, mask)
		if err != nil {
			t.Fatalf("%s: %v", p.Op, err)
		}
		if strings.Contains(r.Output, "allowops_reader") || strings.Contains(r.Output, "demo_dw") {
			t.Errorf("%s: the mask was not applied:\n%.600s", p.Op, r.Output)
		}
	}
	// Errors name the stage and the status only.
	d.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/apiv2/login" {
			writeJSON(w, 401, `{"errorMessage":"Invalid password `+testPassword+`"}`)
			return true
		}
		return false
	}
	_, err := d.run(DiagParams{Op: OpNodes}, nil)
	if err == nil || strings.Contains(err.Error(), testPassword) || !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("login error: %v", err)
	}
	d.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasPrefix(r.URL.Path, "/apiv2/support/") {
			writeJSON(w, 500, `{"errorMessage":"stack trace SELECT secret FROM hidden `+testToken+`"}`)
			return true
		}
		return false
	}
	_, err = d.run(DiagParams{Op: OpJobProfile, JobID: diagJobID}, nil)
	if err == nil || strings.Contains(err.Error(), "hidden") || strings.Contains(err.Error(), testToken) || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("download error: %v", err)
	}
}

func TestDiagSysQueryFailureAndTimeout(t *testing.T) {
	d := newDiagServer(t)
	d.override = func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v3/job/0000000") && !strings.HasSuffix(r.URL.Path, "/results"):
			writeJSON(w, 200, `{"jobState":"FAILED","errorMessage":"Unable to retrieve sys.nodes secret-detail"}`)
			return true
		}
		return false
	}
	_, err := d.run(DiagParams{Op: OpNodes}, nil)
	if err == nil || !strings.Contains(err.Error(), "FAILED") || strings.Contains(err.Error(), "secret-detail") {
		t.Fatalf("failed job: %v", err)
	}

	// A job that does not end before the timeout is cancelled, and the session is closed.
	d = newDiagServer(t)
	d.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v3/job/0000000") && !strings.HasSuffix(r.URL.Path, "/results") {
			writeJSON(w, 200, `{"jobState":"RUNNING"}`)
			return true
		}
		return false
	}
	cfg := d.config()
	cfg.Timeout = 300 * time.Millisecond
	_, err = RunDiag(context.Background(), cfg, DiagParams{Op: OpReflection})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	if got := d.find(http.MethodPost, "/api/v3/job/00000001-0000-4000-8000-000000000000/cancel"); len(got) != 1 {
		t.Errorf("the job is cancelled once: %+v", d.all())
	}
	if got := d.find(http.MethodDelete, "/apiv2/login"); len(got) != 1 {
		t.Errorf("logout: %d", len(got))
	}
}

func TestDiagCancelledContextSendsNothing(t *testing.T) {
	d := newDiagServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunDiag(ctx, d.config(), DiagParams{Op: OpNodes}); err == nil {
		t.Fatal("a cancelled context")
	}
	if got := d.all(); len(got) != 0 {
		t.Errorf("requests: %+v", got)
	}
}
