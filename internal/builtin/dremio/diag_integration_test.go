package dremio

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/builtin/credfile"
)

// These tests need the same local environment and variables as
// integration_test.go (ALLOWOPS_DREMIO_URL, ALLOWOPS_DREMIO_SOURCE,
// ALLOWOPS_DREMIO_SCRATCH_SOURCE). They only read from Dremio.

func diagIntegration(t *testing.T) (DiagConfig, credfile.Credential) {
	t.Helper()
	cfg, cred := integration(t)
	return DiagConfig{Credential: cfg.Credential, URL: cfg.URL, MaxRows: cfg.MaxRows, MaxBytes: cfg.MaxBytes, Timeout: cfg.Timeout}, cred
}

func diagRun(t *testing.T, cfg DiagConfig, p DiagParams) Result {
	t.Helper()
	r, err := RunDiag(context.Background(), cfg, p)
	if err != nil {
		t.Fatalf("%+v: %v", p, err)
	}
	return r
}

// findJob runs a statement and returns the id of its job, taken from the job list.
func findJob(t *testing.T, cfg DiagConfig, cred credfile.Credential, statement string) string {
	t.Helper()
	marker := fmt.Sprintf("/* diag-%d */ ", time.Now().UnixNano())
	query := Config{Credential: cfg.Credential, URL: cfg.URL, Timeout: cfg.Timeout}
	if _, err := RunRedacted(context.Background(), query, Params{SQL: marker + expand(statement)}, nil); err != nil && !strings.Contains(statement, "no_such_table") {
		t.Fatalf("%s: %v", statement, err)
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		r := diagRun(t, cfg, DiagParams{Op: OpJobs, Since: ptr(5 * time.Minute), User: cred.Username, Limit: ptr(100)})
		for _, line := range strings.Split(r.Output, "\n")[1:] {
			if cells := strings.Split(line, "\t"); len(cells) == len(jobColumns) && strings.Contains(cells[len(cells)-1], strings.TrimSpace(strings.Trim(marker, "/* "))) {
				return cells[0]
			}
		}
	}
	t.Fatalf("no job with the marker for %s", statement)
	return ""
}

func TestIntegrationDiagNodesAndReflections(t *testing.T) {
	cfg, _ := diagIntegration(t)
	r := diagRun(t, cfg, DiagParams{Op: OpNodes})
	if !strings.HasPrefix(r.Output, "# sys.nodes\nname\thostname\t") || !strings.Contains(r.Output, "\n# sys.memory\nnode_id\t") || !strings.Contains(r.Output, "green") || r.Rows < 2 {
		t.Errorf("nodes:\n%s", r.Output)
	}
	r = diagRun(t, cfg, DiagParams{Op: OpReflection})
	if !strings.HasPrefix(r.Output, "reflection_id\treflection_name\t") {
		t.Errorf("reflections:\n%s", r.Output)
	}
}

func TestIntegrationDiagJobs(t *testing.T) {
	cfg, cred := diagIntegration(t)
	id := findJob(t, cfg, cred, `SELECT count(*) AS n FROM {src}.demo_dw.dim_user`)

	// Filters narrow the list; a filter that matches nothing returns the header only.
	header := strings.Join(jobColumns, "\t") + "\n"
	for name, p := range map[string]DiagParams{
		"unknown user":       {Op: OpJobs, User: "no.such.user"},
		"duration too long":  {Op: OpJobs, Since: ptr(time.Hour), MinDuration: ptr(100 * time.Hour)},
		"future-only window": {Op: OpJobs, Since: ptr(time.Nanosecond), User: "no.such.user"},
	} {
		if r := diagRun(t, cfg, p); r.Output != header || r.Rows != 0 {
			t.Errorf("%s: %q", name, r.Output)
		}
	}
	failed := diagRun(t, cfg, DiagParams{Op: OpJobs, State: "FAILED", Since: ptr(24 * time.Hour), Limit: ptr(50)})
	for _, line := range strings.Split(strings.TrimSpace(failed.Output), "\n")[1:] {
		if cells := strings.Split(line, "\t"); cells[1] != "FAILED" {
			t.Errorf("state filter: %q", line)
		}
	}
	slow := diagRun(t, cfg, DiagParams{Op: OpJobs, Since: ptr(24 * time.Hour), MinDuration: ptr(50 * time.Millisecond), Limit: ptr(50)})
	last := int64(1 << 62)
	for _, line := range strings.Split(strings.TrimSpace(slow.Output), "\n")[1:] {
		var d int64
		cells := strings.Split(line, "\t")
		if _, err := fmt.Sscan(cells[6], &d); err != nil || d < 50 || d > last {
			t.Errorf("min_duration filter or order: %q", line)
		}
		last = d
	}
	// The limit is applied and reported.
	r := diagRun(t, cfg, DiagParams{Op: OpJobs, Since: ptr(24 * time.Hour), Limit: ptr(2)})
	if r.Rows != 2 || !r.Truncated {
		t.Errorf("limit 2: rows=%d truncated=%v", r.Rows, r.Truncated)
	}

	status := diagRun(t, cfg, DiagParams{Op: OpJob, JobID: id})
	var job map[string]any
	if err := json.Unmarshal([]byte(status.Output), &job); err != nil || job["state"] != "COMPLETED" || job["job_id"] != id {
		t.Errorf("job: %v %s", err, status.Output)
	}
	if _, err := RunDiag(context.Background(), cfg, DiagParams{Op: OpJob, JobID: "ffffffff-ffff-4fff-8fff-ffffffffffff"}); err == nil {
		t.Error("an unknown job")
	}
}

func TestIntegrationDiagJobProfile(t *testing.T) {
	cfg, cred := diagIntegration(t)
	profile := func(statement string) Summary {
		id := findJob(t, cfg, cred, statement)
		r := diagRun(t, cfg, DiagParams{Op: OpJobProfile, JobID: id, TopN: ptr(5)})
		var s Summary
		if err := json.Unmarshal([]byte(r.Output), &s); err != nil {
			t.Fatalf("%s: %v\n%s", statement, err, r.Output)
		}
		if s.JobID != id {
			t.Errorf("job id %s; want %s", s.JobID, id)
		}
		return s
	}
	small := profile(`SELECT user_id FROM {src}.demo_dw.dim_user WHERE level = 2`)
	if small.State != "COMPLETED" || small.TotalMs <= 0 || len(small.Operators) == 0 || len(small.PushdownSQL) != 1 || !strings.Contains(small.PushdownSQL[0], "dim_user") || len(small.Hits) != 0 {
		t.Errorf("small: %+v", small)
	}
	large := profile(`SELECT order_id, user_id, amount FROM {src}.demo_dw.fact_orders`)
	if large.ScanRecords < 500000 || len(large.Hits) != 1 || large.Hits[0].Rule != "DR-SCAN-1" {
		t.Errorf("large scan: records=%d hits=%+v", large.ScanRecords, large.Hits)
	}
	cross := profile(`SELECT u.city, count(*) AS c FROM {src}.demo_dw.fact_orders f JOIN {scratch}.demo_dw.dim_user u ON f.user_id = u.user_id GROUP BY u.city`)
	rules := map[string]bool{}
	for _, h := range cross.Hits {
		rules[h.Rule] = true
	}
	if !rules["DR-JOIN-1"] || !rules["DR-SCAN-1"] || len(cross.PushdownSQL) != 2 {
		t.Errorf("cross-source join: hits=%v pushdown=%d", rules, len(cross.PushdownSQL))
	}
	failed := profile(`SELECT * FROM {src}.demo_dw.no_such_table`)
	if failed.State != "FAILED" || len(failed.Hits) != 1 || failed.Hits[0].Rule != "DR-FAIL-1" {
		t.Errorf("failed: %+v", failed)
	}
	if _, err := RunDiag(context.Background(), cfg, DiagParams{Op: OpJobProfile, JobID: "ffffffff-ffff-4fff-8fff-ffffffffffff"}); err == nil {
		t.Error("the profile of an unknown job")
	}
	// A profile limit below the size of the profile is an error that names the limit.
	cfg.MaxProfileBytes = 1 << 10
	if _, err := RunDiag(context.Background(), cfg, DiagParams{Op: OpJobProfile, JobID: findJob(t, cfg, cred, `SELECT count(*) AS n FROM {src}.demo_dw.dim_product`)}); err == nil {
		t.Error("a profile above max_profile_bytes")
	}
}
