package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
)

// The job layer owns the defaults: an omitted option must reach it as absent so
// that the gateway configuration, not a constant in this package, decides.
func TestOmittedJobOptionsStayAbsent(t *testing.T) {
	r, _, err := actionRequest(testAction(), json.RawMessage(`{"targets":{"hosts":["web-01"]},"params":{"mode":"recent"},"reason":"investigation"}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.WaitSeconds != nil || r.BatchSize != nil || r.MaxFailures != nil {
		t.Fatalf("omitted options were sent: wait_seconds=%d batch_size=%d max_failures=%d; want all absent", r.GetWaitSeconds(), r.GetBatchSize(), r.GetMaxFailures())
	}
}

// With limits tighter than the built-in 30/20/5, a caller that passes no
// wait_seconds, batch_size or max_failures must be served by the configured
// defaults instead of being rejected for exceeding them.
func TestTightenedJobConfigServesCallsWithoutOptions(t *testing.T) {
	f := newTransportFixture(t)
	ctx := context.Background()
	router, err := hostconn.New(f.db, nil, hostconn.DefaultConfig(), hostconn.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err = router.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(router.Close)
	cfg := job.Config{BatchSize: 5, MaxFailures: 1, MaxWaitSeconds: 20, WaitSeconds: 10}
	jobs, err := job.New(f.db, f.identity, router, p6CancelStorage{}, audit.New(f.db.Pool, audit.Config{}), f.catalogs.Trusted, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jobs.Close)
	f.service.jobs = jobs
	c, _ := f.client(t, f.admin, nil)
	args := actionArgs()
	delete(args, "wait_seconds")
	started := time.Now()
	run := call(t, c, "logs_read", args)
	data := content(t, run)
	if run.IsError || data["job_id"] == nil {
		t.Fatalf("action without options rejected: %v", data)
	}
	if elapsed := time.Since(started); elapsed > time.Duration(cfg.WaitSeconds)*time.Second {
		t.Fatalf("action waited %s, beyond the configured %ds default", elapsed, cfg.WaitSeconds)
	}
	get := call(t, c, "jobs_get", map[string]any{"job_id": data["job_id"]})
	if got := content(t, get); get.IsError {
		t.Fatalf("jobs_get without wait_seconds rejected: %v", got)
	}
}
