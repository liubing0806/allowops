package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
)

// The job layer owns the defaults: an omitted option must reach it as absent so
// that the gateway configuration, not a constant in this package, decides.
func TestOmittedJobOptionsStayAbsent(t *testing.T) {
	r, _, err := actionRequest(testAction(), json.RawMessage(`{"targets":{"hosts":["web-01"]},"params":{"mode":"recent"},"reason":"investigation"}`), job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if r.WaitSeconds != nil || r.BatchSize != nil || r.MaxFailures != nil {
		t.Fatalf("omitted options were sent: wait_seconds=%d batch_size=%d max_failures=%d; want all absent", r.GetWaitSeconds(), r.GetBatchSize(), r.GetMaxFailures())
	}
}

var tightJobConfig = job.Config{BatchSize: 5, MaxFailures: 1, MaxWaitSeconds: 20, WaitSeconds: 10}

// With limits tighter than the built-in 30/20/5, a caller that passes no
// wait_seconds, batch_size or max_failures must be served by the configured
// defaults instead of being rejected for exceeding them.
func TestTightenedJobConfigServesCallsWithoutOptions(t *testing.T) {
	f := newTransportFixture(t)
	cfg := tightJobConfig
	ctx := context.Background()
	router, err := hostconn.New(f.db, nil, hostconn.DefaultConfig(), hostconn.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err = router.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(router.Close)
	f.service.config.Jobs = cfg
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

// Defaults and maxima in the schemas are the effective limits: the lower of the
// gateway configuration and the action's own value.
func TestSchemaAdvertisesEffectiveJobLimits(t *testing.T) {
	cfg := tightJobConfig
	failures := 3
	for _, tc := range []struct {
		name                    string
		batch                   int
		failures                *int
		wantBatch, wantFailures uint32
	}{
		{"action without limits uses configuration", 0, nil, 5, 1},
		{"action limit above configuration is capped", 50, &failures, 5, 1},
		{"action limit below configuration wins", 2, new(int), 2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := testAction()
			a.BatchSize, a.MaxFailures = tc.batch, tc.failures
			tool, err := actionTool(a, cfg)
			if err != nil {
				t.Fatal(err)
			}
			props := mustMap(t, tool.InputSchema["properties"])
			for name, want := range map[string]uint32{"batch_size": tc.wantBatch, "max_failures": tc.wantFailures} {
				p := mustMap(t, props[name])
				if p["maximum"] != want || p["default"] != want {
					t.Errorf("%s=%v; want default and maximum %d", name, p, want)
				}
			}
			wait := mustMap(t, props["wait_seconds"])
			if wait["default"] != cfg.WaitSeconds || wait["maximum"] != cfg.MaxWaitSeconds {
				t.Errorf("wait_seconds=%v; want default %d maximum %d", wait, cfg.WaitSeconds, cfg.MaxWaitSeconds)
			}
		})
	}
	for _, tool := range fixedTools(cfg) {
		if tool.Name != "jobs_get" {
			continue
		}
		wait := mustMap(t, mustMap(t, tool.InputSchema["properties"])["wait_seconds"])
		if wait["default"] != cfg.WaitSeconds || wait["maximum"] != cfg.MaxWaitSeconds {
			t.Errorf("jobs_get wait_seconds=%v; want default %d maximum %d", wait, cfg.WaitSeconds, cfg.MaxWaitSeconds)
		}
	}
}

// Explicit values may only tighten the effective limits and pass through
// unchanged; the job layer re-checks them with the same rules.
func TestExplicitJobOptionsFollowEffectiveLimits(t *testing.T) {
	cfg := tightJobConfig
	const base = `{"targets":{"hosts":["web-01"]},"params":{"mode":"recent"},"reason":"x"`
	r, _, err := actionRequest(testAction(), json.RawMessage(base+`,"wait_seconds":0,"batch_size":2,"max_failures":0}`), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.WaitSeconds == nil || r.BatchSize == nil || r.MaxFailures == nil || *r.WaitSeconds != 0 || *r.BatchSize != 2 || *r.MaxFailures != 0 {
		t.Fatalf("explicit options not passed through: %+v", r)
	}
	for field, want := range map[string]string{`"wait_seconds":21`: "20", `"batch_size":6`: "5", `"max_failures":2`: "1"} {
		if _, _, err = actionRequest(testAction(), json.RawMessage(base+","+field+"}"), cfg); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error=%v; want limit %s", field, err, want)
		}
	}
}

func mustMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%T is not an object", v)
	}
	return m
}
