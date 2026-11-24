package job_test

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/mcp"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type interceptingJobs struct {
	*job.Service
	once      sync.Once
	beforeRun func()
}

func (j *interceptingJobs) RunJob(ctx context.Context, r *v1.RunJobRequest) (*v1.RunJobResponse, error) {
	if j.beforeRun != nil {
		j.once.Do(j.beforeRun)
	}
	return j.Service.RunJob(ctx, r)
}

func TestRunJobExpectedRiskRejectsMidCallEscalation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	publication := &catalogsvc.Service{Store: f.DB, Trusted: f.Trusted, MaxEnvelopeBytes: 64 << 20, MaxActionBytes: 256 << 10}

	escalateStable := func() {
		actions := maps.Clone(f.Package.Actions)
		stable := actions["stable"]
		stable.Risk = "dangerous"
		actions["stable"] = stable
		pkg, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: "p6"}, Actions: actions}, catalog.BuildOptions{Now: time.Now().Add(2 * time.Second), TTL: time.Hour})
		if err != nil {
			t.Errorf("build escalated catalog: %v", err)
			return
		}
		payload, err := catalog.CanonicalJSON(pkg)
		if err != nil {
			t.Errorf("canonical escalated catalog: %v", err)
			return
		}
		env, err := catalog.Sign(payload, catalog.SigningKey{PrivateKey: f.Signer})
		if err != nil {
			t.Errorf("sign escalated catalog: %v", err)
			return
		}
		raw, err := json.Marshal(env)
		if err != nil {
			t.Errorf("marshal escalated catalog: %v", err)
			return
		}
		if _, err := publication.Publish(context.Background(), raw); err != nil {
			t.Errorf("publish escalated catalog: %v", err)
		}
	}

	wrapped := &interceptingJobs{Service: f.A.Job, beforeRun: escalateStable}
	svc, err := mcp.New(f.A.Job.Access.(*api.Service), publication, wrapped, mcp.Config{Mode: "progressive"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(svc.Handler())
	t.Cleanup(server.Close)
	client := sdk.NewClient(&sdk.Implementation{Name: "expected-risk-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: &http.Client{Transport: &tokenTransport{base: server.Client().Transport, token: f.Token}}, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })

	before := countRows(t, f)
	r, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "actions_invoke_read", Arguments: map[string]any{
		"action":       "stable",
		"targets":      map[string]any{"hosts": []string{"a-host"}},
		"reason":       "mid-call escalation test",
		"wait_seconds": 5,
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r.StructuredContent)
	var content map[string]any
	_ = json.Unmarshal(raw, &content)
	if !r.IsError || content["reason"] != "ACTION_RISK_MISMATCH" {
		t.Fatalf("mid-call escalation result: isError=%t content=%v", r.IsError, content)
	}
	requireRejectedWithoutJob(t, f, before)

	// Calling with the matching risk invocation tool now succeeds.
	r, err = session.CallTool(ctx, &sdk.CallToolParams{Name: "actions_invoke_dangerous", Arguments: map[string]any{
		"action":       "stable",
		"targets":      map[string]any{"hosts": []string{"a-host"}},
		"reason":       "matching dangerous invoke",
		"wait_seconds": 5,
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(r.StructuredContent)
	content = nil
	_ = json.Unmarshal(raw, &content)
	if r.IsError || content["status"] != "succeeded" {
		t.Fatalf("dangerous invoke after escalation: isError=%t content=%v", r.IsError, content)
	}
	awaitFixtureOutputs(t, f)
}
