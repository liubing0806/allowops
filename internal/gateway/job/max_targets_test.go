package job_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/cli"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/mcp"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
)

const limitedAction = "name: limited\ndescription: target limit fixture\nrisk: read\nexec: [/usr/bin/printf, ok]\ntimeout: 5s\nmax_output: 1KB\nmax_targets: 2\n"

// rowCounts reports what a rejected run must not change (jobs, tasks, the
// "authorized" audit event written just before a job is created) and what it
// must add (one denied result audit event).
type rowCounts struct{ jobs, tasks, authorized, deniedResults int }

func countRows(t *testing.T, f *fixture) rowCounts {
	t.Helper()
	var n rowCounts
	err := f.DB.Pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM jobs),
		(SELECT count(*) FROM tasks),
		(SELECT count(*) FROM audit_events WHERE operation='run_job' AND reason='authorized'),
		(SELECT count(*) FROM audit_events WHERE operation='run_job' AND reason='result' AND decision='deny')`).Scan(&n.jobs, &n.tasks, &n.authorized, &n.deniedResults)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func requireRejectedWithoutJob(t *testing.T, f *fixture, before rowCounts) {
	t.Helper()
	after := countRows(t, f)
	want := before
	want.deniedResults++
	if after != want {
		t.Fatalf("rows after rejection=%+v want %+v (no job, no task, no authorized audit; one denied result audit)", after, want)
	}
}

func hostsRequest(action string, names ...string) *v1.RunJobRequest {
	return &v1.RunJobRequest{Action: action, Reason: "max_targets test", Targets: &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: names}}}, WaitSeconds: proto.Uint32(5)}
}

func errorDetail(t *testing.T, err error) *v1.ErrorDetail {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("error=%v; want a Connect error", err)
	}
	for _, d := range ce.Details() {
		if value, derr := d.Value(); derr == nil {
			if detail, ok := value.(*v1.ErrorDetail); ok {
				return detail
			}
		}
	}
	t.Fatalf("error %v has no ErrorDetail", err)
	return nil
}

func requireMaxTargetsDetail(t *testing.T, detail *v1.ErrorDetail, limit, actual uint64) {
	t.Helper()
	text := fmt.Sprintf("at most %d target hosts", limit)
	if detail.Reason != "MAX_TARGETS_EXCEEDED" || detail.GetActualCount() != actual || len(detail.Violations) != 1 || detail.Violations[0].Field != "targets" || !strings.Contains(detail.Violations[0].Description, text) {
		t.Fatalf("detail=%v; want MAX_TARGETS_EXCEEDED, actual_count=%d and a targets violation containing %q", detail, actual, text)
	}
}

type tokenTransport struct {
	base  http.RoundTripper
	token string
}

func (b *tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func TestMaxTargets(t *testing.T) {
	action, err := catalog.ParseAction([]byte(limitedAction))
	if err != nil {
		t.Fatal(err)
	}
	f := setup(t, func(f *fixture) { f.ExtraActions = append(f.ExtraActions, action) })
	ctx := context.Background()

	t.Run("connect_hosts", func(t *testing.T) {
		// The CLI and the console use this Connect RPC.
		v := run(t, f.A, hostsRequest("limited", "a-host", "b-host"))
		if v.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED || v.Job.TotalTasks != 2 {
			t.Fatalf("targets equal to max_targets: job=%v", v.Job)
		}
		before := countRows(t, f)
		_, err := f.A.Client.RunJob(ctx, connect.NewRequest(hostsRequest("limited", "a-host", "b-host", "c-host")))
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("error=%v; want FailedPrecondition, the code of the expected_count mismatch", err)
		}
		requireMaxTargetsDetail(t, errorDetail(t, err), 2, 3)
		requireRejectedWithoutJob(t, f, before)
		// An action without max_targets has no limit.
		v = run(t, f.A, hostsRequest("stable", "a-host", "b-host", "c-host"))
		if v.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED || v.Job.TotalTasks != 3 {
			t.Fatalf("action without max_targets: job=%v", v.Job)
		}
	})

	t.Run("cli_run", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", dir)
		if err := os.MkdirAll(filepath.Join(dir, "allowops"), 0700); err != nil {
			t.Fatal(err)
		}
		caPath := filepath.Join(dir, "ca.pem")
		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Certificate.Certificate[len(f.Certificate.Certificate)-1]})
		if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
			t.Fatal(err)
		}
		credential, _ := json.Marshal(map[string]any{"gateway": "https://" + f.A.Address, "ca_file": caPath, "token": f.Token, "expires_at": time.Now().Add(time.Hour)})
		if err := os.WriteFile(filepath.Join(dir, "allowops", "credentials"), credential, 0600); err != nil {
			t.Fatal(err)
		}
		allowops := func(hosts string) (string, error) {
			cmd := cli.NewRunCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs([]string{"limited", "--hosts", hosts, "--reason", "max_targets cli test", "--wait-seconds", "5"})
			err := cmd.Execute()
			return out.String(), err
		}
		if out, err := allowops("a-host,b-host"); err != nil || !strings.Contains(out, "succeeded") {
			t.Fatalf("allowops run with 2 hosts: err=%v output=%q", err, out)
		}
		before := countRows(t, f)
		out, err := allowops("a-host,b-host,c-host")
		if err == nil || !strings.Contains(err.Error(), "MAX_TARGETS_EXCEEDED") || !strings.Contains(err.Error(), "at most 2 target hosts") || !strings.Contains(err.Error(), `"actualCount":"3"`) {
			t.Fatalf("allowops run with 3 hosts: err=%v output=%q", err, out)
		}
		requireRejectedWithoutJob(t, f, before)
	})

	t.Run("mcp_call", func(t *testing.T) {
		svc, err := mcp.New(f.A.Job.Access.(*api.Service), &catalogsvc.Service{Store: f.DB, Trusted: f.Trusted, MaxEnvelopeBytes: 64 << 20, MaxActionBytes: 256 << 10}, f.A.Job, mcp.Config{})
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewTLSServer(svc.Handler())
		t.Cleanup(server.Close)
		client := sdk.NewClient(&sdk.Implementation{Name: "max-targets-test", Version: "1"}, nil)
		session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: &http.Client{Transport: &tokenTransport{base: server.Client().Transport, token: f.Token}}, DisableStandaloneSSE: true}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = session.Close() })
		tools, err := session.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		described := false
		for _, tool := range tools.Tools {
			if tool.Name == "limited" {
				described = strings.Contains(tool.Description, "at most 2 target hosts")
			}
		}
		if !described {
			t.Fatalf("tool limited does not state its limit: %v", tools.Tools)
		}
		call := func(hosts ...string) (*sdk.CallToolResult, map[string]any) {
			r, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "limited", Arguments: map[string]any{"targets": map[string]any{"hosts": hosts}, "reason": "max_targets mcp test", "wait_seconds": 5}})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(r.StructuredContent)
			var content map[string]any
			_ = json.Unmarshal(raw, &content)
			return r, content
		}
		if r, content := call("a-host", "b-host"); r.IsError || content["status"] != "succeeded" {
			t.Fatalf("2 hosts: isError=%t content=%v", r.IsError, content)
		}
		before := countRows(t, f)
		r, content := call("a-host", "b-host", "c-host")
		violations, _ := content["violations"].([]any)
		if !r.IsError || content["reason"] != "MAX_TARGETS_EXCEEDED" || content["actual_count"] != float64(3) || len(violations) != 1 || !strings.Contains(violations[0].(map[string]any)["description"].(string), "at most 2 target hosts") {
			t.Fatalf("3 hosts: isError=%t content=%v", r.IsError, content)
		}
		if after := countRows(t, f); after.jobs != before.jobs || after.tasks != before.tasks || after.authorized != before.authorized {
			t.Fatalf("rows after MCP rejection=%+v before=%+v", after, before)
		}
	})

	t.Run("selector", func(t *testing.T) {
		before := countRows(t, f)
		// Every host carries env=test, so the selector resolves to three hosts.
		r := request("limited")
		_, err := f.A.Client.RunJob(ctx, connect.NewRequest(r))
		requireMaxTargetsDetail(t, errorDetail(t, err), 2, 3)
		requireRejectedWithoutJob(t, f, before)
		// expected_count is checked first and keeps its own error.
		r.ExpectedCount = proto.Uint64(2)
		_, err = f.A.Client.RunJob(ctx, connect.NewRequest(r))
		if detail := errorDetail(t, err); detail.Reason != "EXPECTED_COUNT_MISMATCH" || detail.GetActualCount() != 3 {
			t.Fatalf("detail=%v; want EXPECTED_COUNT_MISMATCH with actual_count=3", detail)
		}
		// A selector that resolves to the limit passes.
		if _, err := f.DB.Pool.Exec(ctx, `UPDATE hosts SET authorization_labels='{"env":"other"}' WHERE host_id=$1`, f.Hosts[2]); err != nil {
			t.Fatal(err)
		}
		v := run(t, f.A, r)
		if v.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED || v.Job.TotalTasks != 2 {
			t.Fatalf("selector resolving to max_targets: job=%v", v.Job)
		}
	})
}
