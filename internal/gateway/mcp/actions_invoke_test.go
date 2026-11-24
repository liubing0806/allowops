package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/api"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func invokeArgs(action string) map[string]any {
	args := actionArgs()
	args["action"] = action
	return args
}

func (f *transportFixture) jobCount() int {
	f.jobs.mu.Lock()
	defer f.jobs.mu.Unlock()
	return f.jobs.sequence
}

// resultEvents returns the result audit events appended since before.
func (f *transportFixture) resultEvents(before int) []api.AuditEvent {
	events := []api.AuditEvent{}
	for _, e := range f.audit.snapshot()[before:] {
		if e.Phase == "result" {
			events = append(events, e)
		}
	}
	return events
}

func TestActionsInvokeRunsVisibleActionOfMatchingRisk(t *testing.T) {
	f := newProgressiveFixture(t, func(c *Config) { c.Mode = modeProgressive })
	admin := f.headerClient(t, f.admin, nil)
	before := len(f.audit.snapshot())
	r := call(t, admin, "actions_invoke_read", invokeArgs("logs_read"))
	if r.IsError || content(t, r)["job_id"] == "" {
		t.Fatalf("read invoke=%v", content(t, r))
	}
	if events := f.resultEvents(before); len(events) != 1 || events[0].Operation != "mcp/logs_read" || events[0].Outcome != "allow" || events[0].JobID == "" {
		t.Fatalf("audit=%+v", events)
	}
	write := map[string]any{"action": "svc_restart", "targets": map[string]any{"hosts": []string{"web-01"}}, "reason": "restart", "params": map[string]any{"unit": "nginx"}, "wait_seconds": 0}
	if r := call(t, admin, "actions_invoke_write", write); r.IsError {
		t.Fatalf("write invoke=%v", content(t, r))
	}
	// Selector targets keep the expected_count check.
	args := invokeArgs("logs_read")
	args["targets"] = map[string]any{"selector": "env=test"}
	args["expected_count"] = 1
	if r := call(t, admin, "actions_invoke_read", args); !r.IsError || content(t, r)["actual_count"] != float64(2) {
		t.Fatalf("count mismatch=%v", content(t, r))
	}
	args = invokeArgs("logs_read")
	delete(args, "expected_count")
	args["targets"] = map[string]any{"selector": "env=test"}
	if r := call(t, admin, "actions_invoke_read", args); !r.IsError || !strings.Contains(content(t, r)["error"].(string), "expected_count required") {
		t.Fatalf("missing expected_count=%v", content(t, r))
	}
	// Unknown arguments list action with the action's own names and filters.
	args = invokeArgs("logs_read")
	args["unexpected"] = true
	r = call(t, admin, "actions_invoke_read", args)
	if message, _ := content(t, r)["error"].(string); !r.IsError || !strings.Contains(message, "[action params") || !strings.Contains(message, "tail") {
		t.Fatalf("unknown argument=%v", content(t, r))
	}
	args = invokeArgs("logs_read")
	args["params"] = map[string]any{"mode": "invalid"}
	if r := call(t, admin, "actions_invoke_read", args); !r.IsError || !strings.Contains(content(t, r)["error"].(string), "recent") {
		t.Fatalf("parameter error=%v", content(t, r))
	}
}

func TestActionsInvokeRejectsRiskMismatchAndHiddenActions(t *testing.T) {
	f := newProgressiveFixture(t, func(c *Config) { c.Mode = modeProgressive })
	admin := f.headerClient(t, f.admin, nil)
	reader := f.headerClient(t, f.reader, nil)
	const hidden = "tool removed or unavailable for this identity; call actions_search to refresh"
	jobs := f.jobCount()
	for _, tc := range []struct {
		name      string
		client    *sdk.ClientSession
		tool      string
		args      map[string]any
		error     string
		operation string
	}{
		{"read tool runs write action", admin, "actions_invoke_read", invokeArgs("svc_restart"), "action risk does not match invocation tool; call the matching actions_invoke_write tool", "mcp/svc_restart"},
		{"read tool runs dangerous action", admin, "actions_invoke_read", invokeArgs("data_purge"), "action risk does not match invocation tool; call the matching actions_invoke_dangerous tool", "mcp/data_purge"},
		{"dangerous tool runs read action", admin, "actions_invoke_dangerous", invokeArgs("logs_read"), "action risk does not match invocation tool; call the matching actions_invoke_read tool", "mcp/logs_read"},
		{"missing action", admin, "actions_invoke_read", invokeArgs("missing_action"), hidden, "mcp/actions_invoke_read"},
		{"hidden action", reader, "actions_invoke_read", invokeArgs("svc_restart"), hidden, "mcp/actions_invoke_read"},
		{"hidden dangerous action", reader, "actions_invoke_read", invokeArgs("data_purge"), hidden, "mcp/actions_invoke_read"},
		{"fixed tool as action", admin, "actions_invoke_read", invokeArgs("jobs_cancel"), "action required; allowed: action name returned by actions_search", "mcp/actions_invoke_read"},
		{"meta tool as action", admin, "actions_invoke_read", invokeArgs("actions_search"), "action required; allowed: action name returned by actions_search", "mcp/actions_invoke_read"},
		{"invalid action name", admin, "actions_invoke_read", invokeArgs("Logs-Read"), "action required; allowed: action name returned by actions_search", "mcp/actions_invoke_read"},
		{"action not string", admin, "actions_invoke_read", map[string]any{"action": 1, "targets": map[string]any{"hosts": []string{"web-01"}}, "reason": "x"}, "action required; allowed: action name returned by actions_search", "mcp/actions_invoke_read"},
		{"action null", admin, "actions_invoke_read", map[string]any{"action": nil, "targets": map[string]any{"hosts": []string{"web-01"}}, "reason": "x"}, "action required; allowed: action name returned by actions_search", "mcp/actions_invoke_read"},
		{"action missing", admin, "actions_invoke_read", actionArgs(), "action required; allowed: action name returned by actions_search", "mcp/actions_invoke_read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(f.audit.snapshot())
			r := call(t, tc.client, tc.tool, tc.args)
			if data := content(t, r); !r.IsError || data["error"] != tc.error {
				t.Fatalf("result=%v", data)
			}
			if events := f.resultEvents(before); len(events) != 1 || events[0].Operation != tc.operation || events[0].Outcome != "deny" {
				t.Fatalf("audit=%+v", events)
			}
		})
	}
	// Missing and hidden actions give byte-identical results.
	missing := mustJSON(t, call(t, reader, "actions_invoke_read", invokeArgs("missing_action")))
	if hiddenResult := mustJSON(t, call(t, reader, "actions_invoke_read", invokeArgs("svc_restart"))); string(missing) != string(hiddenResult) {
		t.Fatalf("hidden=%s missing=%s", hiddenResult, missing)
	}
	if f.jobCount() != jobs {
		t.Fatal("rejected invocations dispatched jobs")
	}
	// A catalog update that raises the risk is enforced on the next call.
	raised := progressiveActions()
	logs := raised["logs_read"]
	logs.Risk = "dangerous"
	raised["logs_read"] = logs
	f.publishActions(t, raised, 2*time.Second)
	r := call(t, admin, "actions_invoke_read", invokeArgs("logs_read"))
	if data := content(t, r); !r.IsError || data["error"] != "action risk does not match invocation tool; call the matching actions_invoke_dangerous tool" {
		t.Fatalf("raised risk=%v", data)
	}
	if f.jobCount() != jobs {
		t.Fatal("raised risk dispatched a job")
	}
}

// resultFailureAudit fails result events of one operation after the job
// module recorded its authorization.
type resultFailureAudit struct {
	delegate   api.Auditor
	operations []string
}

func (a resultFailureAudit) Append(ctx context.Context, e api.AuditEvent) error {
	if e.Phase == "result" && slices.Contains(a.operations, e.Operation) {
		return errors.New("fixture result audit unavailable")
	}
	return a.delegate.Append(ctx, e)
}

func TestActionsInvokeResultAuditFailureMayHaveCommitted(t *testing.T) {
	f := newProgressiveFixture(t, func(c *Config) { c.Mode = modeProgressive })
	f.identity.Audit = resultFailureAudit{delegate: f.audit, operations: []string{"mcp/logs_read", "mcp/actions_search"}}
	admin := f.headerClient(t, f.admin, nil)
	r := call(t, admin, "actions_invoke_read", invokeArgs("logs_read"))
	data := content(t, r)
	if !r.IsError || data["error"] != "result audit unavailable; operation may have committed" || data["job_id"] == nil {
		t.Fatalf("result=%v", data)
	}
	r = call(t, admin, "actions_search", map[string]any{})
	if data := content(t, r); !r.IsError || data["error"] != "result audit unavailable" {
		t.Fatalf("search result=%v", data)
	}
}

func TestActionsInvokeArgumentObject(t *testing.T) {
	a := testAction()
	scope := &serverScope{allAvailable: map[string]catalog.Action{a.Name: a, "future": {Name: "future", Risk: "read"}}, unsupported: map[string]bool{"future": true}}
	s := &Service{}
	for _, raw := range []string{`[]`, `{"action":"logs_read","action":"logs_read"}`, `{"action":"logs_read"} {}`, `"logs_read"`} {
		state := &callState{}
		_, err := s.invokeAction(context.Background(), &sdk.CallToolRequest{Params: &sdk.CallToolParamsRaw{Name: "actions_invoke_read", Arguments: json.RawMessage(raw)}}, scope, "read", state)
		if connect.CodeOf(err) != connect.CodeInvalidArgument || state.operation != "" || state.mutating {
			t.Fatalf("%s error=%v state=%+v", raw, err, state)
		}
	}
	state := &callState{}
	_, err := s.invokeAction(context.Background(), &sdk.CallToolRequest{Params: &sdk.CallToolParamsRaw{Name: "actions_invoke_read", Arguments: json.RawMessage(`{"action":"future"}`)}}, scope, "read", state)
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || err.(*connect.Error).Message() != errUnsupportedActionSchema.Error() || state.operation != "mcp/future" || state.mutating {
		t.Fatalf("unsupported error=%v state=%+v", err, state)
	}
}
