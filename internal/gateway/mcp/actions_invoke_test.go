package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
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

// Historical signed catalogs published before progressive tool names were
// reserved stay runnable in flat mode (directly) and in progressive mode
// (through actions_invoke_<risk>) without leaking hidden actions.
func TestHistoricalProgressiveNamedActionsWorkInBothModes(t *testing.T) {
	f := newProgressiveFixture(t, nil)
	now := time.Now().UTC().Add(5 * time.Second).Truncate(time.Second)
	historicalSearch := catalog.Action{Name: "actions_search", Description: "Legacy search action", Risk: "read", Timeout: "1s", MaxOutput: 8192, Exec: []any{"/usr/bin/true"}}
	historicalInvoke := catalog.Action{Name: "actions_invoke_read", Description: "Legacy write action", Risk: "write", Timeout: "1s", MaxOutput: 8192, Exec: []any{"/usr/bin/true"}}
	actions := map[string]catalog.Action{
		"actions_search":      historicalSearch,
		"actions_invoke_read": historicalInvoke,
		"logs_read":           progressiveActions()["logs_read"],
	}
	pkg := &catalog.Package{
		SchemaVersion: 1,
		CatalogID:     "fixture",
		Version:       20991124000000,
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
		Actions:       actions,
		Digests:       map[string]string{},
	}
	names := make([]string, 0, len(actions))
	for name, a := range actions {
		d, err := catalog.ActionDigest(a)
		if err != nil {
			t.Fatal(err)
		}
		pkg.Digests[name] = d
		names = append(names, name)
	}
	slices.Sort(names)
	payload, err := catalog.CanonicalJSON(pkg)
	if err != nil {
		t.Fatal(err)
	}
	env, err := catalog.Sign(payload, catalog.SigningKey{PrivateKey: f.key})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if err := f.db.Publish(context.Background(), db.InsertCatalogParams{
		CatalogID:   pkg.CatalogID,
		Version:     pkg.Version,
		Dsse:        raw,
		Digest:      digest[:],
		ExpiresAt:   store.Timestamp(pkg.ExpiresAt),
		ActionNames: names,
	}); err != nil {
		t.Fatal(err)
	}

	plainArgs := map[string]any{"targets": map[string]any{"hosts": []string{"web-01"}}, "reason": "legacy", "wait_seconds": 0}
	// Flat mode: calling the historical actions directly runs them as catalog actions, not meta-tools.
	flatAdmin := f.headerClient(t, f.admin, map[string]string{"X-Allowops-MCP-Mode": "flat"})
	for _, name := range []string{"actions_search", "actions_invoke_read"} {
		before := f.jobCount()
		r := call(t, flatAdmin, name, plainArgs)
		if r.IsError || content(t, r)["job_id"] == "" || f.jobCount() != before+1 {
			t.Fatalf("flat %s: isError=%t content=%v jobs=%d->%d", name, r.IsError, content(t, r), before, f.jobCount())
		}
	}

	// Progressive mode: actions_search lists the legacy actions, and
	// actions_invoke_<risk> runs them while keeping hidden ones opaque.
	progAdmin := f.headerClient(t, f.admin, map[string]string{"X-Allowops-MCP-Mode": "progressive"})
	progReader := f.headerClient(t, f.reader, map[string]string{"X-Allowops-MCP-Mode": "progressive"})
	searchRes := call(t, progAdmin, "actions_search", map[string]any{})
	if searchRes.IsError {
		t.Fatalf("progressive actions_search=%v", content(t, searchRes))
	}
	for _, tc := range []struct {
		tool   string
		action string
	}{
		{"actions_invoke_read", "actions_search"},
		{"actions_invoke_write", "actions_invoke_read"},
	} {
		before := f.jobCount()
		args := map[string]any{"action": tc.action, "targets": map[string]any{"hosts": []string{"web-01"}}, "reason": "legacy", "wait_seconds": 0}
		r := call(t, progAdmin, tc.tool, args)
		if r.IsError || content(t, r)["job_id"] == "" || f.jobCount() != before+1 {
			t.Fatalf("progressive %s(%s): isError=%t content=%v", tc.tool, tc.action, r.IsError, content(t, r))
		}
	}
	// Reader cannot see the write-risk legacy action actions_invoke_read and sees
	// the exact same InvalidArgument error as for an absent meta-tool name.
	hiddenWrite := mustJSON(t, call(t, progReader, "actions_invoke_read", map[string]any{"action": "actions_invoke_read", "targets": map[string]any{"hosts": []string{"web-01"}}, "reason": "probe"}))
	absentMeta := mustJSON(t, call(t, progReader, "actions_invoke_read", map[string]any{"action": "actions_invoke_dangerous", "targets": map[string]any{"hosts": []string{"web-01"}}, "reason": "probe"}))
	if string(hiddenWrite) != string(absentMeta) {
		t.Fatalf("hidden legacy meta-named action leaked existence: hidden=%s absent=%s", hiddenWrite, absentMeta)
	}
}
