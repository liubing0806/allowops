package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestUnsupportedSchemaKeepsOtherValidationErrors(t *testing.T) {
	for _, mutate := range []func(*catalog.Action){
		func(a *catalog.Action) { a.Params["mode"] = params.Definition{Type: params.Enum, Description: "mode"} },
		func(a *catalog.Action) { a.Params["mode"] = params.Definition{Description: "mode"} },
		func(a *catalog.Action) { a.BatchSize = int(int64(1) << 32) },
		func(a *catalog.Action) { a.Filters = []string{"unknown"} },
	} {
		a := testAction()
		mutate(&a)
		if _, err := actionTool(a); err == nil || errors.Is(err, errUnsupportedActionSchema) {
			t.Error("ordinary schema error swallowed as unsupported capability")
		}
	}
}

func TestSDKPublishedUnsupportedSchemaIsolation(t *testing.T) {
	for _, kind := range []string{"future_parameter", "unknown_builtin"} {
		t.Run(kind, func(t *testing.T) {
			f := newTransportFixture(t)
			ctx := context.Background()
			admin, _ := f.client(t, f.admin, nil)
			viewer, _ := f.client(t, f.viewer, nil)
			if r := call(t, admin, "logs_read", actionArgs()); r.IsError {
				t.Fatal("normal tool control failed before unsupported publication")
			}
			p, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: "fixture"}, Actions: map[string]catalog.Action{"logs_read": testAction()}}, catalog.BuildOptions{Now: time.Now().Add(time.Second)})
			if err != nil {
				t.Fatal(err)
			}
			a := catalog.Action{Name: "unsupported_action", Description: "future", Risk: "read", Timeout: "1s", MaxOutput: 1024}
			if kind == "future_parameter" {
				a.Exec = []any{"/usr/bin/printf", "{value}"}
				a.Params = map[string]params.Definition{"value": {Type: "future_type", Description: "future", Default: "future-default", MaxLen: 10}}
			} else {
				a.Builtin = "future_builtin"
				a.BuiltinConfig = map[string]any{"future": true}
			}
			p.Actions[a.Name] = a
			p.Digests[a.Name], err = catalog.ActionDigest(a)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := catalog.CanonicalJSON(p)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := catalog.Sign(payload, catalog.SigningKey{PrivateKey: f.key})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.catalogs.Publish(ctx, raw); err != nil {
				t.Fatal("signed mixed catalog publication failed")
			}
			listed, err := admin.ListTools(ctx, nil)
			if err != nil {
				t.Error("tools/list failed after supported publication; want normal tools with unsupported action omitted")
			} else if len(listed.Tools) != 5 {
				t.Errorf("admin tool count=%d; want 5", len(listed.Tools))
			} else {
				for _, tool := range listed.Tools {
					if tool.Name == a.Name {
						t.Error("listed unsupported schema")
					}
				}
			}
			if list, err := viewer.ListTools(ctx, nil); err != nil || len(list.Tools) != 4 {
				t.Error("hidden-action list changed; want four fixed tools")
			}
			f.jobs.mu.Lock()
			before := f.jobs.sequence
			f.jobs.mu.Unlock()
			checkCall := func(c *sdk.ClientSession, name, want string) {
				t.Helper()
				result, err := c.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: map[string]any{"targets": map[string]any{"hosts": []string{"sensitive-target"}}, "reason": "private-input"}})
				if err != nil {
					t.Error("tools/call transport failed; want stable tool error")
					return
				}
				data := content(t, result)
				if !result.IsError || data["error"] != want || len(data) != 2 || data["output_trust"] != "untrusted" {
					t.Errorf("tool error=%q; want %q and only output_trust", data["error"], want)
				}
			}
			const unsupported = "action schema unsupported by this gateway"
			const hidden = "tool removed or unavailable for this identity; call tools/list to refresh"
			checkCall(admin, a.Name, unsupported)
			checkCall(viewer, a.Name, hidden)
			checkCall(viewer, "nonexistent_action", hidden)
			policy, err := f.identity.GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{}))
			if err != nil {
				t.Fatal(err)
			}
			for i, labels := range []map[string]string{{"env": "test"}, nil} {
				rules := &v1.PolicyRules{Rules: append(append([]*v1.PolicyRule{}, policy.Msg.Policy.Rules.Rules...), &v1.PolicyRule{Name: "unsupported-deny", Roles: []string{"admin"}, Operations: []string{"execute_action"}, Actions: []string{a.Name}, HostLabels: labels, Effect: v1.PolicyEffect_POLICY_EFFECT_DENY})}
				encoded, err := json.Marshal(rules)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.db.Pool.Exec(ctx, `INSERT INTO policy_versions(version,rules,created_by) VALUES ($1,$2,'fixture')`, i+2, encoded); err != nil {
					t.Fatal(err)
				}
				want := unsupported
				if labels == nil {
					want = hidden
				}
				checkCall(admin, a.Name, want)
			}
			f.jobs.mu.Lock()
			after := f.jobs.sequence
			f.jobs.mu.Unlock()
			if after != before {
				t.Errorf("unsupported calls dispatched jobs: before=%d after=%d", before, after)
			}
			if result, err := admin.CallTool(ctx, &sdk.CallToolParams{Name: "logs_read", Arguments: actionArgs()}); err != nil || result.IsError {
				t.Error("normal tool failed after unsupported publication")
			}
		})
	}
}
