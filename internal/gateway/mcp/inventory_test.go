package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/jsonschema-go/jsonschema"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
	"github.com/liubing0806/allowops/plugin/inventory"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
)

type inventoryStub struct {
	sources  []string
	entities []pluginhost.Result
	errors   []pluginhost.SourceError
	called   bool
	query    pluginhost.Query
	selected []string
}

func (i *inventoryStub) InventorySources() []string { return i.sources }
func (i *inventoryStub) SearchInventory(ctx context.Context, q pluginhost.Query, sources []string) ([]pluginhost.Result, []pluginhost.SourceError) {
	i.called = true
	i.query = q
	i.selected = sources
	return i.entities, i.errors
}

type inventoryIdentity struct {
	Identity
	visible         map[string]bool
	denied          bool
	visibilityError error
	required        bool
}

func (i *inventoryIdentity) Require(ctx context.Context, op authz.Operation, a authz.Action, h authz.Host) (authz.Result, error) {
	if op != authz.ViewInventory || !reflect.DeepEqual(a, authz.Action{}) || !reflect.DeepEqual(h, authz.Host{}) {
		panic("wrong authorization input")
	}
	i.required = true
	if i.denied {
		return authz.Result{Decision: "deny"}, accessError(connect.CodePermissionDenied, "operation denied")
	}
	return authz.Result{Decision: "allow"}, nil
}
func (i *inventoryIdentity) VisibleHostnames(context.Context, []string) (map[string]bool, error) {
	return i.visible, i.visibilityError
}

func TestInventoryToolSchema(t *testing.T) {
	tools := fixedTools(job.DefaultConfig(), "static", "labels")
	if len(tools) != 5 {
		t.Fatal(tools)
	}
	tool := tools[4]
	if tool.Name != "entities_search" || !tool.Annotations.ReadOnlyHint || !strings.HasSuffix(tool.Description, toolInstructions) {
		t.Fatal(tool)
	}
	raw := mustJSON(t, tool.InputSchema)
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []any{map[string]any{}, map[string]any{"kind": "", "name": "API", "sources": []any{"static"}, "limit": float64(1)}} {
		if err := resolved.Validate(input); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []any{map[string]any{"unknown": true}, map[string]any{"sources": []any{"missing"}}, map[string]any{"limit": float64(0)}} {
		if err := resolved.Validate(input); err == nil {
			t.Fatalf("schema accepted %v", input)
		}
	}
}

func TestInventoryArgumentErrorsAndPermission(t *testing.T) {
	for _, input := range []string{`[]`, `{"extra":1}`, `{"kind":1}`, `{"name":null}`, `{"sources":"static"}`, `{"sources":[1]}`, `{"sources":[null]}`, `{"sources":["missing"]}`, `{"limit":0}`, `{"limit":101}`, `{"limit":1.5}`, `{"limit":null}`} {
		t.Run(input, func(t *testing.T) {
			source := &inventoryStub{sources: []string{"static"}}
			id := &inventoryIdentity{}
			s := &Service{identity: id, config: Config{Inventory: source}}
			_, err := s.searchEntities(context.Background(), json.RawMessage(input))
			if connect.CodeOf(err) != connect.CodeInvalidArgument || id.required || source.called {
				t.Fatalf("error=%v required=%v called=%v", err, id.required, source.called)
			}
			if strings.Contains(input, "sources") && !strings.Contains(err.Error(), "static") {
				t.Fatal(err)
			}
		})
	}
	source := &inventoryStub{sources: []string{"static"}}
	id := &inventoryIdentity{denied: true}
	s := &Service{identity: id, config: Config{Inventory: source}}
	_, err := s.execute(context.Background(), &sdk.CallToolRequest{Params: &sdk.CallToolParamsRaw{Name: "entities_search", Arguments: json.RawMessage(`{}`)}}, map[string]bool{"entities_search": true}, &callState{})
	if connect.CodeOf(err) != connect.CodePermissionDenied || source.called {
		t.Fatalf("error=%v called=%v", err, source.called)
	}
}

func TestInventoryVisibilityBeforeLimitAndHostCount(t *testing.T) {
	source := &inventoryStub{sources: []string{"static"}, entities: []pluginhost.Result{
		{Entity: inventory.Entity{Kind: "service", Name: "a-private", Hosts: []string{"private"}, Selector: "service=secret"}, Source: "static"},
		{Entity: inventory.Entity{Kind: "service", Name: "b-visible", Hosts: []string{"public", "private"}}, Source: "static"},
		{Entity: inventory.Entity{Kind: "service", Name: "c-configured", Selector: "service=configured"}, Source: "static"},
	}}
	s := &Service{identity: &inventoryIdentity{visible: map[string]bool{"public": true}}, config: Config{Inventory: source}}
	result, err := s.searchEntities(context.Background(), json.RawMessage(`{"kind":"service","name":"test","sources":["static"],"limit":1}`))
	if err != nil {
		t.Fatal(err)
	}
	out := result.StructuredContent.(inventoryResult)
	if len(out.Entities) != 1 || out.Entities[0].Name != "b-visible" || !out.Truncated || out.Entities[0].HostCount != 1 || !reflect.DeepEqual(out.Entities[0].Hosts, []string{"public"}) || source.query != (pluginhost.Query{Kind: "service", Name: "test"}) || !reflect.DeepEqual(source.selected, []string{"static"}) {
		t.Fatalf("output=%+v source=%+v", out, source)
	}
	result, err = s.searchEntities(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	out = result.StructuredContent.(inventoryResult)
	if len(out.Entities) != 2 || out.Truncated || out.Entities[1].Name != "c-configured" {
		t.Fatalf("configured entity=%+v", out)
	}
	// Neither filtering nor truncation modifies the plugin's result.
	if len(source.entities[1].Hosts) != 2 {
		t.Fatal(source.entities)
	}
	source.entities = source.entities[:1]
	result, err = s.searchEntities(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out = result.StructuredContent.(inventoryResult)
	if len(out.Entities) != 0 || out.Truncated {
		t.Fatalf("private derived entity leaked: %+v", out)
	}
	hosts := []string{}
	visible := map[string]bool{}
	for n := range 25 {
		name := fmt.Sprintf("h-%02d", n)
		hosts = append(hosts, name)
		visible[name] = true
	}
	source.entities = []pluginhost.Result{{Entity: inventory.Entity{Kind: "service", Name: "many", Hosts: hosts}, Source: "static"}}
	s.identity = &inventoryIdentity{visible: visible}
	result, err = s.searchEntities(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out = result.StructuredContent.(inventoryResult)
	if out.Entities[0].HostCount != 25 || len(out.Entities[0].Hosts) != 20 {
		t.Fatal(out)
	}
}

func TestInventoryCompleteResultByteLimit(t *testing.T) {
	source := &inventoryStub{sources: []string{"static"}}
	for n := range 32 {
		source.errors = append(source.errors, pluginhost.SourceError{Source: "source-" + fmt.Sprintf("%057d", n), Reason: "timeout"})
	}
	s := &Service{identity: &inventoryIdentity{}, config: Config{Inventory: source}}
	check := func() inventoryResult {
		t.Helper()
		result, err := s.searchEntities(context.Background(), json.RawMessage(`{"limit":100}`))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(result)
		if err != nil || len(raw) > resultByteLimit {
			t.Fatalf("complete result size=%d error=%v", len(raw), err)
		}
		out := result.StructuredContent.(inventoryResult)
		if out.OutputTrust != "untrusted" || len(out.SourceErrors) != 32 {
			t.Fatal(out)
		}
		return out
	}
	out := check()
	if len(out.Entities) != 0 || out.Truncated {
		t.Fatal(out)
	}
	// Quote-heavy attributes make the embedded text copy substantially larger.
	for n := range 100 {
		source.entities = append(source.entities, pluginhost.Result{Entity: inventory.Entity{Kind: "service", Name: fmt.Sprint(n), Attrs: map[string]string{"data": strings.Repeat(`"<`, 150)}}, Source: "static"})
	}
	out = check()
	if len(out.Entities) == 0 || len(out.Entities) >= 100 || !out.Truncated {
		t.Fatal(out)
	}
	oneMore := out
	oneMore.Entities = append(oneMore.Entities, inventoryEntity{Kind: "service", Name: fmt.Sprint(len(out.Entities)), Attrs: source.entities[len(out.Entities)].Attrs, Source: "static"})
	_, size, _ := toolResult(oneMore)
	if size <= resultByteLimit {
		t.Fatalf("binary search left room for another entity: size=%d", size)
	}
	source.entities = source.entities[:1]
	source.entities[0].Attrs["data"] = strings.Repeat("x", resultByteLimit)
	out = check()
	if len(out.Entities) != 0 || !out.Truncated {
		t.Fatal(out)
	}
}

func TestInventoryEmptyAndSourceFailures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		entities []pluginhost.Result
		errors   []pluginhost.SourceError
	}{
		{name: "empty"},
		{name: "partial", entities: []pluginhost.Result{{Entity: inventory.Entity{Kind: "service", Name: "ok"}, Source: "ok"}}, errors: []pluginhost.SourceError{{Source: "failed", Reason: "failed"}}},
		{name: "all failed", errors: []pluginhost.SourceError{{Source: "failed", Reason: "failed"}, {Source: "panic", Reason: "panic"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &inventoryStub{sources: []string{"ok"}, entities: tc.entities, errors: tc.errors}
			s := &Service{identity: &inventoryIdentity{}, config: Config{Inventory: source}}
			result, err := s.searchEntities(context.Background(), nil)
			if err != nil || result.IsError {
				t.Fatalf("result=%v error=%v", result, err)
			}
			out := result.StructuredContent.(inventoryResult)
			if len(out.Entities) != len(tc.entities) || len(out.SourceErrors) != len(tc.errors) || out.Truncated {
				t.Fatal(out)
			}
			text := result.Content[0].Text
			if strings.Contains(text, `"entities":null`) || strings.Contains(text, `"source_errors":null`) {
				t.Fatal(text)
			}
		})
	}
}

func inventorySession(t *testing.T, f *transportFixture, identity *api.Service, source Inventory) *sdk.ClientSession {
	t.Helper()
	service, err := New(identity, f.catalogs, nil, Config{Inventory: source})
	if err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewTLSServer(service.Handler())
	t.Cleanup(gateway.Close)
	client := sdk.NewClient(&sdk.Implementation{Name: "inventory-test", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), &sdk.StreamableClientTransport{Endpoint: gateway.URL + "/mcp", HTTPClient: &http.Client{Transport: &bearerTransport{base: gateway.Client().Transport, token: f.viewer}}, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

func TestInventorySDKVisibilityAuditAndExistingPolicy(t *testing.T) {
	f := newTransportFixture(t)
	source := &inventoryStub{sources: []string{"static"}, errors: []pluginhost.SourceError{{Source: "static", Reason: "failed"}}}
	session := inventorySession(t, f, f.identity, source)
	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range tools.Tools {
		if tool.Name == "entities_search" {
			found = true
		}
	}
	if !found {
		t.Fatal("inventory tool missing for viewer")
	}
	result := call(t, session, "entities_search", map[string]any{})
	if result.IsError || len(content(t, result)["source_errors"].([]any)) != 1 {
		t.Fatal(result)
	}
	events := f.audit.snapshot()
	event := events[len(events)-1]
	if event.Operation != "mcp/entities_search" || event.Outcome != "allow" {
		t.Fatal(event)
	}
	var raw []byte
	if err := f.db.Pool.QueryRow(context.Background(), `SELECT rules FROM policy_versions WHERE version=1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var policy v1.PolicyRules
	if err := protojson.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	for _, r := range policy.Rules {
		ops := []string{}
		for _, op := range r.Operations {
			if op != "view_inventory" {
				ops = append(ops, op)
			}
		}
		r.Operations = ops
	}
	raw, err = protojson.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(context.Background(), `UPDATE policy_versions SET rules=$1 WHERE version=1`, raw); err != nil {
		t.Fatal(err)
	}
	restarted, err := api.New(context.Background(), f.db, f.identity.Config, f.audit)
	if err != nil {
		t.Fatal(err)
	}
	session = inventorySession(t, f, restarted, &inventoryStub{sources: []string{"static"}})
	result = call(t, session, "entities_search", map[string]any{})
	data := content(t, result)
	if !result.IsError || data["error"] != "operation denied" {
		t.Fatalf("existing-policy viewer result=%v", data)
	}
	events = f.audit.snapshot()
	event = events[len(events)-1]
	if event.Operation != "mcp/entities_search" || event.Outcome != "deny" {
		t.Fatal(event)
	}
}
