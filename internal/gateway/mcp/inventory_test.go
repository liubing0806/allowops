package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/plugin/inventory"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/yaml.v3"
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
	auditError      error
	auditEvents     []reqctx.AuditEvent
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

func (i *inventoryIdentity) AppendResultAudit(_ context.Context, event reqctx.AuditEvent) error {
	if !i.required {
		panic("audit before authorization")
	}
	i.auditEvents = append(i.auditEvents, event)
	return i.auditError
}

func TestInventoryToolSchema(t *testing.T) {
	tools := fixedTools(job.DefaultConfig(), "static", "labels")
	if len(tools) != 6 {
		t.Fatal(tools)
	}
	tool := tools[5]
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
			if connect.CodeOf(err) != connect.CodeInvalidArgument || id.required || source.called || len(id.auditEvents) != 0 {
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
	if connect.CodeOf(err) != connect.CodePermissionDenied || source.called || len(id.auditEvents) != 0 {
		t.Fatalf("error=%v called=%v", err, source.called)
	}
}

func TestInventoryAuthorizationAuditFailureSkipsSearch(t *testing.T) {
	source := &inventoryStub{sources: []string{"static"}}
	id := &inventoryIdentity{auditError: errors.New("audit backend details")}
	s := &Service{identity: id, config: Config{Inventory: source}}
	result, err := s.searchEntities(t.Context(), nil)
	if result != nil || connect.CodeOf(err) != connect.CodeUnavailable || strings.Contains(err.Error(), "audit backend details") || source.called {
		t.Fatalf("result=%v error=%v called=%v", result, err, source.called)
	}
	want := []reqctx.AuditEvent{{Operation: "mcp/entities_search", Phase: "authorized", Outcome: "allow"}}
	if !reflect.DeepEqual(id.auditEvents, want) {
		t.Fatalf("events=%+v, want=%+v", id.auditEvents, want)
	}
}

func TestInventoryVisibilityBeforeLimitAndHostCount(t *testing.T) {
	source := &inventoryStub{sources: []string{"static"}, entities: []pluginhost.Result{
		{Entity: inventory.Entity{Kind: "service", Name: "a-private", Hosts: []string{"private"}, Selector: "service=secret"}, Source: "static"},
		{Entity: inventory.Entity{Kind: "service", Name: "b-visible", Hosts: []string{"public", "private"}}, Source: "static"},
		{Entity: inventory.Entity{Kind: "service", Name: "c-configured", Selector: "service=configured"}, Source: "static"},
	}}
	s := &Service{identity: &inventoryIdentity{visible: map[string]bool{"public": true}}, config: Config{Inventory: source}}
	result, err := s.searchEntities(context.Background(), json.RawMessage(`{"kind":"service","name":"i","sources":["static"],"limit":1}`))
	if err != nil {
		t.Fatal(err)
	}
	out := result.StructuredContent.(inventoryResult)
	if len(out.Entities) != 1 || out.Entities[0].Name != "b-visible" || !out.Truncated || out.Entities[0].HostCount != 1 || !reflect.DeepEqual(out.Entities[0].Hosts, []string{"public"}) || source.query != (pluginhost.Query{Kind: "service", Name: "i"}) || !reflect.DeepEqual(source.selected, []string{"static"}) {
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

func TestInventoryMergesVisibleSources(t *testing.T) {
	source := &inventoryStub{sources: []string{"a", "b", "hidden"}, entities: []pluginhost.Result{
		{Source: "b", Entity: inventory.Entity{
			Kind: "service", Name: "api", Hosts: []string{"two", "one"}, Attrs: map[string]string{"team": "platform", "env": "prod"},
			Selector: "env=prod", DependsOn: []string{"db/b", "db/a"},
		}},
		{Source: "a", Entity: inventory.Entity{
			Kind: "service", Name: "api", Hosts: []string{"one", "private"}, Attrs: map[string]string{"team": "platform", "env": "test"},
			Selector: "env=test", DependsOn: []string{"db/a"},
		}},
		{Source: "hidden", Entity: inventory.Entity{
			Kind: "service", Name: "api", Hosts: []string{"private"}, Attrs: map[string]string{"secret": "hidden-attribute"},
			Selector: "env=hidden", DependsOn: []string{"db/hidden"},
		}},
	}}
	id := &inventoryIdentity{visible: map[string]bool{"one": true, "two": true}}
	s := &Service{identity: id, config: Config{Inventory: source}}
	result, err := s.searchEntities(t.Context(), json.RawMessage(`{"name":"API"}`))
	if err != nil {
		t.Fatal(err)
	}
	out := result.StructuredContent.(inventoryResult)
	want := []inventoryEntity{{
		Kind: "service", Name: "api", Sources: []string{"a", "b"}, Hosts: []string{"one", "two"}, HostCount: 2,
		Attrs: map[string]string{"team": "platform"}, DependsOn: []string{"db/a", "db/b"},
		Conflicts:         map[string]map[string]string{"env": {"a": "test", "b": "prod"}},
		SelectorConflicts: map[string]string{"a": "env=test", "b": "env=prod"},
	}}
	if !reflect.DeepEqual(out.Entities, want) || strings.Contains(result.Content[0].Text, `"source":`) {
		t.Fatalf("entities=%+v text=%s", out.Entities, result.Content[0].Text)
	}
}

func TestInventoryPropagatesNameRedactionOnlyAcrossVisibleSources(t *testing.T) {
	const secret = "opaque-name"
	files := []struct{ id, contents string }{
		{"a", `entities:
  - kind: service
    name: opaque-name
    attrs: {password: opaque-name}
    hosts: [host-a]`},
		{"b", `entities:
  - kind: service
    name: opaque-name
    attrs: {memo: tag-opaque-name}
    hosts: [host-b]
    selector: app=opaque-name
    depends_on: [database/opaque-name]`},
	}
	var configs []pluginhost.Config
	for _, file := range files {
		path := filepath.Join(t.TempDir(), file.id+".yaml")
		if err := os.WriteFile(path, []byte(file.contents), 0600); err != nil {
			t.Fatal(err)
		}
		var config yaml.Node
		if err := config.Encode(map[string]string{"file": path}); err != nil {
			t.Fatal(err)
		}
		configs = append(configs, pluginhost.Config{ID: file.id, Module: "inventory.static", Config: config, Required: true})
	}
	host, err := pluginhost.New(t.Context(), configs, pluginhost.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(t.Context())
	id := &inventoryIdentity{visible: map[string]bool{"host-a": true, "host-b": true}}
	s := &Service{identity: id, config: Config{Inventory: host}}
	search := func(args string) (*ToolResult, []inventoryEntity) {
		t.Helper()
		result, err := s.searchEntities(t.Context(), json.RawMessage(args))
		if err != nil {
			t.Fatal(err)
		}
		return result, result.StructuredContent.(inventoryResult).Entities
	}
	result, rows := search(`{"name":"[redacted"}`)
	if len(rows) != 2 || strings.Contains(string(mustJSON(t, result)), secret) ||
		rows[0].Source != "a" || !reflect.DeepEqual(rows[0].Sources, []string{"a"}) ||
		rows[1].Source != "b" || !reflect.DeepEqual(rows[1].Sources, []string{"b"}) || rows[1].Selector != "" {
		t.Fatalf("both visible: %+v", rows)
	}
	if _, rows := search(`{"name":"OPAQUE"}`); len(rows) != 0 {
		t.Fatalf("name filter matched a redacted value: %+v", rows)
	}
	assertB := func(rows []inventoryEntity) {
		t.Helper()
		if len(rows) != 1 || rows[0].Name != secret || rows[0].Source != "b" || !reflect.DeepEqual(rows[0].Sources, []string{"b"}) ||
			rows[0].Attrs["memo"] != "tag-"+secret || rows[0].Selector != "app="+secret ||
			!reflect.DeepEqual(rows[0].DependsOn, []string{"database/" + secret}) {
			t.Fatalf("only B visible: %+v", rows)
		}
	}
	_, rows = search(`{"sources":["b"],"name":"OPAQUE"}`)
	assertB(rows)
	delete(id.visible, "host-a")
	_, rows = search(`{"name":"OPAQUE"}`)
	assertB(rows)
}

func TestInventoryDegradesConflictsBeforeAttributes(t *testing.T) {
	const oversized = resultByteLimit
	for _, clipAttributes := range []bool{false, true} {
		t.Run(fmt.Sprint(clipAttributes), func(t *testing.T) {
			note := "keep"
			if clipAttributes {
				note = strings.Repeat("<", oversized)
			}
			source := &inventoryStub{sources: []string{"a", "b"}, entities: []pluginhost.Result{
				{Source: "a", Entity: inventory.Entity{Kind: "service", Name: "api", Hosts: []string{"host-a"},
					Attrs: map[string]string{"env": strings.Repeat("a", oversized), "note": note}, Selector: "env=a", DependsOn: []string{"db/a"}}},
				{Source: "b", Entity: inventory.Entity{Kind: "service", Name: "api", Hosts: []string{"host-b"},
					Attrs: map[string]string{"env": "b"}, Selector: "env=b", DependsOn: []string{"db/b"}}},
			}}
			id := &inventoryIdentity{visible: map[string]bool{"host-a": true, "host-b": true}}
			s := &Service{identity: id, config: Config{Inventory: source}}
			result, err := s.searchEntities(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			size := len(mustJSON(t, result))
			out := result.StructuredContent.(inventoryResult)
			if size > resultByteLimit || !out.Truncated || len(out.Entities) != 1 {
				t.Fatalf("size=%d entities=%d truncated=%t", size, len(out.Entities), out.Truncated)
			}
			row := out.Entities[0]
			if row.Kind != "service" || row.Name != "api" || !reflect.DeepEqual(row.Sources, []string{"a", "b"}) ||
				!reflect.DeepEqual(row.Hosts, []string{"host-a", "host-b"}) || row.HostCount != 2 ||
				!row.ConflictsTruncated || len(row.Conflicts) != 0 || len(row.SelectorConflicts) != 0 || row.AttrsTruncated != clipAttributes {
				t.Fatalf("unexpected first row (size=%d)", size)
			}
			if clipAttributes {
				if len(row.Attrs) != 0 || len(row.DependsOn) != 0 {
					t.Fatal("attributes or dependencies exceeded the budget")
				}
			} else if row.Attrs["note"] != "keep" || !reflect.DeepEqual(row.DependsOn, []string{"db/a", "db/b"}) {
				t.Fatal("attributes or dependencies were removed while they still fit")
			}
		})
	}
}

func TestInventoryOversizedHostPreviewRetainsHostCount(t *testing.T) {
	var hosts []string
	id := &inventoryIdentity{visible: map[string]bool{}}
	for n := range 20 {
		host := fmt.Sprintf("%02d%s", n, strings.Repeat("<", 251))
		hosts = append(hosts, host)
		id.visible[host] = true
	}
	source := &inventoryStub{sources: []string{"a"}, entities: []pluginhost.Result{
		{Source: "a", Entity: inventory.Entity{Kind: "service", Name: "api", Hosts: hosts}},
	}}
	s := &Service{identity: id, config: Config{Inventory: source}}
	result, err := s.searchEntities(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := result.StructuredContent.(inventoryResult)
	if len(mustJSON(t, result)) > resultByteLimit || !out.Truncated || len(out.Entities) != 1 {
		t.Fatalf("entities=%d truncated=%t", len(out.Entities), out.Truncated)
	}
	row := out.Entities[0]
	if row.HostCount != len(hosts) || len(row.Hosts) == 0 || len(row.Hosts) >= len(hosts) || !reflect.DeepEqual(row.Hosts, hosts[:len(row.Hosts)]) {
		t.Fatalf("host_count=%d preview=%d", row.HostCount, len(row.Hosts))
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
		source.entities = append(source.entities, pluginhost.Result{Entity: inventory.Entity{Kind: "service", Name: fmt.Sprintf("%03d", n), Attrs: map[string]string{"data": strings.Repeat(`"<`, 150)}}, Source: "static"})
	}
	out = check()
	if len(out.Entities) == 0 || len(out.Entities) >= 100 || !out.Truncated {
		t.Fatal(out)
	}
	oneMore := out
	next := source.entities[len(out.Entities)]
	oneMore.Entities = append(oneMore.Entities, inventoryEntity{Kind: next.Kind, Name: next.Name, Attrs: next.Attrs, Source: "static", Sources: []string{"static"}})
	_, size, _ := toolResult(oneMore)
	if size <= resultByteLimit {
		t.Fatalf("binary search left room for another entity: size=%d", size)
	}
	source.entities = source.entities[:1]
	source.entities[0].Attrs["data"] = strings.Repeat("x", resultByteLimit)
	out = check()
	if len(out.Entities) != 1 || !out.Truncated || out.Entities[0].Name != "000" || !out.Entities[0].AttrsTruncated {
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
	authorized := events[len(events)-2]
	event := events[len(events)-1]
	if authorized.Operation != "mcp/entities_search" || authorized.Phase != "authorized" || authorized.Outcome != "allow" ||
		event.Operation != "mcp/entities_search" || event.Phase != "result" || event.Outcome != "allow" {
		t.Fatalf("authorized=%+v result=%+v", authorized, event)
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
