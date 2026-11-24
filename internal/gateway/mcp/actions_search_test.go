package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type testRequest struct{ id *reqctx.Identity }

func (r testRequest) Identity() *reqctx.Identity { return r.id }
func (r testRequest) SourceIP() string           { return "" }
func (r testRequest) PolicyVersion() uint64      { return 0 }
func (r testRequest) MatchedRules() []string     { return nil }
func (r testRequest) Fork() reqctx.Request       { return r }

func callerContext(id string, roles ...string) context.Context {
	return reqctx.With(context.Background(), testRequest{&reqctx.Identity{Subject: authz.Subject{ID: id, Kind: "service_account", Roles: roles}}})
}

// hostIdentity answers AllowedActionsOnHost from a fixed table.
type hostIdentity struct {
	Identity
	allowed    map[string]map[string]bool
	hostname   string
	candidates []authz.Action
}

func (h *hostIdentity) AllowedActionsOnHost(_ context.Context, hostname string, actions []authz.Action) (map[string]bool, error) {
	h.hostname, h.candidates = hostname, actions
	out := map[string]bool{}
	for _, a := range actions {
		if h.allowed[hostname][a.Name] {
			out[a.Name] = true
		}
	}
	return out, nil
}

func searchScope(t *testing.T, actions ...catalog.Action) *serverScope {
	t.Helper()
	scope := &serverScope{tools: map[string]bool{}, allAvailable: map[string]catalog.Action{}, visible: map[string]catalog.Action{}, unsupported: map[string]bool{}, flatDefs: map[string]ToolDefinition{}, mode: modeProgressive, versions: "v1"}
	for _, a := range actions {
		tool, err := actionTool(a, job.DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		scope.allAvailable[a.Name], scope.visible[a.Name], scope.flatDefs[a.Name] = a, a, *tool
	}
	return scope
}

func searchActionsFor(t *testing.T, s *Service, ctx context.Context, scope *serverScope, args string) (actionsSearchResult, error) {
	t.Helper()
	result, err := s.searchActions(ctx, json.RawMessage(args), scope)
	if err != nil {
		return actionsSearchResult{}, err
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > resultByteLimit {
		t.Fatalf("result has %d bytes", len(data))
	}
	return result.StructuredContent.(actionsSearchResult), nil
}

func entryNames(out actionsSearchResult) []string {
	names := []string{}
	for _, a := range out.Actions {
		names = append(names, a.Name)
	}
	return names
}

func searchCatalog() []catalog.Action {
	var out []catalog.Action
	for _, a := range progressiveActions() {
		out = append(out, a)
	}
	return out
}

func TestActionsSearchOrderFiltersAndMetadata(t *testing.T) {
	s := &Service{identity: &hostIdentity{}}
	ctx := callerContext("alice", "ops")
	scope := searchScope(t, searchCatalog()...)
	out, err := searchActionsFor(t, s, ctx, scope, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(entryNames(out), []string{"disk_usage", "logs_read", "svc_restart", "data_purge"}) || out.Total != 4 || out.NextCursor != "" || out.Truncated || out.OutputTrust != "untrusted" {
		t.Fatalf("result=%+v", out)
	}
	if !slices.Equal(out.Toolsets, []toolsetCount{{"logs", 1}, {"system", 2}}) {
		t.Fatalf("toolsets=%v", out.Toolsets)
	}
	logs := out.Actions[1]
	if logs.InvokeTool != "actions_invoke_read" || !logs.Idempotent || logs.Toolset != "logs" || !slices.Equal(logs.Tags, []string{"app"}) || !slices.Equal(logs.EntityKinds, []string{"service"}) || !slices.Equal(logs.RequiredParams, []string{"mode"}) || !slices.Equal(logs.OptionalParams, []string{"lines", "reason"}) || len(logs.Filters) != 5 || logs.InputSchema != nil {
		t.Fatalf("logs entry=%+v", logs)
	}
	purge := out.Actions[3]
	if purge.InvokeTool != "actions_invoke_dangerous" || purge.Toolset != "" || len(purge.RequiredParams) != 0 || len(purge.OptionalParams) != 0 || purge.Filters != nil {
		t.Fatalf("purge entry=%+v", purge)
	}
	raw, err := json.Marshal(purge)
	if err != nil {
		t.Fatal(err)
	}
	for _, omitted := range []string{"toolset", "tags", "max_targets", "filters", "required_params", "optional_params", "input_schema"} {
		if strings.Contains(string(raw), `"`+omitted+`"`) {
			t.Fatalf("%s not omitted: %s", omitted, raw)
		}
	}
	for args, want := range map[string][]string{
		`{"query":"SERVICE unit"}`:                      {"svc_restart"},
		`{"query":"app"}`:                               {"logs_read"},
		`{"query":"service"}`:                           {"logs_read", "svc_restart"},
		`{"query":"service restart"}`:                   {"svc_restart"},
		`{"query":"nothing matches"}`:                   {},
		`{"names":["data_purge","logs_read","absent"]}`: {"logs_read", "data_purge"},
		`{"toolset":"system"}`:                          {"disk_usage", "svc_restart"},
		`{"tag":"disk"}`:                                {"disk_usage"},
		`{"entity_kind":"service"}`:                     {"logs_read", "svc_restart"},
		`{"risk":"write"}`:                              {"svc_restart"},
		`{"toolset":"system","risk":"read"}`:            {"disk_usage"},
	} {
		out, err := searchActionsFor(t, s, ctx, scope, args)
		if err != nil || !slices.Equal(entryNames(out), want) || out.Total != len(want) {
			t.Fatalf("%s names=%v error=%v want=%v", args, entryNames(out), err, want)
		}
	}
	out, err = searchActionsFor(t, s, ctx, scope, `{"names":["logs_read"],"include_schema":true}`)
	if err != nil {
		t.Fatal(err)
	}
	schema := out.Actions[0].InputSchema
	params, _ := schema.Params.(map[string]any)
	if schema == nil || params["type"] != "object" || params["properties"].(map[string]any)["mode"] == nil || schema.EffectiveBatchSize != job.DefaultConfig().BatchSize || schema.EffectiveMaxFailures != job.DefaultConfig().MaxFailures || schema.MaxTargets != nil || len(schema.AllowedFilters) != 5 {
		t.Fatalf("schema=%+v", schema)
	}
	// Only annotated toolsets are counted, and toolsets is omitted without any.
	out, err = searchActionsFor(t, s, ctx, scope, `{"risk":"dangerous"}`)
	if err != nil || out.Toolsets != nil {
		t.Fatalf("toolsets=%v error=%v", out.Toolsets, err)
	}
}

func TestActionsSearchHostname(t *testing.T) {
	id := &hostIdentity{allowed: map[string]map[string]bool{"web-01": {"logs_read": true, "svc_restart": true, "not_candidate": true}}}
	s := &Service{identity: id}
	ctx := callerContext("alice", "ops")
	scope := searchScope(t, searchCatalog()...)
	out, err := searchActionsFor(t, s, ctx, scope, `{"hostname":"web-01","risk":"read"}`)
	if err != nil || !slices.Equal(entryNames(out), []string{"logs_read"}) || id.hostname != "web-01" || !slices.Equal(id.candidates, []authz.Action{{Name: "disk_usage", Risk: "read"}, {Name: "logs_read", Risk: "read"}}) {
		t.Fatalf("names=%v error=%v candidates=%v", entryNames(out), err, id.candidates)
	}
	out, err = searchActionsFor(t, s, ctx, scope, `{"hostname":"web-01"}`)
	if err != nil || !slices.Equal(entryNames(out), []string{"logs_read", "svc_restart"}) || out.Total != 2 {
		t.Fatalf("names=%v error=%v", entryNames(out), err)
	}
	empty, err := searchActionsFor(t, s, ctx, scope, `{"hostname":"missing"}`)
	if err != nil || len(empty.Actions) != 0 || empty.Total != 0 || empty.Toolsets != nil {
		t.Fatalf("missing host=%+v error=%v", empty, err)
	}
	// No candidates: no precheck call.
	id.hostname = ""
	if _, err := searchActionsFor(t, s, ctx, scope, `{"hostname":"web-01","names":["absent"]}`); err != nil || id.hostname != "" {
		t.Fatalf("precheck without candidates host=%q error=%v", id.hostname, err)
	}
}

func TestActionsSearchPaginationAndCursorBinding(t *testing.T) {
	s := &Service{identity: &hostIdentity{}}
	ctx := callerContext("alice", "ops")
	scope := searchScope(t, searchCatalog()...)
	var names []string
	args := `{"limit":3}`
	first, err := searchActionsFor(t, s, ctx, scope, args)
	if err != nil || len(first.Actions) != 3 || first.NextCursor == "" || first.Toolsets == nil || first.Total != 4 || first.Truncated {
		t.Fatalf("first=%+v error=%v", first, err)
	}
	names = append(names, entryNames(first)...)
	second, err := searchActionsFor(t, s, ctx, scope, fmt.Sprintf(`{"limit":3,"next_cursor":%q}`, first.NextCursor))
	if err != nil || len(second.Actions) != 1 || second.NextCursor != "" || second.Toolsets != nil || second.Total != 4 {
		t.Fatalf("second=%+v error=%v", second, err)
	}
	names = append(names, entryNames(second)...)
	if !slices.Equal(names, []string{"disk_usage", "logs_read", "svc_restart", "data_purge"}) {
		t.Fatalf("pages=%v", names)
	}
	invalid := func(name string, ctx context.Context, scope *serverScope, args string) {
		t.Helper()
		_, err := s.searchActions(ctx, json.RawMessage(args), scope)
		if connect.CodeOf(err) != connect.CodeInvalidArgument || err.(*connect.Error).Message() != invalidActionsCursor {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	cursor := first.NextCursor
	invalid("changed limit", ctx, scope, fmt.Sprintf(`{"limit":2,"next_cursor":%q}`, cursor))
	invalid("changed filter", ctx, scope, fmt.Sprintf(`{"limit":3,"risk":"read","next_cursor":%q}`, cursor))
	invalid("changed hostname", ctx, scope, fmt.Sprintf(`{"limit":3,"hostname":"web-01","next_cursor":%q}`, cursor))
	invalid("changed schema option", ctx, scope, fmt.Sprintf(`{"limit":3,"include_schema":true,"next_cursor":%q}`, cursor))
	invalid("other identity", callerContext("bob", "ops"), scope, fmt.Sprintf(`{"limit":3,"next_cursor":%q}`, cursor))
	invalid("changed roles", callerContext("alice", "ops", "admin"), scope, fmt.Sprintf(`{"limit":3,"next_cursor":%q}`, cursor))
	for name, change := range map[string]func(*serverScope){
		"versions": func(c *serverScope) { c.versions = "v2" },
		"mode":     func(c *serverScope) { c.mode = modeFlat },
		"toolsets": func(c *serverScope) { c.toolsets = []string{"system"} },
	} {
		changed := *scope
		change(&changed)
		invalid(name, ctx, &changed, fmt.Sprintf(`{"limit":3,"next_cursor":%q}`, cursor))
	}
	var decoded actionsCursor
	data, _ := base64.RawURLEncoding.DecodeString(cursor)
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	snapshot, err := actionsSnapshot(ctx, scope, actionsQuery{Limit: 3}, matchActions(actionsQuery{Limit: 3}, scope.visible))
	if err != nil {
		t.Fatal(err)
	}
	tamperedOffset, _ := json.Marshal(actionsCursor{Offset: 1, Tag: decoded.Tag})
	nonStrict := cursor
	if last := nonStrict[len(nonStrict)-1]; last == 'A' {
		nonStrict = nonStrict[:len(nonStrict)-1] + "B"
	} else {
		// Force non-zero trailing unused bits on a 2-char remainder payload.
		nonStrict = base64.RawURLEncoding.EncodeToString(data)
		for _, ch := range []byte{'B', 'C', 'D'} {
			cand := nonStrict[:len(nonStrict)-1] + string(ch)
			if cand != nonStrict {
				nonStrict = cand
				break
			}
		}
	}
	for name, forged := range map[string]string{
		"tampered offset": base64.RawURLEncoding.EncodeToString(tamperedOffset),
		"offset zero":     encodeActionsCursor(snapshot, 0),
		"offset beyond":   encodeActionsCursor(snapshot, 4),
		"not base64":      "%%%",
		"non-strict b64":  nonStrict,
		"unknown field":   base64.RawURLEncoding.EncodeToString([]byte(`{"offset":3,"tag":"` + decoded.Tag + `","x":1}`)),
		"duplicate key":   base64.RawURLEncoding.EncodeToString([]byte(`{"offset":1,"offset":3,"tag":"` + decoded.Tag + `"}`)),
		"trailing value":  base64.RawURLEncoding.EncodeToString([]byte(`{"offset":3,"tag":"` + decoded.Tag + `"} {}`)),
		"too long":        cursor + strings.Repeat("A", 257),
	} {
		invalid(name, ctx, scope, fmt.Sprintf(`{"limit":3,"next_cursor":%q}`, forged))
	}
	if len(cursor) > 256 {
		t.Fatalf("cursor has %d bytes", len(cursor))
	}
	// Host precheck drift (e.g. host authorization labels changed between pages
	// without changing catalog or policy versions) invalidates the cursor.
	hostID := &hostIdentity{allowed: map[string]map[string]bool{"web-01": {"disk_usage": true, "logs_read": true, "svc_restart": true}}}
	hs := &Service{identity: hostID}
	page1, err := searchActionsFor(t, hs, ctx, scope, `{"hostname":"web-01","limit":2}`)
	if err != nil || page1.NextCursor == "" {
		t.Fatalf("host page1=%+v err=%v", page1, err)
	}
	hostID.allowed["web-01"]["data_purge"] = true
	if _, err := hs.searchActions(ctx, json.RawMessage(fmt.Sprintf(`{"hostname":"web-01","limit":2,"next_cursor":%q}`, page1.NextCursor)), scope); connect.CodeOf(err) != connect.CodeInvalidArgument || err.(*connect.Error).Message() != invalidActionsCursor {
		t.Fatalf("host precheck drift error=%v", err)
	}
}

func TestActionsSearchArguments(t *testing.T) {
	id := &hostIdentity{}
	s := &Service{identity: id}
	ctx := callerContext("alice", "ops")
	scope := searchScope(t, searchCatalog()...)
	names := make([]string, 21)
	for i := range names {
		names[i] = fmt.Sprintf("a%d", i)
	}
	namesJSON, _ := json.Marshal(names)
	for _, args := range []string{
		`[]`, `{"query":"a","query":"b"}`, `{"unknown":1}`,
		`{"query":null}`, `{"query":""}`, `{"query":"   "}`, `{"query":1}`, fmt.Sprintf(`{"query":%q}`, strings.Repeat("é", 201)),
		`{"names":null}`, `{"names":[]}`, `{"names":"logs_read"}`, `{"names":["Logs"]}`, `{"names":["logs_read","logs_read"]}`, `{"names":[null]}`, `{"names":` + string(namesJSON) + `}`,
		`{"toolset":""}`, `{"toolset":"Sys"}`, `{"toolset":null}`, `{"tag":"a-b"}`, `{"entity_kind":"1kind"}`, `{"entity_kind":"` + strings.Repeat("k", 33) + `"}`,
		`{"risk":"admin"}`, `{"risk":""}`, `{"risk":null}`,
		`{"hostname":""}`, `{"hostname":" "}`, `{"hostname":"web\n01"}`, `{"hostname":null}`,
		`{"include_schema":"true"}`, `{"include_schema":null}`,
		`{"limit":0}`, `{"limit":51}`, `{"limit":1.5}`, `{"limit":"2"}`, `{"limit":null}`,
		`{"next_cursor":""}`, `{"next_cursor":null}`, `{"next_cursor":1}`,
	} {
		_, err := s.searchActions(ctx, json.RawMessage(args), scope)
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("%s error=%v", args, err)
		}
	}
	if id.hostname != "" {
		t.Fatal("invalid arguments reached the host precheck")
	}
	for _, args := range []string{``, `{}`, fmt.Sprintf(`{"query":%q}`, strings.Repeat("é", 200)), `{"limit":50,"include_schema":false}`, `{"names":["a0","a1"]}`} {
		if _, err := s.searchActions(ctx, json.RawMessage(args), scope); err != nil {
			t.Fatalf("%s error=%v", args, err)
		}
	}
}

func TestActionsSearchResultBudget(t *testing.T) {
	s := &Service{identity: &hostIdentity{}}
	ctx := callerContext("alice", "ops")
	action := func(name, description, toolset string) catalog.Action {
		return catalog.Action{Name: name, Description: description, Risk: "read", Toolset: toolset, Timeout: "1s", MaxOutput: 1024, Exec: []any{"/usr/bin/true"}}
	}
	// Quote escaping doubles in the text copy; ten entries cannot share one page.
	var large []catalog.Action
	for i := range 10 {
		large = append(large, action(fmt.Sprintf("big_%02d", i), strings.Repeat(`"`, 3000), "big"))
	}
	scope := searchScope(t, large...)
	var names []string
	cursor := ""
	pages := 0
	for {
		args := `{"limit":50}`
		if cursor != "" {
			args = fmt.Sprintf(`{"limit":50,"next_cursor":%q}`, cursor)
		}
		out, err := searchActionsFor(t, s, ctx, scope, args)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Actions) == 0 || (out.NextCursor != "") != out.Truncated {
			t.Fatalf("page=%d actions=%d truncated=%v cursor=%q", pages, len(out.Actions), out.Truncated, out.NextCursor)
		}
		names = append(names, entryNames(out)...)
		pages++
		if cursor = out.NextCursor; cursor == "" {
			break
		}
	}
	if pages < 2 || len(names) != 10 || !slices.IsSorted(names) || len(slices.Compact(slices.Clone(names))) != 10 {
		t.Fatalf("pages=%d names=%v", pages, names)
	}
	// One entry fits only without the toolset counts.
	var toolsets []catalog.Action
	for i := range 400 {
		toolsets = append(toolsets, action(fmt.Sprintf("set_%03d", i), "x", fmt.Sprintf("toolset_%03d_padding_name", i)))
	}
	toolsets[0].Description = strings.Repeat("d", 9000)
	scope = searchScope(t, toolsets...)
	out, err := searchActionsFor(t, s, ctx, scope, `{"limit":1}`)
	if err != nil || len(out.Actions) != 1 || out.Toolsets != nil || !out.Truncated || out.NextCursor == "" {
		t.Fatalf("toolsets dropped=%v actions=%d truncated=%v error=%v", out.Toolsets != nil, len(out.Actions), out.Truncated, err)
	}
	// One entry over the budget on its own is refused, with or without schema.
	scope = searchScope(t, action("aaa_huge", strings.Repeat(`"`, 9000), "big"), action("zzz_small", "small", ""))
	for _, args := range []string{`{}`, `{"include_schema":true}`} {
		_, err := s.searchActions(ctx, json.RawMessage(args), scope)
		if connect.CodeOf(err) != connect.CodeResourceExhausted || err.(*connect.Error).Message() != "action entry exceeds 32KB result limit" {
			t.Fatalf("%s error=%v", args, err)
		}
		if message := content(t, toolError(err, &callState{}))["error"]; message != "action entry exceeds 32KB result limit" {
			t.Fatalf("tool error=%v", message)
		}
	}
}

func TestActionsSearchTransport(t *testing.T) {
	f := newProgressiveFixture(t, func(c *Config) { c.Mode = modeProgressive })
	if _, err := f.db.Pool.Exec(context.Background(), `INSERT INTO hosts(host_id,hostname,authorization_labels,certificate_serial,certificate_expires_at) VALUES ('bare-01','bare-01','{}','fixture',now()+interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	admin := f.headerClient(t, f.admin, nil)
	reader := f.headerClient(t, f.reader, nil)
	names := func(c any) []string {
		out := []string{}
		for _, a := range c.(map[string]any)["actions"].([]any) {
			out = append(out, a.(map[string]any)["name"].(string))
		}
		return out
	}
	before := len(f.audit.snapshot())
	r := call(t, admin, "actions_search", map[string]any{})
	if data := content(t, r); r.IsError || !slices.Equal(names(data), []string{"disk_usage", "logs_read", "svc_restart", "data_purge"}) || data["output_trust"] != "untrusted" {
		t.Fatalf("admin=%v", data)
	}
	if events := f.resultEvents(before); len(events) != 1 || events[0].Operation != "mcp/actions_search" || events[0].Outcome != "allow" {
		t.Fatalf("audit=%+v", events)
	}
	for _, tc := range []struct {
		client *sdk.ClientSession
		host   string
		want   []string
	}{
		{reader, "web-01", []string{"disk_usage", "logs_read"}},
		{admin, "web-01", []string{"disk_usage", "logs_read", "svc_restart", "data_purge"}},
		{admin, "bare-01", []string{}},
		{admin, "missing-01", []string{}},
	} {
		r := call(t, tc.client, "actions_search", map[string]any{"hostname": tc.host})
		if data := content(t, r); r.IsError || !slices.Equal(names(data), tc.want) {
			t.Fatalf("%s=%v", tc.host, data)
		}
	}
	scoped := f.headerClient(t, f.admin, map[string]string{"X-Allowops-Toolsets": "system"})
	if data := content(t, call(t, scoped, "actions_search", map[string]any{})); !slices.Equal(names(data), []string{"disk_usage", "svc_restart"}) {
		t.Fatalf("scoped=%v", data)
	}
	before = len(f.audit.snapshot())
	if r := call(t, admin, "actions_search", map[string]any{"limit": 0}); !r.IsError {
		t.Fatal("invalid limit accepted")
	}
	if events := f.resultEvents(before); len(events) != 1 || events[0].Operation != "mcp/actions_search" || events[0].Outcome != "deny" {
		t.Fatalf("audit=%+v", events)
	}
}
