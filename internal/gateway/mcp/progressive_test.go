package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// progressiveActions covers every risk, annotated and unannotated toolsets,
// and entity kinds.
func progressiveActions() map[string]catalog.Action {
	logs := testAction()
	logs.Toolset, logs.Tags, logs.EntityKinds = "logs", []string{"app"}, []string{"service"}
	action := func(name, description, risk, toolset string, kinds ...string) catalog.Action {
		return catalog.Action{Name: name, Description: description, Risk: risk, Toolset: toolset, EntityKinds: kinds, Timeout: "1s", MaxOutput: 8192, Exec: []any{"/usr/bin/true"}}
	}
	disk := action("disk_usage", "Show filesystem usage", "read", "system", "host")
	disk.Tags = []string{"disk"}
	restart := action("svc_restart", "Restart a service unit", "write", "system", "service")
	restart.Params = map[string]params.Definition{"unit": {Type: params.String, Description: "Unit name", Regex: "^[a-z]+$"}}
	purge := action("data_purge", "Purge expired data", "dangerous", "", "database")
	return map[string]catalog.Action{logs.Name: logs, disk.Name: disk, restart.Name: restart, purge.Name: purge}
}

type progressiveFixture struct {
	*transportFixture
	reader string
}

// newProgressiveFixture publishes progressiveActions and adds a reader
// service account that may only execute read actions. configure runs before
// any MCP request.
func newProgressiveFixture(t *testing.T, configure func(*Config)) *progressiveFixture {
	t.Helper()
	f := &progressiveFixture{transportFixture: newTransportFixture(t)}
	if configure != nil {
		configure(&f.service.config)
	}
	f.publishActions(t, progressiveActions(), time.Second)
	f.reader = f.mint(t, "reader", "reader")
	ctx := context.Background()
	policy, err := f.identity.GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	rules := policy.Msg.Policy.Rules
	rules.Rules = append(rules.Rules,
		&v1.PolicyRule{Name: "reader-view", Roles: []string{"reader"}, Operations: []string{"view_hosts", "view_jobs", "view_output"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW},
		&v1.PolicyRule{Name: "reader-run", Roles: []string{"reader"}, Operations: []string{"execute_action"}, Risks: []string{"read"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW})
	data, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(ctx, `INSERT INTO policy_versions(version,rules,created_by) VALUES (2,$1,'fixture')`, data); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *transportFixture) publishActions(t *testing.T, actions map[string]catalog.Action, offset time.Duration) {
	t.Helper()
	p, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: "fixture"}, Actions: actions}, catalog.BuildOptions{Now: time.Now().Add(offset)})
	if err != nil {
		t.Fatal(err)
	}
	data, err := catalog.CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	env, err := catalog.Sign(data, catalog.SigningKey{PrivateKey: f.key})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.catalogs.Publish(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
}

func (f *transportFixture) mint(t *testing.T, id, role string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := f.db.Pool.Exec(ctx, `INSERT INTO service_accounts(account_id,name,owner_user_id,roles) VALUES ($1,$1,'owner',$2)`, id, []string{role}); err != nil {
		t.Fatal(err)
	}
	token, record, err := authn.GenerateServiceToken(time.Now(), 30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(ctx, `INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES ($1,$1,$2,$3)`, id, record.Hash[:], record.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	return token
}

type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for name, value := range h.headers {
		r.Header.Set(name, value)
	}
	return h.base.RoundTrip(r)
}

// headerClient connects with extra request headers on every MCP request.
func (f *transportFixture) headerClient(t *testing.T, token string, headers map[string]string) *sdk.ClientSession {
	t.Helper()
	transport := headerTransport{base: &bearerTransport{base: f.gateway.Client().Transport, token: token}, headers: headers}
	client := sdk.NewClient(&sdk.Implementation{Name: "allowops-test", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), &sdk.StreamableClientTransport{Endpoint: f.gateway.URL + "/mcp", HTTPClient: &http.Client{Transport: transport}, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func toolNames(t *testing.T, c *sdk.ClientSession) []string {
	t.Helper()
	list, err := c.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func toolList(t *testing.T, c *sdk.ClientSession) map[string]*sdk.Tool {
	t.Helper()
	list, err := c.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]*sdk.Tool{}
	for _, tool := range list.Tools {
		tools[tool.Name] = tool
	}
	return tools
}

// fixedToolNames and withFixed are sorted, as the SDK lists tools by name.
var fixedToolNames = []string{"hosts_search", "jobs_cancel", "jobs_get", "jobs_list"}

func withFixed(names ...string) []string {
	return slices.Sorted(slices.Values(append(slices.Clone(fixedToolNames), names...)))
}

func TestProgressiveToolMatrix(t *testing.T) {
	f := newProgressiveFixture(t, nil)
	progressive := map[string]string{"X-Allowops-MCP-Mode": "progressive"}
	for _, tc := range []struct {
		name    string
		token   string
		headers map[string]string
		want    []string
	}{
		{"admin default flat", f.admin, nil, withFixed("data_purge", "disk_usage", "logs_read", "svc_restart")},
		{"admin progressive", f.admin, progressive, withFixed("actions_search", "actions_invoke_read", "actions_invoke_write", "actions_invoke_dangerous")},
		{"reader progressive", f.reader, progressive, withFixed("actions_search", "actions_invoke_read")},
		{"viewer progressive", f.viewer, progressive, fixedToolNames},
		{"viewer flat", f.viewer, nil, fixedToolNames},
		{"admin system toolset progressive", f.admin, map[string]string{"X-Allowops-Toolsets": "system", "X-Allowops-MCP-Mode": " progressive "}, withFixed("actions_search", "actions_invoke_read", "actions_invoke_write")},
		{"admin toolsets flat", f.admin, map[string]string{"X-Allowops-Toolsets": " system,logs , system"}, withFixed("disk_usage", "logs_read", "svc_restart")},
		{"admin unknown toolset", f.admin, map[string]string{"X-Allowops-Toolsets": "absent", "X-Allowops-MCP-Mode": "progressive"}, fixedToolNames},
		{"reader system toolset", f.reader, map[string]string{"X-Allowops-Toolsets": "system", "X-Allowops-MCP-Mode": "progressive"}, withFixed("actions_search", "actions_invoke_read")},
		{"admin explicit flat", f.admin, map[string]string{"X-Allowops-MCP-Mode": "flat"}, withFixed("data_purge", "disk_usage", "logs_read", "svc_restart")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := toolNames(t, f.headerClient(t, tc.token, tc.headers))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("tools=%v want=%v", got, tc.want)
			}
		})
	}
	tools := toolList(t, f.headerClient(t, f.admin, progressive))
	for name, want := range map[string]struct {
		readOnly    bool
		destructive *bool
	}{"actions_search": {true, nil}, "actions_invoke_read": {true, nil}, "actions_invoke_write": {false, new(bool)}, "actions_invoke_dangerous": {false, func() *bool { b := true; return &b }()}} {
		got := tools[name].Annotations
		if got.ReadOnlyHint != want.readOnly || (got.DestructiveHint == nil) != (want.destructive == nil) || got.DestructiveHint != nil && *got.DestructiveHint != *want.destructive || got.IdempotentHint {
			t.Fatalf("%s annotations=%+v", name, got)
		}
	}
}

func TestAutoModeThreshold(t *testing.T) {
	f := newProgressiveFixture(t, func(c *Config) { c.Mode = modeAuto; c.AutoThreshold = 3 })
	if got := toolNames(t, f.headerClient(t, f.admin, nil)); !slices.Equal(got, withFixed("actions_search", "actions_invoke_read", "actions_invoke_write", "actions_invoke_dangerous")) {
		t.Fatalf("admin above threshold=%v", got)
	}
	if got := toolNames(t, f.headerClient(t, f.reader, nil)); !slices.Equal(got, withFixed("disk_usage", "logs_read")) {
		t.Fatalf("reader at or below threshold=%v", got)
	}
	// The threshold counts the actions left after toolset narrowing.
	if got := toolNames(t, f.headerClient(t, f.admin, map[string]string{"X-Allowops-Toolsets": "system,logs"})); !slices.Equal(got, withFixed("disk_usage", "logs_read", "svc_restart")) {
		t.Fatalf("admin narrowed=%v", got)
	}
	if got := toolNames(t, f.headerClient(t, f.admin, map[string]string{"X-Allowops-MCP-Mode": "flat"})); len(got) != 8 {
		t.Fatalf("header override=%v", got)
	}
}

func TestScopeHeaderValidation(t *testing.T) {
	f := newTransportFixture(t)
	post := func(headers http.Header) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, f.gateway.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header = headers.Clone()
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+f.admin)
		response, err := f.gateway.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	many := make([]string, 17)
	for i := range many {
		many[i] = fmt.Sprintf("set_%d", i)
	}
	for _, headers := range []http.Header{
		{"X-Allowops-Toolsets": {"system", "logs"}},
		{"X-Allowops-Toolsets": {""}},
		{"X-Allowops-Toolsets": {"   "}},
		{"X-Allowops-Toolsets": {","}},
		{"X-Allowops-Toolsets": {"system,,logs"}},
		{"X-Allowops-Toolsets": {"System"}},
		{"X-Allowops-Toolsets": {"1system"}},
		{"X-Allowops-Toolsets": {"sys-tem"}},
		{"X-Allowops-Toolsets": {strings.Repeat("a", 33)}},
		{"X-Allowops-Toolsets": {strings.Join(many, ",")}},
		{"X-Allowops-Mcp-Mode": {"auto"}},
		{"X-Allowops-Mcp-Mode": {""}},
		{"X-Allowops-Mcp-Mode": {"FLAT"}},
		{"X-Allowops-Mcp-Mode": {"flat", "flat"}},
	} {
		before := len(f.audit.snapshot())
		if status := post(headers); status != http.StatusBadRequest {
			t.Fatalf("headers=%v status=%d", headers, status)
		}
		events := f.audit.snapshot()[before:]
		if len(events) != 1 || events[0].Operation != "mcp/request" || events[0].Phase != "result" || events[0].Outcome != "deny" || events[0].ActorID != "admin" {
			t.Fatalf("headers=%v audit=%+v", headers, events)
		}
	}
	for _, headers := range []http.Header{
		{"X-Allowops-Toolsets": {strings.Join(many[:16], ",")}},
		{"X-Allowops-Toolsets": {" a , a,b_1 "}},
		{"X-Allowops-Mcp-Mode": {" progressive "}},
	} {
		if status := post(headers); status != http.StatusOK {
			t.Fatalf("headers=%v status=%d", headers, status)
		}
	}
	f.audit.mu.Lock()
	f.audit.fail = true
	f.audit.mu.Unlock()
	if status := post(http.Header{"X-Allowops-Mcp-Mode": {"auto"}}); status != http.StatusServiceUnavailable {
		t.Fatalf("audit failure status=%d", status)
	}
	scope, err := parseScopeHeaders(http.Header{"X-Allowops-Toolsets": {" b,a , b "}, "X-Allowops-Mcp-Mode": {"flat"}})
	if err != nil || !slices.Equal(scope.toolsets, []string{"a", "b"}) || scope.mode != "flat" {
		t.Fatalf("scope=%+v error=%v", scope, err)
	}
}

// Header combinations build servers per request: they never add LRU entries
// or reload the verified catalog.
func TestScopedServersBypassIdentityCache(t *testing.T) {
	f := newProgressiveFixture(t, nil)
	if got := toolNames(t, f.headerClient(t, f.admin, nil)); len(got) != 8 {
		t.Fatal(got)
	}
	f.service.mu.Lock()
	entries, server := f.service.lru.Len(), f.service.lru.Front().Value.(*cacheEntry).view.defaultServer
	f.service.mu.Unlock()
	f.service.catalogMu.Lock()
	snapshot := f.service.catalog
	f.service.catalogMu.Unlock()
	for i := range 20 {
		headers := map[string]string{"X-Allowops-Toolsets": fmt.Sprintf("set_%d,system", i)}
		if i%2 == 0 {
			headers["X-Allowops-MCP-Mode"] = "progressive"
		}
		toolNames(t, f.headerClient(t, f.admin, headers))
	}
	toolNames(t, f.headerClient(t, f.admin, map[string]string{"X-Allowops-MCP-Mode": "flat"}))
	f.service.mu.Lock()
	after, latest := f.service.lru.Len(), f.service.lru.Front().Value.(*cacheEntry).view.defaultServer
	f.service.mu.Unlock()
	f.service.catalogMu.Lock()
	reloaded := f.service.catalog != snapshot
	f.service.catalogMu.Unlock()
	if after != entries || latest != server || reloaded {
		t.Fatalf("entries=%d->%d server reused=%v catalog reloaded=%v", entries, after, latest == server, reloaded)
	}
	// Other identities share the tier 1 snapshot.
	toolNames(t, f.headerClient(t, f.reader, nil))
	f.service.catalogMu.Lock()
	shared := f.service.catalog == snapshot
	f.service.catalogMu.Unlock()
	if !shared {
		t.Fatal("second identity reloaded the catalog")
	}
}

func TestCatalogLoadIsShared(t *testing.T) {
	s := &Service{loads: map[string]*catalogLoad{}}
	want := &catalogSnapshot{versions: "v"}
	load := &catalogLoad{done: make(chan struct{})}
	s.loads["v"] = load
	go func() {
		load.snapshot = want
		close(load.done)
	}()
	got, err := s.catalogFor(context.Background(), &serverSnapshot{versions: "v"})
	if err != nil || got != want {
		t.Fatalf("snapshot=%v error=%v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.loads["w"] = &catalogLoad{done: make(chan struct{})}
	if _, err := s.catalogFor(ctx, &serverSnapshot{versions: "w"}); err != context.Canceled {
		t.Fatalf("cancelled wait error=%v", err)
	}
	s.catalog = want
	if got, err := s.catalogFor(context.Background(), &serverSnapshot{versions: "v"}); err != nil || got != want {
		t.Fatalf("cached snapshot=%v error=%v", got, err)
	}
}

type blockingCatalogTracer struct {
	once      sync.Once
	started   chan struct{}
	release   chan struct{}
	mu        sync.Mutex
	loadCtxOK bool
}

func (b *blockingCatalogTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	// GetCatalog reads the DSSE envelope from catalog_versions; intercept it
	// once to pause the shared tier-1 load without any production test hook.
	if strings.Contains(data.SQL, "name: GetCatalog :one") {
		b.once.Do(func() {
			close(b.started)
			<-b.release
			b.mu.Lock()
			b.loadCtxOK = ctx.Err() == nil
			b.mu.Unlock()
		})
	}
	return ctx
}

func (b *blockingCatalogTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestCatalogLoadSurvivesFirstCallerCancel(t *testing.T) {
	f := newProgressiveFixture(t, nil)
	tracer := &blockingCatalogTracer{started: make(chan struct{}), release: make(chan struct{})}
	cfg := f.db.Pool.Config()
	cfg.ConnConfig.Tracer = tracer
	tracedPool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tracedPool.Close)
	f.identity.Store = &store.Store{Pool: tracedPool, Queries: db.New(tracedPool)}

	snap, err := f.service.snapshot(callerContext("admin", "admin"))
	if err != nil {
		t.Fatal(err)
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	err1Ch := make(chan error, 1)
	go func() {
		_, err := f.service.catalogFor(ctx1, snap)
		err1Ch <- err
	}()
	<-tracer.started
	type result struct {
		snap *catalogSnapshot
		err  error
	}
	res2Ch := make(chan result, 1)
	go func() {
		got, err := f.service.catalogFor(context.Background(), snap)
		res2Ch <- result{got, err}
	}()
	// Wait until caller 2 has joined the in-flight load before cancelling caller 1.
	time.Sleep(20 * time.Millisecond)
	cancel1()
	if err := <-err1Ch; err != context.Canceled {
		t.Fatalf("first caller error=%v, want context.Canceled", err)
	}
	close(tracer.release)
	res2 := <-res2Ch
	if res2.err != nil || res2.snap == nil || len(res2.snap.actions) == 0 {
		t.Fatalf("second caller snap=%v err=%v", res2.snap, res2.err)
	}
	tracer.mu.Lock()
	ok := tracer.loadCtxOK
	tracer.mu.Unlock()
	if !ok {
		t.Fatal("shared catalog load context was cancelled with first caller")
	}
	f.service.catalogMu.Lock()
	cached := f.service.catalog
	f.service.catalogMu.Unlock()
	if cached != res2.snap {
		t.Fatalf("catalog cache not populated: got %v want %v", cached, res2.snap)
	}
}

func TestProgressiveDirectActionCalls(t *testing.T) {
	f := newProgressiveFixture(t, func(c *Config) { c.Mode = modeProgressive })
	admin := f.headerClient(t, f.admin, nil)
	reader := f.headerClient(t, f.reader, nil)
	f.jobs.mu.Lock()
	before := f.jobs.sequence
	f.jobs.mu.Unlock()
	for _, tc := range []struct {
		client    *sdk.ClientSession
		tool      string
		error     string
		operation string
	}{
		{admin, "logs_read", "action is not directly exposed in progressive mode; call the matching actions_invoke_read tool", "mcp/logs_read"},
		{admin, "data_purge", "action is not directly exposed in progressive mode; call the matching actions_invoke_dangerous tool", "mcp/data_purge"},
		{admin, "missing_action", "tool removed or unavailable for this identity; call tools/list to refresh", "mcp/unknown_tool"},
		{reader, "svc_restart", "tool removed or unavailable for this identity; call tools/list to refresh", "mcp/unknown_tool"},
		{reader, "actions_invoke_write", "tool removed or unavailable for this identity; call tools/list to refresh", "mcp/unknown_tool"},
	} {
		before := len(f.audit.snapshot())
		r := call(t, tc.client, tc.tool, actionArgs())
		if data := content(t, r); !r.IsError || data["error"] != tc.error {
			t.Fatalf("%s result=%v", tc.tool, data)
		}
		events := f.audit.snapshot()[before:]
		if len(events) != 1 || events[0].Operation != tc.operation || events[0].Outcome != "deny" {
			t.Fatalf("%s audit=%+v", tc.tool, events)
		}
	}
	f.jobs.mu.Lock()
	after := f.jobs.sequence
	f.jobs.mu.Unlock()
	if after != before {
		t.Fatal("direct progressive calls dispatched jobs")
	}
}

func TestConfigModeValidation(t *testing.T) {
	f := newTransportFixture(t)
	for _, tc := range []struct {
		cfg Config
		ok  bool
	}{
		{Config{}, true},
		{Config{Mode: "progressive", AutoThreshold: 1}, true},
		{Config{Mode: "auto", AutoThreshold: 1000}, true},
		{Config{Mode: "Flat"}, false},
		{Config{Mode: "lazy"}, false},
		{Config{AutoThreshold: -1}, false},
		{Config{AutoThreshold: 1001}, false},
	} {
		s, err := New(f.identity, f.catalogs, f.jobs, tc.cfg)
		if (err == nil) != tc.ok {
			t.Fatalf("config=%+v error=%v", tc.cfg, err)
		}
		if tc.ok && (s.config.Mode == "" || s.config.AutoThreshold == 0) {
			t.Fatalf("defaults not applied: %+v", s.config)
		}
	}
}
