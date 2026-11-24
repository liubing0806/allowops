package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
	storedb "github.com/liubing0806/allowops/internal/store/db"
	"github.com/liubing0806/allowops/plugin"
	_ "github.com/liubing0806/allowops/plugins/standard"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/yaml.v3"
)

func writeServerCAPEM(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	cert := srv.Certificate()
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func yamlNode(t *testing.T, text string) yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Content) == 0 {
		return yaml.Node{}
	}
	return *doc.Content[0]
}

func TestInvestigationContextEndToEnd(t *testing.T) {
	f := newTransportFixture(t)
	ctx := context.Background()

	// Seed one visible host and one invisible host (no authorization labels).
	if _, err := f.db.Pool.Exec(ctx, `INSERT INTO hosts(host_id,hostname,authorization_labels,certificate_serial,certificate_expires_at) VALUES ('h-vis','app-01','{"service":"order-api"}','ser-vis',now()+interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(ctx, `INSERT INTO hosts(host_id,hostname,authorization_labels,certificate_serial,certificate_expires_at) VALUES ('h-hid','secret-01','{"scope":"restricted"}','ser-hid',now()+interval '1 hour')`); err != nil {
		t.Fatal(err)
	}

	// TLS external CMDB inventory server.
	cmdbSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cmdb-secret-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"entities":[{"kind":"service","name":"order-api","attrs":{"env":"prod","owner":"ops"},"hosts":["app-01","secret-01"],"selector":"service=order-api"}]}`)
	}))
	defer cmdbSrv.Close()
	cmdbCA := writeServerCAPEM(t, cmdbSrv)
	cmdbCredDir := t.TempDir()
	cmdbCredFile := filepath.Join(cmdbCredDir, "cmdb.token")
	if err := os.WriteFile(cmdbCredFile, []byte("cmdb-secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Static topology file sharing order-api with conflicting owner.
	topoFile := filepath.Join(t.TempDir(), "topology.yaml")
	if err := os.WriteFile(topoFile, []byte("entities:\n  - kind: service\n    name: order-api\n    attrs:\n      env: prod\n      owner: trade\n    hosts: [app-01]\n    selector: service=order-api\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// TLS external Changes feed server.
	now := time.Now().UTC().Truncate(time.Second)
	extChangeTime := now.Add(-10 * time.Minute)
	changesSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"changes": []map[string]any{{
				"at":      extChangeTime.Format(time.RFC3339),
				"kind":    "deploy",
				"service": "order-api",
				"summary": "deployed order-api v2.4.1",
				"actor":   "ci-bot",
				"ref":     "release-241",
			}},
			"has_more": false,
		})
	}))
	defer changesSrv.Close()
	changesCA := writeServerCAPEM(t, changesSrv)

	// Local runbooks directory with normal runbook + large runbook for 32 KiB test.
	kbDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(kbDir, "orders"), 0o755); err != nil {
		t.Fatal(err)
	}
	orderDocPath := filepath.Join(kbDir, "orders", "high-latency.md")
	orderDocBody := "---\ntitle: Order API High Latency\nsummary: Steps for order-api latency spikes\ntags: [order-api, latency]\n---\n# Order API High Latency\n\n## Triage\nCheck recent deploys and database pool saturation.\n\n## Mitigation\nDrain traffic from degraded instances.\n"
	if err := os.WriteFile(orderDocPath, []byte(orderDocBody), 0o644); err != nil {
		t.Fatal(err)
	}
	largeDocPath := filepath.Join(kbDir, "orders", "large.md")
	largeDocBody := "# Large Runbook\n\n" + strings.Repeat("Check slow query logs and \"quoted\" lines.\n", 1200)
	if err := os.WriteFile(largeDocPath, []byte(largeDocBody), 0o644); err != nil {
		t.Fatal(err)
	}

	// Build pluginhost with all 3 namespaces.
	host, err := pluginhost.New(ctx, []pluginhost.Config{
		{
			ID:       "inv-static",
			Module:   "inventory.static",
			Required: true,
			Config:   yamlNode(t, "file: "+topoFile),
		},
		{
			ID:          "inv-cmdb",
			Module:      "inventory.cmdb_http",
			Required:    true,
			Egress:      []string{cmdbSrv.URL},
			CAFile:      cmdbCA,
			Credentials: map[string]string{"tok": cmdbCredFile},
			Config:      yamlNode(t, "url: "+cmdbSrv.URL+"/entities\ncredential_ref: tok\n"),
		},
		{
			ID:       "chg-allowops",
			Module:   "changes.allowops",
			Required: true,
			Config:   yamlNode(t, "include_catalog: true\ninclude_policy: true\n"),
		},
		{
			ID:       "chg-http",
			Module:   "changes.http",
			Required: true,
			Egress:   []string{changesSrv.URL},
			CAFile:   changesCA,
			Config:   yamlNode(t, "url: "+changesSrv.URL+"/changes\n"),
		},
		{
			ID:       "kb-ops",
			Module:   "knowledge.git_markdown",
			Required: true,
			Config:   yamlNode(t, "dir: "+kbDir+"\nrefresh_ttl: 1ms\n"),
		},
	}, pluginhost.Deps{
		ControlPlaneChanges: func(ctx context.Context, from, to time.Time, limit int) ([]plugin.ControlPlaneChange, bool, error) {
			polRows, err := f.db.Queries.ListPolicyChangeHistory(ctx, storedb.ListPolicyChangeHistoryParams{
				CreatedAt:   pgtype.Timestamptz{Time: from, Valid: true},
				CreatedAt_2: pgtype.Timestamptz{Time: to, Valid: true},
				Limit:       int32(limit + 1),
			})
			if err != nil {
				return nil, false, err
			}
			hasMore := len(polRows) > limit
			if hasMore {
				polRows = polRows[:limit]
			}
			out := make([]plugin.ControlPlaneChange, 0, len(polRows))
			for _, r := range polRows {
				out = append(out, plugin.ControlPlaneChange{
					At:             r.CreatedAt.Time.UTC(),
					Kind:           "policy",
					Version:        r.Version,
					Actor:          r.CreatedBy,
					Reason:         r.Reason,
					RolledBackFrom: r.RolledBackFrom,
				})
			}
			return out, hasMore, nil
		},
	})
	if err != nil {
		t.Fatalf("pluginhost.New failed: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		host.Close(closeCtx)
	})

	svc, err := New(f.identity, f.catalogs, nil, Config{
		Inventory: host,
		Changes:   host,
		Knowledge: host,
	})
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewTLSServer(svc.Handler())
	defer gw.Close()

	client := sdk.NewClient(&sdk.Implementation{Name: "investigation-e2e", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint:             gw.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: &bearerTransport{base: gw.Client().Transport, token: f.viewer}},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	// 1. tools/list exposes all four context tools without a job service.
	listedTools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var toolNames []string
	for _, tool := range listedTools.Tools {
		toolNames = append(toolNames, tool.Name)
	}
	for _, want := range []string{"entities_search", "changes_list", "runbooks_search", "runbooks_read"} {
		if !slices.Contains(toolNames, want) {
			t.Fatalf("missing tool %q in %v", want, toolNames)
		}
	}

	// 2. entities_search merges inv-static + inv-cmdb with conflicts and host visibility.
	entRes := call(t, session, "entities_search", map[string]any{"kind": "service", "name": "order-api"})
	if entRes.IsError {
		t.Fatalf("entities_search error: %v", content(t, entRes))
	}
	entData := content(t, entRes)
	entities := entData["entities"].([]any)
	if len(entities) != 1 {
		t.Fatalf("expected 1 merged entity, got %v", entData)
	}
	ent := entities[0].(map[string]any)
	if ent["output_trust"] != nil || entData["output_trust"] != "untrusted" {
		t.Fatalf("unexpected output_trust: %v", entData)
	}
	conflicts := ent["conflicts"].(map[string]any)
	ownerConflict := conflicts["owner"].(map[string]any)
	if ownerConflict["inv-cmdb"] != "ops" || ownerConflict["inv-static"] != "trade" {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}

	// 3. changes_list merges allowops DB policy history + external HTTP deploy.
	chgRes := call(t, session, "changes_list", map[string]any{"limit": 20})
	if chgRes.IsError {
		t.Fatalf("changes_list error: %v", content(t, chgRes))
	}
	chgData := content(t, chgRes)
	if chgData["output_trust"] != "untrusted" {
		t.Fatalf("missing output_trust: %v", chgData)
	}
	changes := chgData["changes"].([]any)
	seenSources := map[string]bool{}
	for _, item := range changes {
		seenSources[item.(map[string]any)["source"].(string)] = true
	}
	if !seenSources["chg-allowops"] || !seenSources["chg-http"] {
		t.Fatalf("expected both chg-allowops and chg-http in %v", changes)
	}

	// 4. runbooks_search + runbooks_read (section + revision).
	rbSearch := call(t, session, "runbooks_search", map[string]any{"query": "latency", "tags": []string{"order-api"}})
	if rbSearch.IsError {
		t.Fatalf("runbooks_search error: %v", content(t, rbSearch))
	}
	docs := content(t, rbSearch)["docs"].([]any)
	if len(docs) != 1 || docs[0].(map[string]any)["id"] != "orders/high-latency.md" {
		t.Fatalf("unexpected runbooks_search result: %v", docs)
	}
	rbRead := call(t, session, "runbooks_read", map[string]any{"source": "kb-ops", "id": "orders/high-latency.md", "section": "Triage"})
	if rbRead.IsError {
		t.Fatalf("runbooks_read error: %v", content(t, rbRead))
	}
	rbData := content(t, rbRead)
	if !strings.Contains(rbData["content"].(string), "database pool saturation") || rbData["output_trust"] != "untrusted" {
		t.Fatalf("unexpected runbooks_read section result: %v", rbData)
	}

	// 5. MCP Resources over real HTTP: templates, list (including omitted params), and 32 KiB capped read.
	tplRes, err := session.ListResourceTemplates(ctx, nil)
	if err != nil || len(tplRes.ResourceTemplates) != 1 || tplRes.ResourceTemplates[0].URITemplate != runbookResourceTemplateURI {
		t.Fatalf("ListResourceTemplates: res=%+v err=%v", tplRes, err)
	}
	resList, err := session.ListResources(ctx, nil)
	if err != nil || len(resList.Resources) != 2 {
		t.Fatalf("ListResources: res=%+v err=%v", resList, err)
	}

	// Raw JSON-RPC POST omitting params for resources/list, and wire-size check <= 32 KiB for large resources/read.
	rawRPC := func(body string) ([]byte, http.Header) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, gw.URL+"/mcp", bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.viewer)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := gw.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d body=%s", resp.StatusCode, string(raw))
		}
		return raw, resp.Header
	}
	listWire, listHdr := rawRPC(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)
	if cc := listHdr.Get("Cache-Control"); !strings.Contains(cc, "no-store") && !strings.Contains(cc, "no-cache") {
		t.Fatalf("expected non-cacheable Cache-Control, got %q", cc)
	}
	if !strings.Contains(string(listWire), "allowops://runbooks/kb-ops/orders/high-latency.md") {
		t.Fatalf("unexpected raw resources/list wire: %s", string(listWire))
	}
	largeReadWire, _ := rawRPC(`{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"allowops://runbooks/kb-ops/orders/large.md"}}`)
	if len(largeReadWire) > resultByteLimit+512 {
		t.Fatalf("large resources/read wire response too large: %d", len(largeReadWire))
	}
	if !strings.Contains(string(largeReadWire), `"truncated":true`) || !strings.Contains(string(largeReadWire), `"output_trust":"untrusted"`) {
		t.Fatalf("expected truncated + untrusted markers in large resources/read: %s", string(largeReadWire))
	}

	// 6. Refresh TOCTOU: update file metadata to hide its ID via secret propagation; both runbooks_read & resources/read must reject.
	time.Sleep(5 * time.Millisecond)
	secretDoc := "---\ntitle: password=high-latency.md\nsummary: secret\n---\n# Secret\nbody\n"
	if err := os.WriteFile(orderDocPath, []byte(secretDoc), 0o644); err != nil {
		t.Fatal(err)
	}
	hiddenTool := call(t, session, "runbooks_read", map[string]any{"source": "kb-ops", "id": "orders/high-latency.md"})
	if !hiddenTool.IsError {
		t.Fatalf("expected hidden runbook to fail in runbooks_read: %v", content(t, hiddenTool))
	}
	if _, err := session.ReadResource(ctx, &sdk.ReadResourceParams{URI: "allowops://runbooks/kb-ops/orders/high-latency.md"}); err == nil {
		t.Fatal("expected hidden runbook to fail in resources/read")
	}

	// Verify audit recorded both authorized and result phases for changes_list and resources/read.
	events := f.audit.snapshot()
	hasAudit := func(op, phase, outcome string) bool {
		return slices.ContainsFunc(events, func(e api.AuditEvent) bool {
			return e.Operation == op && e.Phase == phase && e.Outcome == outcome
		})
	}
	for _, check := range [][3]string{
		{"mcp/entities_search", "authorized", "allow"},
		{"mcp/entities_search", "result", "allow"},
		{"mcp/changes_list", "authorized", "allow"},
		{"mcp/changes_list", "result", "allow"},
		{"mcp/runbooks_search", "authorized", "allow"},
		{"mcp/runbooks_search", "result", "allow"},
		{"mcp/resources/list", "authorized", "allow"},
		{"mcp/resources/list", "result", "allow"},
		{"mcp/resources/read", "authorized", "allow"},
	} {
		if !hasAudit(check[0], check[1], check[2]) {
			t.Fatalf("missing audit event %v in %+v", check, events)
		}
	}

	// 7. Single-namespace knowledge-only server does not list inventory or changes tools.
	kbOnlyHost, err := pluginhost.New(ctx, []pluginhost.Config{{
		ID:       "kb-only",
		Module:   "knowledge.git_markdown",
		Required: true,
		Config:   yamlNode(t, "dir: "+kbDir+"\n"),
	}}, pluginhost.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	defer kbOnlyHost.Close(ctx)
	kbSvc, err := New(f.identity, f.catalogs, nil, Config{Inventory: kbOnlyHost, Changes: kbOnlyHost, Knowledge: kbOnlyHost})
	if err != nil {
		t.Fatal(err)
	}
	kbGW := httptest.NewTLSServer(kbSvc.Handler())
	defer kbGW.Close()
	kbSession, err := client.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint:             kbGW.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: &bearerTransport{base: kbGW.Client().Transport, token: f.viewer}},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer kbSession.Close()
	kbTools, err := kbSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range kbTools.Tools {
		if tool.Name == "entities_search" || tool.Name == "changes_list" {
			t.Fatalf("knowledge-only server unexpectedly exposed %s", tool.Name)
		}
	}

	// 8. Existing policy without view_changes / view_knowledge denies tools and resources.
	var rawPolicy []byte
	if err := f.db.Pool.QueryRow(ctx, `SELECT rules FROM policy_versions WHERE version=1`).Scan(&rawPolicy); err != nil {
		t.Fatal(err)
	}
	var policy v1.PolicyRules
	if err := protojson.Unmarshal(rawPolicy, &policy); err != nil {
		t.Fatal(err)
	}
	for _, r := range policy.Rules {
		r.Operations = slices.DeleteFunc(r.Operations, func(op string) bool {
			return op == "view_changes" || op == "view_knowledge"
		})
	}
	rawPolicy, err = protojson.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(ctx, `UPDATE policy_versions SET rules=$1 WHERE version=1`, rawPolicy); err != nil {
		t.Fatal(err)
	}
	restarted, err := api.New(ctx, f.db, f.identity.Config, f.audit)
	if err != nil {
		t.Fatal(err)
	}
	deniedSvc, err := New(restarted, f.catalogs, nil, Config{Inventory: host, Changes: host, Knowledge: host})
	if err != nil {
		t.Fatal(err)
	}
	deniedGW := httptest.NewTLSServer(deniedSvc.Handler())
	defer deniedGW.Close()
	deniedSession, err := client.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint:             deniedGW.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: &bearerTransport{base: deniedGW.Client().Transport, token: f.viewer}},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer deniedSession.Close()
	if res := call(t, deniedSession, "changes_list", map[string]any{}); !res.IsError || content(t, res)["error"] != "operation denied" {
		t.Fatalf("expected denied changes_list, got %v", content(t, res))
	}
	if res := call(t, deniedSession, "runbooks_search", map[string]any{}); !res.IsError || content(t, res)["error"] != "operation denied" {
		t.Fatalf("expected denied runbooks_search, got %v", content(t, res))
	}
	if _, err := deniedSession.ListResources(ctx, nil); err == nil {
		t.Fatal("expected denied resources/list")
	}
}
