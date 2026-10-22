package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/server"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/http2"
)

func TestSDKCLIAndHostSearch(t *testing.T) {
	f := newTransportFixture(t)
	mintSession := func(client, prefix string) string {
		t.Helper()
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			t.Fatal(err)
		}
		token := prefix + base64.RawURLEncoding.EncodeToString(bytes)
		digest := sha256.Sum256([]byte(token))
		if _, err := f.db.Pool.Exec(context.Background(), `INSERT INTO identity_sessions(session_id,user_id,token_hash,client,expires_at) VALUES ($1,'owner',$2,$1,now()+interval '1 hour')`, client, digest[:]); err != nil {
			t.Fatal(err)
		}
		return token
	}
	cli := mintSession("cli", "aops_cli_")
	console := mintSession("console", "aops_web_")
	c, _ := f.client(t, cli, nil)
	if tools, err := c.ListTools(context.Background(), nil); err != nil || len(tools.Tools) != 5 {
		t.Fatalf("CLI tools=%v error=%v", tools, err)
	}
	hosts := call(t, c, "hosts_search", map[string]any{"selector": "env=test"})
	data := content(t, hosts)
	if hosts.IsError || data["total"] != float64(2) || data["next_cursor"] == "" || data["label_distribution"] == nil {
		t.Fatalf("hosts=%+v", hosts)
	}
	next := call(t, c, "hosts_search", map[string]any{"selector": "env=test", "next_cursor": data["next_cursor"]})
	if next.IsError || content(t, next)["next_cursor"] != "" {
		t.Fatalf("next hosts=%+v", next)
	}
	first := data["hosts"].([]any)[0].(map[string]any)
	if first["host"] != "web-01" || first["online"] != false || first["labels"].(map[string]any)["env"] != "test" {
		t.Fatalf("host=%v", first)
	}
	all := call(t, c, "hosts_search", nil)
	if all.IsError || content(t, all)["total"] != float64(2) || content(t, all)["next_cursor"] == "" {
		t.Fatalf("A27 all hosts=%+v", all)
	}
	run := call(t, c, "logs_read", actionArgs())
	if run.IsError {
		t.Fatalf("CLI action=%+v", run)
	}
	jobs := call(t, c, "jobs_list", nil)
	if jobs.IsError || len(content(t, jobs)["jobs"].([]any)) != 1 {
		t.Fatalf("CLI jobs=%+v", jobs)
	}
	req, _ := http.NewRequest(http.MethodPost, f.gateway.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.AddCookie(&http.Cookie{Name: "__Host-allowops-session", Value: console})
	res, err := f.gateway.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("console cookie status=%d", res.StatusCode)
	}
	if _, err = f.db.Pool.Exec(context.Background(), `UPDATE identity_sessions SET revoked_at=now() WHERE session_id='cli'`); err != nil {
		t.Fatal(err)
	}
	if _, err = c.ListTools(context.Background(), nil); err == nil {
		t.Fatal("revoked CLI session reached cache")
	}
}

func TestSDKDiscoveryIgnoresIPButExecutionAndDenyRemainAuthoritative(t *testing.T) {
	f := newTransportFixture(t)
	c, _ := f.client(t, f.viewer, nil)
	policy, err := f.identity.GetPolicy(context.Background(), connect.NewRequest(&v1.GetPolicyRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	rules := policy.Msg.Policy.Rules
	rules.Rules = append(rules.Rules, &v1.PolicyRule{Name: "allow-viewer-from-other-ip", Roles: []string{"viewer"}, Operations: []string{"execute_action"}, Actions: []string{"logs_read"}, SourceCidrs: []string{"192.0.2.0/24"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW})
	save := func(version int) {
		t.Helper()
		data, err := json.Marshal(rules)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.db.Pool.Exec(context.Background(), `INSERT INTO policy_versions(version,rules,created_by) VALUES ($1,$2,'fixture')`, version, data); err != nil {
			t.Fatal(err)
		}
	}
	save(2)
	if list, err := c.ListTools(context.Background(), nil); err != nil || len(list.Tools) != 5 {
		t.Fatalf("IP display precheck tools=%v error=%v", list, err)
	}
	if !call(t, c, "logs_read", actionArgs()).IsError {
		t.Fatal("display precheck granted execution")
	}
	rules.Rules = append(rules.Rules, &v1.PolicyRule{Name: "deny-viewer-every-host", Roles: []string{"viewer"}, Operations: []string{"execute_action"}, Actions: []string{"logs_read"}, Effect: v1.PolicyEffect_POLICY_EFFECT_DENY})
	save(3)
	if list, err := c.ListTools(context.Background(), nil); err != nil || len(list.Tools) != 4 {
		t.Fatalf("unconstrained deny tools=%v error=%v", list, err)
	}
}

func TestSDKP4GatewayMCPALPN(t *testing.T) {
	f := newTransportFixture(t)
	dir := t.TempDir()
	ca, err := hostconn.OpenCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	agent, err := hostconn.New(f.db, ca, hostconn.DefaultConfig(), hostconn.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gateway := server.New(agent, f.gateway.TLS.Certificates[0])
	gateway.Catalogs = f.catalogs
	gateway.UseIdentity(f.identity)
	gateway.MCP = f.service.Handler()
	done := make(chan error, 1)
	go func() { done <- gateway.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := gateway.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(f.gateway.Certificate())
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, NextProtos: []string{server.MCPALPN}}
	//lint:ignore SA1019 Custom MCP ALPN requires raw HTTP/2 as in the P4 server tests.
	transport := &http2.Transport{DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
		conn, err := (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, network, address)
		if err == nil && conn.(*tls.Conn).ConnectionState().NegotiatedProtocol != server.MCPALPN {
			conn.Close()
			return nil, io.ErrUnexpectedEOF
		}
		return conn, err
	}}
	//lint:ignore SA1019 Close the raw transport required for the custom MCP ALPN test.
	t.Cleanup(transport.CloseIdleConnections)
	client := sdk.NewClient(&sdk.Implementation{Name: "allowops-alpn-test", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), &sdk.StreamableClientTransport{Endpoint: "https://" + listener.Addr().String() + "/mcp", HTTPClient: &http.Client{Transport: &bearerTransport{base: transport, token: f.admin}}, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if list, err := session.ListTools(context.Background(), nil); err != nil || len(list.Tools) != 5 {
		t.Fatalf("P4 ALPN tools=%v error=%v", list, err)
	}
	if result := call(t, session, "logs_read", actionArgs()); result.IsError {
		t.Fatalf("P4 ALPN action=%+v", result)
	}
}

func TestSDKLegacyBatchIsolatesAuditContext(t *testing.T) {
	f := newTransportFixture(t)
	messages := []map[string]any{}
	for i := range 8 {
		messages = append(messages, map[string]any{"jsonrpc": "2.0", "id": i + 1, "method": "tools/call", "params": map[string]any{"name": "hosts_search", "arguments": map[string]any{"hostname": "web-01"}}})
	}
	body, _ := json.Marshal(messages)
	req, _ := http.NewRequest(http.MethodPost, f.gateway.URL+"/mcp", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+f.admin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-03-26")
	response, err := f.gateway.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || strings.Count(string(data), "structuredContent") != 8 {
		t.Fatalf("batch status=%d result=%s", response.StatusCode, data)
	}
	events := f.audit.snapshot()
	if len(events) != 8 {
		t.Fatalf("batch result audits=%d", len(events))
	}
	for _, event := range events {
		if event.Operation != "mcp/hosts_search" || event.Phase != "result" || event.Outcome != "allow" || event.PolicyVersion == 0 {
			t.Fatalf("batch audit=%+v", event)
		}
	}
}
