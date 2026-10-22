package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *safeBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

func TestGatewayCommands(t *testing.T) {
	dsn := testpg.Start(t)
	dir := t.TempDir()
	// Build the exact binary used by the requested ./bin commands. Database
	// credentials stay in the child environment and never enter arguments/logs.
	binary, err := filepath.Abs("../../bin/allowops-gateway")
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gateway: %v\n%s", err, output)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPath, keyPath := filepath.Join(dir, "tls.pem"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := configuration{Address: "127.0.0.1:0", TLSCertificate: certPath, TLSKey: keyPath, CACertificate: filepath.Join(dir, "ca.pem"), CAKey: filepath.Join(dir, "ca.key"), Gateway: hostconn.DefaultConfig(), Identity: api.Config{Origin: "https://localhost"}}
	cfg.Jobs = job.DefaultConfig()
	cfg.Output = output.Config{Bucket: "fixture", Region: "us-east-1", Endpoint: "http://127.0.0.1:1"}
	config, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	environment := append(os.Environ(), "ALLOWOPS_DATABASE_URL="+dsn)
	command := exec.Command(binary, "serve", "--config", configPath)
	command.Env = environment
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "schema unavailable") {
		t.Fatalf("unmigrated serve: err=%v output=%s", err, output)
	}
	t.Logf("./bin/allowops-gateway serve --config <fixture>: exit 1: %s", strings.TrimSpace(string(output)))
	command = exec.Command(binary, "migrate")
	command.Env = environment
	output, err = command.CombinedOutput()
	if err != nil {
		t.Fatalf("migrate: %v\n%s", err, output)
	}
	t.Logf("./bin/allowops-gateway migrate: exit 0: %s", strings.TrimSpace(string(output)))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command = exec.CommandContext(ctx, binary, "serve", "--config", configPath)
	command.Env = environment
	logs := new(safeBuffer)
	command.Stdout = logs
	command.Stderr = logs
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	defer command.Process.Kill()
	var address string
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		for _, line := range strings.Split(logs.String(), "\n") {
			if strings.HasPrefix(line, "gateway serving ") {
				address = strings.Fields(line)[2]
				break
			}
		}
		if address != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if address == "" {
		t.Fatalf("serve not ready: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "gateway TLS CA pin unavailable; CreateJoinToken disabled; configure management.ca_pin") {
		t.Fatal("missing G35 startup warning")
	}
	roots := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	roots.AddCert(parsed)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get("https://" + address + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || strings.TrimSpace(string(body)) != "Bearer authentication required" || response.Header.Get("WWW-Authenticate") != `Bearer realm="allowops"` {
		t.Fatalf("new runtime behavior status=%d body=%q", response.StatusCode, body)
	}
	auditClient := allowopsv1connect.NewAuditServiceClient(client, "https://"+address)
	_, err = auditClient.VerifyAudit(ctx, connect.NewRequest(&v1.VerifyAuditRequest{FromSeq: 1, ToSeq: 1}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("P7 audit route error=%v, want unauthenticated", err)
	}
	t.Log("P7 AuditService route active: unauthenticated request rejected")
	loginClient := allowopsv1connect.NewAuthServiceClient(client, "https://"+address)
	if _, err := loginClient.GetLoginMethods(ctx, connect.NewRequest(&v1.GetLoginMethodsRequest{})); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE operation=$1 AND reason='result' AND decision='allow'", allowopsv1connect.AuthServiceGetLoginMethodsProcedure).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("production P7 audit rows=%d; want 1", count)
	}
	t.Log("production gateway Append recorded GetLoginMethods in the P7 chain")
	// The running gateway must use P6's client rather than the old nil boundary.
	if _, err := db.Pool.Exec(ctx, `INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username,manual_roles) VALUES ('mcp-owner','fixture','mcp-owner','ldap','mcp-owner',ARRAY['admin']); INSERT INTO service_accounts(account_id,name,owner_user_id,roles) VALUES ('mcp-account','mcp-account','mcp-owner',ARRAY['admin'])`); err != nil {
		t.Fatal(err)
	}
	token, record, err := authn.GenerateServiceToken(time.Now(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES ('mcp-token','mcp-account',$1,$2)`, record.Hash[:], record.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	mcpClient := sdk.NewClient(&sdk.Implementation{Name: "gateway-runtime-test", Version: "1"}, nil)
	mcpSession, err := mcpClient.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: "https://" + address + "/mcp", HTTPClient: &http.Client{Transport: runtimeBearer{base: transport, token: token}}, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := mcpSession.CallTool(ctx, &sdk.CallToolParams{Name: "jobs_list"})
	if err != nil || result.IsError {
		t.Fatalf("runtime MCP job backend result=%+v error=%v", result, err)
	}
	if err = mcpSession.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := <-waited; err != nil {
		t.Fatalf("serve exit: %v output=%s", err, logs.String())
	}
	if !strings.Contains(logs.String(), "gateway stopped") {
		t.Fatal("missing graceful stop")
	}
	t.Logf("./bin/allowops-gateway serve --config <fixture>: SIGTERM exit 0:\n%s", logs.String())
}

type runtimeBearer struct {
	base  http.RoundTripper
	token string
}

func (b runtimeBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}
