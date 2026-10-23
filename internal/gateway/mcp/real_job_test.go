package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/agent"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/server"
	"github.com/liubing0806/allowops/internal/testseaweedfs"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func awaitJobCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("local job condition not satisfied within 15 seconds")
}

func TestSDKRealJobBackendAgentsAndSeaweedFS(t *testing.T) {
	f := newTransportFixture(t)
	ctx := context.Background()
	objects := testseaweedfs.Start(t)
	dir := t.TempDir()
	ca, err := hostconn.OpenCA(filepath.Join(dir, "host-ca.pem"), filepath.Join(dir, "host-ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	tlsCA, err := hostconn.OpenCA(filepath.Join(dir, "tls-ca.pem"), filepath.Join(dir, "tls-ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(tlsCA.PEM)
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyData, err := os.ReadFile(filepath.Join(dir, "tls-ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := catalog.ParsePrivateKey(keyData)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, pub, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := catalog.MarshalPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), tlsCA.PEM...), private)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(tlsCA.PEM)
	cfg := hostconn.DefaultConfig()
	cfg.HeartbeatInterval = 100 * time.Millisecond
	cfg.HeartbeatTimeout = 3 * time.Second
	cfg.CleanupInterval = 100 * time.Millisecond
	hosts, err := hostconn.New(f.db, ca, cfg, hostconn.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := job.New(f.db, f.identity, hosts, objects, audit.New(f.db.Pool, audit.Config{}), f.catalogs.Trusted, job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	hosts.Hooks = jobs.Hooks()
	if err = hosts.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs.Start()
	mcpService, err := New(f.identity, f.catalogs, jobs, Config{ProgressInterval: 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gateway := server.New(hosts, certificate, server.WithIdentity(f.identity), server.WithMCP(mcpService.Handler()))
	gateway.Jobs = jobs
	gateway.Catalogs = f.catalogs
	f.identity.ConfigureJobDependencies(jobs, objects)
	done := make(chan error, 1)
	go func() { done <- gateway.Serve(listener) }()
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}}
	t.Cleanup(func() {
		shutdown, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := gateway.Shutdown(shutdown); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
		jobs.Close()
		httpClient.CloseIdleConnections()
	})
	payload := strings.Repeat("中文日志", 2500)
	action := testAction()
	action.Exec = []any{"/usr/bin/printf", "%s", payload}
	action.Timeout = "5s"
	action.MaxOutput = 64 << 10
	slow := testAction()
	slow.Name = "slow_read"
	slow.Exec = []any{"/usr/bin/sleep", "20"}
	slow.Timeout = "30s"
	steps := testAction()
	steps.Name = "steps_read"
	steps.Exec = nil
	steps.Steps = []catalog.Step{{Name: "first", Exec: []any{"/usr/bin/printf", "step-zero"}}, {Name: "second", Exec: []any{"/usr/bin/printf", "step-one"}}}
	pkg, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: "fixture"}, Actions: map[string]catalog.Action{"logs_read": action, "slow_read": slow, "steps_read": steps}}, catalog.BuildOptions{Now: time.Now().Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := catalog.CanonicalJSON(pkg)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := catalog.Sign(raw, catalog.SigningKey{PrivateKey: f.key})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.catalogs.Publish(ctx, raw); err != nil {
		t.Fatal(err)
	}
	keysDir := t.TempDir()
	signer, err := catalog.MarshalPublicKey(f.key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(keysDir, "signer.pem"), signer, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Pool.Exec(ctx, "DELETE FROM hosts"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"web-01", "web-02"} {
		joinToken, err := hosts.CreateJoinToken(ctx, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		dataDir := t.TempDir()
		if err = os.Chmod(dataDir, 0700); err != nil {
			t.Fatal(err)
		}
		agentCfg := agent.Config{Upstream: listener.Addr().String(), CAPin: api.TLSCAPin(certificate.Certificate)}
		identity, err := agent.Join(ctx, agentCfg, joinToken, name, dataDir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.db.Pool.Exec(ctx, `UPDATE hosts SET authorization_labels='{"env":"test"}' WHERE host_id=$1`, identity.HostID); err != nil {
			t.Fatal(err)
		}
		hostAgent, err := agent.New(agentCfg, agent.Options{DataDir: dataDir, KeysDir: keysDir, KeyOwner: os.Getuid(), Version: cfg.Version})
		if err != nil {
			t.Fatal(err)
		}
		agentCtx, stop := context.WithCancel(ctx)
		agentDone := make(chan error, 1)
		go func() { agentDone <- hostAgent.Run(agentCtx) }()
		t.Cleanup(func() {
			stop()
			select {
			case <-agentDone:
			case <-time.After(5 * time.Second):
				t.Error("local agent did not stop")
			}
		})
		awaitJobCondition(t, func() bool {
			report := hosts.CatalogReport(identity.HostID, pkg.CatalogID)
			return report != nil && report.Loaded
		})
	}
	if _, err = f.db.Pool.Exec(ctx, `INSERT INTO hosts(host_id,hostname,authorization_labels,certificate_serial,certificate_expires_at) VALUES ('offline-host','web-offline','{"env":"test"}','fixture',now()+interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "real-job-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: "https://" + listener.Addr().String() + "/mcp", HTTPClient: &http.Client{Transport: &bearerTransport{base: httpClient.Transport, token: f.admin}}, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 7 {
		t.Fatalf("tools=%v error=%v", tools, err)
	}
	args := actionArgs()
	args["targets"] = map[string]any{"selector": "env=test"}
	args["expected_count"] = 3
	args["wait_seconds"] = 5
	run := call(t, session, "logs_read", args)
	m := content(t, run)
	if run.IsError || m["groups"] == nil {
		t.Fatalf("real action=%v", m)
	}
	id := m["job_id"].(string)
	groups := m["groups"].([]any)
	if len(groups) != 1 || groups[0].(map[string]any)["host_count"] != float64(2) || m["output_trust"] != "untrusted" || m["offline_hosts"] == nil {
		t.Fatalf("P6 grouped summary=%v", m)
	}
	if m["offline_hosts"].([]any)[0] != "web-offline" || groups[0].(map[string]any)["truncated"] != true {
		t.Fatalf("offline/truncation=%v", m)
	}
	awaitJobCondition(t, func() bool {
		var stored int
		err := f.db.Pool.QueryRow(ctx, "SELECT count(*) FROM tasks WHERE job_id=$1 AND output_stored", id).Scan(&stored)
		return err == nil && stored == 2
	})
	summary := call(t, session, "jobs_get", map[string]any{"job_id": id, "wait_seconds": 0, "response_format": "detailed"})
	if summary.IsError || len(content(t, summary)["groups"].([]any)[0].(map[string]any)["hosts"].([]any)) != 2 {
		t.Fatalf("real detailed summary=%v", content(t, summary))
	}
	var combined []byte
	offset := uint64(0)
	pages := 0
	for {
		result := call(t, session, "jobs_get", map[string]any{"job_id": id, "host": "web-01", "wait_seconds": 0, "offset": offset})
		data := content(t, result)
		encoded, _ := json.Marshal(result)
		if result.IsError || len(encoded) > resultByteLimit || data["encoding"] != "base64" || data["output_trust"] != "untrusted" {
			t.Fatalf("real output=%v bytes=%d", data, len(encoded))
		}
		decoded, err := base64.StdEncoding.DecodeString(data["data_base64"].(string))
		if err != nil {
			t.Fatal(err)
		}
		combined = append(combined, decoded...)
		pages++
		next := uint64(data["next_offset"].(float64))
		if next != offset+uint64(len(decoded)) {
			t.Fatalf("offset=%d next=%d bytes=%d", offset, next, len(decoded))
		}
		if data["eof"] == true {
			break
		}
		if next <= offset {
			t.Fatal("output cursor stalled")
		}
		offset = next
	}
	if pages < 2 || !bytes.Equal(combined, []byte(payload)) {
		t.Fatalf("pages=%d reconstructed bytes=%d want=%d", pages, len(combined), len(payload))
	}
	split := call(t, session, "jobs_get", map[string]any{"job_id": id, "host": "web-01", "wait_seconds": 0, "offset": 1})
	splitBytes, err := base64.StdEncoding.DecodeString(content(t, split)["data_base64"].(string))
	if err != nil || !bytes.Equal(splitBytes, []byte(payload)[1:1+len(splitBytes)]) {
		t.Fatal("split UTF-8 output lost bytes")
	}
	listed := call(t, session, "jobs_list", nil)
	if listed.IsError || content(t, listed)["jobs"].([]any)[0].(map[string]any)["job_id"] != id {
		t.Fatalf("jobs list=%v", content(t, listed))
	}
	var authorized, toolResults int
	if err = f.db.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE operation='run_job' AND reason='authorized'),count(*) FILTER (WHERE operation='mcp/logs_read' AND job_id=$1) FROM audit_events`, id).Scan(&authorized, &toolResults); err != nil {
		t.Fatal(err)
	}
	if authorized != 1 || toolResults != 1 {
		t.Fatalf("authorized=%d tool results=%d", authorized, toolResults)
	}
	otherClient := sdk.NewClient(&sdk.Implementation{Name: "other-account-test", Version: "1"}, nil)
	other, err := otherClient.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: "https://" + listener.Addr().String() + "/mcp", HTTPClient: &http.Client{Transport: &bearerTransport{base: httpClient.Transport, token: f.viewer}}, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	for _, name := range []string{"jobs_get", "jobs_cancel"} {
		denied := call(t, other, name, map[string]any{"job_id": id})
		if !denied.IsError || content(t, denied)["reason"] != "JOB_OWNER_REQUIRED" {
			t.Fatalf("other account %s=%v", name, content(t, denied))
		}
	}
	otherJobs := call(t, other, "jobs_list", nil)
	if otherJobs.IsError || len(content(t, otherJobs)["jobs"].([]any)) != 0 {
		t.Fatalf("other account jobs=%v", content(t, otherJobs))
	}
	compositeArgs := actionArgs()
	compositeArgs["wait_seconds"] = 5
	composite := call(t, session, "steps_read", compositeArgs)
	if composite.IsError {
		t.Fatalf("composite=%v", content(t, composite))
	}
	compositeID := content(t, composite)["job_id"].(string)
	awaitJobCondition(t, func() bool {
		var stored bool
		err := f.db.Pool.QueryRow(ctx, "SELECT output_stored FROM tasks WHERE job_id=$1", compositeID).Scan(&stored)
		return err == nil && stored
	})
	omitted := call(t, session, "jobs_get", map[string]any{"job_id": compositeID, "host": "web-01", "wait_seconds": 0})
	omittedData := content(t, omitted)
	omittedMessage, _ := omittedData["error"].(string)
	if !omitted.IsError || omittedData["reason"] != "INVALID_OUTPUT_STEP" || !strings.Contains(omittedMessage, "step_index") || !strings.Contains(omittedMessage, "one step at a time") {
		t.Fatalf("missing composite step=%v", omittedData)
	}
	for step, want := range []string{"step-zero", "step-one"} {
		result := call(t, session, "jobs_get", map[string]any{"job_id": compositeID, "host": "web-01", "wait_seconds": 0, "step_index": step})
		m := content(t, result)
		if result.IsError {
			t.Fatalf("step %d=%v", step, m)
		}
		raw, err := base64.StdEncoding.DecodeString(m["data_base64"].(string))
		if err != nil || string(raw) != want || m["step_index"] != float64(step) {
			t.Fatalf("step %d data=%s metadata=%v", step, raw, m)
		}
	}
	slowArgs := actionArgs()
	slowArgs["targets"] = map[string]any{"hosts": []string{"web-01", "web-02"}}
	slowArgs["batch_size"] = 1
	slowRun := call(t, session, "slow_read", slowArgs)
	if slowRun.IsError {
		t.Fatalf("slow action=%v", content(t, slowRun))
	}
	slowID := content(t, slowRun)["job_id"].(string)
	awaitJobCondition(t, func() bool {
		var running int
		err := f.db.Pool.QueryRow(ctx, "SELECT count(*) FROM tasks WHERE job_id=$1 AND status=2", slowID).Scan(&running)
		return err == nil && running == 1
	})
	cancelled := call(t, session, "jobs_cancel", map[string]any{"job_id": slowID})
	if cancelled.IsError {
		t.Fatalf("cancel=%v", content(t, cancelled))
	}
	terminal := call(t, session, "jobs_get", map[string]any{"job_id": slowID, "wait_seconds": 5})
	if terminal.IsError || content(t, terminal)["status"] != "cancelled" || content(t, terminal)["counts"].(map[string]any)["cancelled"] != float64(2) {
		t.Fatalf("cancelled job=%v", content(t, terminal))
	}
}
