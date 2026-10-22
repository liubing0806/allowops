package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/server"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
)

func TestP4GatewayJoinConnectCatalogAndExecute(t *testing.T) {
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	dir := t.TempDir()
	hostCA, err := hostconn.OpenCA(filepath.Join(dir, "host-ca.pem"), filepath.Join(dir, "host-ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	// G22: the pinned TLS CA differs from the CA used for host identities.
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
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, public, issuerKey)
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
	config := hostconn.DefaultConfig()
	config.HeartbeatInterval = 100 * time.Millisecond
	config.HeartbeatTimeout = 3 * time.Second
	events := make(chan hostconn.Event, 256)
	service, err := hostconn.New(database, hostCA, config, hostconn.Hooks{OnMessage: func(ctx context.Context, event hostconn.Event) error {
		select {
		case events <- event:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := server.New(service, certificate)
	done := make(chan error, 1)
	go func() { done <- upstream.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := upstream.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	if AgentALPN != server.AgentALPN || JoinALPN != server.JoinALPN {
		t.Fatal("ALPN differs from P4")
	}
	token, err := service.CreateJoinToken(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(issuer.Raw)
	agentConfig := Config{Upstream: listener.Addr().String(), CAPin: "sha256:" + hex.EncodeToString(pin[:]), ReportedLabels: map[string]string{"test": "P3-P4"}}
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := Join(ctx, agentConfig, token, "p3-p4-host", dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if string(identity.ClientCA) != string(hostCA.PEM) {
		t.Fatal("wrong host CA persisted")
	}
	keys := t.TempDir()
	signerPublic, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := catalog.MarshalPublicKey(signerPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "signer.pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := New(agentConfig, Options{DataDir: dataDir, KeysDir: keys, KeyOwner: os.Getuid(), Version: config.Version})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	agentDone := make(chan error, 1)
	go func() { agentDone <- a.Run(runCtx) }()
	t.Cleanup(func() {
		cancelRun()
		select {
		case <-agentDone:
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop")
		}
	})
	action := catalog.Action{Name: "p4_exec", Description: "local P4 exec integration", Risk: "read", Exec: []any{"/usr/bin/printf", "P3-P4 connected"}, Timeout: "5s", MaxOutput: 1024}
	logPath := filepath.Join(dir, "host.log")
	if err := os.WriteFile(logPath, []byte("P4 log match password=secret\nother\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stepsAction := catalog.Action{Name: "p4_steps", Description: "P4 steps", Risk: "read", Steps: []catalog.Step{{Name: "one", Exec: []any{"/usr/bin/printf", "P4 first"}}, {Name: "two", Exec: []any{"/usr/bin/printf", "P4 second"}}}, Timeout: "5s", MaxOutput: 1024}
	logAction := catalog.Action{Name: "p4_logs", Description: "P4 log_search", Risk: "read", Builtin: "log_search", BuiltinConfig: map[string]any{"allowed_roots": []string{dir}}, Timeout: "5s", MaxOutput: 4096}
	actions := map[string]catalog.Action{action.Name: action, stepsAction.Name: stepsAction, logAction.Name: logAction}
	p, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: "p3-p4"}, Actions: actions}, catalog.BuildOptions{Now: time.Now(), TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := catalog.CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := catalog.Sign(payload, catalog.SigningKey{PrivateKey: signer})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	publication := &catalogsvc.Service{Store: database, Trusted: map[string]ed25519.PublicKey{catalog.KeyID(signerPublic): signerPublic}, MaxEnvelopeBytes: 64 << 20, MaxActionBytes: 256 << 10}
	if _, err := publication.Publish(ctx, raw); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for service.CatalogReport(identity.HostID, p.CatalogID) == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	report := service.CatalogReport(identity.HostID, p.CatalogID)
	if report == nil || !report.Loaded {
		t.Fatalf("P4 load report: %v", report)
	}
	// G18: retain the existing stream after renewal, then pull a new catalog
	// over a fresh TLS session authenticated with the replacement certificate.
	before, err := Status(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	renewClient, renewTransport, err := newClient(agentConfig, a.identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := renew(ctx, renewClient, agentConfig, dataDir, a.identity); err != nil {
		t.Fatal(err)
	}
	renewTransport.CloseIdleConnections()
	action.Description = "local P4 exec after renewal"
	actions[action.Name] = action
	p, err = catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: p.CatalogID}, Actions: actions}, catalog.BuildOptions{Now: p.CreatedAt.Add(time.Second), TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	payload, err = catalog.CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err = catalog.Sign(payload, catalog.SigningKey{PrivateKey: signer})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.Publish(ctx, raw); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		report = service.CatalogReport(identity.HostID, p.CatalogID)
		if report != nil && report.Catalog.Version == uint64(p.Version) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if report == nil || !report.Loaded || report.Catalog.Version != uint64(p.Version) {
		t.Fatalf("post-renewal pull: %v", report)
	}
	after, err := Status(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if before.ConnectionID == "" || after.ConnectionID != before.ConnectionID {
		t.Fatalf("renewal replaced stream: %q -> %q", before.ConnectionID, after.ConnectionID)
	}
	for _, scenario := range []struct {
		action catalog.Action
		id     string
		params map[string]any
		output string
		steps  int
	}{
		{action, "p4-exec", map[string]any{}, "P3-P4 connected", 0},
		{stepsAction, "p4-steps", map[string]any{}, "P4 firstP4 second", 2},
		{logAction, "p4-log", map[string]any{"path_glob": logPath, "pattern": "P4 log", "fixed": true}, "", 0},
	} {
		t.Run(scenario.id, func(t *testing.T) {
			executeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			assignment := task(p, scenario.action.Name, scenario.id)
			assignment.Params.Json, err = json.Marshal(scenario.params)
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.Send(executeCtx, identity.HostID, &v1.ConnectResponse{Message: &v1.ConnectResponse_Task{Task: assignment}})
			if err != nil {
				t.Fatal(err)
			}
			if result.Result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED || result.Result.GetExitCode() != 0 || int(result.CompletedSteps) != scenario.steps {
				t.Fatalf("P4 result: %v", result)
			}
			var output []byte
			started, completedSteps := false, 0
			eof := map[uint32]int{}
			for {
				select {
				case event := <-events:
					message := event.Message
					if message.GetTaskStarted().GetTaskId() == scenario.id {
						started = true
					}
					if chunk := message.GetOutput(); chunk != nil && chunk.TaskId == scenario.id {
						if !started {
							t.Fatal("output before actual start")
						}
						if chunk.Stream == v1.OutputStream_OUTPUT_STREAM_STDOUT {
							output = append(output, chunk.Data...)
						}
						if chunk.StepIndex != nil && chunk.Eof {
							eof[*chunk.StepIndex]++
						}
					}
					if step := message.GetStepCompleted(); step != nil && step.TaskId == scenario.id {
						if int(step.StepIndex) != completedSteps || eof[step.StepIndex] != 2 {
							t.Fatalf("step ordering: %v EOF=%v", step, eof)
						}
						completedSteps++
					}
					if message.GetTaskCompleted().GetTaskId() == scenario.id {
						if !started || completedSteps != scenario.steps {
							t.Fatalf("started=%v steps=%d", started, completedSteps)
						}
						if scenario.output != "" && string(output) != scenario.output {
							t.Fatalf("P4 output=%q", output)
						}
						if scenario.id == "p4-log" && (!strings.Contains(string(output), "P4 log match [REDACTED:credential]") || strings.Contains(string(output), "secret")) {
							t.Fatalf("log output=%q", output)
						}
						return
					}
				case <-executeCtx.Done():
					t.Fatal("P4 completion event missing")
				}
			}
		})
	}
}
