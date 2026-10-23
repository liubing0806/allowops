package server_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/server"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestP4BCLISmokeAndDeletion(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	chain := audit.New(f.store.Pool, audit.Config{})
	identity, err := api.New(ctx, f.store, api.Config{Origin: "https://" + address}, api.NewAuditor(chain))
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	agent, err := hostconn.New(f.store, f.ca, hostconn.DefaultConfig(), hostconn.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err = agent.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	certificate, roots := managementTLS(t)
	if err = identity.ConfigureManagement(api.ManagementConfig{Upstream: "https://" + address, CAPin: api.TLSCAPin(certificate.Certificate)}, agent, f.catalogs); err != nil {
		t.Fatal(err)
	}
	native := server.New(agent, certificate, server.WithIdentity(identity), server.WithAudit(&audit.Service{Store: chain}))
	native.Catalogs = f.catalogs
	done := make(chan error, 1)
	go func() { done <- native.Serve(listener) }()
	defer func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := native.Shutdown(c); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	if _, err = f.store.Pool.Exec(ctx, `INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username) VALUES ('owner','fixture','owner','ldap','owner')`); err != nil {
		t.Fatal(err)
	}
	tokens := map[string]string{}
	for _, role := range []string{"admin", "publisher"} {
		if _, err = f.store.Pool.Exec(ctx, "INSERT INTO service_accounts(account_id,name,owner_user_id,roles) VALUES ($1,$1,'owner',$2)", role, []string{role}); err != nil {
			t.Fatal(err)
		}
		raw, record, err := authn.GenerateServiceToken(time.Now(), 30)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.store.Pool.Exec(ctx, "INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES ($1,$1,$2,$3)", role, record.Hash[:], record.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		tokens[role] = raw
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "allowops")
	if output, err := exec.CommandContext(ctx, "go", "build", "-o", binary, "../../../cmd/allowops").CombinedOutput(); err != nil {
		t.Fatalf("CLI build: %v\n%s", err, output)
	}
	ca := filepath.Join(dir, "tls.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[1]}), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(role string, args ...string) []byte {
		t.Helper()
		if role != "" {
			args = append(args, "--gateway", "https://"+address, "--ca-file", ca, "--token-env", "P4B_SMOKE_TOKEN")
		}
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = append(os.Environ(), "P4B_SMOKE_TOKEN="+tokens[role])
		started := time.Now()
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI %v failed after %s: %v\n%s", args, time.Since(started), err, b)
		}
		t.Logf("allowops %s: exit 0 in %s", strings.Join(args, " "), time.Since(started))
		return b
	}
	created := &v1.CreateJoinTokenResponse{}
	if err = protojson.Unmarshal(run("admin", "jointoken", "create", "--uses", "2", "--ttl", "24h", "--json"), created); err != nil {
		t.Fatal(err)
	}
	if created.Token.MaxUses != 2 || created.CaPin == "" {
		t.Fatal("CLI join token response invalid")
	}
	request, key := csr(t)
	registered, err := f.a.client(t, server.JoinALPN, nil).Join(ctx, connect.NewRequest(&v1.JoinRequest{JoinToken: created.Secret, Hostname: "cli-host", CsrPem: request}))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(registered.Msg.Certificate.CertificateChainPem, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(run("admin", "hosts", "list"), []byte("cli-host")) {
		t.Fatal("CLI host list missing registered host")
	}
	run("admin", "hosts", "label", "cli-host", "--set", "env=test", "--set", "temporary=value")
	run("admin", "hosts", "label", "--selector", "env=test", "--expected-count", "1", "--remove", "temporary", "--json")
	pkg := filepath.Join(dir, "catalog.json")
	envelope := filepath.Join(dir, "catalog.dsse")
	// Build examples with the actual CLI, sign with the fixture publisher key.
	run("", "catalog", "build", "--dir", "../../../examples/catalog", "--out", pkg)
	packageData, err := os.ReadFile(pkg)
	if err != nil {
		t.Fatal(err)
	}
	signedEnvelope, err := catalog.Sign(packageData, catalog.SigningKey{PrivateKey: f.signer})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := json.Marshal(signedEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(envelope, signed, 0600); err != nil {
		t.Fatal(err)
	}
	stream := f.b.client(t, server.AgentALPN, &cert).Connect(ctx)
	defer stream.CloseRequest()
	defer stream.CloseResponse()
	if err = stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Hello{Hello: &v1.AgentHello{AgentVersion: "2.3.4", MaxConcurrentTasks: 4, Capabilities: &v1.AgentCapabilities{ExecutionModes: []string{"exec"}, Features: []string{"feature"}}}}}); err != nil {
		t.Fatal(err)
	}
	if receive(t, stream).GetHello() == nil {
		t.Fatal("missing gateway hello")
	}
	published := &v1.PublishCatalogResponse{}
	if err = protojson.Unmarshal(run("publisher", "catalog", "publish", "-f", envelope, "--json"), published); err != nil {
		t.Fatal(err)
	}
	if published.Catalog.ActionCount == 0 {
		t.Fatal("CLI publish returned empty catalog")
	}
	notice := receive(t, stream)
	if notice.GetCatalogAvailable() == nil {
		t.Fatalf("published catalog not notified: %T", notice.Message)
	}
	report := &v1.CatalogLoadReport{Catalog: published.Catalog.Catalog, ReportId: "complete", Loaded: true, FinalPage: false}
	if err = stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_CatalogLoad{CatalogLoad: report}}); err != nil {
		t.Fatal(err)
	}
	if err = stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Heartbeat{Heartbeat: &v1.AgentHeartbeat{Sequence: 1}}}); err != nil {
		t.Fatal(err)
	}
	if receive(t, stream).GetHeartbeat() == nil {
		t.Fatal("missing heartbeat")
	}
	var partial int
	if err = f.store.Pool.QueryRow(ctx, "SELECT count(*) FROM host_catalog_reports WHERE host_id=$1", registered.Msg.Certificate.HostId).Scan(&partial); err != nil || partial != 0 {
		t.Fatalf("partial reports persisted=%d error=%v", partial, err)
	}
	report.PageIndex = 1
	report.FinalPage = true
	if err = stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_CatalogLoad{CatalogLoad: report}}); err != nil {
		t.Fatal(err)
	}
	waitReport(t, func() bool {
		var n int
		_ = f.store.Pool.QueryRow(ctx, "SELECT count(*) FROM host_catalog_reports WHERE host_id=$1 AND loaded", registered.Msg.Certificate.HostId).Scan(&n)
		return n == 1
	})
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := rpc.NewHostServiceClient(&http.Client{Transport: transport}, "https://"+address)
	hreq := connect.NewRequest(&v1.GetHostRequest{Hostname: "cli-host"})
	hreq.Header().Set("Authorization", "Bearer "+tokens["admin"])
	h, err := client.GetHost(ctx, hreq)
	if err != nil || len(h.Msg.Host.LoadedCatalogs) != 1 || h.Msg.Host.GetCapabilities().GetFeatures()[0] != "feature" {
		t.Fatal("complete loaded catalog report not visible", err)
	}
	denied := connect.NewRequest(&v1.DeleteHostRequest{HostId: h.Msg.Host.HostId, ExpectedRevision: h.Msg.Host.Revision})
	denied.Header().Set("Authorization", "Bearer "+tokens["publisher"])
	if _, err = client.DeleteHost(ctx, denied); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("publisher host deletion code=%s error=%v", connect.CodeOf(err), err)
	}
	var denialCount int
	if err = f.store.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE operation=$1 AND decision='deny'", rpc.HostServiceDeleteHostProcedure).Scan(&denialCount); err != nil || denialCount != 1 {
		t.Fatalf("real denial audit count=%d error=%v", denialCount, err)
	}
	// Keep a second instance stream alive until DeleteHost commits.
	run("admin", "hosts", "delete", "cli-host")
	end := make(chan error, 1)
	go func() { _, err := stream.Receive(); end <- err }()
	select {
	case err := <-end:
		if err == nil {
			t.Fatal("deleted host stream remained open")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("delete notification did not disconnect remote instance")
	}
	for _, g := range []*gateway{f.a, f.b} {
		if _, err = g.client(t, server.AgentALPN, &cert).RenewCertificate(ctx, connect.NewRequest(&v1.RenewCertificateRequest{CsrPem: request})); err == nil {
			t.Fatal("deleted certificate accepted on gateway")
		}
	}
	if err = f.store.CheckIdentity(ctx, registered.Msg.Certificate.HostId, cert.Leaf.SerialNumber.Text(16)); err == nil {
		t.Fatal("deleted certificate still valid in store")
	}
	var last uint64
	if err = f.store.Pool.QueryRow(ctx, "SELECT max(seq) FROM audit_events").Scan(&last); err != nil {
		t.Fatal(err)
	}
	verified, err := chain.Verify(ctx, audit.VerifyOptions{From: 1, To: last})
	if err != nil || !verified.Valid {
		t.Fatal("CLI smoke audit chain invalid", err)
	}
	for _, operation := range []string{rpc.JoinTokenServiceCreateJoinTokenProcedure, rpc.HostServiceSetHostLabelsProcedure, rpc.CatalogServicePublishCatalogProcedure, rpc.HostServiceDeleteHostProcedure} {
		var before, after int
		if err = f.store.Pool.QueryRow(ctx, "SELECT count(*) FILTER(WHERE reason='authorized'),count(*) FILTER(WHERE reason='result' AND decision='allow') FROM audit_events WHERE operation=$1", operation).Scan(&before, &after); err != nil || before == 0 || before != after {
			t.Fatalf("audit %s authorized=%d result=%d error=%v", operation, before, after, err)
		}
	}
	t.Logf("CLI jointoken -> hosts list/label -> publisher catalog publish -> hosts delete; P7 verified %d events", verified.CheckedCount)
}

func waitReport(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("complete report persistence timed out")
}

func managementTLS(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "local gateway TLS CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := x509.ParseCertificate(root)
	pub, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(11), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	return tls.Certificate{Certificate: [][]byte{der, root}, PrivateKey: leafKey, Leaf: parsed}, roots
}
