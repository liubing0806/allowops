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
	"errors"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/server"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"golang.org/x/net/http2"
)

type gateway struct {
	server  *server.Server
	service *hostconn.Service
	address string
	roots   *x509.CertPool
}

type fixture struct {
	store       *store.Store
	ca          *hostconn.CA
	a, b        *gateway
	catalogs    *catalogsvc.Service
	signer      ed25519.PrivateKey
	events      chan hostconn.Event
	disconnects chan hostconn.Event
}

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	dir := t.TempDir()
	ca, err := hostconn.OpenCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{store: s, ca: ca, events: make(chan hostconn.Event, 128), disconnects: make(chan hostconn.Event, 128)}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	f.signer = key
	f.catalogs = &catalogsvc.Service{Store: s, Trusted: map[string]ed25519.PublicKey{catalog.KeyID(pub): pub}, MaxEnvelopeBytes: 64 << 20, MaxActionBytes: 256 << 10}
	f.a = f.start(t)
	f.b = f.start(t)
	return f
}

func (f *fixture) start(t *testing.T) *gateway {
	t.Helper()
	config := hostconn.DefaultConfig()
	config.Version = "2.3.4"
	config.HeartbeatInterval = 100 * time.Millisecond
	// Fixture clients send heartbeats explicitly, without a periodic loop.
	// Allow slow race-enabled protocol flows; expiry tests set a short timeout.
	config.HeartbeatTimeout = 30 * time.Second
	config.CleanupInterval = 100 * time.Millisecond
	config.FlushInterval = 100 * time.Millisecond
	agent, err := hostconn.New(f.store, f.ca, config, hostconn.Hooks{OnMessage: func(ctx context.Context, e hostconn.Event) error {
		select {
		case f.events <- e:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, OnDisconnect: func(e hostconn.Event) { f.disconnects <- e }})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	tlsCert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	roots.AddCert(parsed)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(agent, tlsCert)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return &gateway{srv, agent, listener.Addr().String(), roots}
}

func (g *gateway) client(t *testing.T, protocol string, certificate *tls.Certificate) allowopsv1connect.AgentServiceClient {
	t.Helper()
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: g.roots, NextProtos: []string{protocol}}
	if certificate != nil {
		config.Certificates = []tls.Certificate{*certificate}
	}
	//lint:ignore SA1019 Raw HTTP/2 transport is needed to test custom ALPN; standard Transport selects HTTP/2 only for h2.
	transport := &http2.Transport{DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
		d := tls.Dialer{Config: config}
		return d.DialContext(ctx, network, address)
	}}
	//lint:ignore SA1019 Close the custom ALPN test transport.
	t.Cleanup(transport.CloseIdleConnections)
	return allowopsv1connect.NewAgentServiceClient(&http.Client{Transport: transport}, "https://"+g.address, connect.WithGRPC())
}

func csr(t *testing.T) ([]byte, []byte) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "admin"}, DNSNames: []string{"forged"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func (f *fixture) join(t *testing.T, g *gateway, name string) (*v1.HostCertificate, tls.Certificate) {
	t.Helper()
	token, err := g.service.CreateJoinToken(context.Background(), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	csr, key := csr(t)
	res, err := g.client(t, server.JoinALPN, nil).Join(context.Background(), connect.NewRequest(&v1.JoinRequest{JoinToken: token, Hostname: name, CsrPem: csr}))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(res.Msg.Certificate.CertificateChainPem, key)
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg.Certificate, cert
}

func open(t *testing.T, g *gateway, cert tls.Certificate, version string) (*connect.BidiStreamForClient[v1.ConnectRequest, v1.ConnectResponse], *v1.GatewayHello) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream := g.client(t, server.AgentALPN, &cert).Connect(ctx)
	if err := stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Hello{Hello: &v1.AgentHello{AgentVersion: version, MaxConcurrentTasks: 4}}}); err != nil {
		t.Fatal(err)
	}
	res, err := stream.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if res.GetHello() == nil {
		t.Fatalf("first gateway frame=%T", res.Message)
	}
	t.Cleanup(func() { stream.CloseRequest(); stream.CloseResponse() })
	return stream, res.GetHello()
}

func receive(t *testing.T, stream *connect.BidiStreamForClient[v1.ConnectRequest, v1.ConnectResponse]) *v1.ConnectResponse {
	t.Helper()
	type result struct {
		r *v1.ConnectResponse
		e error
	}
	ch := make(chan result, 1)
	go func() { r, e := stream.Receive(); ch <- result{r, e} }()
	select {
	case res := <-ch:
		if res.e != nil {
			t.Fatal(res.e)
		}
		return res.r
	case <-time.After(5 * time.Second):
		t.Fatal("receive timeout")
		return nil
	}
}

func expectCode(t *testing.T, err error, code connect.Code) {
	t.Helper()
	if connect.CodeOf(err) != code {
		t.Fatalf("RPC code=%s (%v), want %s", connect.CodeOf(err), err, code)
	}
}

func TestHeartbeatTimeout(t *testing.T) {
	f := setup(t)
	const timeout = time.Second
	// This fixture has no active streams yet. Heartbeat expiry is tested with
	// an explicit short timeout rather than the shared fixture default.
	f.b.service.Config.HeartbeatTimeout = timeout
	_, cert := f.join(t, f.a, "heartbeat-expiry")
	stream, hello := open(t, f.b, cert, "2.3.4")
	if got := hello.Limits.HeartbeatTimeout.AsDuration(); got != timeout {
		t.Fatalf("advertised heartbeat timeout=%v, want %v", got, timeout)
	}
	done := make(chan error, 1)
	go func() { _, err := stream.Receive(); done <- err }()
	select {
	case err := <-done:
		expectCode(t, err, connect.CodeDeadlineExceeded)
		if !strings.Contains(err.Error(), "heartbeat timeout") {
			t.Fatalf("idle stream error=%v, want heartbeat timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("idle stream did not expire at its short heartbeat timeout")
	}
}

func TestTwoGatewayEndToEnd(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	t.Run("join_limits_expiry_duplicates", func(t *testing.T) {
		client := f.a.client(t, server.JoinALPN, nil)
		request, key := csr(t)
		_ = key
		token, err := f.a.service.CreateJoinToken(ctx, 2, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		join := func(name string) error {
			_, err := client.Join(ctx, connect.NewRequest(&v1.JoinRequest{JoinToken: token, Hostname: name, CsrPem: request}))
			return err
		}
		if err := join("same"); err != nil {
			t.Fatal(err)
		}
		expectCode(t, join("same"), connect.CodeAlreadyExists)
		if err := join("second"); err != nil {
			t.Fatalf("duplicate consumed use: %v", err)
		}
		expectCode(t, join("third"), connect.CodeUnauthenticated)
		token, err = f.a.service.CreateJoinToken(ctx, 1, time.Nanosecond)
		if err != nil {
			t.Fatal(err)
		}
		expectCode(t, join("expired"), connect.CodeUnauthenticated)
		token, err = f.a.service.CreateJoinToken(ctx, 1, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.RevokeJoinToken(ctx, token); err != nil {
			t.Fatal(err)
		}
		expectCode(t, join("revoked"), connect.CodeUnauthenticated)
	})
	t.Run("mtls_renew_delete", func(t *testing.T) {
		host, certificate := f.join(t, f.a, "renewable")
		csr, key := csr(t)
		foreignDir := t.TempDir()
		foreignCA, err := hostconn.OpenCA(filepath.Join(foreignDir, "ca.pem"), filepath.Join(foreignDir, "ca.key"))
		if err != nil {
			t.Fatal(err)
		}
		foreign, err := foreignCA.Issue(host.HostId, csr, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		foreignCert, err := tls.X509KeyPair(foreign.PEM, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.a.client(t, server.AgentALPN, &foreignCert).RenewCertificate(ctx, connect.NewRequest(&v1.RenewCertificateRequest{CsrPem: csr})); err == nil {
			t.Fatal("foreign CA certificate accepted")
		}
		_, err = f.a.client(t, server.AgentALPN, nil).RenewCertificate(ctx, connect.NewRequest(&v1.RenewCertificateRequest{CsrPem: csr}))
		if err == nil {
			t.Fatal("mTLS accepted absent certificate")
		}
		_, err = f.a.client(t, server.JoinALPN, nil).RenewCertificate(ctx, connect.NewRequest(&v1.RenewCertificateRequest{CsrPem: csr}))
		expectCode(t, err, connect.CodeUnimplemented)
		_, err = f.a.client(t, server.AgentALPN, &certificate).Join(ctx, connect.NewRequest(&v1.JoinRequest{}))
		if err == nil {
			t.Fatal("Join accessible on mTLS ALPN")
		}
		response, err := f.a.client(t, server.AgentALPN, &certificate).RenewCertificate(ctx, connect.NewRequest(&v1.RenewCertificateRequest{CsrPem: csr}))
		if err != nil {
			t.Fatal(err)
		}
		if response.Msg.Certificate.HostId != host.HostId || bytes.Equal(response.Msg.Certificate.CertificateChainPem, host.CertificateChainPem) {
			t.Fatal("renewal did not preserve identity with new certificate")
		}
		newCertificate, err := tls.X509KeyPair(response.Msg.Certificate.CertificateChainPem, key)
		if err != nil {
			t.Fatal(err)
		}
		stream, _ := open(t, f.b, newCertificate, "2.3.4")
		if err := f.store.DeleteHost(ctx, host.HostId); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Receive(); err == nil {
			t.Fatal("deleted host connection survived")
		}
		for _, g := range []*gateway{f.a, f.b} {
			_, err := g.client(t, server.AgentALPN, &newCertificate).RenewCertificate(ctx, connect.NewRequest(&v1.RenewCertificateRequest{CsrPem: csr}))
			if err == nil {
				t.Fatal("deleted certificate renewed")
			}
			c := g.client(t, server.AgentALPN, &newCertificate).Connect(ctx)
			_ = c.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Hello{Hello: &v1.AgentHello{AgentVersion: "2.3.4", MaxConcurrentTasks: 1}}})
			if _, err := c.Receive(); err == nil {
				t.Fatal("deleted certificate reconnected")
			}
			c.CloseResponse()
		}
		newHost, _ := f.join(t, f.a, "renewable")
		if newHost.HostId == host.HostId {
			t.Fatal("deleted hostname reused identity")
		}
	})
	t.Run("cross_instance_notify_and_replacement", func(t *testing.T) {
		host, cert := f.join(t, f.a, "routed")
		old, hello := open(t, f.b, cert, "2.3.4")
		type result struct {
			v *v1.TaskCompleted
			e error
		}
		ch := make(chan result, 1)
		request := &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{TaskId: "first", Reason: strings.Repeat("x", 20000)}}}
		go func() { v, e := f.a.service.Send(ctx, host.HostId, request); ch <- result{v, e} }()
		msg := receive(t, old)
		if msg.GetCancel() == nil || msg.GetCancel().TaskId != "first" || len(msg.GetCancel().Reason) != 20000 {
			t.Fatalf("wrong dispatch: %T", msg.Message)
		}
		if err := old.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Output{Output: &v1.TaskOutputChunk{TaskId: "first", Data: []byte("owner-only-output")}}}); err != nil {
			t.Fatal(err)
		}
		if err := old.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_TaskCompleted{TaskCompleted: &v1.TaskCompleted{TaskId: "first"}}}); err != nil {
			t.Fatal(err)
		}
		select {
		case r := <-ch:
			if r.e != nil || r.v.TaskId != "first" {
				t.Fatalf("route result=%v, %v", r.v, r.e)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("route result timeout")
		}
		select {
		case e := <-f.events:
			if e.Message.GetOutput() == nil {
				t.Fatalf("owner output hook=%T", e.Message.Message)
			}
		case <-time.After(time.Second):
			t.Fatal("missing owner output hook")
		}
		fresh, newHello := open(t, f.a, cert, "2.3.4")
		if newHello.ConnectionId == hello.ConnectionId {
			t.Fatal("generation unchanged")
		}
		if _, err := old.Receive(); err == nil {
			t.Fatal("old connection not replaced")
		}
		// Model slow test work with no periodic heartbeat before dispatch.
		time.Sleep(4 * time.Second)
		request = &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{TaskId: "second"}}}
		go func() { v, e := f.b.service.Send(ctx, host.HostId, request); ch <- result{v, e} }()
		if m := receive(t, fresh); m.GetCancel() == nil || m.GetCancel().TaskId != "second" {
			t.Fatalf("new connection message=%T", m.Message)
		}
		if err := fresh.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_TaskCompleted{TaskCompleted: &v1.TaskCompleted{TaskId: "second"}}}); err != nil {
			t.Fatal(err)
		}
		select {
		case r := <-ch:
			if r.e != nil {
				t.Fatal(r.e)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("new route timeout")
		}
	})
	t.Run("catalog_chunks_signature_rollback_and_report", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		host, cert := f.join(t, f.a, "catalog-host")
		stream, _ := open(t, f.b, cert, "2.3.4")
		raw := f.signed(t, "main", time.Now(), "diagnose")
		limited := *f.catalogs
		limited.MaxReferenceBytes = 3
		if _, err := limited.Publish(ctx, raw); err == nil {
			t.Fatal("catalog reference exceeded tightened transport limit")
		}
		pkg, err := f.catalogs.Publish(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		available := receive(t, stream).GetCatalogAvailable()
		if available == nil || available.Catalog.CatalogId != "main" {
			t.Fatalf("catalog notification=%v", available)
		}
		client := f.b.client(t, server.AgentALPN, &cert)
		pull, err := client.PullCatalog(ctx, connect.NewRequest(&v1.PullCatalogRequest{Catalog: available.Catalog}))
		if err != nil {
			t.Fatal(err)
		}
		var joined []byte
		chunks, eof := 0, 0
		for pull.Receive() {
			m := pull.Msg()
			if m.Offset != uint64(len(joined)) || len(m.Data) > 64<<10 {
				t.Fatalf("bad chunk offset=%d size=%d", m.Offset, len(m.Data))
			}
			joined = append(joined, m.Data...)
			chunks++
			if m.Eof {
				eof++
			}
		}
		if err := pull.Err(); err != nil {
			t.Fatal(err)
		}
		pull.Close()
		if !bytes.Equal(joined, raw) || chunks < 2 || eof != 1 {
			t.Fatalf("raw bytes match=%v chunks=%d eof=%d", bytes.Equal(joined, raw), chunks, eof)
		}
		envelope, _ := catalog.ParseEnvelope(joined)
		if _, err := catalog.Verify(envelope, f.catalogs.Trusted, catalog.VerifyOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.catalogs.Publish(ctx, raw); !errors.Is(err, store.ErrRollback) {
			t.Fatalf("same version=%v", err)
		}
		older := f.signed(t, "main", time.Now().Add(-time.Minute), "diagnose")
		if _, err := f.catalogs.Publish(ctx, older); !errors.Is(err, store.ErrRollback) {
			t.Fatalf("rollback=%v", err)
		}
		tampered := append([]byte(nil), raw...)
		tampered = bytes.Replace(tampered, []byte("application/vnd.allowops.catalog.v1+json"), []byte("application/vnd.allowops.catalog.v2+json"), 1)
		if _, err := f.catalogs.Publish(ctx, tampered); err == nil {
			t.Fatal("tampered envelope published")
		}
		wrongSigner := *f
		_, wrongSigner.signer, _ = ed25519.GenerateKey(rand.Reader)
		if _, err := f.catalogs.Publish(ctx, wrongSigner.signed(t, "untrusted", time.Now(), "other")); err == nil {
			t.Fatal("untrusted signature published")
		}
		if _, err := f.catalogs.Publish(ctx, f.signed(t, "conflict", time.Now(), "diagnose")); !errors.Is(err, store.ErrActionConflict) {
			t.Fatalf("action conflict=%v", err)
		}
		ref := &v1.CatalogRef{CatalogId: pkg.CatalogID, Version: uint64(pkg.Version)}
		if err := stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_CatalogLoad{CatalogLoad: &v1.CatalogLoadReport{Catalog: ref, ReportId: "load", Loaded: true}}}); err != nil {
			t.Fatal(err)
		}
		heartbeat(t, stream, 1)
		if f.b.service.CatalogReport(host.HostId, "main") != nil {
			t.Fatal("partial load report accepted")
		}
		if err := stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_CatalogLoad{CatalogLoad: &v1.CatalogLoadReport{Catalog: ref, ReportId: "load", Loaded: true, PageIndex: 1, FinalPage: true}}}); err != nil {
			t.Fatal(err)
		}
		// The ordered heartbeat acknowledgement follows processing the report.
		heartbeat(t, stream, 2)
		if f.b.service.CatalogReport(host.HostId, "main") == nil {
			t.Fatal("complete load report missing")
		}
		// Model verification work delayed beyond the former 3s fixture heartbeat
		// timeout. This test client does not run an agent heartbeat loop.
		time.Sleep(4 * time.Second)
		updated, err := f.catalogs.Publish(ctx, f.signed(t, "main", time.Now().Add(time.Second), "diagnose"))
		if err != nil {
			t.Fatal(err)
		}
		if m := receive(t, stream).GetCatalogAvailable(); m == nil || m.Catalog.Version != uint64(updated.Version) {
			t.Fatalf("update notification=%v", m)
		}
	})
	t.Run("mailbox_limits_expiry_and_disconnect", func(t *testing.T) {
		host, cert := f.join(t, f.a, "mailbox-host")
		stream, hello := open(t, f.b, cert, "2.3.4")
		if receive(t, stream).GetCatalogAvailable() == nil {
			t.Fatal("missing initial catalog")
		}
		f.a.service.Config.MailboxRows = 1
		defer func() { f.a.service.Config.MailboxRows = 1024 }()
		waiting := make(chan error, 1)
		sendCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		go func() {
			_, err := f.a.service.Send(sendCtx, host.HostId, &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{TaskId: "pending"}}})
			waiting <- err
		}()
		if receive(t, stream).GetCancel() == nil {
			t.Fatal("pending request not delivered")
		}
		_, err := f.a.service.Send(ctx, host.HostId, &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{TaskId: "capacity"}}})
		if !errors.Is(err, store.ErrCapacity) {
			t.Fatalf("row capacity=%v", err)
		}
		f.b.service.Config.MailboxBytes = 2 << 20
		_, err = f.b.service.Send(ctx, host.HostId, &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{TaskId: "byte-capacity"}}})
		f.b.service.Config.MailboxBytes = 64 << 20
		if !errors.Is(err, store.ErrCapacity) {
			t.Fatalf("byte capacity=%v", err)
		}
		if err := stream.CloseResponse(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-waiting:
			if !errors.Is(err, store.ErrOffline) {
				t.Fatalf("disconnect result=%v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("disconnect not propagated to sender")
		}
		found := false
		deadline := time.After(time.Second)
		for !found {
			select {
			case e := <-f.disconnects:
				found = e.HostID == host.HostId && e.ConnectionID == hello.ConnectionId
			case <-deadline:
				t.Fatal("disconnect hook not delivered")
			}
		}
		var rows int
		if err := f.store.Pool.QueryRow(ctx, "SELECT count(*) FROM gateway_messages").Scan(&rows); err != nil || rows != 0 {
			t.Fatalf("messages after disconnect=%d, err=%v", rows, err)
		}
		_, err = f.store.Pool.Exec(ctx, "INSERT INTO gateway_messages(message_id,origin_instance,host_id,connection_id,request,expires_at) VALUES ('orphan',$1,$2,'old','x',now()-interval '1 second')", f.a.service.InstanceID, host.HostId)
		if err != nil {
			t.Fatal(err)
		}
		until := time.Now().Add(time.Second)
		for time.Now().Before(until) {
			if err := f.store.Pool.QueryRow(ctx, "SELECT count(*) FROM gateway_messages WHERE message_id='orphan'").Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if rows == 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if rows != 0 {
			t.Fatal("expired crash residue not cleaned")
		}
	})
	t.Run("cancel_running_message", func(t *testing.T) {
		host, cert := f.join(t, f.a, "cancel-host")
		stream, _ := open(t, f.b, cert, "2.3.4")
		receive(t, stream)
		// Delay before starting the task context, isolating heartbeat expiry.
		time.Sleep(4 * time.Second)
		errCh := make(chan error, 2)
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		go func() {
			_, err := f.a.service.Send(cctx, host.HostId, &v1.ConnectResponse{Message: &v1.ConnectResponse_Task{Task: &v1.TaskAssignment{TaskId: "active"}}})
			errCh <- err
		}()
		if receive(t, stream).GetTask() == nil {
			t.Fatal("assignment not received")
		}
		go func() {
			_, err := f.a.service.Send(cctx, host.HostId, &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{TaskId: "active"}}})
			errCh <- err
		}()
		if receive(t, stream).GetCancel() == nil {
			t.Fatal("active cancellation not received")
		}
		if err := stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_TaskCompleted{TaskCompleted: &v1.TaskCompleted{TaskId: "active"}}}); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("version_rejection", func(t *testing.T) {
		_, cert := f.join(t, f.a, "version-host")
		for _, version := range []string{"2.3.5", "3.0.0", "0.9.0", "2.03.4"} {
			c := f.a.client(t, server.AgentALPN, &cert).Connect(ctx)
			if err := c.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Hello{Hello: &v1.AgentHello{AgentVersion: version, MaxConcurrentTasks: 1}}}); err != nil {
				t.Fatal(err)
			}
			_, err := c.Receive()
			expectCode(t, err, connect.CodeUnimplemented)
			c.CloseResponse()
		}
		open(t, f.a, cert, "1.99.0")
	})
	t.Run("heartbeat_and_input_limits", func(t *testing.T) {
		_, cert := f.join(t, f.a, "heartbeat-host")
		stream, _ := open(t, f.a, cert, "2.3.4")
		receive(t, stream)
		if err := stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Heartbeat{Heartbeat: &v1.AgentHeartbeat{Sequence: 1}}}); err != nil {
			t.Fatal(err)
		}
		if m := receive(t, stream).GetHeartbeat(); m == nil || m.Sequence != 1 {
			t.Fatalf("heartbeat ack=%v", m)
		}
		if err := stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Output{Output: &v1.TaskOutputChunk{Data: make([]byte, 65537)}}}); err != nil {
			t.Fatal(err)
		}
		_, err := stream.Receive()
		expectCode(t, err, connect.CodeResourceExhausted)
	})
	t.Run("graceful_reconnect", func(t *testing.T) {
		host, cert := f.join(t, f.a, "drain-host")
		stream, _ := open(t, f.a, cert, "2.3.4")
		// The current catalog is announced immediately after Hello.
		if receive(t, stream).GetCatalogAvailable() == nil {
			t.Fatal("missing initial catalog")
		}
		done := make(chan error, 1)
		go func() {
			drain, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			done <- f.a.service.Drain(drain)
		}()
		m := receive(t, stream).GetReconnect()
		if m == nil || m.RetryAfterMin.AsDuration() < time.Second || m.RetryAfterMax.AsDuration() > 30*time.Second {
			t.Fatalf("Reconnect=%v", m)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if _, err := f.a.service.Send(ctx, host.HostId, &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{TaskId: "draining"}}}); !errors.Is(err, store.ErrOffline) {
			t.Fatalf("dispatch during drain=%v", err)
		}
		open(t, f.b, cert, "2.3.4")
	})
}

func (f *fixture) signed(t *testing.T, id string, now time.Time, name string) []byte {
	t.Helper()
	action := catalog.Action{Name: name, Description: strings.Repeat("diagnostic ", 10000), Risk: "read", Exec: []any{"/usr/bin/true"}, Timeout: "1s", MaxOutput: 1024}
	p, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: id}, Actions: map[string]catalog.Action{name: action}}, catalog.BuildOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := catalog.CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	e, err := catalog.Sign(payload, catalog.SigningKey{PrivateKey: f.signer})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func TestALPNConsoleAndMCP(t *testing.T) {
	f := setup(t)
	for _, protocol := range []string{"h2", "http/1.1", server.MCPALPN} {
		t.Run(protocol, func(t *testing.T) {
			config := &tls.Config{RootCAs: f.a.roots, NextProtos: []string{protocol}, MinVersion: tls.VersionTLS13}
			conn, err := tls.Dial("tcp", f.a.address, config)
			if err != nil {
				t.Fatal(err)
			}
			if conn.ConnectionState().NegotiatedProtocol != protocol {
				t.Fatal("wrong ALPN")
			}
			conn.Close()
		})
	}
}
