package server_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/server"
)

func heartbeat(t *testing.T, stream *connect.BidiStreamForClient[v1.ConnectRequest, v1.ConnectResponse], sequence uint64) {
	t.Helper()
	if err := stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Heartbeat{Heartbeat: &v1.AgentHeartbeat{Sequence: sequence}}}); err != nil {
		t.Fatalf("existing stream heartbeat send: %v", err)
	}
	if response := receive(t, stream).GetHeartbeat(); response == nil || response.Sequence != sequence {
		t.Fatalf("existing stream heartbeat=%v, want sequence %d", response, sequence)
	}
}

func expectClosed(t *testing.T, stream *connect.BidiStreamForClient[v1.ConnectRequest, v1.ConnectResponse]) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := stream.Receive(); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("connection remained open")
		}
		return err
	case <-time.After(time.Second):
		t.Fatal("connection did not close within one second")
		return nil
	}
}

func TestRenewalConnectionLifecycle(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	t.Run("preserve_inflight_replace_and_delete", func(t *testing.T) {
		host, cert := f.join(t, f.a, "renew-stream")
		client := f.a.client(t, server.AgentALPN, &cert)
		old := client.Connect(ctx)
		t.Cleanup(func() { old.CloseRequest(); old.CloseResponse() })
		if err := old.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Hello{Hello: &v1.AgentHello{AgentVersion: "2.3.4", MaxConcurrentTasks: 4}}}); err != nil {
			t.Fatal(err)
		}
		if receive(t, old).GetHello() == nil {
			t.Fatal("missing GatewayHello")
		}
		result := make(chan error, 1)
		go func() {
			_, err := f.b.service.Send(ctx, host.HostId, &v1.ConnectResponse{Message: &v1.ConnectResponse_Task{Task: &v1.TaskAssignment{TaskId: "renew-inflight"}}})
			result <- err
		}()
		if receive(t, old).GetTask() == nil {
			t.Fatal("missing in-flight assignment")
		}
		request, key := csr(t)
		renewed, err := client.RenewCertificate(ctx, connect.NewRequest(&v1.RenewCertificateRequest{CsrPem: request}))
		if err != nil {
			t.Fatal(err)
		}
		// The same HTTP/2 TLS session must reject later RPCs using the old leaf.
		_, err = client.RenewCertificate(ctx, connect.NewRequest(&v1.RenewCertificateRequest{CsrPem: request}))
		expectCode(t, err, connect.CodeUnauthenticated)
		for _, g := range []*gateway{f.a, f.b} {
			config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: g.roots, NextProtos: []string{server.AgentALPN}, Certificates: []tls.Certificate{cert}}
			dialer := tls.Dialer{Config: config}
			conn, err := dialer.DialContext(ctx, "tcp", g.address)
			if err == nil {
				conn.SetReadDeadline(time.Now().Add(time.Second))
				_, err = conn.Read(make([]byte, 1))
				conn.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "tls:") {
				t.Fatalf("old certificate TLS handshake error=%v, want TLS rejection", err)
			}
		}
		// Cross two identity-check ticks; renewal must not disconnect this stream.
		time.Sleep(250 * time.Millisecond)
		heartbeat(t, old, 1)
		if err := old.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_TaskCompleted{TaskCompleted: &v1.TaskCompleted{TaskId: "renew-inflight"}}}); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			if err != nil {
				t.Fatalf("in-flight result after renewal: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("missing in-flight result")
		}
		newCert, err := tls.X509KeyPair(renewed.Msg.Certificate.CertificateChainPem, key)
		if err != nil {
			t.Fatal(err)
		}
		current, _ := open(t, f.b, newCert, "2.3.4")
		expectCode(t, expectClosed(t, old), connect.CodeUnavailable)
		// Renew again while the latest connection remains established, then delete
		// from the other instance. No old or current stream may survive deletion.
		request, _ = csr(t)
		if _, err := f.a.client(t, server.AgentALPN, &newCert).RenewCertificate(ctx, connect.NewRequest(&v1.RenewCertificateRequest{CsrPem: request})); err != nil {
			t.Fatal(err)
		}
		time.Sleep(250 * time.Millisecond)
		heartbeat(t, current, 1)
		if err := f.store.DeleteHost(ctx, host.HostId); err != nil {
			t.Fatal(err)
		}
		expectClosed(t, current)
	})
	t.Run("original_certificate_expiry", func(t *testing.T) {
		request, key := csr(t)
		token, err := f.a.service.CreateJoinToken(ctx, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		var issued *hostconn.IssuedCertificate
		id, err := f.store.Register(ctx, token, "short-renew-stream", func(id string) (string, time.Time, error) {
			var err error
			issued, err = f.ca.Issue(id, request, 3*time.Second)
			if err != nil {
				return "", time.Time{}, err
			}
			return issued.Serial, issued.ExpiresAt, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		cert, err := tls.X509KeyPair(issued.PEM, key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		old, _ := open(t, f.a, cert, "2.3.4")
		request, _ = csr(t)
		if err := f.store.Renew(ctx, id, issued.Serial, func() (string, time.Time, error) {
			renewed, err := f.ca.Issue(id, request, time.Hour)
			if err != nil {
				return "", time.Time{}, err
			}
			return renewed.Serial, renewed.ExpiresAt, nil
		}); err != nil {
			t.Fatal(err)
		}
		// Keep sending heartbeats so certificate expiry, rather than heartbeat
		// timeout, is what closes this otherwise live connection.
		sendCtx, stop := context.WithCancel(ctx)
		defer stop()
		go func() {
			tick := time.NewTicker(100 * time.Millisecond)
			defer tick.Stop()
			var sequence uint64
			for {
				select {
				case <-sendCtx.Done():
					return
				case <-tick.C:
					sequence++
					if old.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Heartbeat{Heartbeat: &v1.AgentHeartbeat{Sequence: sequence}}}) != nil {
						return
					}
				}
			}
		}()
		for {
			_, err := old.Receive()
			if err != nil {
				if time.Now().Before(leaf.NotAfter) {
					t.Fatalf("stream closed before original certificate expiry: %v", err)
				}
				expectCode(t, err, connect.CodeUnauthenticated)
				break
			}
		}
	})
}
