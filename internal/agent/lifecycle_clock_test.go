package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Join returns a five-minute leaf already in its renewal window. Subsequent
// renewals use the fixture's usual lifetime and the same CA.
func newLifecycleAgent(t *testing.T) (*Agent, *testGateway, *httptest.Server) {
	t.Helper()
	gateway, server, config := startGateway(t, false)
	shortLivedJoin := func(ctx context.Context, req *connect.Request[v1.JoinRequest]) (*connect.Response[v1.JoinResponse], error) {
		res, err := gateway.Join(ctx, req)
		if err != nil {
			return nil, err
		}
		cert := res.Msg.Certificate
		block, chain := pem.Decode(cert.CertificateChainPem)
		if block == nil {
			return nil, errors.New("fixture Join returned no PEM certificate")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC().Truncate(time.Second)
		leaf.NotAfter = now.Add(5 * time.Minute)
		der, err := x509.CreateCertificate(rand.Reader, leaf, gateway.ca, leaf.PublicKey, gateway.key)
		if err != nil {
			return nil, err
		}
		cert.CertificateChainPem = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), chain...)
		cert.ExpiresAt, cert.RenewAfter = timestamppb.New(leaf.NotAfter), timestamppb.New(now)
		return res, nil
	}
	const join = allowopsv1connect.AgentServiceJoinProcedure
	server.Config.Handler.(*http.ServeMux).Handle(join, connect.NewUnaryHandler(join, shortLivedJoin))
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Join(t.Context(), config, "test-token", "test-host", dir); err != nil {
		t.Fatal(err)
	}
	a, err := New(config, Options{DataDir: dir, KeysDir: t.TempDir(), KeyOwner: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	return a, gateway, server
}

type pendingSleep struct {
	delay time.Duration
	wake  chan struct{}
}

type sleepRequests chan pendingSleep

func (requests sleepRequests) sleep(ctx context.Context, delay time.Duration) error {
	request := pendingSleep{delay: delay, wake: make(chan struct{})}
	select {
	case requests <- request:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-request.wake:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (requests sleepRequests) next(t *testing.T) pendingSleep {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not request a sleep")
		return pendingSleep{}
	}
}

// Cleanup joins Run while any unreleased sleeps are still pending.
func runWithControlledSleeps(t *testing.T, a *Agent) (sleepRequests, context.CancelFunc) {
	t.Helper()
	requests := make(sleepRequests)
	a.options.Sleep = requests.sleep
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Agent.Run returned %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Agent.Run did not return after cancellation")
		}
	})
	return requests, cancel
}

func TestAgentCertLifecycleRenewBeforeExpiry(t *testing.T) {
	a, gateway, server := newLifecycleAgent(t)
	original := a.identity.get()
	// Observe the verified client leaf on each Connect RPC while preserving
	// the fixture's mTLS checks and bidirectional stream handler.
	peers := make(chan []byte, 2)
	mux := server.Config.Handler.(*http.ServeMux)
	path := allowopsv1connect.AgentServiceConnectProcedure
	handler, _ := mux.Handler(httptest.NewRequest(http.MethodPost, path, nil))
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
			select {
			case peers <- r.TLS.VerifiedChains[0][0].Raw:
			case <-r.Context().Done():
				return
			}
		}
		handler.ServeHTTP(w, r)
	})
	connectWith := func(identity Identity) {
		t.Helper()
		connection(t, gateway)
		leaf, _ := pem.Decode(identity.Certificate)
		select {
		case presented := <-peers:
			if leaf == nil || !bytes.Equal(presented, leaf.Bytes) {
				t.Fatal("Connect presented a different client certificate than the one on disk")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Connect did not present a verified client certificate")
		}
	}

	waits, _ := runWithControlledSleeps(t, a)
	connectWith(original)
	first := waits.next(t)
	if first.delay != time.Second || gateway.renewals.Load() != 0 {
		t.Fatalf("before renewal: delay=%s RPCs=%d, want 1s and 0 RPCs", first.delay, gateway.renewals.Load())
	}
	close(first.wake)
	// The next renewal sleep is requested after saving and installing the response.
	next := waits.next(t)
	renewed, err := LoadIdentity(a.options.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if gateway.renewals.Load() != 1 || bytes.Equal(original.Certificate, renewed.Certificate) || !renewed.ExpiresAt.After(original.ExpiresAt) {
		t.Fatalf("renewal RPCs=%d old expiry=%s new expiry=%s", gateway.renewals.Load(), original.ExpiresAt, renewed.ExpiresAt)
	}
	if next.delay <= original.ExpiresAt.Sub(original.RenewAfter) || next.delay > renewed.RenewAfter.Sub(original.RenewAfter) {
		t.Fatalf("next renewal sleep=%s, new renew_after=%s", next.delay, renewed.RenewAfter)
	}
	// Disconnect the active stream. Run enters backoff only after observing the
	// transport failure, so its next connection must perform a fresh handshake.
	server.CloseClientConnections()
	reconnect := waits.next(t)
	close(reconnect.wake)
	connectWith(renewed)
}

func TestAgentCertLifecycleExpiredExit(t *testing.T) {
	a, _, server := newLifecycleAgent(t)
	expires := a.identity.get().ExpiresAt
	server.Close()
	synctest.Test(t, func(t *testing.T) {
		// A renewal attempt after 1s hits the offline gateway. Only 500ms
		// remain, less than even the minimum retry backoff.
		synctest.Sleep(time.Until(expires.Add(-1500 * time.Millisecond)))
		var waitedUntilExpiry atomic.Bool
		a.options.Sleep = func(ctx context.Context, delay time.Duration) error {
			if delay == 500*time.Millisecond && time.Now().Add(delay).Equal(expires) {
				waitedUntilExpiry.Store(true)
			}
			return sleep(ctx, delay)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- a.Run(ctx) }()

		synctest.Sleep(time.Until(expires) - time.Nanosecond)
		select {
		case err := <-done:
			t.Fatalf("Agent.Run returned before certificate expiry: %v", err)
		default:
		}
		synctest.Sleep(time.Nanosecond)
		select {
		case err := <-done:
			if err == nil || !strings.HasPrefix(err.Error(), "CERTIFICATE_EXPIRED") {
				t.Fatalf("Agent.Run at expiry: %v, want CERTIFICATE_EXPIRED prefix", err)
			}
		default:
			t.Fatal("Agent.Run was still running at certificate expiry")
		}
		if !waitedUntilExpiry.Load() {
			t.Fatal("offline renewal did not cap its retry sleep to the remaining 500ms")
		}
	})
}

func TestAgentReconnectBackoffBoundsAndCancel(t *testing.T) {
	h := newSessionHarness(t, Limits{})
	allowFailures := make(chan struct{})
	ctx := t.Context()
	var failures atomic.Int32
	h.g.mu.Lock()
	h.g.hello = func() (*v1.ConnectResponse, error) {
		select {
		case <-allowFailures:
			failures.Add(1)
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("gateway unavailable"))
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	h.g.mu.Unlock()
	waits, cancel := runWithControlledSleeps(t, h.a)
	// Hold the long-lived certificate's renewal sleep before failing any
	// sessions, so every subsequent request is a reconnect delay.
	_ = waits.next(t)
	close(allowFailures)
	const attempts = 7
	for i := range attempts {
		wait := waits.next(t)
		upper := min(time.Second<<(i+1), 30*time.Second)
		if got := failures.Load(); got != int32(i+1) {
			t.Fatalf("backoff %d: gateway saw %d failed sessions, want %d", i+1, got, i+1)
		}
		if wait.delay < time.Second || wait.delay > upper {
			t.Fatalf("backoff %d: delay=%s outside [1s, %s]", i+1, wait.delay, upper)
		}
		if i+1 < attempts {
			close(wait.wake)
		}
	}
	// Neither the last reconnect sleep nor the renewal sleep has been released.
	cancel()
}
