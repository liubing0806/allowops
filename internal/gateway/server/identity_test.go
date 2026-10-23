package server_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/api"
	auditstore "github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/server"
)

type identityAudit struct {
	mu     sync.Mutex
	events []api.AuditEvent
}

func (a *identityAudit) Append(_ context.Context, e api.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}

func TestIdentityMountedOnP4TLS(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	audit := &identityAudit{}
	identity, err := api.New(ctx, f.store, api.Config{Origin: "https://" + address}, audit)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	agent, err := hostconn.New(f.store, f.ca, hostconn.DefaultConfig(), hostconn.Hooks{})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	if err := agent.Start(ctx); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	native := server.New(agent, f.a.server.TLS.Certificates[0], server.WithIdentity(identity), server.WithAudit(&auditstore.Service{Store: auditstore.New(f.store.Pool, auditstore.Config{})}))
	if _, err := native.Audit.Store.Append(ctx, auditstore.Payload{SubjectID: "fixture", Operation: "fixture", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- native.Serve(listener) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := native.Shutdown(shutdown); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	if _, err := f.store.Pool.Exec(ctx, "INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username) VALUES ('owner','fixture','owner','ldap','owner')"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, "INSERT INTO service_accounts(account_id,name,owner_user_id,roles) VALUES ('fixture','fixture','owner',ARRAY['admin'])"); err != nil {
		t.Fatal(err)
	}
	raw, record, err := authn.GenerateServiceToken(time.Now(), 30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, "INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES ('fixture','fixture',$1,$2)", record.Hash[:], record.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	for _, http2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP1", true: "HTTP2"}[http2], func(t *testing.T) {
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.a.roots, MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: http2}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			login := rpc.NewAuthServiceClient(client, "https://"+address)
			if _, err := login.GetLoginMethods(ctx, connect.NewRequest(&v1.GetLoginMethodsRequest{})); err != nil {
				t.Fatal(err)
			}
			policy := rpc.NewPolicyServiceClient(client, "https://"+address)
			request := connect.NewRequest(&v1.GetPolicyRequest{})
			request.Header().Set("Authorization", "Bearer "+raw)
			request.Header().Set("X-Forwarded-For", "198.51.100.1")
			response, err := policy.GetPolicy(ctx, request)
			if err != nil || response.Msg.Policy.Version != 1 {
				t.Fatalf("P4 mounted policy: error=%v", err)
			}
			auditClient := rpc.NewAuditServiceClient(client, "https://"+address)
			verify := connect.NewRequest(&v1.VerifyAuditRequest{FromSeq: 1, ToSeq: 1})
			verify.Header().Set("Authorization", "Bearer "+raw)
			verified, err := auditClient.VerifyAudit(ctx, verify)
			if err != nil || !verified.Msg.GetValid() {
				t.Fatalf("P7 authenticated verification: %v", err)
			}
			if _, err := auditClient.VerifyAudit(ctx, connect.NewRequest(&v1.VerifyAuditRequest{FromSeq: 1, ToSeq: 1})); connect.CodeOf(err) != connect.CodeUnauthenticated {
				t.Fatalf("anonymous audit verification: %v", err)
			}
			if _, err := f.store.Pool.Exec(ctx, "UPDATE service_accounts SET roles=ARRAY['viewer'] WHERE account_id='fixture'"); err != nil {
				t.Fatal(err)
			}
			if _, err := auditClient.VerifyAudit(ctx, verify); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("viewer audit verification: %v", err)
			}
			if _, err := f.store.Pool.Exec(ctx, "UPDATE service_accounts SET roles=ARRAY['admin'] WHERE account_id='fixture'"); err != nil {
				t.Fatal(err)
			}

			if _, err := policy.GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
				t.Fatalf("anonymous policy: %v", err)
			}
		})
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.events) != 12 {
		t.Fatalf("mounted RPC audit events=%d; want 12", len(audit.events))
	}
	for _, event := range audit.events {
		if event.SourceIP != "127.0.0.1" {
			t.Fatalf("untrusted or missing source IP=%s", event.SourceIP)
		}
	}
}
