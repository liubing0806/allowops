package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/authz"
)

type phasedAuditFixture struct {
	mu     sync.Mutex
	failAt int
	events []AuditEvent
	counts []int
	f      *fixture
}

func (a *phasedAuditFixture) Append(ctx context.Context, e AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var count int
	if err := a.f.db.Pool.QueryRow(ctx, "SELECT count(*) FROM service_accounts").Scan(&count); err != nil {
		return err
	}
	a.counts = append(a.counts, count)
	a.events = append(a.events, e)
	if len(a.events) == a.failAt {
		return errors.New("audit fixture failure")
	}
	return nil
}

func TestWriteAuditBeforeAndAfterMutation(t *testing.T) {
	for _, failAt := range []int{1, 2, 0} {
		t.Run([]string{"success", "authorization failure", "result failure"}[failAt], func(t *testing.T) {
			f := newFixture(t)
			a := &phasedAuditFixture{failAt: failAt, f: f}
			f.service.Audit = a
			svc := rpc.NewServiceAccountServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(f.adminToken)))
			_, err := svc.CreateServiceAccount(context.Background(), connect.NewRequest(&v1.CreateServiceAccountRequest{Name: "automation", OwnerUserId: f.admin.UserId, Roles: []string{"admin"}}))
			if failAt != 0 {
				code(t, err, connect.CodeUnavailable)
			} else if err != nil {
				t.Fatal(err)
			}
			var count int
			if err := f.db.Pool.QueryRow(context.Background(), "SELECT count(*) FROM service_accounts").Scan(&count); err != nil {
				t.Fatal(err)
			}
			wantCount, wantEvents := 1, 2
			if failAt == 1 {
				wantCount, wantEvents = 0, 1
			}
			if count != wantCount {
				t.Fatalf("accounts=%d after audit failure at %d; want %d", count, failAt, wantCount)
			}
			if failAt == 2 && !strings.Contains(err.Error(), "may have committed") {
				t.Fatalf("result failure did not report possible commit: %v", err)
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if len(a.events) != wantEvents || a.counts[0] != 0 {
				t.Fatalf("audit calls=%d database counts=%v; want %d calls starting before mutation", len(a.events), a.counts, wantEvents)
			}
			if wantEvents == 2 && a.counts[1] != 1 {
				t.Fatalf("result audit ran before mutation: %v", a.counts)
			}
			if a.events[0].Phase != "authorized" || a.events[0].Outcome != "allow" || a.events[0].ActorID != f.admin.UserId || a.events[0].PolicyVersion != 1 {
				t.Fatalf("authorization event=%+v", a.events[0])
			}
			if wantEvents == 2 && (a.events[1].Phase != "result" || a.events[1].Outcome != "allow") {
				t.Fatalf("result event=%+v", a.events[1])
			}
		})
	}
}

func TestWriteAuditProtectsLoginAndPolicyPreview(t *testing.T) {
	f := newFixture(t)
	f.addOIDC(t, newOIDC(t))
	f.audit.mu.Lock()
	f.audit.fail = true
	f.audit.mu.Unlock()
	ctx := context.Background()
	beginRequest := connect.NewRequest(&v1.BeginOidcLoginRequest{ProviderId: "test", Client: v1.LoginClient_LOGIN_CLIENT_CONSOLE})
	beginRequest.Header().Set("Origin", f.server.URL)
	_, err := f.auth("").BeginOidcLogin(ctx, beginRequest)
	code(t, err, connect.CodeUnavailable)
	_, err = f.policy(f.adminToken).TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: defaultRules()}}))
	code(t, err, connect.CodeUnavailable)
	_, err = f.auth(f.adminToken).Logout(ctx, connect.NewRequest(&v1.LogoutRequest{}))
	code(t, err, connect.CodeUnavailable)
	var transactions, previews, revoked int
	if err := f.db.Pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM oidc_transactions),(SELECT count(*) FROM policy_tests),(SELECT count(*) FROM identity_sessions WHERE revoked_at IS NOT NULL)").Scan(&transactions, &previews, &revoked); err != nil {
		t.Fatal(err)
	}
	if transactions != 0 || previews != 0 || revoked != 0 {
		t.Fatalf("audit failure permitted writes: transactions=%d previews=%d revoked=%d", transactions, previews, revoked)
	}
}

func TestOIDCStartAuditProtectsBrowserBinding(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run([]string{"", "authorization failure", "result failure"}[failAt], func(t *testing.T) {
			f := newFixture(t)
			f.addOIDC(t, newOIDC(t))
			beginRequest := connect.NewRequest(&v1.BeginOidcLoginRequest{ProviderId: "test", Client: v1.LoginClient_LOGIN_CLIENT_CONSOLE})
			beginRequest.Header().Set("Origin", f.server.URL)
			begin, err := f.auth("").BeginOidcLogin(context.Background(), beginRequest)
			if err != nil {
				t.Fatal(err)
			}
			a := &phasedAuditFixture{failAt: failAt, f: f}
			f.service.Audit = a
			browser := *f.server.Client()
			browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			r, err := browser.Get(begin.Msg.AuthorizationUrl)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			if r.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("OIDC start status=%d; want 503", r.StatusCode)
			}
			if failAt == 2 && !strings.Contains(string(body), "may have committed") {
				t.Fatalf("OIDC result failure: %s", body)
			}
			u, _ := url.Parse(begin.Msg.AuthorizationUrl)
			var bound bool
			if err := f.db.Pool.QueryRow(context.Background(), "SELECT binding_hash IS NOT NULL FROM oidc_transactions WHERE state_hash=$1", hash(u.Query().Get("state"))).Scan(&bound); err != nil {
				t.Fatal(err)
			}
			if bound != (failAt == 2) {
				t.Fatalf("browser bound=%t after audit failure at %d", bound, failAt)
			}
		})
	}
}

func TestUnlabeledHostsDeniedInSharedBoundaryAndPreview(t *testing.T) {
	f := newFixture(t)
	populateResources(t, f)
	ctx := context.Background()
	if _, err := f.db.Pool.Exec(ctx, "UPDATE hosts SET authorization_labels='{}',reported_labels=$1", `{"env":"test"}`); err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewTLSServer(f.service.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := f.service.Require(r.Context(), authz.ExecuteAction, authz.Action{Name: "restart", Risk: "dangerous"}, authz.Host{ID: "host-a", Labels: map[string]string{}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})))
	defer endpoint.Close()
	request, _ := http.NewRequest(http.MethodPost, endpoint.URL, nil)
	request.Header.Set("Authorization", "Bearer "+f.adminToken)
	response, err := endpoint.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "no authorization labels") {
		t.Errorf("unlabeled admin execution status=%d body=%s; want explicit deny", response.StatusCode, body)
	}
	p := f.policy(f.adminToken)
	tested, err := p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: defaultRules()}, Cases: []*v1.PolicyTestCase{{SubjectId: f.admin.UserId, Operation: string(authz.ExecuteAction), Action: "restart", Targets: &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "reported.env=test"}}}}}))
	if err != nil {
		t.Fatal(err)
	}
	if tested.Msg.Test.ChangedCount != 0 || tested.Msg.Test.EvaluatedCount != 1 {
		t.Fatalf("unlabeled preview counts: %v", tested.Msg.Test)
	}
	changes, err := p.GetPolicyTestChanges(ctx, connect.NewRequest(&v1.GetPolicyTestChangesRequest{TestId: tested.Msg.Test.TestId}))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Msg.Changes) != 1 {
		t.Fatalf("unlabeled diagnostics=%d; want 1", len(changes.Msg.Changes))
	}
	for _, d := range []*v1.PolicyDecision{changes.Msg.Changes[0].Before, changes.Msg.Changes[0].After} {
		if d.Effect != v1.PolicyEffect_POLICY_EFFECT_DENY || d.ErrorReason != "HOST_UNLABELED" || len(d.MatchedRules) != 0 {
			t.Fatalf("unlabeled decision=%v", d)
		}
	}
}

func TestConsoleSessionDefaultsSevenDaysAndConfigOverride(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, ttl := range []time.Duration{7 * 24 * time.Hour, 12 * time.Hour} {
		s := f.service
		if ttl == 12*time.Hour {
			cfg := s.Config
			cfg.ConsoleTTL = ttl
			var err error
			s, err = New(ctx, f.db, cfg, f.audit)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
		}
		session, _, err := s.issueSession(ctx, f.db.Pool, f.admin.UserId, v1.LoginClient_LOGIN_CLIENT_CONSOLE)
		if err != nil {
			t.Fatal(err)
		}
		if got := session.ExpiresAt.AsTime().Sub(session.CreatedAt.AsTime()); got < ttl-time.Second || got > ttl+time.Second {
			t.Fatalf("console TTL=%s; want %s", got, ttl)
		}
	}
}
