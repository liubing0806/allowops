package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	jose "github.com/go-jose/go-jose/v4"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"
)

type auditFixture struct {
	mu     sync.Mutex
	events []AuditEvent
	fail   bool
}

func (a *auditFixture) Append(_ context.Context, e AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("fixture failure")
	}
	a.events = append(a.events, e)
	return nil
}

type fixture struct {
	service                 *Service
	db                      *store.Store
	server                  *httptest.Server
	audit                   *auditFixture
	admin, viewer           *v1.User
	adminToken, viewerToken string
}

func newFixture(t *testing.T, decorate ...func(*Service, http.Handler) http.Handler) *fixture {
	t.Helper()
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	audit := &auditFixture{}
	s, err := New(ctx, db, Config{Origin: origin, RoleMappings: []RoleMappingConfig{{ProviderID: "test", Group: "ops", Roles: []string{"admin"}}, {ProviderID: "test", Group: "readers", Roles: []string{"viewer"}}}}, audit)
	if err != nil {
		t.Fatal(err)
	}
	handler := s.Handler()
	if len(decorate) > 0 {
		handler = decorate[0](s, handler)
	}
	server.Config.Handler = handler
	server.StartTLS()
	t.Cleanup(server.Close)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	admin, err := s.syncUser(ctx, "test", authn.Identity{ID: "admin", Kind: "oidc", Email: "admin@example.org", Groups: []string{"ops"}})
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := s.syncUser(ctx, "test", authn.Identity{ID: "viewer", Kind: "oidc", Groups: []string{"readers"}})
	if err != nil {
		t.Fatal(err)
	}
	_, at, err := s.issueSession(ctx, db.Pool, admin.UserId, v1.LoginClient_LOGIN_CLIENT_CLI)
	if err != nil {
		t.Fatal(err)
	}
	_, vt, err := s.issueSession(ctx, db.Pool, viewer.UserId, v1.LoginClient_LOGIN_CLIENT_CLI)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{s, db, server, audit, admin, viewer, at, vt}
}
func bearerTest(token string) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
			if token != "" {
				r.Header().Set("Authorization", "Bearer "+token)
			}
			return next(ctx, r)
		}
	})
}
func (f *fixture) auth(token string) rpc.AuthServiceClient {
	return rpc.NewAuthServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(token)))
}
func (f *fixture) policy(token string) rpc.PolicyServiceClient {
	return rpc.NewPolicyServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(token)))
}
func (f *fixture) users() rpc.UserServiceClient {
	return rpc.NewUserServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(f.adminToken)))
}
func code(t *testing.T, err error, want connect.Code) {
	t.Helper()
	if connect.CodeOf(err) != want {
		t.Fatalf("error=%v code=%s; want %s", err, connect.CodeOf(err), want)
	}
}

func TestTokenLifecycleAndCurrentRoles(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	svc := rpc.NewServiceAccountServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(f.adminToken)))
	created, err := svc.CreateServiceAccount(ctx, connect.NewRequest(&v1.CreateServiceAccountRequest{Name: "automation", OwnerUserId: f.admin.UserId, Roles: []string{"admin"}}))
	if err != nil {
		t.Fatal(err)
	}
	a := created.Msg.Account
	if _, err := svc.GetServiceAccount(ctx, connect.NewRequest(&v1.GetServiceAccountRequest{AccountId: a.AccountId})); err != nil {
		t.Fatal(err)
	}
	if list, err := svc.ListServiceAccounts(ctx, connect.NewRequest(&v1.ListServiceAccountsRequest{})); err != nil || len(list.Msg.GetAccounts()) != 1 {
		t.Fatalf("account list: %v", err)
	}
	minted, err := svc.CreateServiceAccountToken(ctx, connect.NewRequest(&v1.CreateServiceAccountTokenRequest{AccountId: a.AccountId}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(minted.Msg.Secret, "aops_") || minted.Msg.Token.ExpiresAt.AsTime().Sub(minted.Msg.Token.CreatedAt.AsTime()) < 30*24*time.Hour-time.Second {
		t.Fatal("wrong token format or default TTL")
	}
	var digest []byte
	if err := f.db.Pool.QueryRow(ctx, "SELECT token_hash FROM service_account_tokens WHERE token_id=$1", minted.Msg.Token.TokenId).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest, hash(minted.Msg.Secret)) {
		t.Fatal("token stored without SHA-256")
	}
	listed, err := svc.ListServiceAccountTokens(ctx, connect.NewRequest(&v1.ListServiceAccountTokensRequest{AccountId: a.AccountId}))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(listed.Msg)
	if bytes.Contains(b, []byte(minted.Msg.Secret)) || bytes.Contains(b, digest) {
		t.Fatal("token secret or hash re-exposed")
	}
	if _, err := f.policy(minted.Msg.Secret).GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{})); err != nil {
		t.Fatal(err)
	}
	// The random part of a service token can itself begin with cli_. Its
	// canonical length distinguishes it from a longer CLI session token.
	serviceOverlap := "aops_cli_" + strings.Repeat("A", 39)
	if _, err := f.db.Pool.Exec(ctx, "UPDATE service_account_tokens SET token_hash=$1 WHERE token_id=$2", hash(serviceOverlap), minted.Msg.Token.TokenId); err != nil {
		t.Fatal(err)
	}
	if _, err := f.policy(serviceOverlap).GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{})); err != nil {
		t.Fatalf("valid service token with cli_ random prefix rejected: %v", err)
	}
	if _, err := f.db.Pool.Exec(ctx, "UPDATE service_account_tokens SET token_hash=$1 WHERE token_id=$2", hash(minted.Msg.Secret), minted.Msg.Token.TokenId); err != nil {
		t.Fatal(err)
	}
	listed, err = svc.ListServiceAccountTokens(ctx, connect.NewRequest(&v1.ListServiceAccountTokensRequest{AccountId: a.AccountId}))
	if err != nil || listed.Msg.Tokens[0].LastUsedAt == nil {
		t.Fatal("last_used_at not updated")
	}
	updated, err := svc.UpdateServiceAccount(ctx, connect.NewRequest(&v1.UpdateServiceAccountRequest{AccountId: a.AccountId, ExpectedRevision: a.Revision, OwnerUserId: f.admin.UserId, Roles: []string{"viewer"}}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.policy(minted.Msg.Secret).GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{}))
	code(t, err, connect.CodePermissionDenied)
	_, err = svc.UpdateServiceAccount(ctx, connect.NewRequest(&v1.UpdateServiceAccountRequest{AccountId: a.AccountId, ExpectedRevision: a.Revision, OwnerUserId: f.admin.UserId}))
	code(t, err, connect.CodeAborted)
	if updated.Msg.Account.Revision == a.Revision {
		t.Fatal("account revision did not advance")
	}
	if _, err := svc.RevokeServiceAccountToken(ctx, connect.NewRequest(&v1.RevokeServiceAccountTokenRequest{AccountId: a.AccountId, TokenId: minted.Msg.Token.TokenId})); err != nil {
		t.Fatal(err)
	}
	_, err = f.policy(minted.Msg.Secret).GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{}))
	code(t, err, connect.CodeUnauthenticated)
	if _, err := f.db.Pool.Exec(ctx, "UPDATE service_account_tokens SET revoked_at=NULL,created_at=now()-interval '2 days',expires_at=now()-interval '1 day' WHERE token_id=$1", minted.Msg.Token.TokenId); err != nil {
		t.Fatal(err)
	}
	_, err = f.policy(minted.Msg.Secret).GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{}))
	code(t, err, connect.CodeUnauthenticated)
	for _, days := range []uint32{0, 366} {
		_, err := svc.CreateServiceAccountToken(ctx, connect.NewRequest(&v1.CreateServiceAccountTokenRequest{AccountId: a.AccountId, ValidDays: &days}))
		code(t, err, connect.CodeInvalidArgument)
	}
	for _, days := range []uint32{1, 365} {
		_, err := svc.CreateServiceAccountToken(ctx, connect.NewRequest(&v1.CreateServiceAccountTokenRequest{AccountId: a.AccountId, ValidDays: &days}))
		if err != nil {
			t.Fatal(err)
		}
	}
	// Query tokens alone cannot authenticate a request.
	request, _ := http.NewRequest(http.MethodPost, f.server.URL+rpc.PolicyServiceGetPolicyProcedure+"?token="+url.QueryEscape(f.adminToken), strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	response, err := f.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("query token authenticated: %d", response.StatusCode)
	}
	mappings, err := f.users().GetRoleMappings(ctx, connect.NewRequest(&v1.GetRoleMappingsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.users().SetUserRoles(ctx, connect.NewRequest(&v1.SetUserRolesRequest{UserId: f.viewer.UserId, ManualRoles: []string{"auditor"}, ExpectedRevision: f.viewer.Revision})); err != nil {
		t.Fatal(err)
	}
	current, err := f.auth(f.viewerToken).GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(current.Msg.User.EffectiveRoles, ",") != "auditor,viewer" {
		t.Fatalf("roles=%v", current.Msg.User.EffectiveRoles)
	}
	if _, err := f.users().SaveRoleMappings(ctx, connect.NewRequest(&v1.SaveRoleMappingsRequest{Mappings: []*v1.RoleMapping{{ProviderId: "test", Group: "ops", Roles: []string{"admin"}}, {ProviderId: "test", Group: "readers", Roles: []string{"operator"}}}, ExpectedRevision: mappings.Msg.Revision})); err != nil {
		t.Fatal(err)
	}
	current, err = f.auth(f.viewerToken).GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	if err != nil || strings.Join(current.Msg.User.EffectiveRoles, ",") != "auditor,operator" {
		t.Fatalf("current mapped roles=%v error=%v", current.Msg.GetUser().GetEffectiveRoles(), err)
	}
	if _, err := f.users().ListUsers(ctx, connect.NewRequest(&v1.ListUsersRequest{Query: "viewer"})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.users().GetUser(ctx, connect.NewRequest(&v1.GetUserRequest{UserId: f.viewer.UserId})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.users().ListRoles(ctx, connect.NewRequest(&v1.ListRolesRequest{})); err != nil {
		t.Fatal(err)
	}
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	for _, event := range f.audit.events {
		b, _ := json.Marshal(event)
		if bytes.Contains(b, []byte(minted.Msg.Secret)) || bytes.Contains(b, []byte(f.adminToken)) {
			t.Fatal("audit exposed a secret")
		}
	}
}

func TestSessionsOwnershipExpiryCookieAndCSRF(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	viewer := f.auth(f.viewerToken)
	self, err := viewer.ListCliSessions(ctx, connect.NewRequest(&v1.ListCliSessionsRequest{}))
	if err != nil || len(self.Msg.Sessions) != 1 {
		t.Fatalf("self sessions=%v error=%v", self, err)
	}
	if ttl := self.Msg.Sessions[0].ExpiresAt.AsTime().Sub(self.Msg.Sessions[0].CreatedAt.AsTime()); ttl < 7*24*time.Hour-time.Second || ttl > 7*24*time.Hour+time.Second {
		t.Fatalf("CLI TTL=%s", ttl)
	}
	_, err = viewer.ListCliSessions(ctx, connect.NewRequest(&v1.ListCliSessionsRequest{UserId: f.admin.UserId}))
	code(t, err, connect.CodePermissionDenied)
	admins, err := f.auth(f.adminToken).ListCliSessions(ctx, connect.NewRequest(&v1.ListCliSessionsRequest{UserId: f.admin.UserId}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = viewer.RevokeCliSession(ctx, connect.NewRequest(&v1.RevokeCliSessionRequest{SessionId: admins.Msg.Sessions[0].SessionId}))
	code(t, err, connect.CodeNotFound)
	_, err = viewer.RevokeCliSession(ctx, connect.NewRequest(&v1.RevokeCliSessionRequest{SessionId: admins.Msg.Sessions[0].SessionId, UserId: f.admin.UserId}))
	code(t, err, connect.CodePermissionDenied)
	_, _, err = f.service.issueSession(ctx, f.db.Pool, f.viewer.UserId, v1.LoginClient_LOGIN_CLIENT_CLI)
	if err != nil {
		t.Fatal(err)
	}
	paged, err := f.auth(f.adminToken).ListCliSessions(ctx, connect.NewRequest(&v1.ListCliSessionsRequest{UserId: f.viewer.UserId, Page: &v1.PageRequest{PageSize: 1}}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.auth(f.adminToken).ListCliSessions(ctx, connect.NewRequest(&v1.ListCliSessionsRequest{UserId: f.admin.UserId, Page: &v1.PageRequest{PageSize: 1, PageToken: paged.Msg.Page.NextPageToken}}))
	code(t, err, connect.CodeInvalidArgument)
	if _, err := f.auth(f.adminToken).RevokeCliSession(ctx, connect.NewRequest(&v1.RevokeCliSessionRequest{UserId: f.viewer.UserId, SessionId: self.Msg.Sessions[0].SessionId})); err != nil {
		t.Fatal(err)
	}
	_, err = viewer.GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	code(t, err, connect.CodeUnauthenticated)
	session, raw, err := f.service.issueSession(ctx, f.db.Pool, f.viewer.UserId, v1.LoginClient_LOGIN_CLIENT_CLI)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.auth(raw).RevokeCliSession(ctx, connect.NewRequest(&v1.RevokeCliSessionRequest{SessionId: session.SessionId})); err != nil {
		t.Fatal(err)
	}
	session, raw, err = f.service.issueSession(ctx, f.db.Pool, f.viewer.UserId, v1.LoginClient_LOGIN_CLIENT_CLI)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(ctx, "UPDATE identity_sessions SET created_at=now()-interval '8 days',expires_at=now()-interval '1 day' WHERE session_id=$1", session.SessionId); err != nil {
		t.Fatal(err)
	}
	_, err = f.auth(raw).GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	code(t, err, connect.CodeUnauthenticated)
	web, raw, err := f.service.issueSession(ctx, f.db.Pool, f.admin.UserId, v1.LoginClient_LOGIN_CLIENT_CONSOLE)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	tctx := context.WithValue(ctx, requestKey{}, &requestState{writer: w})
	f.service.sessionCookie(tctx, raw, web.ExpiresAt.AsTime())
	cookie := w.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("unsafe session cookie: Secure=%t HttpOnly=%t SameSite=%d Path=%q Domain=%q", cookie.Secure, cookie.HttpOnly, cookie.SameSite, cookie.Path, cookie.Domain)
	}
	webClient := rpc.NewAuthServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
			r.Header().Set("Cookie", cookie.String())
			return next(ctx, r)
		}
	})))
	current, err := webClient.GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	if err != nil || current.Msg.CsrfToken == "" {
		t.Fatal("missing CSRF token")
	}
	for _, headers := range [][2]string{{"", ""}, {f.server.URL, ""}, {"https://evil.example", current.Msg.CsrfToken}} {
		request := connect.NewRequest(&v1.LogoutRequest{})
		request.Header().Set("Origin", headers[0])
		request.Header().Set("X-CSRF-Token", headers[1])
		_, err := webClient.Logout(ctx, request)
		code(t, err, connect.CodePermissionDenied)
	}
	request := connect.NewRequest(&v1.LogoutRequest{})
	request.Header().Set("Origin", f.server.URL)
	request.Header().Set("X-CSRF-Token", current.Msg.CsrfToken)
	if _, err := webClient.Logout(ctx, request); err != nil {
		t.Fatal(err)
	}
	_, err = webClient.GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	code(t, err, connect.CodeUnauthenticated)
}

func TestPolicyPreviewConflictRollbackRefreshAndBootstrap(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := f.policy(f.adminToken)
	second, err := New(ctx, f.db, f.service.Config, f.audit)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	current, err := p.GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	rules := proto.Clone(current.Msg.Policy.Rules).(*v1.PolicyRules)
	rules.Rules = append(rules.Rules, &v1.PolicyRule{Name: "operators-view-policy", Roles: []string{"viewer"}, Operations: []string{string(authz.ModifyPolicy)}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW})
	tested, err := p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: rules}}))
	if err != nil {
		t.Fatal(err)
	}
	if tested.Msg.Test.ChangedCount == 0 || tested.Msg.Test.EvaluatedCount == 0 || !tested.Msg.Test.RetainsPolicyAdministrator {
		t.Fatalf("test=%v", tested.Msg.Test)
	}
	changes, err := p.GetPolicyTestChanges(ctx, connect.NewRequest(&v1.GetPolicyTestChangesRequest{TestId: tested.Msg.Test.TestId}))
	if err != nil || len(changes.Msg.Changes) == 0 {
		t.Fatal("missing policy changes")
	}
	if _, err := p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: rules, TestId: tested.Msg.Test.TestId})); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(3 * time.Second)
	for second.state.Load().version != 2 && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	if second.state.Load().version != 2 {
		t.Fatal("LISTEN/NOTIFY did not refresh second instance")
	}
	_, err = p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: rules, TestId: tested.Msg.Test.TestId}))
	code(t, err, connect.CodeAborted)
	rollback, err := p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 2, Candidate: &v1.TestPolicyRequest_HistoricalVersion{HistoricalVersion: 1}}))
	if err != nil {
		t.Fatal(err)
	}
	rolled, err := p.RollbackPolicy(ctx, connect.NewRequest(&v1.RollbackPolicyRequest{BaseVersion: 2, TargetVersion: 1, TestId: rollback.Msg.Test.TestId}))
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Msg.Policy.Version != 3 || rolled.Msg.Policy.GetRolledBackFrom() != 1 {
		t.Fatalf("rollback=%v", rolled.Msg.Policy)
	}
	history, err := p.ListPolicyHistory(ctx, connect.NewRequest(&v1.ListPolicyHistoryRequest{}))
	if err != nil || len(history.Msg.Policies) != 3 {
		t.Fatal("missing policy history")
	}
	empty := &v1.PolicyRules{}
	tested, err = p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 3, Candidate: &v1.TestPolicyRequest_Rules{Rules: empty}}))
	if err != nil {
		t.Fatal(err)
	}
	if tested.Msg.Test.RetainsPolicyAdministrator {
		t.Fatal("lockout test claimed administrator")
	}
	_, err = p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 3, Rules: empty, TestId: tested.Msg.Test.TestId}))
	code(t, err, connect.CodeFailedPrecondition)
	tested, err = p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 3, Candidate: &v1.TestPolicyRequest_Rules{Rules: rules}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.users().SetUserRoles(ctx, connect.NewRequest(&v1.SetUserRolesRequest{UserId: f.viewer.UserId, ManualRoles: []string{"auditor"}, ExpectedRevision: f.viewer.Revision})); err != nil {
		t.Fatal(err)
	}
	_, err = p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 3, Rules: rules, TestId: tested.Msg.Test.TestId}))
	code(t, err, connect.CodeAborted)
	bootstrap, err := New(ctx, f.db, Config{Origin: f.server.URL, BootstrapAdmins: []string{f.admin.Email}}, f.audit)
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Close()
	bs := httptest.NewTLSServer(bootstrap.Handler())
	defer bs.Close()
	bp := rpc.NewPolicyServiceClient(bs.Client(), bs.URL, connect.WithInterceptors(bearerTest(f.adminToken)))
	tested, err = bp.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 3, Candidate: &v1.TestPolicyRequest_Rules{Rules: empty}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bp.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 3, Rules: empty, TestId: tested.Msg.Test.TestId})); err != nil {
		t.Fatal(err)
	}
	if _, err := bp.GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{})); err != nil {
		t.Fatal("bootstrap lost policy access:", err)
	}
	_, err = f.policy(f.viewerToken).GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{}))
	code(t, err, connect.CodePermissionDenied)
}

type fakeOIDC struct {
	server     *httptest.Server
	key        *rsa.PrivateKey
	mu         sync.Mutex
	codes      map[string]fakeCode
	wrongNonce bool
}
type fakeCode struct{ nonce, challenge string }

func newOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeOIDC{key: key, codes: map[string]fakeCode{}}
	p.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": p.server.URL, "jwks_uri": p.server.URL + "/keys", "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key", Use: "sig", Algorithm: "RS256"}}})
		case "/authorize":
			q := r.URL.Query()
			if q.Get("code_challenge_method") != "S256" {
				http.Error(w, "PKCE required", 400)
				return
			}
			code := secret("")
			p.mu.Lock()
			p.codes[code] = fakeCode{q.Get("nonce"), q.Get("code_challenge")}
			p.mu.Unlock()
			dest, _ := url.Parse(q.Get("redirect_uri"))
			dest.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
			http.Redirect(w, r, dest.String(), http.StatusFound)
		case "/token":
			r.ParseForm()
			p.mu.Lock()
			binding, ok := p.codes[r.Form.Get("code")]
			delete(p.codes, r.Form.Get("code"))
			wrong := p.wrongNonce
			p.mu.Unlock()
			if !ok || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != binding.challenge {
				http.Error(w, "invalid code", http.StatusBadRequest)
				return
			}
			nonce := binding.nonce
			if wrong {
				nonce = "wrong"
			}
			signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "key"))
			claims, _ := json.Marshal(map[string]any{"iss": p.server.URL, "aud": "allowops", "sub": "oidc-user", "nonce": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "email": "oidc@example.org", "email_verified": true, "groups": []string{"ops"}})
			signed, _ := signer.Sign(claims)
			raw, _ := signed.CompactSerialize()
			json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture", "token_type": "Bearer", "id_token": raw})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.server.Close)
	return p
}
func (f *fixture) addOIDC(t *testing.T, p *fakeOIDC) {
	t.Helper()
	if err := f.service.AddOIDC(context.Background(), "test", "test OIDC", "", authn.OIDCConfig{IssuerURL: p.server.URL, ClientID: "allowops", HTTPClient: p.server.Client()}); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) begin(t *testing.T, kind v1.LoginClient, pv string) (*url.URL, *http.Cookie) {
	t.Helper()
	req := connect.NewRequest(&v1.BeginOidcLoginRequest{ProviderId: "test", Client: kind})
	if kind == v1.LoginClient_LOGIN_CLIENT_CLI {
		req.Msg.CliLoopbackUri = "http://127.0.0.1:54321/callback"
		req.Msg.CliState = secret("")
		req.Msg.CliCodeChallenge = oauth2.S256ChallengeFromVerifier(pv)
	} else {
		req.Header().Set("Origin", f.server.URL)
	}
	begun, err := f.auth("").BeginOidcLogin(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	client := *f.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Get(begun.Msg.AuthorizationUrl)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 302 {
		t.Fatalf("OIDC start=%d", res.StatusCode)
	}
	dest, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return dest, res.Cookies()[0]
}
func (f *fixture) complete(t *testing.T, p *fakeOIDC, dest *url.URL, cookie *http.Cookie, state string) (*connect.Response[v1.CompleteOidcLoginResponse], error) {
	t.Helper()
	providerCode := secret("")
	p.mu.Lock()
	p.codes[providerCode] = fakeCode{dest.Query().Get("nonce"), dest.Query().Get("code_challenge")}
	p.mu.Unlock()
	req := connect.NewRequest(&v1.CompleteOidcLoginRequest{Code: providerCode, State: state})
	req.Header().Set("Origin", f.server.URL)
	if cookie != nil {
		req.Header().Set("Cookie", cookie.Name+"="+cookie.Value)
	}
	return f.auth("").CompleteOidcLogin(context.Background(), req)
}
func TestOIDCStateNonceBrowserAndPKCE(t *testing.T) {
	f := newFixture(t)
	p := newOIDC(t)
	f.addOIDC(t, p)
	ctx := context.Background()
	pv := oauth2.GenerateVerifier()
	for _, bad := range []struct {
		name   string
		state  bool
		cookie bool
		nonce  bool
	}{{"state", true, false, false}, {"binding", false, true, false}, {"nonce", false, false, true}} {
		t.Run(bad.name, func(t *testing.T) {
			dest, cookie := f.begin(t, v1.LoginClient_LOGIN_CLIENT_CLI, pv)
			state := dest.Query().Get("state")
			if bad.state {
				state = "wrong"
			}
			if bad.cookie {
				cookie = nil
			}
			p.mu.Lock()
			p.wrongNonce = bad.nonce
			p.mu.Unlock()
			_, err := f.complete(t, p, dest, cookie, state)
			code(t, err, connect.CodeUnauthenticated)
		})
	}
	p.mu.Lock()
	p.wrongNonce = false
	p.mu.Unlock()
	dest, cookie := f.begin(t, v1.LoginClient_LOGIN_CLIENT_CLI, pv)
	response, err := f.complete(t, p, dest, cookie, dest.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	loop, _ := url.Parse(response.Msg.RedirectUri)
	q := loop.Query()
	if len(q) != 2 || q.Get("code") == "" || q.Get("state") == "" || strings.Contains(response.Msg.RedirectUri, "aops_") {
		t.Fatal("loopback leaked session or invalid fields")
	}
	_, err = f.auth("").ExchangeCliSession(ctx, connect.NewRequest(&v1.ExchangeCliSessionRequest{Code: q.Get("code"), CodeVerifier: oauth2.GenerateVerifier()}))
	code(t, err, connect.CodeUnauthenticated)
	exchanged, err := f.auth("").ExchangeCliSession(ctx, connect.NewRequest(&v1.ExchangeCliSessionRequest{Code: q.Get("code"), CodeVerifier: pv}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.auth("").ExchangeCliSession(ctx, connect.NewRequest(&v1.ExchangeCliSessionRequest{Code: q.Get("code"), CodeVerifier: pv}))
	code(t, err, connect.CodeUnauthenticated)
	if _, err := f.auth(exchanged.Msg.SessionToken).GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{})); err != nil {
		t.Fatal(err)
	}
	_, err = f.complete(t, p, dest, cookie, dest.Query().Get("state"))
	code(t, err, connect.CodeUnauthenticated)
	for _, uri := range []string{"http://localhost:123/callback", "https://evil.example/callback", "http://127.0.0.1/callback", "http://127.0.0.1:123/callback?token=x"} {
		_, err := f.auth("").BeginOidcLogin(ctx, connect.NewRequest(&v1.BeginOidcLoginRequest{ProviderId: "test", Client: v1.LoginClient_LOGIN_CLIENT_CLI, CliLoopbackUri: uri, CliState: secret(""), CliCodeChallenge: oauth2.S256ChallengeFromVerifier(pv)}))
		code(t, err, connect.CodeInvalidArgument)
	}
}

func TestBinaryLoginPolicySmoke(t *testing.T) {
	f := newFixture(t, func(s *Service, h http.Handler) http.Handler {
		s.Audit = NewAuditor(audit.New(s.Store.Pool, audit.Config{}))
		return h
	})
	p := newOIDC(t)
	f.addOIDC(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := f.db.Pool.Exec(ctx, "INSERT INTO role_mappings(provider_id,group_name,roles) VALUES ('test','unused',ARRAY['viewer'])"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "allowops-bin")
	build := exec.Command("go", "build", "-o", binary, "../../../cmd/allowops")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("CLI build: %v\n%s", err, b)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, cert, 0600); err != nil {
		t.Fatal(err)
	}
	environment := append(os.Environ(), "XDG_CONFIG_HOME="+dir)
	login := exec.CommandContext(ctx, binary, "login", "--gateway", f.server.URL, "--provider", "test", "--ca-file", ca, "--no-browser")
	login.Env = environment
	stdout, err := login.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	login.Stderr = &stderr
	if err := login.Start(); err != nil {
		t.Fatal(err)
	}
	defer login.Process.Kill()
	// Only the public start URL crosses stdout. The callback receives code/state.
	var line []byte
	single := make([]byte, 1)
	for {
		if _, err := stdout.Read(single); err != nil {
			t.Fatal(err)
		}
		if single[0] == '\n' {
			break
		}
		line = append(line, single[0])
	}
	browser := *f.server.Client()
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	start, err := browser.Get(string(line))
	if err != nil {
		t.Fatal(err)
	}
	start.Body.Close()
	dest, _ := url.Parse(start.Header.Get("Location"))
	cookie := start.Cookies()[0]
	completed, err := f.complete(t, p, dest, cookie, dest.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Get(completed.Msg.RedirectUri)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	var remaining bytes.Buffer
	remaining.ReadFrom(stdout)
	if err := login.Wait(); err != nil {
		t.Fatalf("binary login: %v %s", err, stderr.String())
	}
	if !strings.Contains(remaining.String(), "Logged in") {
		t.Fatal("binary login did not report success")
	}
	path := filepath.Join(dir, "allowops", "credentials")
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("credentials mode: %v %v", st, err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = environment
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("allowops %v: %v\n%s", args, err, b)
		}
		t.Logf("allowops %v: exit 0", args)
		return b
	}
	rules := run("policy", "get")
	path = filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, rules, 0600); err != nil {
		t.Fatal(err)
	}
	run("policy", "apply", "-f", path)
	run("policy", "test", "-f", path)
	chain := audit.New(f.db.Pool, audit.Config{})
	var last uint64
	if err := f.db.Pool.QueryRow(ctx, "SELECT max(seq) FROM audit_events").Scan(&last); err != nil {
		t.Fatal(err)
	}
	verified, err := chain.Verify(ctx, audit.VerifyOptions{From: 1, To: last})
	if err != nil || !verified.Valid {
		t.Fatalf("binary smoke audit chain: valid=%t error=%v", verified.Valid, err)
	}
	var authorized, results int
	if err := f.db.Pool.QueryRow(ctx, "SELECT count(*) FILTER (WHERE reason='authorized'),count(*) FILTER (WHERE reason='result') FROM audit_events WHERE operation=$1", rpc.PolicyServiceSavePolicyProcedure).Scan(&authorized, &results); err != nil {
		t.Fatal(err)
	}
	if authorized != 1 || results != 1 {
		t.Fatalf("binary policy save audit: authorized=%d result=%d", authorized, results)
	}
	t.Logf("OIDC login and policy get/apply/test: P7 chain verified %d events", verified.CheckedCount)
}
