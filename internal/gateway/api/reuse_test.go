package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/authz"
)

func TestReusableMiddlewareRejectsPlaintextAndCookieCSRF(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	handler := f.service.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := f.service.Require(r.Context(), authz.ModifyPolicy, authz.Action{}, authz.Host{})
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	plain := httptest.NewServer(handler)
	defer plain.Close()
	request, _ := http.NewRequest("POST", plain.URL, nil)
	request.Header.Set("Authorization", "Bearer "+f.adminToken)
	response, err := plain.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("shared middleware authenticated over plaintext")
	}
	tls := httptest.NewTLSServer(handler)
	defer tls.Close()
	_, raw, err := f.service.issueSession(ctx, f.db.Pool, f.admin.UserId, v1.LoginClient_LOGIN_CLIENT_CONSOLE)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := f.service.authenticate(ctx, raw, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{403, 200} {
		request, _ := http.NewRequest("POST", tls.URL, nil)
		request.Header.Set("Cookie", "__Host-allowops-session="+raw)
		if want == 200 {
			request.Header.Set("Origin", f.server.URL)
			request.Header.Set("X-CSRF-Token", identity.CSRF)
		}
		response, err := tls.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("shared Cookie CSRF=%d; want %d", response.StatusCode, want)
		}
	}
	mux := http.NewServeMux()
	mux.Handle(rpc.NewUserServiceHandler(f.service, connect.WithInterceptors(f.service.InterceptorFor(map[string]RPCPermission{rpc.UserServiceListUsersProcedure: {Operation: authz.ManageUserRoles}}))))
	shared := httptest.NewTLSServer(f.service.Middleware(mux))
	defer shared.Close()
	client := rpc.NewUserServiceClient(shared.Client(), shared.URL, connect.WithInterceptors(bearerTest(f.adminToken)))
	if _, err := client.ListUsers(ctx, connect.NewRequest(&v1.ListUsersRequest{})); err != nil {
		t.Fatal(err)
	}
	_, err = client.GetUser(ctx, connect.NewRequest(&v1.GetUserRequest{UserId: f.admin.UserId}))
	code(t, err, connect.CodePermissionDenied)
}

func TestRoleMappingsRemainDatabaseAuthoritative(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	client := f.users()
	before, err := client.GetRoleMappings(ctx, connect.NewRequest(&v1.GetRoleMappingsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SaveRoleMappings(ctx, connect.NewRequest(&v1.SaveRoleMappingsRequest{ExpectedRevision: before.Msg.Revision})); err != nil {
		t.Fatal(err)
	}
	cfg := f.service.Config
	cfg.RoleMappings = []RoleMappingConfig{{ProviderID: "test", Group: "readers", Roles: []string{"admin"}}}
	restarted, err := New(ctx, f.db, cfg, f.audit)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	u, err := loadUser(ctx, f.db.Pool, f.viewer.UserId)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.user.EffectiveRoles) != 0 {
		t.Fatalf("startup config overwrote saved empty mappings: %v", u.user.EffectiveRoles)
	}
	if _, err := New(ctx, f.db, cfg, nil); err == nil {
		t.Fatal("missing audit accepted")
	}
}
