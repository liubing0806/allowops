package api

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/authn"
)

func TestCheckRequestKeepsUnavailableAuthenticationError(t *testing.T) {
	s := &Service{}
	for _, tc := range []struct {
		err  error
		want connect.Code
	}{
		{failure(connect.CodeUnavailable, "identity database unavailable"), connect.CodeUnavailable},
		{authn.ErrInvalidCredentials, connect.CodeUnauthenticated},
	} {
		ctx := context.WithValue(context.Background(), requestKey{}, &requestState{tls: true, err: tc.err})
		code(t, s.CheckRequest(ctx, false), tc.want)
	}
}

// A database failure while resolving a credential is not an invalid credential:
// the console redirects to /login on Unauthenticated but retries on Unavailable.
func TestAuthenticateDatabaseFailureIsUnavailable(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	accounts := rpc.NewServiceAccountServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(f.adminToken)))
	created, err := accounts.CreateServiceAccount(ctx, connect.NewRequest(&v1.CreateServiceAccountRequest{Name: "automation", OwnerUserId: f.admin.UserId, Roles: []string{"admin"}}))
	if err != nil {
		t.Fatal(err)
	}
	minted, err := accounts.CreateServiceAccountToken(ctx, connect.NewRequest(&v1.CreateServiceAccountTokenRequest{AccountId: created.Msg.Account.AccountId}))
	if err != nil {
		t.Fatal(err)
	}
	_, console, err := f.service.issueSession(ctx, f.db.Pool, f.admin.UserId, v1.LoginClient_LOGIN_CLIENT_CONSOLE)
	if err != nil {
		t.Fatal(err)
	}
	consoleClient := rpc.NewAuthServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
			r.Header().Set("Cookie", "__Host-allowops-session="+console)
			return next(ctx, r)
		}
	})))
	current := func(token string) error {
		_, err := f.policy(token).GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{}))
		return err
	}
	// Well-formed tokens that are not in the database.
	unknownService := "aops_" + strings.Repeat("A", 43)
	unknownCLI := "aops_cli_" + strings.Repeat("A", 43)

	// Healthy database: unknown tokens stay Unauthenticated, known ones succeed.
	code(t, current(unknownService), connect.CodeUnauthenticated)
	code(t, current(unknownCLI), connect.CodeUnauthenticated)
	if err := current(f.adminToken); err != nil {
		t.Fatalf("session token rejected with healthy database: %v", err)
	}
	if err := current(minted.Msg.Secret); err != nil {
		t.Fatalf("service account token rejected with healthy database: %v", err)
	}
	if _, err := consoleClient.GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{})); err != nil {
		t.Fatal(err)
	}

	f.db.Pool.Close()
	code(t, current(f.adminToken), connect.CodeUnavailable)
	code(t, current(minted.Msg.Secret), connect.CodeUnavailable)
	code(t, current(unknownCLI), connect.CodeUnavailable)
	code(t, current(unknownService), connect.CodeUnavailable)
	_, err = consoleClient.GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	code(t, err, connect.CodeUnavailable)
	// Malformed credentials are rejected before any database access.
	code(t, current("not-a-token"), connect.CodeUnauthenticated)
}
