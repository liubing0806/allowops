package api

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"golang.org/x/oauth2"
)

func consoleSessionRequest(raw string) *connect.Request[v1.GetCurrentSessionRequest] {
	req := connect.NewRequest(&v1.GetCurrentSessionRequest{})
	req.Header().Set("Cookie", "__Host-allowops-session="+raw)
	return req
}

func TestDisableUserRevokesSessionsAndBlocksOIDC(t *testing.T) {
	f := newFixture(t)
	p := newOIDC(t)
	f.addOIDC(t, p)
	ctx := context.Background()
	login := func(client v1.LoginClient, verifier string) (*connect.Response[v1.CompleteOidcLoginResponse], error) {
		dest, cookie := f.begin(t, client, verifier)
		return f.complete(t, p, dest, cookie, dest.Query().Get("state"))
	}
	newCLICode := func(verifier string) string {
		resp, err := login(v1.LoginClient_LOGIN_CLIENT_CLI, verifier)
		if err != nil {
			t.Fatal(err)
		}
		callback, err := url.Parse(resp.Msg.RedirectUri)
		if err != nil || callback.Query().Get("code") == "" {
			t.Fatalf("invalid CLI callback: %v", err)
		}
		return callback.Query().Get("code")
	}
	console, err := login(v1.LoginClient_LOGIN_CLIENT_CONSOLE, "")
	if err != nil {
		t.Fatal(err)
	}
	consoleRaw := (&http.Response{Header: console.Header()}).Cookies()[0].Value
	verifier := oauth2.GenerateVerifier()
	exchange := func(rawCode string) (*connect.Response[v1.ExchangeCliSessionResponse], error) {
		return f.auth("").ExchangeCliSession(ctx, connect.NewRequest(&v1.ExchangeCliSessionRequest{Code: rawCode, CodeVerifier: verifier}))
	}
	cli, err := exchange(newCLICode(verifier))
	if err != nil {
		t.Fatal(err)
	}
	pending := newCLICode(verifier)
	current, err := f.auth(cli.Msg.SessionToken).GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	u := current.Msg.User
	set := func(client rpc.UserServiceClient, rev string, disabled bool) (*v1.User, error) {
		res, err := client.SetUserDisabled(ctx, connect.NewRequest(&v1.SetUserDisabledRequest{UserId: u.UserId, ExpectedRevision: rev, Disabled: disabled}))
		if err != nil {
			return nil, err
		}
		return res.Msg.User, nil
	}
	viewer := rpc.NewUserServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(f.viewerToken)))
	_, err = set(viewer, u.Revision, true)
	code(t, err, connect.CodePermissionDenied)
	_, err = set(f.users(), "1", true)
	code(t, err, connect.CodeAborted)
	if _, err := f.auth("").GetCurrentSession(ctx, consoleSessionRequest(consoleRaw)); err != nil {
		t.Fatalf("a rejected disable revoked the console session: %v", err)
	}
	disabled, err := set(f.users(), u.Revision, true)
	if err != nil || !disabled.GetDisabled() || disabled.GetRevision() == u.Revision {
		t.Fatalf("disabled user=%v err=%v", disabled, err)
	}
	var revoked int
	if err := f.db.Pool.QueryRow(ctx, "SELECT count(*) FROM identity_sessions WHERE user_id=$1 AND revoked_at IS NOT NULL", u.UserId).Scan(&revoked); err != nil || revoked != 2 {
		t.Fatalf("revoked sessions=%d err=%v; want 2", revoked, err)
	}
	_, err = f.auth("").GetCurrentSession(ctx, consoleSessionRequest(consoleRaw))
	code(t, err, connect.CodeUnauthenticated)
	_, err = f.auth(cli.Msg.SessionToken).GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	code(t, err, connect.CodeUnauthenticated)
	_, err = exchange(pending)
	code(t, err, connect.CodeUnauthenticated)
	_, err = login(v1.LoginClient_LOGIN_CLIENT_CONSOLE, "")
	code(t, err, connect.CodeUnauthenticated)
	_, err = login(v1.LoginClient_LOGIN_CLIENT_CLI, verifier)
	code(t, err, connect.CodeUnauthenticated)
	enabled, err := set(f.users(), disabled.Revision, false)
	if err != nil || enabled.GetDisabled() || enabled.GetRevision() == disabled.Revision {
		t.Fatalf("re-enabled user=%v err=%v", enabled, err)
	}
	_, err = exchange(pending)
	code(t, err, connect.CodeUnauthenticated)
	_, err = f.auth(cli.Msg.SessionToken).GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	code(t, err, connect.CodeUnauthenticated)
	if _, err := login(v1.LoginClient_LOGIN_CLIENT_CONSOLE, ""); err != nil {
		t.Fatalf("fresh OIDC login after re-enabling: %v", err)
	}
	if _, err := exchange(newCLICode(verifier)); err != nil {
		t.Fatalf("fresh CLI exchange after re-enabling: %v", err)
	}
	assertUserSessionAudit(t, f, rpc.UserServiceSetUserDisabledProcedure, f.admin.UserId, u.UserId)
}

func TestRevokeUserSessions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, err := f.auth(f.viewerToken).RevokeUserSessions(ctx, connect.NewRequest(&v1.RevokeUserSessionsRequest{UserId: f.admin.UserId}))
	code(t, err, connect.CodePermissionDenied)
	_, err = f.auth(f.adminToken).RevokeUserSessions(ctx, connect.NewRequest(&v1.RevokeUserSessionsRequest{UserId: "missing"}))
	code(t, err, connect.CodeNotFound)
	for _, self := range []bool{false, true} {
		_, console, err := f.service.issueSession(ctx, f.db.Pool, f.viewer.UserId, v1.LoginClient_LOGIN_CLIENT_CONSOLE)
		if err != nil {
			t.Fatal(err)
		}
		_, cli, err := f.service.issueSession(ctx, f.db.Pool, f.viewer.UserId, v1.LoginClient_LOGIN_CLIENT_CLI)
		if err != nil {
			t.Fatal(err)
		}
		if self {
			current, err := f.auth("").GetCurrentSession(ctx, consoleSessionRequest(console))
			if err != nil {
				t.Fatal(err)
			}
			req := connect.NewRequest(&v1.RevokeUserSessionsRequest{})
			req.Header().Set("Cookie", "__Host-allowops-session="+console)
			req.Header().Set("Origin", f.server.URL)
			_, err = f.auth("").RevokeUserSessions(ctx, req)
			code(t, err, connect.CodePermissionDenied)
			req.Header().Set("X-CSRF-Token", current.Msg.CsrfToken)
			if _, err := f.auth("").RevokeUserSessions(ctx, req); err != nil {
				t.Fatal(err)
			}
			assertUserSessionAudit(t, f, rpc.AuthServiceRevokeUserSessionsProcedure, f.viewer.UserId, f.viewer.UserId)
		} else {
			if _, err := f.auth(f.adminToken).RevokeUserSessions(ctx, connect.NewRequest(&v1.RevokeUserSessionsRequest{UserId: f.viewer.UserId})); err != nil {
				t.Fatal(err)
			}
			assertUserSessionAudit(t, f, rpc.AuthServiceRevokeUserSessionsProcedure, f.admin.UserId, f.viewer.UserId)
		}
		_, err = f.auth("").GetCurrentSession(ctx, consoleSessionRequest(console))
		code(t, err, connect.CodeUnauthenticated)
		_, err = f.auth(cli).GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
		code(t, err, connect.CodeUnauthenticated)
	}
	if _, err := f.auth(f.adminToken).GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{})); err != nil {
		t.Fatalf("revocation affected a different user: %v", err)
	}
}

func TestCannotDisableLastEnabledAdministrator(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, err := f.users().SetUserDisabled(ctx, connect.NewRequest(&v1.SetUserDisabledRequest{UserId: f.admin.UserId, ExpectedRevision: f.admin.Revision, Disabled: true}))
	code(t, err, connect.CodeFailedPrecondition)
	if _, err := f.auth(f.adminToken).GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{})); err != nil {
		t.Fatalf("last administrator was locked out: %v", err)
	}
}

func TestDisabledUserRejectsPersistedCredentials(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, console, err := f.service.issueSession(ctx, f.db.Pool, f.viewer.UserId, v1.LoginClient_LOGIN_CLIENT_CONSOLE)
	if err != nil {
		t.Fatal(err)
	}
	verifier := oauth2.GenerateVerifier()
	pending := secret("")
	if err := insertCliLoginCode(ctx, f.db.Pool, hash(pending), f.viewer.UserId, oauth2.S256ChallengeFromVerifier(verifier), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Leave the session and code rows intact to exercise authentication independently of revocation.
	if _, err := f.db.Pool.Exec(ctx, "UPDATE console_users SET disabled=true WHERE user_id=$1", f.viewer.UserId); err != nil {
		t.Fatal(err)
	}
	_, err = f.auth("").GetCurrentSession(ctx, consoleSessionRequest(console))
	code(t, err, connect.CodeUnauthenticated)
	_, err = f.auth(f.viewerToken).GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	code(t, err, connect.CodeUnauthenticated)
	_, err = f.auth("").ExchangeCliSession(ctx, connect.NewRequest(&v1.ExchangeCliSessionRequest{Code: pending, CodeVerifier: verifier}))
	code(t, err, connect.CodeUnauthenticated)
}

func TestRevocationIncludesSessionsIssuedWhileWaiting(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := f.db.Pool.Exec(ctx, "ALTER DATABASE fixture SET default_transaction_isolation='repeatable read'"); err != nil {
		t.Fatal(err)
	}
	f.db.Pool.Reset()
	for _, disable := range []bool{false, true} {
		tx, err := f.db.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		_, raw, err := f.service.issueSession(ctx, tx, f.viewer.UserId, v1.LoginClient_LOGIN_CLIENT_CLI)
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			if disable {
				_, err := f.users().SetUserDisabled(ctx, connect.NewRequest(&v1.SetUserDisabledRequest{UserId: f.viewer.UserId, ExpectedRevision: f.viewer.Revision, Disabled: true}))
				result <- err
			} else {
				_, err := f.auth(f.adminToken).RevokeUserSessions(ctx, connect.NewRequest(&v1.RevokeUserSessionsRequest{UserId: f.viewer.UserId}))
				result <- err
			}
		}()
		pid := int32(tx.Conn().PgConn().PID())
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			var waiting bool
			err := f.db.Pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))", pid).Scan(&waiting)
			if err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			select {
			case err := <-result:
				t.Fatalf("revocation returned before issuance finished: %v", err)
			case <-ticker.C:
			case <-ctx.Done():
				t.Fatal("revocation did not wait for issuance")
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		var revoked bool
		if err := f.db.Pool.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM identity_sessions WHERE token_hash=$1", hash(raw)).Scan(&revoked); err != nil || !revoked {
			t.Fatalf("session issued before revocation: disabled=%v revoked=%v err=%v", disable, revoked, err)
		}
	}
}

func assertUserSessionAudit(t *testing.T, f *fixture, operation, actor, target string) {
	t.Helper()
	want := targetResource(auditTarget{Type: "user", ID: target})
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	for _, event := range f.audit.events {
		if event.Operation == operation && event.ActorID == actor && event.Phase == "result" && event.Outcome == "allow" && event.Resource == want {
			return
		}
	}
	t.Fatalf("result audit did not record user %s for %s", target, operation)
}
