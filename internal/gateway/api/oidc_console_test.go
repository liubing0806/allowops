package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"golang.org/x/oauth2"
)

func TestOIDCConsoleReloginAndHTTPCallback(t *testing.T) {
	f := newFixture(t)
	p := newOIDC(t)
	f.addOIDC(t, p)
	ctx := context.Background()
	// Strict cookies need not be sent on the cross-site provider callback. The
	// callback must deliver a same-origin fragment completion, never a session.
	dest, cookie := f.begin(t, v1.LoginClient_LOGIN_CLIENT_CONSOLE, "")
	providerBrowser := *p.server.Client()
	providerBrowser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	authorized, err := providerBrowser.Get(dest.String())
	if err != nil {
		t.Fatal(err)
	}
	authorized.Body.Close()
	callback := authorized.Header.Get("Location")
	if !strings.HasPrefix(callback, f.server.URL+"/auth/oidc/callback?") {
		t.Fatal("provider callback differs from gateway fixed callback")
	}
	browser := *f.server.Client()
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	bridged, err := browser.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	bridged.Body.Close()
	completion, _ := url.Parse(bridged.Header.Get("Location"))
	if completion.Path != "/auth/oidc/complete" || completion.RawQuery != "" || completion.Fragment == "" || len(bridged.Cookies()) != 0 {
		t.Fatal("invalid callback bridge")
	}
	values, _ := url.ParseQuery(completion.Fragment)
	_, old, err := f.service.issueSession(ctx, f.db.Pool, f.admin.UserId, v1.LoginClient_LOGIN_CLIENT_CONSOLE)
	if err != nil {
		t.Fatal(err)
	}
	req := connect.NewRequest(&v1.CompleteOidcLoginRequest{Code: values.Get("code"), State: values.Get("state")})
	req.Header().Set("Origin", f.server.URL)
	req.Header().Set("Cookie", cookie.Name+"="+cookie.Value+"; __Host-allowops-session="+old)
	response, err := f.auth("").CompleteOidcLogin(ctx, req)
	if err != nil {
		t.Fatalf("existing console session prevented OIDC login: %v", err)
	}
	if response.Msg.RedirectUri != f.server.URL+"/" || strings.Contains(response.Msg.RedirectUri, "aops_") {
		t.Fatal("console token leaked to redirect")
	}
	result := (&http.Response{Header: response.Header()}).Cookies()
	if len(result) != 1 || !result[0].HttpOnly || !result[0].Secure || result[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("console login omitted secure cookie")
	}
	if ttl := time.Until(result[0].Expires); ttl < DefaultConsoleTTL-time.Minute || ttl > DefaultConsoleTTL+time.Minute {
		t.Fatalf("console cookie TTL=%s", ttl)
	}
	// A revoked session cookie must permit login while still being rejected for
	// authenticated operations.
	if _, err := f.db.Pool.Exec(ctx, "UPDATE identity_sessions SET revoked_at=now() WHERE token_hash=$1", hash(old)); err != nil {
		t.Fatal(err)
	}
	dest, cookie = f.begin(t, v1.LoginClient_LOGIN_CLIENT_CONSOLE, "")
	providerCode := secret("")
	p.mu.Lock()
	p.codes[providerCode] = fakeCode{dest.Query().Get("nonce"), dest.Query().Get("code_challenge")}
	p.mu.Unlock()
	req = connect.NewRequest(&v1.CompleteOidcLoginRequest{Code: providerCode, State: dest.Query().Get("state")})
	req.Header().Set("Origin", f.server.URL)
	req.Header().Set("Cookie", cookie.Name+"="+cookie.Value+"; __Host-allowops-session="+old)
	if _, err := f.auth("").CompleteOidcLogin(ctx, req); err != nil {
		t.Fatalf("revoked console cookie prevented OIDC login: %v", err)
	}
}

func TestOIDCCodeExpiryAndConcurrentExchange(t *testing.T) {
	f := newFixture(t)
	p := newOIDC(t)
	f.addOIDC(t, p)
	ctx := context.Background()
	pv := oauth2.GenerateVerifier()
	dest, cookie := f.begin(t, v1.LoginClient_LOGIN_CLIENT_CLI, pv)
	response, err := f.complete(t, p, dest, cookie, dest.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	loop, _ := url.Parse(response.Msg.RedirectUri)
	raw := loop.Query().Get("code")
	var expiry time.Time
	if err := f.db.Pool.QueryRow(ctx, "SELECT expires_at FROM cli_login_codes WHERE code_hash=$1", hash(raw)).Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	if time.Until(expiry) > time.Minute || time.Until(expiry) < time.Minute-time.Second {
		t.Fatal("one-time code TTL differs from 60 seconds")
	}
	if _, err := f.db.Pool.Exec(ctx, "UPDATE cli_login_codes SET expires_at=now()-interval '1 second' WHERE code_hash=$1", hash(raw)); err != nil {
		t.Fatal(err)
	}
	_, err = f.auth("").ExchangeCliSession(ctx, connect.NewRequest(&v1.ExchangeCliSessionRequest{Code: raw, CodeVerifier: pv}))
	code(t, err, connect.CodeUnauthenticated)
	dest, cookie = f.begin(t, v1.LoginClient_LOGIN_CLIENT_CLI, pv)
	response, err = f.complete(t, p, dest, cookie, dest.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	loop, _ = url.Parse(response.Msg.RedirectUri)
	raw = loop.Query().Get("code")
	results := make(chan error, 10)
	for range 10 {
		go func() {
			_, err := f.auth("").ExchangeCliSession(ctx, connect.NewRequest(&v1.ExchangeCliSessionRequest{Code: raw, CodeVerifier: pv}))
			results <- err
		}()
	}
	succeeded := 0
	for range 10 {
		err := <-results
		if err == nil {
			succeeded++
		} else {
			code(t, err, connect.CodeUnauthenticated)
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful code exchanges=%d; want 1", succeeded)
	}
	dest, cookie = f.begin(t, v1.LoginClient_LOGIN_CLIENT_CLI, pv)
	if _, err := f.db.Pool.Exec(ctx, "UPDATE oidc_transactions SET expires_at=now()-interval '1 second' WHERE state_hash=$1", hash(dest.Query().Get("state"))); err != nil {
		t.Fatal(err)
	}
	_, err = f.complete(t, p, dest, cookie, dest.Query().Get("state"))
	code(t, err, connect.CodeUnauthenticated)
}
