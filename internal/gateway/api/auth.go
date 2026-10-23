package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"golang.org/x/oauth2"
)

type OIDCProvider struct {
	method   *v1.LoginMethod
	verifier *authn.OIDC
	oauth    oauth2.Config
	client   *http.Client
}

type LDAPProvider struct {
	Method        *v1.LoginMethod
	Authenticator *authn.LDAP
	Directory     authn.DirectoryCredentials
}

// Register providers before Handler/Start. Secrets belong to operator-supplied
// configuration and are never returned by GetLoginMethods or copied into audit.
func (s *Service) AddOIDC(ctx context.Context, id, name, clientSecret string, cfg authn.OIDCConfig) error {
	if id == "" || s.oidc[id] != nil || s.ldap[id].Method != nil {
		return errors.New("duplicate or empty provider ID")
	}
	verifier, err := authn.NewOIDC(ctx, cfg)
	if err != nil {
		return err
	}
	if cfg.HTTPClient != nil {
		ctx = oidc.ClientContext(ctx, cfg.HTTPClient)
	}
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return err
	}
	endpoint := provider.Endpoint()
	for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return errors.New("OIDC requires HTTPS OAuth endpoints")
		}
	}
	s.oidc[id] = &OIDCProvider{method: &v1.LoginMethod{ProviderId: id, DisplayName: name, Kind: "oidc"}, verifier: verifier, oauth: oauth2.Config{ClientID: cfg.ClientID, ClientSecret: clientSecret, Endpoint: endpoint, RedirectURL: s.Config.Origin + "/auth/oidc/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"}}, client: cfg.HTTPClient}
	return nil
}

func (s *Service) AddLDAP(id, name string, auth *authn.LDAP, directory authn.DirectoryCredentials) error {
	if id == "" || auth == nil || s.oidc[id] != nil || s.ldap[id].Method != nil {
		return errors.New("invalid LDAP provider")
	}
	s.ldap[id] = LDAPProvider{Method: &v1.LoginMethod{ProviderId: id, DisplayName: name, Kind: "ldap"}, Authenticator: auth, Directory: directory}
	return nil
}

func (s *Service) GetLoginMethods(context.Context, *connect.Request[v1.GetLoginMethodsRequest]) (*connect.Response[v1.GetLoginMethodsResponse], error) {
	ids := []string{}
	for id := range s.oidc {
		ids = append(ids, id)
	}
	for id := range s.ldap {
		ids = append(ids, id)
	}
	methods := []*v1.LoginMethod{}
	for _, id := range unique(ids) {
		if p := s.oidc[id]; p != nil {
			methods = append(methods, p.method)
		} else {
			methods = append(methods, s.ldap[id].Method)
		}
	}
	return connect.NewResponse(&v1.GetLoginMethodsResponse{Methods: methods}), nil
}

func loopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/callback" {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.IsLoopback() {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	return err == nil && port > 0 && port <= 65535
}

func challenge(raw string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	return err == nil && len(b) == sha256.Size
}

func verifier(raw string) bool {
	if len(raw) < 43 || len(raw) > 128 {
		return false
	}
	for _, r := range raw {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~", r)) {
			return false
		}
	}
	return true
}

func (s *Service) BeginOidcLogin(ctx context.Context, r *connect.Request[v1.BeginOidcLoginRequest]) (*connect.Response[v1.BeginOidcLoginResponse], error) {
	m := r.Msg
	if s.oidc[m.ProviderId] == nil {
		return nil, failure(connect.CodeInvalidArgument, "OIDC provider not found")
	}
	client := "console"
	switch m.Client {
	case v1.LoginClient_LOGIN_CLIENT_CLI:
		client = "cli"
		if !loopback(m.CliLoopbackUri) || len(m.CliState) < 32 || len(m.CliState) > 256 || !challenge(m.CliCodeChallenge) {
			return nil, failure(connect.CodeInvalidArgument, "invalid CLI loopback, state or S256 challenge")
		}
	case v1.LoginClient_LOGIN_CLIENT_CONSOLE:
		if r.Header().Get("Origin") != s.Config.Origin || m.CliLoopbackUri != "" || m.CliState != "" || m.CliCodeChallenge != "" {
			return nil, failure(connect.CodePermissionDenied, "console origin rejected")
		}
	default:
		return nil, failure(connect.CodeInvalidArgument, "login client required")
	}
	// Serialize OIDC login-transaction admission (shared cap of 10000 live transactions) across
	// providers and gateway instances (design A47). Read
	// Committed takes a fresh count snapshot after waiting for this shared lock.
	tx, err := s.Store.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	if err = lockOidcAdmission(ctx, tx); err != nil {
		return nil, dbError(err)
	}
	if err = purgeOidcTransactions(ctx, tx); err != nil {
		return nil, dbError(err)
	}
	live, err := countOidcTransactions(ctx, tx)
	if err != nil {
		return nil, dbError(err)
	}
	if live >= 10000 {
		// Cleanup remains durable even when there is no room for a new login.
		if err = tx.Commit(ctx); err != nil {
			return nil, dbError(err)
		}
		return nil, failure(connect.CodeResourceExhausted, "OIDC login transaction capacity exhausted")
	}
	state := secret("")
	err = insertOidcTransaction(ctx, tx, oidcTransaction{provider: m.ProviderId, client: client, nonce: secret(""), verifier: oauth2.GenerateVerifier(), loopback: m.CliLoopbackUri, cliState: m.CliState, challenge: m.CliCodeChallenge}, hash(state), time.Now().Add(s.Config.LoginTTL))
	if err != nil {
		return nil, dbError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.BeginOidcLoginResponse{AuthorizationUrl: s.Config.Origin + "/auth/oidc/start?state=" + url.QueryEscape(state)}), nil
}

func (s *Service) oidcStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	event := AuditEvent{ActorID: reqctx.ActorID(r.Context()), Operation: "/auth/oidc/start", Phase: "result", Outcome: "deny", SourceIP: transport(r.Context()).ip}
	if r.Method != http.MethodGet || r.TLS == nil {
		if err := s.AppendResultAudit(r.Context(), event); err != nil {
			http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "invalid login", http.StatusBadRequest)
		return
	}
	authorized := event
	authorized.Phase, authorized.Outcome = "authorized", "allow"
	if err := s.Audit.Append(r.Context(), authorized); err != nil {
		http.Error(w, "authorization audit unavailable; operation not executed", http.StatusServiceUnavailable)
		return
	}
	binding := secret("")
	if c, err := r.Cookie("__Host-allowops-login"); err == nil && len(c.Value) == 43 {
		binding = c.Value
	}
	state := r.URL.Query().Get("state")
	provider, nonce, pv, err := bindOidcTransaction(r.Context(), s.Store.Pool, hash(state), hash(binding))
	if err == nil && s.oidc[provider] != nil {
		event.Outcome = "allow"
	}
	if auditErr := s.AppendResultAudit(r.Context(), event); auditErr != nil {
		http.Error(w, "result audit unavailable; operation may have committed", http.StatusServiceUnavailable)
		return
	}
	if err != nil || s.oidc[provider] == nil {
		http.Error(w, "invalid login", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-allowops-login", Value: binding, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int(s.Config.LoginTTL.Seconds())})
	dest := s.oidc[provider].oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pv))
	http.Redirect(w, r, dest, http.StatusFound)
}

func (s *Service) oidcCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet || r.TLS == nil || r.URL.Query().Get("code") == "" || r.URL.Query().Get("state") == "" || r.URL.Query().Get("error") != "" {
		http.Error(w, "invalid login", http.StatusBadRequest)
		return
	}
	// A fragment keeps the provider code out of the completion-page request and
	// referrer. This same-origin navigation restores the Strict binding cookie.
	fragment := url.Values{"code": {r.URL.Query().Get("code")}, "state": {r.URL.Query().Get("state")}}.Encode()
	http.Redirect(w, r, s.Config.Origin+"/auth/oidc/complete#"+fragment, http.StatusFound)
}

func (s *Service) oidcPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.TLS == nil {
		http.Error(w, "invalid login", http.StatusBadRequest)
		return
	}
	nonce := secret("")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	fmt.Fprintf(w, `<!doctype html><title>allowops login</title><p id="status">Completing login</p><script nonce="%s">const p=new URLSearchParams(location.hash.slice(1));history.replaceState(null,'',location.pathname);fetch('/allowops.v1.AuthService/CompleteOidcLogin',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','Connect-Protocol-Version':'1'},body:JSON.stringify({code:p.get('code'),state:p.get('state')})}).then(async r=>{if(!r.ok)throw Error();const v=await r.json();location.replace(v.redirectUri||v.redirect_uri)}).catch(()=>document.getElementById('status').textContent='Login failed');</script>`, nonce)
}

func (s *Service) CompleteOidcLogin(ctx context.Context, r *connect.Request[v1.CompleteOidcLoginRequest]) (*connect.Response[v1.CompleteOidcLoginResponse], error) {
	t := transport(ctx)
	if t == nil || r.Header().Get("Origin") != s.Config.Origin {
		return nil, failure(connect.CodePermissionDenied, "login browser origin rejected")
	}
	req := &http.Request{Header: r.Header()}
	c, err := req.Cookie("__Host-allowops-login")
	if err != nil || c.Value == "" {
		return nil, failure(connect.CodeUnauthenticated, "login browser binding required")
	}
	tr, err := takeOidcTransaction(ctx, s.Store.Pool, hash(r.Msg.State), hash(c.Value))
	provider, client, nonce, pv, loop, state, pkce := tr.provider, tr.client, tr.nonce, tr.verifier, tr.loopback, tr.cliState, tr.challenge
	if err != nil || s.oidc[provider] == nil {
		return nil, failure(connect.CodeUnauthenticated, "invalid login state or browser binding")
	}
	p := s.oidc[provider]
	if p.client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, p.client)
	}
	token, err := p.oauth.Exchange(ctx, r.Msg.Code, oauth2.VerifierOption(pv))
	if err != nil {
		return nil, failure(connect.CodeUnauthenticated, "OIDC code exchange rejected")
	}
	raw, _ := token.Extra("id_token").(string)
	id, err := p.verifier.VerifyNonce(ctx, raw, nonce)
	if err != nil {
		return nil, failure(connect.CodeUnauthenticated, "OIDC identity rejected")
	}
	u, err := s.syncUser(ctx, provider, id)
	if err != nil {
		return nil, err
	}
	t.auditActor = u.UserId
	if client == "cli" {
		code := secret("")
		if err := insertCliLoginCode(ctx, s.Store.Pool, hash(code), u.UserId, pkce, time.Now().Add(s.Config.CodeTTL)); err != nil {
			return nil, dbError(err)
		}
		dest, _ := url.Parse(loop)
		dest.RawQuery = url.Values{"code": {code}, "state": {state}}.Encode()
		return connect.NewResponse(&v1.CompleteOidcLoginResponse{RedirectUri: dest.String()}), nil
	}
	sess, raw, err := s.issueSession(ctx, s.Store.Pool, u.UserId, v1.LoginClient_LOGIN_CLIENT_CONSOLE)
	if err != nil {
		return nil, err
	}
	s.sessionCookie(ctx, raw, sess.ExpiresAt.AsTime())
	return connect.NewResponse(&v1.CompleteOidcLoginResponse{RedirectUri: s.Config.Origin + "/"}), nil
}

func (s *Service) ExchangeCliSession(ctx context.Context, r *connect.Request[v1.ExchangeCliSessionRequest]) (*connect.Response[v1.ExchangeCliSessionResponse], error) {
	if !verifier(r.Msg.CodeVerifier) {
		return nil, failure(connect.CodeUnauthenticated, "invalid PKCE verifier")
	}
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	userID, pkce, err := lockCliLoginCode(ctx, tx, hash(r.Msg.Code))
	if err != nil {
		return nil, failure(connect.CodeUnauthenticated, "invalid or consumed login code")
	}
	got := base64.RawURLEncoding.EncodeToString(hash(r.Msg.CodeVerifier))
	if subtle.ConstantTimeCompare([]byte(got), []byte(pkce)) != 1 {
		return nil, failure(connect.CodeUnauthenticated, "PKCE mismatch")
	}
	if err := deleteCliLoginCode(ctx, tx, hash(r.Msg.Code)); err != nil {
		return nil, dbError(err)
	}
	sess, token, err := s.issueSession(ctx, tx, userID, v1.LoginClient_LOGIN_CLIENT_CLI)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	transport(ctx).auditActor = userID
	return connect.NewResponse(&v1.ExchangeCliSessionResponse{Session: sess, SessionToken: token}), nil
}

func (s *Service) sessionCookie(ctx context.Context, raw string, expires time.Time) {
	http.SetCookie(transport(ctx).writer, &http.Cookie{Name: "__Host-allowops-session", Value: raw, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: max(1, int(time.Until(expires).Seconds()))})
}

func (s *Service) LoginLdap(ctx context.Context, r *connect.Request[v1.LoginLdapRequest]) (*connect.Response[v1.LoginLdapResponse], error) {
	p := s.ldap[r.Msg.ProviderId]
	if p.Authenticator == nil {
		return nil, failure(connect.CodeInvalidArgument, "LDAP provider not found")
	}
	if r.Msg.Client != v1.LoginClient_LOGIN_CLIENT_CLI && r.Msg.Client != v1.LoginClient_LOGIN_CLIENT_CONSOLE {
		return nil, failure(connect.CodeInvalidArgument, "login client required")
	}
	if r.Msg.Client == v1.LoginClient_LOGIN_CLIENT_CONSOLE && r.Header().Get("Origin") != s.Config.Origin {
		return nil, failure(connect.CodePermissionDenied, "console origin rejected")
	}
	id, err := p.Authenticator.Login(ctx, r.Msg.Username, r.Msg.Password, transport(ctx).ip, p.Directory)
	if err != nil {
		code := connect.CodeUnauthenticated
		if errors.Is(err, authn.ErrRateLimited) {
			code = connect.CodeResourceExhausted
		}
		if errors.Is(err, authn.ErrDirectoryUnavailable) {
			code = connect.CodeUnavailable
		}
		return nil, failure(code, "LDAP login rejected")
	}
	u, err := s.syncUser(ctx, r.Msg.ProviderId, id)
	if err != nil {
		return nil, err
	}
	transport(ctx).auditActor = u.UserId
	sess, raw, err := s.issueSession(ctx, s.Store.Pool, u.UserId, r.Msg.Client)
	if err != nil {
		return nil, err
	}
	response := &v1.LoginLdapResponse{User: u}
	if r.Msg.Client == v1.LoginClient_LOGIN_CLIENT_CLI {
		response.CliSession = sess
		response.CliSessionToken = &raw
	} else {
		s.sessionCookie(ctx, raw, sess.ExpiresAt.AsTime())
	}
	return connect.NewResponse(response), nil
}

func (s *Service) GetCurrentSession(ctx context.Context, _ *connect.Request[v1.GetCurrentSessionRequest]) (*connect.Response[v1.GetCurrentSessionResponse], error) {
	id, ok := reqctx.FromContext(ctx)
	if !ok || id.Session == nil {
		return nil, failure(connect.CodeFailedPrecondition, "user session required")
	}
	return connect.NewResponse(&v1.GetCurrentSessionResponse{User: id.User, Client: id.Client, ExpiresAt: id.Session.ExpiresAt, CsrfToken: id.CSRF}), nil
}

func (s *Service) Logout(ctx context.Context, _ *connect.Request[v1.LogoutRequest]) (*connect.Response[v1.LogoutResponse], error) {
	id, ok := reqctx.FromContext(ctx)
	if !ok || id.Session == nil {
		return nil, failure(connect.CodeFailedPrecondition, "user session required")
	}
	if err := revokeSession(ctx, s.Store.Pool, id.Session.SessionId); err != nil {
		return nil, dbError(err)
	}
	if id.Client == v1.LoginClient_LOGIN_CLIENT_CONSOLE {
		http.SetCookie(transport(ctx).writer, &http.Cookie{Name: "__Host-allowops-session", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	}
	return connect.NewResponse(&v1.LogoutResponse{}), nil
}

func (s *Service) sessionUser(ctx context.Context, userID string) (string, error) {
	id, ok := reqctx.FromContext(ctx)
	if !ok || id.User == nil {
		return "", failure(connect.CodePermissionDenied, "user session required")
	}
	if userID == "" || userID == id.User.UserId {
		return id.User.UserId, nil
	}
	admin := false
	for _, role := range id.User.EffectiveRoles {
		if role == "admin" {
			admin = true
		}
	}
	if !admin {
		return "", failure(connect.CodePermissionDenied, "only admin may select another user")
	}
	if _, err := s.Require(ctx, authz.ManageUserRoles, authz.Action{}, authz.Host{}); err != nil {
		return "", err
	}
	return userID, nil
}

func (s *Service) ListCliSessions(ctx context.Context, r *connect.Request[v1.ListCliSessionsRequest]) (*connect.Response[v1.ListCliSessionsResponse], error) {
	uid, err := s.sessionUser(ctx, r.Msg.UserId)
	if err != nil {
		return nil, err
	}
	items, err := listCliSessions(ctx, s.Store.Pool, uid)
	if err != nil {
		return nil, dbError(err)
	}
	items, p, err := page(ctx, s.Config, "cli_sessions:"+uid, r.Msg.Page, items)
	return connect.NewResponse(&v1.ListCliSessionsResponse{Sessions: items, Page: p}), err
}

func (s *Service) RevokeCliSession(ctx context.Context, r *connect.Request[v1.RevokeCliSessionRequest]) (*connect.Response[v1.RevokeCliSessionResponse], error) {
	uid, err := s.sessionUser(ctx, r.Msg.UserId)
	if err != nil {
		return nil, err
	}
	revoked, err := revokeCliSession(ctx, s.Store.Pool, r.Msg.SessionId, uid)
	if err == nil && revoked == 0 {
		return nil, failure(connect.CodeNotFound, "session not found for user")
	}
	return connect.NewResponse(&v1.RevokeCliSessionResponse{}), dbError(err)
}
