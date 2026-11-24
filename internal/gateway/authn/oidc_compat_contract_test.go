package authn_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"golang.org/x/oauth2"
)

var pkceVerifier = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

const (
	issuerURL   = "https://idp.example.test"
	gatewayURL  = "https://gateway.example.test"
	callbackURL = gatewayURL + "/auth/oidc/callback"
	clientID    = "allowops"
	oidcEmail   = "alice@example.test"
)

type idpProfile struct {
	editClaims func(map[string]any)
	userInfo   map[string]any
	status     map[string]int // Endpoint path -> HTTP error.
}

type contractIDP struct {
	profile     idpProfile
	client      *http.Client
	secret      string
	accessToken string

	mu       sync.Mutex
	key      jose.JSONWebKey
	codes    map[string]url.Values // One-use grants bound to the authorization parameters.
	requests map[string][]url.Values
}

func newSigningKey(t *testing.T, kid string) jose.JSONWebKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: "RS256", Use: "sig"}
}

func newContractIDP(t *testing.T, key jose.JSONWebKey, profile idpProfile) *contractIDP {
	t.Helper()
	p := &contractIDP{
		key: key, profile: profile, secret: rand.Text(), accessToken: rand.Text(),
		codes: make(map[string]url.Values), requests: make(map[string][]url.Values),
	}
	p.client = httptest.NewTestServer(t, p).Client()
	return p
}

func (p *contractIDP) received(path string) []url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.requests[path])
}

func (p *contractIDP) sign(nonce string, key jose.JSONWebKey) (string, error) {
	now := time.Now()
	claims := map[string]any{
		"iss": issuerURL, "aud": clientID, "sub": "alice", "nonce": nonce,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"email": oidcEmail, "email_verified": true,
		"groups": []string{"ops", "audit", "also-ops", "ops", "unmapped"},
	}
	if p.profile.editClaims != nil {
		p.profile.editClaims(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return signed.CompactSerialize()
}

func (p *contractIDP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	reject := func(status int, code string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
	}
	params := r.URL.Query()
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			reject(http.StatusBadRequest, "invalid_request")
			return
		}
		params = r.PostForm
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	path := r.URL.Path
	p.requests[path] = append(p.requests[path], params)
	if status := p.profile.status[path]; status != 0 {
		if path == "/token" && status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="idp"`)
			reject(status, "invalid_client")
		} else {
			reject(status, "server_error")
		}
		return
	}
	switch r.Method + " " + path {
	case "GET /.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuerURL, "authorization_endpoint": issuerURL + "/authorize",
			"token_endpoint": issuerURL + "/token", "jwks_uri": issuerURL + "/jwks",
			"userinfo_endpoint": issuerURL + "/userinfo", "response_types_supported": []string{"code"},
			"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic"}, "code_challenge_methods_supported": []string{"S256"},
		})
	case "GET /jwks":
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{p.key.Public()}})
	case "GET /authorize":
		if params.Get("client_id") != clientID || params.Get("redirect_uri") != callbackURL {
			reject(http.StatusBadRequest, "invalid_request")
			return
		}
		challenge, err := base64.RawURLEncoding.Strict().DecodeString(params.Get("code_challenge"))
		if err != nil || len(challenge) != sha256.Size || params.Get("code_challenge_method") != "S256" {
			reject(http.StatusBadRequest, "invalid_request")
			return
		}
		if params.Get("response_type") != "code" || !slices.Contains(strings.Split(params.Get("scope"), " "), "openid") ||
			params.Get("state") == "" || params.Get("nonce") == "" {
			reject(http.StatusBadRequest, "invalid_request")
			return
		}
		code := rand.Text()
		p.codes[code] = params
		query := url.Values{"state": {params.Get("state")}, "code": {code}}
		http.Redirect(w, r, callbackURL+"?"+query.Encode(), http.StatusFound)
	case "POST /token":
		id, secret, ok := r.BasicAuth()
		if !ok || id != clientID || secret != p.secret {
			w.Header().Set("WWW-Authenticate", `Basic realm="idp"`)
			reject(http.StatusUnauthorized, "invalid_client")
			return
		}
		code := params.Get("code")
		grant, ok := p.codes[code]
		delete(p.codes, code)
		if !ok || params.Get("grant_type") != "authorization_code" || params.Get("redirect_uri") != grant.Get("redirect_uri") {
			reject(http.StatusBadRequest, "invalid_grant")
			return
		}
		verifier := params.Get("code_verifier")
		sum := sha256.Sum256([]byte(verifier))
		if !pkceVerifier.MatchString(verifier) || base64.RawURLEncoding.EncodeToString(sum[:]) != grant.Get("code_challenge") {
			reject(http.StatusBadRequest, "invalid_grant")
			return
		}
		token, err := p.sign(grant.Get("nonce"), p.key)
		if err != nil {
			reject(http.StatusInternalServerError, "server_error")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": p.accessToken, "token_type": "Bearer", "id_token": token})
	case "GET /userinfo":
		if r.Header.Get("Authorization") != "Bearer "+p.accessToken {
			reject(http.StatusUnauthorized, "invalid_token")
			return
		}
		info := p.profile.userInfo
		if info == nil {
			info = map[string]any{"sub": "alice"}
		}
		_ = json.NewEncoder(w).Encode(info)
	default:
		http.NotFound(w, r)
	}
}

func (p *contractIDP) config() authn.OIDCConfig {
	return authn.OIDCConfig{
		IssuerURL: issuerURL, ClientID: clientID, HTTPClient: p.client,
		RoleMappings: map[string]string{"ops": "operator", "also-ops": "operator", "audit": "auditor"},
	}
}

func TestOIDCVerifierRejections(t *testing.T) {
	key := newSigningKey(t, "published")
	other := newSigningKey(t, key.KeyID) // Wrong signature with a known kid.
	unpublished := key
	unpublished.KeyID = "unpublished" // Correct signing material with an unknown kid.
	for _, tc := range []struct {
		name    string
		signing jose.JSONWebKey
		profile idpProfile
	}{
		{"invalid signature", other, idpProfile{}},
		{"unknown kid", unpublished, idpProfile{}},
		{"expired", key, idpProfile{editClaims: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }}},
		{"wrong issuer", key, idpProfile{editClaims: func(c map[string]any) { c["iss"] = "https://other.example.test" }}},
		{"wrong audience", key, idpProfile{editClaims: func(c map[string]any) { c["aud"] = "other-client" }}},
		{"wrong nonce", key, idpProfile{editClaims: func(c map[string]any) { c["nonce"] = "other-login" }}},
		{"missing subject", key, idpProfile{editClaims: func(c map[string]any) { delete(c, "sub") }}},
		{"mixed groups", key, idpProfile{editClaims: func(c map[string]any) { c["groups"] = []any{"ops", 1} }}},
		{"JWKS unavailable", key, idpProfile{status: map[string]int{"/jwks": 503}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newContractIDP(t, key, tc.profile)
			verifier, err := authn.NewOIDC(t.Context(), p.config())
			if err != nil {
				t.Fatal(err)
			}
			raw, err := p.sign("this-login", tc.signing)
			if err != nil {
				t.Fatal(err)
			}
			id, err := verifier.VerifyNonce(t.Context(), raw, "this-login")
			if !errors.Is(err, authn.ErrInvalidCredentials) || id.ID != "" || id.Kind != "" || id.Email != "" || len(id.Groups) != 0 || len(id.Roles) != 0 {
				t.Fatalf("VerifyNonce returned identity %+v, error %v", id, err)
			}
			if tc.profile.status["/jwks"] != 0 && len(p.received("/jwks")) == 0 {
				t.Fatal("verification failed without requesting JWKS")
			}
		})
	}
}

func TestOIDCSigningKeyRotation(t *testing.T) {
	first := newSigningKey(t, "first")
	p := newContractIDP(t, first, idpProfile{})
	verifier, err := authn.NewOIDC(t.Context(), p.config())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []jose.JSONWebKey{first, newSigningKey(t, "rotated")} {
		p.mu.Lock()
		p.key = key
		p.mu.Unlock()
		before := len(p.received("/jwks"))
		raw, err := p.sign("login", key)
		if err != nil {
			t.Fatal(err)
		}
		id, err := verifier.VerifyNonce(t.Context(), raw, "login")
		if err != nil || id.ID != "alice" || id.Kind != "oidc" || id.Email != oidcEmail || !slices.Equal(id.Roles, []string{"auditor", "operator"}) {
			t.Fatalf("kid %s returned identity %+v, error %v", key.KeyID, id, err)
		}
		if len(p.received("/jwks")) <= before {
			t.Fatalf("verifier did not fetch the public key for kid %s", key.KeyID)
		}
	}
}

func getOIDCRedirect(t *testing.T, client *http.Client, address, wantEndpoint string) *url.URL {
	t.Helper()
	browser := *client
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := browser.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET %s returned %d, want redirect", resp.Request.URL.Path, resp.StatusCode)
	}
	dest, err := resp.Location()
	if err != nil {
		t.Fatal(err)
	}
	if dest.User != nil || dest.Scheme+"://"+dest.Host+dest.EscapedPath() != wantEndpoint {
		t.Fatalf("redirect from %s did not target %s", resp.Request.URL.Path, wantEndpoint)
	}
	return dest
}

// Drive the production AuthCodeURL and Exchange call sites. The gateway keeps
// state, nonce and verifier in PostgreSQL. Only the IdP is simulated.
func gatewayOIDCLogin(t *testing.T, db *store.Store, p *contractIDP) (*v1.User, error) {
	t.Helper()
	cfg := p.config()
	settings := api.Config{Origin: gatewayURL}
	for group, role := range cfg.RoleMappings {
		settings.RoleMappings = append(settings.RoleMappings, api.RoleMappingConfig{ProviderID: "enterprise", Group: group, Roles: []string{role}})
	}
	ctx := t.Context()
	service, err := api.New(ctx, db, settings, api.NewAuditor(audit.New(db.Pool, audit.Config{})))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.AddOIDC(ctx, "enterprise", "Enterprise", p.secret, cfg); err != nil {
		t.Fatal(err)
	}
	browser := httptest.NewTestServer(t, service.Handler()).Client()
	browser.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	auth := rpc.NewAuthServiceClient(browser, gatewayURL)
	begin := connect.NewRequest(&v1.BeginOidcLoginRequest{ProviderId: "enterprise", Client: v1.LoginClient_LOGIN_CLIENT_CONSOLE})
	begin.Header().Set("Origin", gatewayURL)
	begun, err := auth.BeginOidcLogin(ctx, begin)
	if err != nil {
		t.Fatal(err)
	}
	start, err := url.Parse(begun.Msg.AuthorizationUrl)
	if err != nil {
		t.Fatal(err)
	}
	state := start.Query().Get("state")
	authorization := getOIDCRedirect(t, browser, start.String(), issuerURL+"/authorize")
	callback := getOIDCRedirect(t, p.client, authorization.String(), callbackURL)
	completion := getOIDCRedirect(t, browser, callback.String(), gatewayURL+"/auth/oidc/complete")
	params, err := url.ParseQuery(completion.Fragment)
	if err != nil || params.Get("code") == "" || state == "" || params.Get("state") != state {
		t.Fatal("authorization code or initial state missing from callback")
	}
	requests := p.received("/authorize")
	if len(requests) != 1 {
		t.Fatalf("received %d authorization requests, want 1", len(requests))
	}
	request := requests[0]
	scopes := strings.Split(request.Get("scope"), " ")
	slices.Sort(scopes)
	if !slices.Equal(scopes, []string{"email", "groups", "openid", "profile"}) || request.Get("state") != state ||
		request.Get("nonce") == "" || request.Get("nonce") == state || request.Has("code_verifier") {
		t.Fatalf("invalid authorization parameters (scopes=%v)", scopes)
	}
	complete := connect.NewRequest(&v1.CompleteOidcLoginRequest{Code: params.Get("code"), State: params.Get("state")})
	complete.Header().Set("Origin", gatewayURL)
	_, exchangeErr := auth.CompleteOidcLogin(ctx, complete)
	tokens := p.received("/token")
	if len(tokens) == 0 {
		t.Fatal("gateway did not attempt code exchange")
	}
	for _, token := range tokens { // OAuth clients may retry client authentication after an error.
		verifier := token.Get("code_verifier")
		if !pkceVerifier.MatchString(verifier) || request.Get("code_challenge_method") != "S256" ||
			oauth2.S256ChallengeFromVerifier(verifier) != request.Get("code_challenge") || token.Get("code") != params.Get("code") {
			t.Fatal("code exchange did not present the verifier bound to this authorization code")
		}
	}
	if exchangeErr != nil {
		return nil, exchangeErr
	}
	current, err := auth.GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return current.Msg.User, nil
}

type enterpriseCase struct {
	name          string
	profile       idpProfile
	email         string
	groups, roles []string
}

func enterpriseCases() []enterpriseCase {
	groups := []string{"also-ops", "audit", "ops", "unmapped"}
	roles := []string{"auditor", "operator"}
	return []enterpriseCase{
		{"mapped groups", idpProfile{}, oidcEmail, groups, roles},
		{"unverified email", idpProfile{editClaims: func(c map[string]any) { c["email_verified"] = false }}, "", groups, roles},
		{"missing email verification", idpProfile{editClaims: func(c map[string]any) { delete(c, "email_verified") }}, "", groups, roles},
		{"custom roles claim", idpProfile{editClaims: func(c map[string]any) {
			c["roles"] = c["groups"]
			delete(c, "groups")
		}}, oidcEmail, nil, nil},
		{"userinfo groups only", idpProfile{
			editClaims: func(c map[string]any) { delete(c, "groups") },
			userInfo:   map[string]any{"sub": "alice", "groups": []string{"ops", "audit"}},
		}, oidcEmail, nil, nil},
	}
}

// Exercise claim verification even on machines without the gateway's database.
func TestOIDCEnterpriseClaims(t *testing.T) {
	key := newSigningKey(t, "enterprise")
	for _, tc := range enterpriseCases() {
		t.Run(tc.name, func(t *testing.T) {
			p := newContractIDP(t, key, tc.profile)
			verifier, err := authn.NewOIDC(t.Context(), p.config())
			if err != nil {
				t.Fatal(err)
			}
			raw, err := p.sign("login", key)
			if err != nil {
				t.Fatal(err)
			}
			id, err := verifier.VerifyNonce(t.Context(), raw, "login")
			if err != nil || id.ID != "alice" || id.Email != tc.email || !slices.Equal(id.Roles, tc.roles) {
				t.Fatalf("verified identity=%+v, want email=%q roles=%v, error=%v", id, tc.email, tc.roles, err)
			}
		})
	}
}

func TestOIDCProviderLoginContract(t *testing.T) {
	dsn := testpg.Start(t)
	if err := store.Migrate(t.Context(), dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	key := newSigningKey(t, "enterprise")
	for _, tc := range enterpriseCases() {
		t.Run(tc.name, func(t *testing.T) {
			p := newContractIDP(t, key, tc.profile)
			user, err := gatewayOIDCLogin(t, db, p)
			if err != nil {
				t.Fatal(err)
			}
			if user.GetUserId() == "" || user.GetEmail() != tc.email || !slices.Equal(user.GetGroups(), tc.groups) ||
				!slices.Equal(user.GetEffectiveRoles(), tc.roles) {
				t.Fatalf("session user: email=%q groups=%v roles=%v; want %q %v %v",
					user.GetEmail(), user.GetGroups(), user.GetEffectiveRoles(), tc.email, tc.groups, tc.roles)
			}
			if n := len(p.received("/userinfo")); n != 0 {
				t.Fatalf("gateway requested UserInfo %d times, want zero for ID-token-only mapping", n)
			}
			if tc.profile.userInfo != nil {
				// Positive control: the access token issued to the gateway can
				// actually retrieve the groups from the advertised endpoint.
				ctx := oidc.ClientContext(t.Context(), p.client)
				discovery, err := oidc.NewProvider(ctx, issuerURL)
				if err != nil {
					t.Fatal(err)
				}
				info, err := discovery.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: p.accessToken}))
				if err != nil {
					t.Fatal(err)
				}
				var claims struct{ Groups []string }
				wantGroups, _ := tc.profile.userInfo["groups"].([]string)
				if err := info.Claims(&claims); err != nil || info.Subject != tc.profile.userInfo["sub"] || !slices.Equal(claims.Groups, wantGroups) {
					t.Fatalf("UserInfo subject=%q groups=%v, error=%v", info.Subject, claims.Groups, err)
				}
			}
		})
	}
	for _, tc := range []struct {
		name    string
		profile idpProfile
		message string
	}{
		{"token 401", idpProfile{status: map[string]int{"/token": 401}}, "OIDC code exchange rejected"},
		{"token 500", idpProfile{status: map[string]int{"/token": 500}}, "OIDC code exchange rejected"},
		{"nonce mismatch", idpProfile{editClaims: func(c map[string]any) { c["nonce"] = "other-login" }}, "OIDC identity rejected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user, err := gatewayOIDCLogin(t, db, newContractIDP(t, key, tc.profile))
			var rpcErr *connect.Error
			if !errors.As(err, &rpcErr) || rpcErr.Code() != connect.CodeUnauthenticated || rpcErr.Message() != tc.message || user != nil {
				t.Fatalf("login returned user=%v, error=%v, want unauthenticated: %s", user, err, tc.message)
			}
		})
	}
}
