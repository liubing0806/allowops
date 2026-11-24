package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

func TestOIDCWithLocalProvider(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	var userInfoCalls, insecureCalls atomic.Int32
	insecure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		insecureCalls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer insecure.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys", "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "userinfo_endpoint": issuer + "/userinfo", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}})
		case "/userinfo":
			userInfoCalls.Add(1)
			claims := map[string]any{"sub": "user-1", "email": "userinfo@example.org", "email_verified": true, "departments": []string{"audit"}}
			switch r.Header.Get("Authorization") {
			case "Bearer valid":
			case "Bearer mismatch":
				claims["sub"] = "another-user"
			case "Bearer unverified-email":
				claims["email_verified"] = false
			case "Bearer malformed-groups":
				claims["departments"] = "audit"
			case "Bearer downgrade":
				http.Redirect(w, r, insecure.URL, http.StatusFound)
				return
			default:
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(claims)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	mappings := map[string]string{"ops": "operator", "audit": "auditor", "also-ops": "operator"}
	authenticator, err := NewOIDC(context.Background(), OIDCConfig{IssuerURL: issuer, ClientID: "allowops", HTTPClient: server.Client(), RoleMappings: mappings})
	if err != nil {
		t.Fatal(err)
	}
	mappings["ops"] = "admin"
	sign := func(claims map[string]any, signingKey *rsa.PrivateKey) string {
		t.Helper()
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}, (&jose.SignerOptions{}).WithHeader("kid", "test-key"))
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		object, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		token, err := object.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	claims := func() map[string]any {
		return map[string]any{"iss": issuer, "aud": "allowops", "sub": "user-1", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "email": "alice@example.org", "email_verified": true, "groups": []string{"ops", "audit", "also-ops", "unknown"}}
	}
	validToken := sign(claims(), key)
	identity, err := authenticator.Verify(context.Background(), validToken)
	if err != nil || identity.ID != "user-1" || identity.Kind != "oidc" || identity.Email != "alice@example.org" || !reflect.DeepEqual(identity.Roles, []string{"auditor", "operator"}) {
		t.Fatalf("identity=%+v, error=%v", identity, err)
	}
	for _, tt := range []struct {
		name   string
		modify func(map[string]any)
	}{
		{"wrong issuer", func(c map[string]any) { c["iss"] = issuer + "/wrong" }},
		{"wrong audience", func(c map[string]any) { c["aud"] = "other" }},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
		{"missing subject", func(c map[string]any) { delete(c, "sub") }},
		{"malformed groups", func(c map[string]any) { c["groups"] = "ops" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := claims()
			tt.modify(c)
			got, err := authenticator.Verify(context.Background(), sign(c, key))
			if !errors.Is(err, ErrInvalidCredentials) || got.ID != "" {
				t.Fatalf("accepted invalid token: %+v, %v", got, err)
			}
		})
	}
	forgedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Verify(context.Background(), sign(claims(), forgedKey)); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("forged signature: %v", err)
	}
	c := claims()
	c["email_verified"] = false
	delete(c, "groups")
	identity, err = authenticator.Verify(context.Background(), sign(c, key))
	if err != nil || identity.Email != "" || len(identity.Roles) != 0 {
		t.Fatalf("unverified email/absent groups: %+v, %v", identity, err)
	}
	if _, err := authenticator.Verify(context.Background(), "not-a-token"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("malformed token: %v", err)
	}

	t.Run("custom claims and UserInfo", func(t *testing.T) {
		ctx := context.Background()
		cfg := OIDCConfig{IssuerURL: issuer, ClientID: "allowops", HTTPClient: server.Client(), GroupsClaim: "departments", RoleMappings: map[string]string{"audit": "auditor"}}
		custom, err := NewOIDC(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		cfg.FetchUserInfo = true
		withUserInfo, err := NewOIDC(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		loginToken := func(c map[string]any, access string) *oauth2.Token {
			c["nonce"] = "login-nonce"
			return (&oauth2.Token{AccessToken: access}).WithExtra(map[string]any{"id_token": sign(c, key)})
		}
		c := claims()
		c["departments"] = []string{"audit"}
		got, err := custom.VerifyLogin(ctx, loginToken(c, ""), "login-nonce")
		if err != nil || !reflect.DeepEqual(got.Roles, []string{"auditor"}) || userInfoCalls.Load() != 0 {
			t.Fatalf("custom ID token claim: identity=%+v err=%v userinfo calls=%d", got, err, userInfoCalls.Load())
		}
		delete(c, "departments")
		c["email_verified"] = false
		if _, err := withUserInfo.VerifyLogin(ctx, loginToken(c, "valid"), "wrong-nonce"); !errors.Is(err, ErrInvalidCredentials) || userInfoCalls.Load() != 0 {
			t.Fatalf("unverified ID token used UserInfo: err=%v userinfo calls=%d", err, userInfoCalls.Load())
		}
		got, err = withUserInfo.VerifyLogin(ctx, loginToken(c, "valid"), "login-nonce")
		if err != nil || got.Email != "userinfo@example.org" || !reflect.DeepEqual(got.Groups, []string{"audit"}) || !reflect.DeepEqual(got.Roles, []string{"auditor"}) {
			t.Fatalf("UserInfo fallback: identity=%+v err=%v", got, err)
		}
		got, err = withUserInfo.VerifyLogin(ctx, loginToken(c, "unverified-email"), "login-nonce")
		if err != nil || got.Email != "" {
			t.Fatalf("unverified UserInfo email: identity=%+v err=%v", got, err)
		}
		c["departments"] = []string{}
		c["email_verified"] = true
		got, err = withUserInfo.VerifyLogin(ctx, loginToken(c, "valid"), "login-nonce")
		if err != nil || got.Email != "alice@example.org" || got.Groups == nil || len(got.Groups) != 0 {
			t.Fatalf("UserInfo overwrote ID token claims: identity=%+v err=%v", got, err)
		}
		if _, err := withUserInfo.VerifyLogin(ctx, loginToken(c, "mismatch"), "login-nonce"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("accepted mismatched UserInfo subject: %v", err)
		}
		delete(c, "departments")
		for _, access := range []string{"malformed-groups", "downgrade", ""} {
			if _, err := withUserInfo.VerifyLogin(ctx, loginToken(c, access), "login-nonce"); !errors.Is(err, ErrInvalidCredentials) {
				t.Errorf("UserInfo test case %q accepted: %v", access, err)
			}
		}
		if insecureCalls.Load() != 0 {
			t.Fatal("UserInfo sent a request over HTTP")
		}
	})
}

func TestOIDCRejectsInsecureJWKS(t *testing.T) {
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": "http://127.0.0.1/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	}))
	defer server.Close()
	issuer = server.URL
	if _, err := NewOIDC(context.Background(), OIDCConfig{IssuerURL: issuer, ClientID: "allowops", HTTPClient: server.Client()}); err == nil {
		t.Fatal("insecure JWKS endpoint accepted")
	}
}
