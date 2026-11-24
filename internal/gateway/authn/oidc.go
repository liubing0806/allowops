package authn

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"sort"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const defaultGroupsClaim = "groups"

type OIDC struct {
	provider       *oidc.Provider
	verifier       *oidc.IDTokenVerifier
	roleMappings   map[string]string
	groupsClaim    string
	userInfoClient *http.Client
}

func NewOIDC(ctx context.Context, config OIDCConfig) (*OIDC, error) {
	issuer, err := url.Parse(config.IssuerURL)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || config.ClientID == "" {
		return nil, errors.New("OIDC requires an HTTPS issuer and client ID")
	}
	if config.HTTPClient != nil {
		ctx = oidc.ClientContext(ctx, config.HTTPClient)
	}
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, err
	}
	var discovery struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&discovery); err != nil {
		return nil, err
	}
	keys, err := url.Parse(discovery.JWKSURL)
	if err != nil || keys.Scheme != "https" || keys.Host == "" || keys.User != nil || keys.Fragment != "" {
		return nil, errors.New("OIDC requires an HTTPS JWKS endpoint")
	}
	groupsClaim := config.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = defaultGroupsClaim
	}
	o := &OIDC{provider: provider, verifier: provider.Verifier(&oidc.Config{ClientID: config.ClientID}), roleMappings: maps.Clone(config.RoleMappings), groupsClaim: groupsClaim}
	if config.FetchUserInfo {
		endpoint, err := url.Parse(provider.UserInfoEndpoint())
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
			return nil, errors.New("OIDC requires an HTTPS UserInfo endpoint")
		}
		client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
		if client == nil {
			client = http.DefaultClient
		}
		// Retain the provider's transport and TLS trust, including any redirect
		// restrictions it already has. Never send the access token over HTTP.
		userInfoClient := *client
		userInfoClient.CheckRedirect = func(r *http.Request, via []*http.Request) error {
			if r.URL.Scheme != "https" || r.URL.User != nil || len(via) >= 10 {
				return errors.New("OIDC UserInfo redirect rejected")
			}
			if client.CheckRedirect != nil {
				return client.CheckRedirect(r, via)
			}
			return nil
		}
		o.userInfoClient = &userInfoClient
	}
	return o, nil
}

func (o *OIDC) Endpoint() oauth2.Endpoint { return o.provider.Endpoint() }

// Verify validates the issuer, audience, expiry and signature using the provider's JWKS.
// OAuth state and nonce binding belong to the caller's login flow.
func (o *OIDC) Verify(ctx context.Context, rawIDToken string) (Identity, error) {
	return o.verify(ctx, rawIDToken, "")
}

// VerifyNonce additionally binds a signed ID token to the gateway login transaction.
func (o *OIDC) VerifyNonce(ctx context.Context, rawIDToken, nonce string) (Identity, error) {
	if nonce == "" {
		return Identity{}, ErrInvalidCredentials
	}
	return o.verify(ctx, rawIDToken, nonce)
}

// VerifyLogin validates the ID token before optionally querying UserInfo with
// the access token returned by the same code exchange.
func (o *OIDC) VerifyLogin(ctx context.Context, token *oauth2.Token, nonce string) (Identity, error) {
	raw, _ := token.Extra("id_token").(string)
	id, err := o.VerifyNonce(ctx, raw, nonce)
	if err != nil || o.userInfoClient == nil {
		return id, err
	}
	if token.AccessToken == "" {
		return Identity{}, ErrInvalidCredentials
	}
	info, err := o.provider.UserInfo(oidc.ClientContext(ctx, o.userInfoClient), oauth2.StaticTokenSource(token))
	if err != nil || info.Subject != id.ID {
		return Identity{}, ErrInvalidCredentials
	}
	if id.Email == "" && info.EmailVerified {
		id.Email = info.Email
	}
	if id.Groups == nil {
		id.Groups, err = o.groups(info.Claims)
		if err != nil {
			return Identity{}, ErrInvalidCredentials
		}
		id.Roles = mappedRoles(id.Groups, o.roleMappings)
	}
	return id, nil
}

func (o *OIDC) verify(ctx context.Context, rawIDToken, nonce string) (Identity, error) {
	if o == nil || o.verifier == nil {
		return Identity{}, ErrInvalidCredentials
	}
	token, err := o.verifier.Verify(ctx, rawIDToken)
	if err != nil || token.Subject == "" || (nonce != "" && token.Nonce != nonce) {
		return Identity{}, ErrInvalidCredentials
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := token.Claims(&claims); err != nil {
		return Identity{}, ErrInvalidCredentials
	}
	email := ""
	if claims.EmailVerified {
		email = claims.Email
	}
	groups, err := o.groups(token.Claims)
	if err != nil {
		return Identity{}, ErrInvalidCredentials
	}
	return Identity{ID: token.Subject, Kind: "oidc", Email: email, Groups: groups, Roles: mappedRoles(groups, o.roleMappings)}, nil
}

func (o *OIDC) groups(claims func(any) error) ([]string, error) {
	if o.groupsClaim == defaultGroupsClaim {
		var standard struct {
			Groups []string `json:"groups"`
		}
		err := claims(&standard)
		return standard.Groups, err
	}
	var values map[string]json.RawMessage
	if err := claims(&values); err != nil {
		return nil, err
	}
	var groups []string
	if value := values[o.groupsClaim]; value != nil {
		if err := json.Unmarshal(value, &groups); err != nil {
			return nil, err
		}
	}
	return groups, nil
}

func mappedRoles(groups []string, mappings map[string]string) []string {
	unique := map[string]bool{}
	for _, group := range groups {
		if role := mappings[group]; role != "" {
			unique[role] = true
		}
	}
	roles := make([]string, 0, len(unique))
	for role := range unique {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles
}
