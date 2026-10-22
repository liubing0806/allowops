package authn

import (
	"context"
	"errors"
	"maps"
	"net/url"
	"sort"

	"github.com/coreos/go-oidc/v3/oidc"
)

type OIDC struct {
	verifier     *oidc.IDTokenVerifier
	roleMappings map[string]string
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
	return &OIDC{verifier: provider.Verifier(&oidc.Config{ClientID: config.ClientID}), roleMappings: maps.Clone(config.RoleMappings)}, nil
}

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

func (o *OIDC) verify(ctx context.Context, rawIDToken, nonce string) (Identity, error) {
	if o == nil || o.verifier == nil {
		return Identity{}, ErrInvalidCredentials
	}
	token, err := o.verifier.Verify(ctx, rawIDToken)
	if err != nil || token.Subject == "" || (nonce != "" && token.Nonce != nonce) {
		return Identity{}, ErrInvalidCredentials
	}
	var claims struct {
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Groups        []string `json:"groups"`
	}
	if err := token.Claims(&claims); err != nil {
		return Identity{}, ErrInvalidCredentials
	}
	email := ""
	if claims.EmailVerified {
		email = claims.Email
	}
	return Identity{ID: token.Subject, Kind: "oidc", Email: email, Groups: claims.Groups, Roles: mappedRoles(claims.Groups, o.roleMappings)}, nil
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
