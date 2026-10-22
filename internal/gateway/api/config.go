package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"

	"github.com/liubing0806/allowops/internal/gateway/authn"
)

type ProviderConfig struct {
	ID                   string          `yaml:"id"`
	DisplayName          string          `yaml:"display_name"`
	Kind                 string          `yaml:"kind"`
	CAFile               string          `yaml:"ca_file"`
	IssuerURL            string          `yaml:"issuer_url"`
	ClientID             string          `yaml:"client_id"`
	ClientSecretEnv      string          `yaml:"client_secret_env"`
	URL                  string          `yaml:"url"`
	StartTLS             bool            `yaml:"start_tls"`
	UserBaseDN           string          `yaml:"user_base_dn"`
	UserAttribute        string          `yaml:"user_attribute"`
	GroupBaseDN          string          `yaml:"group_base_dn"`
	GroupMemberAttribute string          `yaml:"group_member_attribute"`
	GroupNameAttribute   string          `yaml:"group_name_attribute"`
	BindDN               string          `yaml:"bind_dn"`
	BindPasswordEnv      string          `yaml:"bind_password_env"`
	RateLimit            authn.RateLimit `yaml:"rate_limit"`
}

func envSecret(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	v := os.Getenv(name)
	if v == "" {
		return "", errors.New("provider secret environment variable required")
	}
	return v, nil
}
func (s *Service) ConfigureProviders(ctx context.Context, configs []ProviderConfig) error {
	ldapCount := 0
	for _, cfg := range configs {
		if cfg.Kind == "ldap" {
			ldapCount++
		}
	}
	if ldapCount > 1 {
		return errors.New("only one LDAP identity source is supported")
	}
	for _, cfg := range configs {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CAFile != "" {
			b, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return errors.New("read provider CA")
			}
			roots, err := x509.SystemCertPool()
			if err != nil {
				roots = x509.NewCertPool()
			}
			if !roots.AppendCertsFromPEM(b) {
				return errors.New("invalid provider CA")
			}
			tlsConfig.RootCAs = roots
		}
		switch cfg.Kind {
		case "oidc":
			secret, err := envSecret(cfg.ClientSecretEnv)
			if err != nil {
				return err
			}
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: s.Config.LoginTTL, CheckRedirect: func(r *http.Request, _ []*http.Request) error {
				if r.URL.Scheme != "https" {
					return errors.New("HTTPS required")
				}
				return nil
			}}
			if err := s.AddOIDC(ctx, cfg.ID, cfg.DisplayName, secret, authn.OIDCConfig{IssuerURL: cfg.IssuerURL, ClientID: cfg.ClientID, HTTPClient: client}); err != nil {
				return err
			}
		case "ldap":
			password, err := envSecret(cfg.BindPasswordEnv)
			if err != nil {
				return err
			}
			auth, err := authn.NewLDAP(authn.LDAPConfig{URL: cfg.URL, StartTLS: cfg.StartTLS, TLSConfig: tlsConfig, UserBaseDN: cfg.UserBaseDN, UserAttribute: cfg.UserAttribute, GroupBaseDN: cfg.GroupBaseDN, GroupMemberAttribute: cfg.GroupMemberAttribute, GroupNameAttribute: cfg.GroupNameAttribute, RateLimit: cfg.RateLimit})
			if err != nil {
				return err
			}
			if err := s.AddLDAP(cfg.ID, cfg.DisplayName, auth, authn.DirectoryCredentials{BindDN: cfg.BindDN, Password: password}); err != nil {
				return err
			}
		default:
			return errors.New("provider kind must be oidc or ldap")
		}
	}
	return nil
}
