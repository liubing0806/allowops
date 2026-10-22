package api

import (
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigureProvidersLDAPLimit(t *testing.T) {
	ldap := func(id string) ProviderConfig {
		return ProviderConfig{ID: id, Kind: "ldap", URL: "ldaps://127.0.0.1:636", UserBaseDN: "ou=users,dc=example,dc=org", GroupBaseDN: "ou=groups,dc=example,dc=org"}
	}
	for _, test := range []struct {
		name      string
		configs   []ProviderConfig
		wantLDAP  int
		wantError bool
	}{
		{name: "no LDAP"},
		{name: "one LDAP", configs: []ProviderConfig{ldap("first")}, wantLDAP: 1},
		{name: "two LDAP", configs: []ProviderConfig{ldap("first"), ldap("second")}, wantError: true},
		{name: "reject before reading provider CA", configs: []ProviderConfig{{ID: "oidc", Kind: "oidc", CAFile: filepath.Join(t.TempDir(), "missing.pem")}, ldap("first"), ldap("second")}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := &Service{ldap: map[string]LDAPProvider{}, oidc: map[string]*OIDCProvider{}}
			err := s.ConfigureProviders(context.Background(), test.configs)
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "only one LDAP") {
					t.Fatalf("ConfigureProviders error=%v; want error explaining only one LDAP identity source is supported", err)
				}
				if len(s.ldap) != 0 || len(s.oidc) != 0 {
					t.Fatal("invalid configuration registered providers")
				}
			} else if err != nil || len(s.ldap) != test.wantLDAP {
				t.Fatalf("ConfigureProviders error=%v LDAP count=%d; want %d", err, len(s.ldap), test.wantLDAP)
			}
		})
	}
}

func TestConfigureProvidersAllowsMultipleOIDCAndOneLDAP(t *testing.T) {
	provider := newOIDC(t)
	ca := filepath.Join(t.TempDir(), "provider.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Service{Config: Config{Origin: "https://127.0.0.1", LoginTTL: 5 * time.Second}, ldap: map[string]LDAPProvider{}, oidc: map[string]*OIDCProvider{}}
	configs := []ProviderConfig{
		{ID: "first", Kind: "oidc", IssuerURL: provider.server.URL, ClientID: "first-client", CAFile: ca},
		{ID: "ldap", Kind: "ldap", URL: "ldaps://127.0.0.1:636", UserBaseDN: "ou=users,dc=example,dc=org", GroupBaseDN: "ou=groups,dc=example,dc=org"},
		{ID: "second", Kind: "oidc", IssuerURL: provider.server.URL, ClientID: "second-client", CAFile: ca},
	}
	if err := s.ConfigureProviders(context.Background(), configs); err != nil {
		t.Fatal(err)
	}
	if len(s.oidc) != 2 || len(s.ldap) != 1 {
		t.Fatalf("registered OIDC=%d LDAP=%d; want 2 and 1", len(s.oidc), len(s.ldap))
	}
}
