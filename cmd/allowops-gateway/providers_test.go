package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"gopkg.in/yaml.v3"
)

func TestServeRejectsMultipleLDAPProviders(t *testing.T) {
	dsn := testpg.Start(t)
	if err := store.Migrate(context.Background(), dsn); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ALLOWOPS_DATABASE_URL", dsn)
	dir := t.TempDir()
	cfg := configuration{Identity: api.Config{Origin: "https://127.0.0.1"}, CACertificate: filepath.Join(dir, "ca.pem"), CAKey: filepath.Join(dir, "ca.key"), Providers: []api.ProviderConfig{
		{ID: "first", Kind: "ldap", URL: "ldaps://127.0.0.1:636", UserBaseDN: "ou=users,dc=example,dc=org", GroupBaseDN: "ou=groups,dc=example,dc=org"},
		{ID: "second", Kind: "ldap", URL: "ldaps://127.0.0.1:636", UserBaseDN: "ou=users,dc=example,dc=org", GroupBaseDN: "ou=groups,dc=example,dc=org"},
	}}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(config, data, 0600); err != nil {
		t.Fatal(err)
	}
	err = run([]string{"serve", "--config", config})
	if err == nil || !strings.Contains(err.Error(), "only one LDAP") {
		t.Fatalf("serve error=%v; want error explaining only one LDAP identity source is supported", err)
	}
}
