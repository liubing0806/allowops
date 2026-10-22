package store

import (
	"context"
	"testing"

	"github.com/liubing0806/allowops/internal/testpg"
)

func TestIdentitySchema(t *testing.T) {
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, name := range []string{"console_users", "roles", "role_mappings", "service_accounts", "service_account_tokens", "identity_sessions", "policy_versions", "policy_tests", "oidc_transactions", "cli_login_codes"} {
		var exists bool
		if err := s.Pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", name).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("missing identity table: %s", name)
		}
	}
}
