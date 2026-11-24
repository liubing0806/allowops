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

func TestConsoleUserDisabledRevision(t *testing.T) {
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
	var disabled bool
	var revision int64
	err = s.Pool.QueryRow(ctx, `INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username)
		VALUES ('user','provider','subject','oidc','subject') RETURNING disabled,revision`).Scan(&disabled, &revision)
	if err != nil || disabled || revision != 1 {
		t.Fatalf("new user: disabled=%v revision=%d err=%v", disabled, revision, err)
	}
	for i, want := range []struct {
		disabled bool
		revision int64
	}{{true, 2}, {true, 2}, {false, 3}} {
		err := s.Pool.QueryRow(ctx, `UPDATE console_users SET disabled=$1 WHERE user_id='user'
			RETURNING disabled,revision`, want.disabled).Scan(&disabled, &revision)
		if err != nil || disabled != want.disabled || revision != want.revision {
			t.Fatalf("update %d: disabled=%v revision=%d err=%v; want %+v", i+1, disabled, revision, err, want)
		}
	}
}
