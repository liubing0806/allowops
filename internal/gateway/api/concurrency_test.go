package api

import (
	"connectrpc.com/connect"
	"context"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"testing"
	"time"
)

func TestPolicySaveAndRoleMappingTransactionUseConsistentLockOrder(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	p := f.policy(f.adminToken)
	rules := defaultRules()
	preview, err := p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: rules}}))
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := f.db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer mapping.Rollback(ctx)
	if _, err := mapping.Exec(ctx, "SET LOCAL deadlock_timeout='100ms'"); err != nil {
		t.Fatal(err)
	}
	if _, err := mapping.Exec(ctx, "UPDATE role_mapping_state SET revision=revision+1"); err != nil {
		t.Fatal(err)
	}
	saved := make(chan error, 1)
	go func() {
		_, err := p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: rules, TestId: preview.Msg.Test.TestId}))
		saved <- err
	}()
	waiting := false
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if err := f.db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'LOCK TABLE console_users%' AND wait_event_type='Lock')").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("policy save did not wait for the mapping transaction")
	}
	if _, err := mapping.Exec(ctx, "DELETE FROM role_mappings"); err != nil {
		t.Fatalf("concurrent mapping edit deadlocked with policy save: %v", err)
	}
	if err := mapping.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	code(t, <-saved, connect.CodeAborted) // The completed mapping edit invalidates the preview.
}
