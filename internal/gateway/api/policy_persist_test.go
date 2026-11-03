package api

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

func TestPersistPolicyRejectsStaleBaseAndMissingTarget(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := f.policy(f.adminToken)
	rules := defaultRules()
	tested, err := p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: rules}}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 7, Rules: rules, TestId: tested.Msg.Test.TestId}))
	code(t, err, connect.CodeAborted)
	_, err = p.RollbackPolicy(ctx, connect.NewRequest(&v1.RollbackPolicyRequest{BaseVersion: 1, TargetVersion: 9, TestId: tested.Msg.Test.TestId}))
	code(t, err, connect.CodeNotFound)
	// Neither rejected request consumed the test or wrote a version.
	var versions int
	var consumed bool
	if err = f.db.Pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM policy_versions),(SELECT consumed FROM policy_tests WHERE test_id=$1)", tested.Msg.Test.TestId).Scan(&versions, &consumed); err != nil {
		t.Fatal(err)
	}
	if versions != 1 || consumed {
		t.Fatalf("versions=%d consumed=%t", versions, consumed)
	}
}
