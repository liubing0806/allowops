package api

import (
	"context"
	"encoding/json"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPolicyTestEnvironmentRoundTripsExplicitTargets(t *testing.T) {
	original := testEnvironment{
		Environment: authz.Environment{TimeNS: 1234567890, SourceIP: "192.0.2.1"},
		Cases: []*v1.PolicyTestCase{
			{SubjectId: "inspector", Operation: "view_hosts"},
			{SubjectId: "inspector", Operation: "execute_action", Action: "inspect", Targets: hostNames("host-a", "host-b"), At: &timestamppb.Timestamp{Seconds: 123, Nanos: 456}, SourceIp: "198.51.100.1"},
			{SubjectId: "inspector", Operation: "execute_action", Action: "inspect", Targets: &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "env=prod"}}},
		},
	}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded testEnvironment
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Environment != original.Environment || len(decoded.Cases) != len(original.Cases) {
		t.Fatalf("decoded environment = %+v, want %+v", decoded, original)
	}
	for i, want := range original.Cases {
		if got := decoded.Cases[i]; !proto.Equal(got, want) {
			t.Errorf("case %d = %v, want %v", i, got, want)
		}
	}
}

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
