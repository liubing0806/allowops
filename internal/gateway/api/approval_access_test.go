package api

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

func TestApprovalPolicyTTLCeiling(t *testing.T) {
	s := &Service{}
	rule := &v1.PolicyRule{
		Name: "approval", Effect: v1.PolicyEffect_POLICY_EFFECT_REQUIRE_APPROVAL,
		Roles: []string{"admin"}, Operations: []string{"execute_action"},
		Approval: &v1.PolicyApprovalConfig{TtlSeconds: 604800},
	}
	rules := &v1.PolicyRules{Rules: []*v1.PolicyRule{rule}}
	if _, err := s.candidateRules(rules); err != nil {
		t.Fatal(err)
	}
	rule.Approval.TtlSeconds++
	if _, err := s.candidateRules(rules); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("TTL above 7d error=%v", err)
	}
	s.SetMaxApprovalTTL(time.Hour)
	for _, seconds := range []uint32{0, 60, 3600, 3601} {
		rule.Approval.TtlSeconds = seconds
		_, err := s.candidateRules(rules)
		if seconds <= 3600 && err != nil || seconds > 3600 && connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("TTL=%d error=%v", seconds, err)
		}
	}
}
