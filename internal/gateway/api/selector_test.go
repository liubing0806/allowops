package api

import (
	"connectrpc.com/connect"
	"context"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"testing"
)

func TestSelectorDoesNotDiscardConflictingConditions(t *testing.T) {
	hosts, err := selectHosts([]authz.Host{{ID: "prod", Labels: map[string]string{"env": "prod"}}}, &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "env=test,env=prod"}})
	if err == nil && len(hosts) > 0 {
		t.Fatalf("conflicting conjunction selected %d hosts; want none or invalid argument", len(hosts))
	}
}
func TestPolicyTrialReportedSelectorUsesAuthorizationLabelsForRules(t *testing.T) {
	f := newFixture(t)
	populateResources(t, f)
	ctx := context.Background()
	if _, err := f.db.Pool.Exec(ctx, "UPDATE hosts SET reported_labels=$1", `{"os":"linux","env":"prod"}`); err != nil {
		t.Fatal(err)
	}
	rules := defaultRules()
	rules.Rules = append(rules.Rules, &v1.PolicyRule{Name: "viewer-test-host", Roles: []string{"viewer"}, Operations: []string{string(authz.ExecuteAction)}, HostLabels: map[string]string{"env": "test"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW})
	response, err := f.policy(f.adminToken).TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: rules}, Cases: []*v1.PolicyTestCase{{SubjectId: f.viewer.UserId, Operation: string(authz.ExecuteAction), Action: "restart", Targets: &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "reported.os=linux"}}}}}))
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.Test.EvaluatedCount != 1 || response.Msg.Test.ChangedCount != 1 {
		t.Fatalf("reported-selector trial evaluated=%d changed=%d; want 1 and 1 using authorization env=test", response.Msg.Test.EvaluatedCount, response.Msg.Test.ChangedCount)
	}
}
