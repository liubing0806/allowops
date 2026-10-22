package api

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

func TestDefaultPolicyTrialIncludesLiveHostPermissions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	addHost(t, f, "matching")
	addHost(t, f, "other")
	if _, err := f.db.Pool.Exec(ctx, `UPDATE hosts SET authorization_labels=jsonb_build_object('env',CASE WHEN hostname='matching' THEN 'prod' ELSE 'dev' END)`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(ctx, `UPDATE console_users SET manual_roles=ARRAY['host-operator'] WHERE user_id=$1`, f.viewer.UserId); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(ctx, `DELETE FROM role_mappings WHERE group_name='readers'`); err != nil {
		t.Fatal(err)
	}
	rules := defaultRules()
	rules.Rules = append(rules.Rules, &v1.PolicyRule{Name: "scoped-host-permissions", Roles: []string{"host-operator"}, Operations: []string{"view_hosts", "manage_hosts"}, HostLabels: map[string]string{"env": "prod"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW})
	p := f.policy(f.adminToken)
	request := func() *connect.Request[v1.TestPolicyRequest] {
		return connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: rules}})
	}
	tested, err := p.TestPolicy(ctx, request())
	if err != nil {
		t.Fatal(err)
	}
	if tested.Msg.Test.ChangedCount != 2 {
		t.Errorf("default trial changed_count=%d; want 2 live host decisions", tested.Msg.Test.ChangedCount)
	}
	changes, err := p.GetPolicyTestChanges(ctx, connect.NewRequest(&v1.GetPolicyTestChangesRequest{TestId: tested.Msg.Test.TestId}))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Msg.Changes) != 2 {
		t.Errorf("default changes=%v; want view_hosts and manage_hosts for matching", changes.Msg.Changes)
	}
	seen := map[uint32]bool{}
	for _, change := range changes.Msg.Changes {
		if change.Host != "matching" || change.Before.Effect != v1.PolicyEffect_POLICY_EFFECT_DENY || change.After.Effect != v1.PolicyEffect_POLICY_EFFECT_ALLOW || seen[change.CaseIndex] {
			t.Errorf("unexpected host decision=%v", change)
		}
		seen[change.CaseIndex] = true
	}
	// The same inputs must count towards the cap on trial and save revalidation.
	const evaluations = 32 // 2 subjects * (12 global + 2 operations * 2 hosts).
	if tested.Msg.Test.EvaluatedCount != evaluations {
		t.Errorf("evaluated_count=%d; want %d", tested.Msg.Test.EvaluatedCount, evaluations)
	}
	f.service.Config.MaxTestEvaluations = evaluations - 1
	_, err = p.TestPolicy(ctx, request())
	code(t, err, connect.CodeResourceExhausted)
	_, err = p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: rules, TestId: tested.Msg.Test.TestId}))
	code(t, err, connect.CodeResourceExhausted)
	f.service.Config.MaxTestEvaluations = evaluations
	_, err = p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: rules, TestId: tested.Msg.Test.TestId}))
	if err != nil {
		t.Fatal(err)
	}
	hosts := hostClient(f, f.viewerToken)
	listed, err := hosts.ListHosts(ctx, connect.NewRequest(&v1.ListHostsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Msg.Hosts) != 1 || listed.Msg.Hosts[0].Hostname != "matching" {
		t.Fatalf("live ListHosts=%v", listed.Msg.Hosts)
	}
	h := listed.Msg.Hosts[0]
	_, err = hosts.SetHostLabels(ctx, connect.NewRequest(&v1.SetHostLabelsRequest{Targets: namedTargets(h.Hostname), ExpectedCount: 1, ExpectedRevisions: []*v1.HostRevision{{HostId: h.HostId, Revision: h.Revision}}, Changes: &v1.LabelChanges{Set: map[string]string{"owner": "ops"}}}))
	if err != nil {
		t.Fatal(err)
	}
}
