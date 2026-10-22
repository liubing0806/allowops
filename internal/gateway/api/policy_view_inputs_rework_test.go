package api

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
)

func TestDefaultPolicyViewInputsCarryStoredActionsAndHosts(t *testing.T) {
	s := &Service{Config: Config{MaxTestEvaluations: 34}}
	snap := &policySnapshot{Subjects: []policySubject{{ID: "inspector", Attributes: authz.Subject{ID: "inspector"}}}, Actions: []authz.Action{{Name: "danger_action", Risk: "dangerous"}, {Name: "read_action", Risk: "read"}}, Hosts: []authz.Host{{ID: "dev", Labels: map[string]string{"env": "dev"}}, {ID: "prod", Labels: map[string]string{"env": "prod"}}}}
	env := authz.Environment{TimeNS: 1234567890, SourceIP: "192.0.2.1"}
	inputs, indices, err := s.inputs(snap, nil, env)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[[3]string]bool{}
	for i, input := range inputs {
		if input.Env != env || indices[i] != uint32(i) {
			t.Errorf("default input lost environment or stable case index at %d", i)
		}
		if input.Action.Name == "" {
			continue
		}
		key := [3]string{string(input.Operation), input.Action.Name, input.Host.ID}
		if seen[key] {
			t.Errorf("duplicate resource input: %v", key)
		}
		seen[key] = true
		wantRisk := "read"
		if input.Action.Name == "danger_action" {
			wantRisk = "dangerous"
		}
		if input.Action.Risk != wantRisk {
			t.Errorf("resource input %v risk=%q; want %q", key, input.Action.Risk, wantRisk)
		}
	}
	for _, action := range snap.Actions {
		if !seen[[3]string{"view_catalog", action.Name, ""}] {
			t.Errorf("missing catalog input for stored action %s", action.Name)
		}
		// A job without tasks is authorised with (action, empty host) (RR-b-01).
		for _, op := range []authz.Operation{authz.ViewJobs, authz.ViewOutput} {
			if !seen[[3]string{string(op), action.Name, ""}] {
				t.Errorf("missing empty-host input op=%s action=%s", op, action.Name)
			}
		}
		for _, op := range []authz.Operation{authz.ViewJobs, authz.ViewOutput, authz.ExecuteAction} {
			for _, host := range snap.Hosts {
				if !seen[[3]string{string(op), action.Name, host.ID}] {
					t.Errorf("missing resource input op=%s action=%s host=%s", op, action.Name, host.ID)
				}
			}
		}
	}
	if len(inputs) != 34 { // S=1, C=12, H=2, A=2: S*(C+2H+3A+3AH).
		t.Errorf("default inputs=%d; want 34", len(inputs))
	}
	s.Config.MaxTestEvaluations = 33
	_, _, err = s.inputs(snap, nil, env)
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("resource matrix over cap code=%v; want resource_exhausted", connect.CodeOf(err))
	}
}

type viewRuleSource []authz.Rule

func (r viewRuleSource) LoadRules(context.Context) ([]authz.Rule, error) { return r, nil }

// RR-b-01b: explicit trial cases carry their action into view_catalog,
// view_jobs and view_output inputs.
func TestExplicitViewCasesUseCaseAction(t *testing.T) {
	s := &Service{Config: Config{MaxTestEvaluations: 100}}
	snap := &policySnapshot{Subjects: []policySubject{{ID: "inspector", Attributes: authz.Subject{ID: "inspector", Roles: []string{"viewer"}}}}, Actions: []authz.Action{{Name: "danger_action", Risk: "dangerous"}, {Name: "read_action", Risk: "read"}}}
	engine, err := authz.New(context.Background(), viewRuleSource{{ID: "read-only", Effect: "allow", Roles: []string{"viewer"}, Operations: []authz.Operation{authz.ViewCatalog, authz.ViewJobs, authz.ViewOutput}, Risks: []string{"read"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	env := authz.Environment{TimeNS: 1234567890, SourceIP: "192.0.2.1"}
	for _, op := range []authz.Operation{authz.ViewCatalog, authz.ViewJobs, authz.ViewOutput} {
		for action, want := range map[string]string{"danger_action": "deny", "read_action": "allow"} {
			inputs, _, err := s.inputs(snap, []*v1.PolicyTestCase{{SubjectId: "inspector", Operation: string(op), Action: action}}, env)
			if err != nil || len(inputs) != 1 {
				t.Fatalf("%s %s: inputs=%d err=%v", op, action, len(inputs), err)
			}
			got, err := engine.Evaluate(context.Background(), inputs[0])
			if err != nil || got.Decision != want {
				t.Errorf("%s %s: input action=%q decision=%s error=%v; want %s", op, action, inputs[0].Action.Name, got.Decision, err, want)
			}
		}
	}
	_, _, err = s.inputs(snap, []*v1.PolicyTestCase{{SubjectId: "inspector", Operation: string(authz.ViewJobs), Action: "missing"}}, env)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("unknown view action code=%v; want invalid_argument", connect.CodeOf(err))
	}
	// A view case without an action stays a global check.
	inputs, _, err := s.inputs(snap, []*v1.PolicyTestCase{{SubjectId: "inspector", Operation: string(authz.ViewJobs)}}, env)
	if err != nil || len(inputs) != 1 || inputs[0].Action.Name != "" {
		t.Errorf("global view case: inputs=%+v err=%v", inputs, err)
	}
}
