package authz

import (
	"context"
	"testing"
)

// RR-b-01: view_catalog, view_jobs and view_output apply the rule's
// actions/risks filter when the request names an action. A request without an
// action (global check) keeps ignoring the filter.
func TestViewOperationsApplyActionAndRiskFilters(t *testing.T) {
	read, danger := Action{Name: "read_action", Risk: "read"}, Action{Name: "danger_action", Risk: "dangerous"}
	for _, op := range []Operation{ViewCatalog, ViewJobs, ViewOutput} {
		rules := map[string]Rule{
			"actions and risks": {ID: "r", Effect: "allow", Roles: []string{"viewer"}, Operations: []Operation{op}, Actions: []string{"read_action"}, Risks: []string{"read"}},
			"actions only":      {ID: "r", Effect: "allow", Roles: []string{"viewer"}, Operations: []Operation{op}, Actions: []string{"read_action"}},
			"risks only":        {ID: "r", Effect: "allow", Roles: []string{"viewer"}, Operations: []Operation{op}, Risks: []string{"read"}},
			"wildcard action":   {ID: "r", Effect: "allow", Roles: []string{"viewer"}, Operations: []Operation{op}, Actions: []string{"*"}},
			"no filter":         {ID: "r", Effect: "allow", Roles: []string{"viewer"}, Operations: []Operation{op}},
		}
		cases := []struct {
			rule   string
			action Action
			want   string
		}{
			{"actions and risks", read, "allow"},
			{"actions and risks", danger, "deny"},
			{"actions and risks", Action{}, "allow"},
			{"actions only", read, "allow"},
			{"actions only", danger, "deny"},
			{"risks only", read, "allow"},
			{"risks only", danger, "deny"},
			{"wildcard action", danger, "allow"},
			{"no filter", danger, "allow"},
			{"no filter", Action{}, "allow"},
		}
		for _, tt := range cases {
			e := engineFor(t, []Rule{rules[tt.rule]}, nil)
			got, err := e.Evaluate(context.Background(), Input{Subject: Subject{Roles: []string{"viewer"}}, Operation: op, Action: tt.action})
			if err != nil || got.Decision != tt.want {
				t.Errorf("%s rule %q action %q: decision=%s error=%v; want %s", op, tt.rule, tt.action.Name, got.Decision, err, tt.want)
			}
		}
	}
}

func TestViewOperationsDenyRuleFiltersByAction(t *testing.T) {
	rules := []Rule{
		{ID: "allow", Effect: "allow", Roles: []string{"viewer"}, Operations: []Operation{ViewJobs}},
		{ID: "deny-danger", Effect: "deny", Roles: []string{"viewer"}, Operations: []Operation{ViewJobs}, Risks: []string{"dangerous"}},
	}
	e := engineFor(t, rules, nil)
	subject := Subject{Roles: []string{"viewer"}}
	for _, tt := range []struct {
		action Action
		want   string
	}{{Action{Name: "read_action", Risk: "read"}, "allow"}, {Action{Name: "danger_action", Risk: "dangerous"}, "deny"}} {
		got, err := e.Evaluate(context.Background(), Input{Subject: subject, Operation: ViewJobs, Action: tt.action})
		if err != nil || got.Decision != tt.want {
			t.Errorf("action %q: decision=%s error=%v; want %s", tt.action.Name, got.Decision, err, tt.want)
		}
	}
}

// RR-b-01a: a global view check (no action) must not match a deny rule that
// carries actions or risks, otherwise it denies the whole job list.
func TestGlobalViewCheckIgnoresActionScopedDenyRules(t *testing.T) {
	rules := []Rule{
		{ID: "allow", Effect: "allow", Roles: []string{"viewer"}, Operations: []Operation{ViewJobs}},
		{ID: "deny-danger", Effect: "deny", Roles: []string{"viewer"}, Operations: []Operation{ViewJobs}, Risks: []string{"dangerous"}},
	}
	e := engineFor(t, rules, nil)
	for _, tt := range []struct {
		name   string
		action Action
		want   string
	}{
		{"global", Action{}, "allow"},
		{"danger_action", Action{Name: "danger_action", Risk: "dangerous"}, "deny"},
		{"read_action", Action{Name: "read_action", Risk: "read"}, "allow"},
	} {
		got, err := e.Evaluate(context.Background(), Input{Subject: Subject{Roles: []string{"viewer"}}, Operation: ViewJobs, Action: tt.action})
		if err != nil || got.Decision != tt.want {
			t.Errorf("%s: decision=%s error=%v; want %s", tt.name, got.Decision, err, tt.want)
		}
	}
	// A deny rule without actions/risks still denies the global check.
	e = engineFor(t, []Rule{rules[0], {ID: "deny-all", Effect: "deny", Roles: []string{"viewer"}, Operations: []Operation{ViewJobs}}}, nil)
	got, err := e.Evaluate(context.Background(), Input{Subject: Subject{Roles: []string{"viewer"}}, Operation: ViewJobs})
	if err != nil || got.Decision != "deny" {
		t.Errorf("unscoped deny global: decision=%s error=%v; want deny", got.Decision, err)
	}
}

// A deny rule whose actions contain "*" matches the global view check (no
// action) and is equivalent to denying everything, for each allow combination.
func TestGlobalViewCheckMatchesWildcardActionDenyRule(t *testing.T) {
	subject := Subject{Roles: []string{"viewer"}}
	for _, op := range []Operation{ViewJobs, ViewCatalog} {
		allows := map[string]Rule{
			"unscoped allow":         {ID: "allow", Effect: "allow", Roles: []string{"viewer"}, Operations: []Operation{op}},
			"wildcard actions allow": {ID: "allow", Effect: "allow", Roles: []string{"viewer"}, Operations: []Operation{op}, Actions: []string{"*"}},
			"actions allow":          {ID: "allow", Effect: "allow", Roles: []string{"viewer"}, Operations: []Operation{op}, Actions: []string{"read_action"}},
			"risks allow":            {ID: "allow", Effect: "allow", Roles: []string{"viewer"}, Operations: []Operation{op}, Risks: []string{"read"}},
		}
		denies := map[string]Rule{
			"wildcard only":       {ID: "deny", Effect: "deny", Roles: []string{"viewer"}, Operations: []Operation{op}, Actions: []string{"*"}},
			"wildcard with names": {ID: "deny", Effect: "deny", Roles: []string{"viewer"}, Operations: []Operation{op}, Actions: []string{"read_action", "*"}},
			"wildcard with risks": {ID: "deny", Effect: "deny", Roles: []string{"viewer"}, Operations: []Operation{op}, Actions: []string{"*"}, Risks: []string{"dangerous"}},
		}
		for allowName, allow := range allows {
			for denyName, deny := range denies {
				e := engineFor(t, []Rule{allow, deny}, nil)
				for _, action := range []Action{{}, {Name: "read_action", Risk: "read"}, {Name: "danger_action", Risk: "dangerous"}} {
					got, err := e.Evaluate(context.Background(), Input{Subject: subject, Operation: op, Action: action})
					if err != nil || got.Decision != "deny" {
						t.Errorf("%s allow %q deny %q action %q: decision=%s error=%v; want deny", op, allowName, denyName, action.Name, got.Decision, err)
					}
				}
			}
		}
	}
}
