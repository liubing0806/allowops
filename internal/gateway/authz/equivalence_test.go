package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// Compare the optimized snapshot against the same Rego over raw, ungrouped rules.
func TestCompactedRulesMatchRawPolicy(t *testing.T) {
	rules := make([]Rule, 500)
	for i := range rules {
		rules[i] = executionRule(fmt.Sprintf("rule-%03d", i), "allow")
		switch i % 10 {
		case 1:
			rules[i].Effect = "deny"
			rules[i].HostLabels = map[string]string{"tier": "core"}
		case 2:
			rules[i].Roles = []string{"auditor"}
		case 3:
			rules[i].Actions = []string{"other"}
			rules[i].Risks = []string{"read"}
		case 4:
			rules[i].Hours = &Hours{From: 9, To: 21}
		case 5:
			rules[i].Teams = []string{"ops"}
		case 6:
			rules[i].Owners = []string{"bob"}
		case 7:
			rules[i].SourceCIDRs = []string{"192.0.2.0/24"}
		case 8:
			rules[i].Operations = []Operation{ModifyPolicy}
			rules[i].HostLabels = nil
		case 9:
			rules[i].Actions = []string{"*"}
			rules[i].HostLabels = map[string]string{}
		}
	}
	bootstrap := []string{"alice"}
	optimized := engineFor(t, rules, bootstrap)
	encoded, err := json.Marshal(map[string]any{"rules": rules, "bootstrap_admins": bootstrap})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(encoded, &data); err != nil {
		t.Fatal(err)
	}
	query, err := rego.New(rego.Query("data.allowops.authz.result"), rego.Module("policy.rego", policy), rego.Store(inmem.NewFromObject(data)), rego.Capabilities(capabilities()), rego.StrictBuiltinErrors(true)).PrepareForEval(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw := &Engine{query: query, ready: true}
	for _, change := range []func(*Input){
		func(*Input) {},
		func(i *Input) { i.Host.Labels = map[string]string{"env": "prod", "tier": "core"} },
		func(i *Input) { i.Host.Labels = nil },
		func(i *Input) { i.Subject.Roles = []string{"auditor"} },
		func(i *Input) { i.Subject.Teams = []string{"ops"}; i.Subject.Owner = "bob" },
		func(i *Input) { i.Action = Action{Name: "other", Risk: "read"} },
		func(i *Input) { i.Env.TimeNS = 0 },
		func(i *Input) { i.Env.SourceIP = "198.51.100.1" },
		func(i *Input) { i.Env.SourceIP = "invalid" },
		func(i *Input) { i.Operation = ModifyPolicy },
	} {
		input := executionInput()
		change(&input)
		got, gotErr := optimized.Evaluate(context.Background(), input)
		want, wantErr := raw.Evaluate(context.Background(), input)
		if !reflect.DeepEqual(got, want) || (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("input %+v: optimized=%+v, %v; raw=%+v, %v", input, got, gotErr, want, wantErr)
		}
	}
}

func TestBatchCacheIsLimitedToOneRequest(t *testing.T) {
	rule := executionRule("restricted", "allow")
	rule.Hours = &Hours{From: 9, To: 21}
	rule.SourceCIDRs = []string{"192.0.2.0/24"}
	e := engineFor(t, []Rule{rule}, nil)
	hosts := []Host{{ID: "host-1", Labels: map[string]string{"env": "prod"}}, {ID: "host-2", Labels: map[string]string{"env": "prod"}}}
	for _, change := range []func(*Input){func(*Input) {}, func(i *Input) { i.Subject.Roles = nil }, func(i *Input) { i.Action.Name = "delete" }, func(i *Input) { i.Env.TimeNS = 0 }, func(i *Input) { i.Env.SourceIP = "invalid" }, func(*Input) {}} {
		input := executionInput()
		change(&input)
		got := e.EvaluateBatch(context.Background(), input, hosts)
		for i, host := range hosts {
			input.Host = host
			want, err := e.Evaluate(context.Background(), input)
			if !reflect.DeepEqual(got[i].Result, want) || (got[i].Err == nil) != (err == nil) {
				t.Fatalf("batch reused another request: got %+v; want %+v, %v", got[i], want, err)
			}
		}
	}
}
