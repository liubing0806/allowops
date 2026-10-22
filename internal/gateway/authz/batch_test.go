package authz

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

func TestBatchMatchesIndividualDecisions(t *testing.T) {
	rules := []Rule{executionRule("allow", "allow"), executionRule("deny", "deny")}
	rules[1].HostLabels = map[string]string{"tier": "core"}
	hosts := []Host{
		{ID: "prod", Labels: map[string]string{"env": "prod", "tier": "app"}},
		{ID: "core", Labels: map[string]string{"env": "prod", "tier": "core"}},
		{ID: "dev", Labels: map[string]string{"env": "dev"}},
		{ID: "prod-2", Labels: map[string]string{"tier": "app", "env": "prod"}},
		{ID: "nil-labels"},
		{ID: "empty-labels", Labels: map[string]string{}},
	}
	e := engineFor(t, rules, nil)
	input := executionInput()
	batch := e.EvaluateBatch(context.Background(), input, hosts)
	if len(batch) != len(hosts) {
		t.Fatalf("got %d results for %d hosts", len(batch), len(hosts))
	}
	for i, host := range hosts {
		in := input
		in.Host = host
		want, err := e.Evaluate(context.Background(), in)
		if err != nil || batch[i].Err != nil || batch[i].HostID != host.ID || !reflect.DeepEqual(batch[i].Result, want) {
			t.Fatalf("host %s: got %+v; want %+v, %v", host.ID, batch[i], want, err)
		}
	}
	batch[0].Result.RuleIDs[0] = "modified"
	if batch[3].Result.RuleIDs[0] != "allow" {
		t.Fatal("batch results share mutable rule IDs")
	}
	if input.Host.ID != "host-1" || hosts[0].Labels["env"] != "prod" {
		t.Fatal("batch mutated arguments")
	}
}

func TestBatchEvaluationErrorsDeny(t *testing.T) {
	rule := executionRule("allow", "allow")
	rule.SourceCIDRs = []string{"192.0.2.0/24"}
	e := engineFor(t, []Rule{rule}, nil)
	input := executionInput()
	input.Env.SourceIP = "invalid"
	hosts := []Host{input.Host, {ID: "same", Labels: input.Host.Labels}}
	for _, result := range e.EvaluateBatch(context.Background(), input, hosts) {
		if result.Err == nil || result.Result.Decision != "deny" {
			t.Fatalf("error did not deny: %+v", result)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, result := range e.EvaluateBatch(ctx, executionInput(), hosts) {
		if result.Err == nil || result.Result.Decision != "deny" {
			t.Fatalf("canceled batch: %+v", result)
		}
	}
	if len(e.EvaluateBatch(context.Background(), input, nil)) != 0 {
		t.Fatal("empty host list returned results")
	}
}

func BenchmarkBatchPolicy500Rules1000Hosts(b *testing.B) {
	rules := make([]Rule, 500)
	for i := range rules {
		rules[i] = executionRule(fmt.Sprintf("rule-%03d", i), "allow")
	}
	e := engineFor(b, rules, nil)
	input := executionInput()
	hosts := make([]Host, 1000)
	for i := range hosts {
		hosts[i] = Host{ID: fmt.Sprintf("host-%04d", i), Labels: map[string]string{"env": "prod"}}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		results := e.EvaluateBatch(context.Background(), input, hosts)
		for _, result := range results {
			if result.Err != nil || result.Result.Decision != "allow" {
				b.Fatalf("%+v", result)
			}
		}
	}
}
