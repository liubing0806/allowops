package authz

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
)

type rulesSource []Rule

func (r rulesSource) LoadRules(context.Context) ([]Rule, error) { return r, nil }

type brokenSource struct{}

func (brokenSource) LoadRules(context.Context) ([]Rule, error) {
	return nil, errors.New("source unavailable")
}

func executionInput() Input {
	return Input{Subject: Subject{ID: "alice", Kind: "ldap", Roles: []string{"oncall"}}, Operation: ExecuteAction,
		Action: Action{Name: "restart", Risk: "write"}, Host: Host{ID: "host-1", Labels: map[string]string{"env": "prod"}},
		Env: Environment{TimeNS: time.Date(2026, 10, 13, 4, 0, 0, 0, time.UTC).UnixNano(), SourceIP: "192.0.2.1"}}
}

func executionRule(id, effect string) Rule {
	return Rule{ID: id, Effect: effect, Roles: []string{"oncall"}, Operations: []Operation{ExecuteAction},
		Actions: []string{"restart"}, HostLabels: map[string]string{"env": "prod"}}
}

func engineFor(t testing.TB, rules []Rule, bootstrap []string) *Engine {
	t.Helper()
	e, err := New(context.Background(), rulesSource(rules), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestDecisions(t *testing.T) {
	tests := []struct {
		name     string
		rules    []Rule
		input    Input
		decision string
		ids      []string
	}{
		{"unmatched", nil, executionInput(), "deny", []string{}},
		{"allow", []Rule{executionRule("allow-1", "allow")}, executionInput(), "allow", []string{"allow-1"}},
		{"deny wins", []Rule{executionRule("z-allow", "allow"), executionRule("a-deny", "deny")}, executionInput(), "deny", []string{"a-deny", "z-allow"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := engineFor(t, tt.rules, nil).Evaluate(context.Background(), tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if got.Decision != tt.decision || !reflect.DeepEqual(got.RuleIDs, tt.ids) {
				t.Fatalf("got %+v, want %s %v", got, tt.decision, tt.ids)
			}
		})
	}
}

func TestConditionsAndOperationIsolation(t *testing.T) {
	rule := executionRule("restricted", "allow")
	rule.Hours = &Hours{From: 9, To: 21}
	rule.Teams = []string{"ops"}
	rule.Owners = []string{"bob"}
	rule.SourceCIDRs = []string{"192.0.2.0/24"}
	in := executionInput()
	in.Subject.Teams = []string{"ops"}
	in.Subject.Owner = "bob"
	e := engineFor(t, []Rule{rule}, nil)
	mutations := []struct {
		name   string
		change func(*Input)
		want   string
	}{
		{"matches", func(*Input) {}, "allow"},
		{"role", func(i *Input) { i.Subject.Roles = nil }, "deny"},
		{"host", func(i *Input) { i.Host.Labels = nil }, "deny"},
		{"empty host labels", func(i *Input) { i.Host.Labels = map[string]string{} }, "deny"},
		{"action", func(i *Input) { i.Action.Name = "delete" }, "deny"},
		{"team", func(i *Input) { i.Subject.Teams = nil }, "deny"},
		{"owner", func(i *Input) { i.Subject.Owner = "eve" }, "deny"},
		{"IP", func(i *Input) { i.Env.SourceIP = "198.51.100.1" }, "deny"},
		{"time", func(i *Input) { i.Env.TimeNS = time.Date(2026, 10, 13, 13, 0, 0, 0, time.UTC).UnixNano() }, "deny"},
		{"console", func(i *Input) { i.Operation = ModifyPolicy }, "deny"},
		{"unknown operation", func(i *Input) { i.Operation = "unknown" }, "deny"},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			input := in
			tt.change(&input)
			got, err := e.Evaluate(context.Background(), input)
			if err != nil || got.Decision != tt.want {
				t.Fatalf("got %+v, %v; want %s", got, err, tt.want)
			}
		})
	}
	// The draft treats action names and risks as alternative selectors.
	rule.Actions = []string{"other"}
	rule.Risks = []string{"write"}
	got, err := engineFor(t, []Rule{rule}, nil).Evaluate(context.Background(), in)
	if err != nil || got.Decision != "allow" {
		t.Fatalf("risk selector: %+v, %v", got, err)
	}
}

func TestDefaultRoles(t *testing.T) {
	permissions := map[string][]Operation{
		"admin":     {ModifyPolicy, ManageServiceAccounts, ManageHosts, CreateJoinToken, ManageUserRoles, PublishCatalog, ViewHosts, ViewCatalog, ViewJobs, ViewOutput, ViewAudit, ViewSystem, ExecuteAction},
		"operator":  {ManageHosts, CreateJoinToken, ViewHosts, ViewJobs, ViewSystem},
		"auditor":   {ViewAudit, ViewJobs, ViewOutput},
		"viewer":    {ViewHosts, ViewCatalog, ViewJobs},
		"publisher": {PublishCatalog},
	}
	e := engineFor(t, DefaultRules(), nil)
	for role, allowed := range permissions {
		for _, operation := range permissions["admin"] {
			want := "deny"
			for _, op := range allowed {
				if op == operation {
					want = "allow"
				}
			}
			in := executionInput()
			in.Subject.Roles = []string{role}
			in.Operation = operation
			got, err := e.Evaluate(context.Background(), in)
			if err != nil || got.Decision != want {
				t.Errorf("%s %s: got %+v, %v; want %s", role, operation, got, err, want)
			}
		}
	}
}

func TestDefaultRoleExecutionRisks(t *testing.T) {
	e := engineFor(t, DefaultRules(), nil)
	for _, role := range []string{"admin", "operator", "auditor", "viewer", "publisher"} {
		for _, risk := range []string{"read", "write", "dangerous"} {
			for _, labels := range []map[string]string{nil, {"env": "dev"}, {"env": "prod", "tier": "core-db"}} {
				in := executionInput()
				in.Subject.Roles = []string{role}
				in.Action = Action{Name: risk + "-action", Risk: risk}
				in.Host.Labels = labels
				want := "deny"
				if role == "admin" {
					want = "allow"
				}
				got, err := e.Evaluate(context.Background(), in)
				if err != nil || got.Decision != want {
					t.Errorf("%s %s labels=%v: got %+v, %v; want %s", role, risk, labels, got, err, want)
				}
			}
		}
	}
}

func TestDefaultAdminExecutionHonorsExplicitDeny(t *testing.T) {
	rules := append(DefaultRules(), Rule{ID: "deny-core", Effect: "deny", Roles: []string{"*"}, Operations: []Operation{ExecuteAction}, Risks: []string{"dangerous"}, HostLabels: map[string]string{"tier": "core-db"}})
	in := executionInput()
	in.Subject.Roles = []string{"admin"}
	in.Action = Action{Name: "delete", Risk: "dangerous"}
	in.Host.Labels = map[string]string{"tier": "core-db"}
	got, err := engineFor(t, rules, nil).Evaluate(context.Background(), in)
	if err != nil || got.Decision != "deny" || !reflect.DeepEqual(got.RuleIDs, []string{"default:admin", "deny-core"}) {
		t.Fatalf("admin explicit deny: %+v, %v", got, err)
	}
}

func TestHoursNanosecondBoundaries(t *testing.T) {
	rule := executionRule("hours", "allow")
	rule.Hours = &Hours{From: 9, To: 21}
	e := engineFor(t, []Rule{rule}, nil)
	start := time.Date(2026, 10, 13, 1, 0, 0, 0, time.UTC).UnixNano()
	end := time.Date(2026, 10, 13, 13, 0, 0, 0, time.UTC).UnixNano()
	for _, tt := range []struct {
		timeNS int64
		want   string
	}{{start - 1, "deny"}, {start, "allow"}, {end - 1, "allow"}, {end, "deny"}} {
		in := executionInput()
		in.Env.TimeNS = tt.timeNS
		got, err := e.Evaluate(context.Background(), in)
		if err != nil || got.Decision != tt.want {
			t.Fatalf("time_ns=%d: %+v, %v; want %s", tt.timeNS, got, err, tt.want)
		}
	}
}

func TestBootstrapAndLockout(t *testing.T) {
	deny := Rule{ID: "deny-policy", Effect: "deny", Roles: []string{"*"}, Operations: []Operation{ModifyPolicy}}
	e := engineFor(t, []Rule{deny}, []string{"alice", "admin@example.org"})
	for _, subject := range []Subject{{ID: "alice", Kind: "ldap"}, {ID: "oidc-sub", Kind: "oidc", Email: "admin@example.org"}} {
		in := executionInput()
		in.Subject = subject
		in.Operation = ModifyPolicy
		got, err := e.Evaluate(context.Background(), in)
		if err != nil || got.Decision != "allow" || !reflect.DeepEqual(got.RuleIDs, []string{"bootstrap_admins"}) {
			t.Fatalf("bootstrap: %+v, %v", got, err)
		}
		in.Operation = ManageUserRoles
		got, err = e.Evaluate(context.Background(), in)
		if err != nil || got.Decision != "deny" {
			t.Fatalf("bootstrap other operation: %+v, %v", got, err)
		}
	}
	in := executionInput()
	in.Subject = Subject{ID: "alice", Kind: "service_account", Email: "admin@example.org"}
	in.Operation = ModifyPolicy
	got, err := e.Evaluate(context.Background(), in)
	if err != nil || got.Decision != "deny" {
		t.Fatalf("service account bypass: %+v, %v", got, err)
	}
	ctx := context.Background()
	subjects := []Subject{{ID: "alice", Kind: "ldap", Roles: []string{"admin"}}}
	if err := CheckPolicyUpdate(ctx, DefaultRules(), subjects, in.Env, nil); err != nil {
		t.Fatal(err)
	}
	if err := CheckPolicyUpdate(ctx, []Rule{deny}, subjects, in.Env, nil); !errors.Is(err, ErrPolicyLockout) {
		t.Fatalf("lockout: %v", err)
	}
	if err := CheckPolicyUpdate(ctx, []Rule{deny}, subjects, in.Env, []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	if err := CheckPolicyUpdate(ctx, DefaultRules(), nil, in.Env, nil); !errors.Is(err, ErrPolicyLockout) {
		t.Fatalf("no subjects: %v", err)
	}
}

func TestFailClosedAndValidation(t *testing.T) {
	if _, err := New(context.Background(), brokenSource{}, nil); err == nil {
		t.Fatal("source errors must propagate")
	}
	e := engineFor(t, []Rule{executionRule("ok", "allow")}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := e.Evaluate(ctx, executionInput())
	if err == nil || got.Decision != "deny" {
		t.Fatalf("canceled evaluation: %+v, %v", got, err)
	}
	var zero Engine
	got, err = zero.Evaluate(context.Background(), executionInput())
	if err == nil || got.Decision != "deny" {
		t.Fatalf("uninitialized engine: %+v, %v", got, err)
	}
	bad := executionRule("bad", "allow")
	bad.SourceCIDRs = []string{"not-a-network"}
	if _, err := New(context.Background(), rulesSource{bad}, nil); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
	bad = executionRule("bad", "allow")
	bad.Effect = "ALLOW"
	if _, err := New(context.Background(), rulesSource{bad}, nil); err == nil {
		t.Fatal("invalid effect accepted")
	}
	bad = executionRule("bad", "allow")
	bad.Hours = &Hours{From: 21, To: 9}
	if _, err := New(context.Background(), rulesSource{bad}, nil); err == nil {
		t.Fatal("invalid hours accepted")
	}
	bad = executionRule("bootstrap_admins", "allow")
	if _, err := New(context.Background(), rulesSource{bad}, nil); err == nil {
		t.Fatal("reserved rule ID accepted")
	}
	bad = executionRule("duplicate", "allow")
	if _, err := New(context.Background(), rulesSource{bad, bad}, nil); err == nil {
		t.Fatal("duplicate IDs accepted")
	}
}

func TestCapabilitiesRejectUnsafeBuiltins(t *testing.T) {
	for _, builtin := range capabilities().Builtins {
		if builtin.IsNondeterministic() {
			t.Errorf("nondeterministic builtin remains enabled: %s", builtin.Name)
		}
	}
	queries := []string{`http.send({"method":"GET","url":"https://localhost"})`, `opa.runtime()`, `time.now_ns()`, `net.lookup_ip_addr("localhost")`, `uuid.rfc4122("x")`, `rand.intn("x", 10)`}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			_, err := rego.New(rego.Query(query), rego.Capabilities(capabilities())).PrepareForEval(context.Background())
			if err == nil || !strings.Contains(err.Error(), "undefined function") {
				t.Fatalf("unsafe builtin compiled: %q: %v", query, err)
			}
		})
	}
}

func TestEvaluationErrorsAndMalformedResultsDeny(t *testing.T) {
	rule := executionRule("allow", "allow")
	rule.SourceCIDRs = []string{"192.0.2.0/24"}
	in := executionInput()
	in.Env.SourceIP = "invalid-ip"
	result, err := engineFor(t, []Rule{rule}, nil).Evaluate(context.Background(), in)
	if err == nil || result.Decision != "deny" {
		t.Fatalf("builtin error: %+v, %v", result, err)
	}
	for _, query := range []string{`{"decision": "invalid", "rules": []}`, `{"decision": "allow"}`, `{"decision": "allow", "rules": [123]}`, `false`} {
		prepared, err := rego.New(rego.Query(query)).PrepareForEval(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		e := &Engine{query: prepared, ready: true}
		result, err := e.Evaluate(context.Background(), executionInput())
		if err == nil || result.Decision != "deny" {
			t.Fatalf("malformed result %s: %+v, %v", query, result, err)
		}
	}
}

func TestBootstrapDoesNotEvaluatePolicyConditions(t *testing.T) {
	rule := Rule{ID: "deny-from-network", Effect: "deny", Roles: []string{"*"}, Operations: []Operation{ModifyPolicy}, SourceCIDRs: []string{"192.0.2.0/24"}}
	in := executionInput()
	in.Subject = Subject{ID: "alice", Kind: "ldap"}
	in.Operation = ModifyPolicy
	in.Env.SourceIP = ""
	got, err := engineFor(t, []Rule{rule}, []string{"alice"}).Evaluate(context.Background(), in)
	if err != nil || got.Decision != "allow" {
		t.Fatalf("bootstrap must be independent of policy conditions: %+v, %v", got, err)
	}
}

func TestSimulationAndSnapshot(t *testing.T) {
	before := []Rule{executionRule("allow", "allow")}
	after := []Rule{executionRule("deny", "deny")}
	in := executionInput()
	other := executionInput()
	other.Host = Host{ID: "host-2", Labels: map[string]string{"env": "dev"}}
	changes, err := Simulate(context.Background(), before, after, []Input{in, other}, nil)
	if err != nil || len(changes) != 1 || changes[0].HostID != "host-1" || changes[0].Before.Decision != "allow" || changes[0].After.Decision != "deny" {
		t.Fatalf("changes: %+v, %v", changes, err)
	}
	if before[0].Effect != "allow" || after[0].Effect != "deny" || in.Host.Labels["env"] != "prod" {
		t.Fatal("simulation mutated arguments")
	}
	e := engineFor(t, before, nil)
	before[0].Roles[0] = "other"
	before[0].HostLabels["env"] = "dev"
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			got, err := e.Evaluate(context.Background(), in)
			if err != nil || got.Decision != "allow" {
				t.Errorf("snapshot/concurrent evaluation: %+v, %v", got, err)
			}
		})
	}
	wg.Wait()
}

func BenchmarkPolicy500Rules1000Hosts(b *testing.B) {
	rules := make([]Rule, 500)
	for i := range rules {
		rules[i] = executionRule(fmt.Sprintf("rule-%03d", i), "allow")
	}
	e := engineFor(b, rules, nil)
	in := executionInput()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for i := range 1000 {
			in.Host.ID = fmt.Sprintf("host-%04d", i)
			result, err := e.Evaluate(context.Background(), in)
			if err != nil || result.Decision != "allow" {
				b.Fatalf("%+v, %v", result, err)
			}
		}
	}
}
