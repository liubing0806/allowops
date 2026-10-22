package authz

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"time"
	_ "time/tzdata"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

var ErrPolicyLockout = errors.New("policy leaves no subject able to modify policy")

//go:embed policy.rego
var policy string

// Engine is an immutable policy snapshot, safe for concurrent evaluation.
type Engine struct {
	query rego.PreparedEvalQuery
	ready bool
}

func New(ctx context.Context, source RuleSource, bootstrapAdmins []string) (*Engine, error) {
	if source == nil {
		return nil, errors.New("nil rule source")
	}
	rules, err := source.LoadRules(ctx)
	if err != nil {
		return nil, err
	}
	return newEngine(ctx, rules, bootstrapAdmins)
}

func newEngine(ctx context.Context, rules []Rule, bootstrapAdmins []string) (*Engine, error) {
	ids := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if rule.ID == "" || rule.ID == "bootstrap_admins" || ids[rule.ID] {
			return nil, fmt.Errorf("invalid or duplicate rule ID %q", rule.ID)
		}
		ids[rule.ID] = true
		if rule.Effect != "allow" && rule.Effect != "deny" {
			return nil, fmt.Errorf("rule %q: invalid effect", rule.ID)
		}
		if len(rule.Roles) == 0 || len(rule.Operations) == 0 {
			return nil, fmt.Errorf("rule %q: roles and operations are required", rule.ID)
		}
		for _, op := range rule.Operations {
			if !validOperation(op) {
				return nil, fmt.Errorf("rule %q: unknown operation %q", rule.ID, op)
			}
		}
		if rule.Hours != nil && (rule.Hours.From < 0 || rule.Hours.To > 24 || rule.Hours.From >= rule.Hours.To) {
			return nil, fmt.Errorf("rule %q: invalid hours", rule.ID)
		}
		if rule.Hours != nil && rule.Hours.Timezone != "" {
			if _, err := time.LoadLocation(rule.Hours.Timezone); err != nil || rule.Hours.Timezone == "Local" {
				return nil, fmt.Errorf("rule %q: invalid timezone", rule.ID)
			}
		}
		for _, cidr := range rule.SourceCIDRs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return nil, fmt.Errorf("rule %q: invalid source CIDR", rule.ID)
			}
		}
	}
	// JSON conversion detaches all slices/maps from caller-owned rule data.
	encoded, err := json.Marshal(map[string]any{"rules": compactRules(rules), "bootstrap_admins": append([]string{}, bootstrapAdmins...)})
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal(encoded, &data); err != nil {
		return nil, err
	}
	query, err := rego.New(rego.Query("data.allowops.authz.result"), rego.Module("policy.rego", policy),
		rego.Store(inmem.NewFromObjectWithOpts(data, inmem.OptReturnASTValuesOnRead(true))), rego.Capabilities(capabilities()), rego.StrictBuiltinErrors(true)).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	return &Engine{query: query, ready: true}, nil
}

type ruleGroup struct {
	Rule
	IDs map[string]bool `json:"ids"`
}

// compactRules evaluates identical conditions/effects once, retaining every rule ID.
// Encoding a typed Rule without its ID gives a stable key for its stored conditions.
func compactRules(rules []Rule) []ruleGroup {
	groups := []ruleGroup{}
	indices := map[string]int{}
	for _, rule := range rules {
		condition := rule
		condition.ID = ""
		key, _ := json.Marshal(condition) // Rule contains only JSON-serializable field types.
		index, exists := indices[string(key)]
		if !exists {
			index = len(groups)
			indices[string(key)] = index
			groups = append(groups, ruleGroup{Rule: rule, IDs: map[string]bool{}})
		}
		groups[index].IDs[rule.ID] = true
	}
	return groups
}

// Evaluate always returns deny alongside an error. Callers must never convert errors into allow.
func (e *Engine) Evaluate(ctx context.Context, input Input) (Result, error) {
	deny := Result{Decision: "deny", RuleIDs: []string{}}
	if e == nil || !e.ready {
		return deny, errors.New("uninitialized policy engine")
	}
	if err := ctx.Err(); err != nil {
		return deny, err
	}
	if !validOperation(input.Operation) {
		return deny, nil
	}
	results, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return deny, err
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		return deny, errors.New("invalid policy result")
	}
	encoded, err := json.Marshal(results[0].Expressions[0].Value)
	if err != nil {
		return deny, err
	}
	var result Result
	if err := json.Unmarshal(encoded, &result); err != nil {
		return deny, err
	}
	if (result.Decision != "allow" && result.Decision != "deny") || result.RuleIDs == nil {
		return deny, errors.New("invalid policy result")
	}
	return result, nil
}

func capabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	allowed := make([]*ast.Builtin, 0, len(caps.Builtins))
	for _, builtin := range caps.Builtins {
		if !builtin.IsNondeterministic() {
			allowed = append(allowed, builtin)
		}
	}
	caps.Builtins = allowed
	caps.AllowNet = []string{}
	return caps
}

func validOperation(op Operation) bool {
	switch op {
	case ExecuteAction, ModifyPolicy, ManageServiceAccounts, ManageHosts, CreateJoinToken, ManageUserRoles, PublishCatalog, ViewHosts, ViewCatalog, ViewJobs, ViewOutput, ViewAudit, ViewSystem:
		return true
	default:
		return false
	}
}

// CheckPolicyUpdate evaluates the supplied, existing subjects at the supplied environment.
// The caller must provide the complete subject set, including eligible bootstrap identities.
func CheckPolicyUpdate(ctx context.Context, proposed []Rule, subjects []Subject, env Environment, bootstrapAdmins []string) error {
	e, err := newEngine(ctx, proposed, bootstrapAdmins)
	if err != nil {
		return err
	}
	for _, subject := range subjects {
		result, err := e.Evaluate(ctx, Input{Subject: subject, Operation: ModifyPolicy, Env: env})
		if err != nil {
			return err
		}
		if result.Decision == "allow" {
			return nil
		}
	}
	return ErrPolicyLockout
}

// Simulate returns changes to decisions or matched rule IDs, in input order, without I/O.
func Simulate(ctx context.Context, before, after []Rule, inputs []Input, bootstrapAdmins []string) ([]HostChange, error) {
	oldEngine, err := newEngine(ctx, before, bootstrapAdmins)
	if err != nil {
		return nil, err
	}
	nextEngine, err := newEngine(ctx, after, bootstrapAdmins)
	if err != nil {
		return nil, err
	}
	changes := []HostChange{}
	for _, input := range inputs {
		oldResult, err := oldEngine.Evaluate(ctx, input)
		if err != nil {
			return nil, err
		}
		newResult, err := nextEngine.Evaluate(ctx, input)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(oldResult, newResult) {
			changes = append(changes, HostChange{HostID: input.Host.ID, Before: oldResult, After: newResult})
		}
	}
	return changes, nil
}
