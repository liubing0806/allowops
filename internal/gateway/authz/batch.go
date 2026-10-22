package authz

import (
	"context"
	"encoding/json"
	"slices"
)

// HostResult is one host's decision, including a fail-closed evaluation error.
type HostResult struct {
	HostID string
	Result Result
	Err    error
}

// EvaluateBatch evaluates hosts in order with a shared subject, operation, action and environment.
// input.Host is replaced by each host. Errors are returned per host, always with deny.
// The fixed policy only inspects host labels, so equal label sets reuse one evaluation.
func (e *Engine) EvaluateBatch(ctx context.Context, input Input, hosts []Host) []HostResult {
	results := make([]HostResult, len(hosts))
	cache := map[string]HostResult{}
	for i, host := range hosts {
		if err := ctx.Err(); err != nil {
			results[i] = HostResult{HostID: host.ID, Result: Result{Decision: "deny", RuleIDs: []string{}}, Err: err}
			continue
		}
		key := ""
		if len(host.Labels) > 0 {
			encoded, _ := json.Marshal(host.Labels) // String maps cannot fail JSON encoding; keys are sorted.
			key = string(encoded)
		}
		cached, exists := cache[key]
		if !exists {
			input.Host = host
			cached.Result, cached.Err = e.Evaluate(ctx, input)
			cache[key] = cached
		}
		results[i] = HostResult{HostID: host.ID, Result: Result{Decision: cached.Result.Decision, RuleIDs: slices.Clone(cached.Result.RuleIDs)}, Err: cached.Err}
	}
	return results
}
