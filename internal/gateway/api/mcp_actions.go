package api

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
)

// AllowedActionsOnHost returns the candidate actions the caller may execute on
// one active host, for the MCP actions_search hostname filter. It is a display
// precheck; the job service still authorizes every call.
//
// A missing host, a host the caller may not view and a host without
// authorization labels all return an empty map, so the result does not reveal
// whether a hostname exists. All decisions use one pinned policy snapshot, and
// matched rule IDs are added to the request audit metadata as can does.
func (s *Service) AllowedActionsOnHost(ctx context.Context, hostname string, actions []authz.Action) (map[string]bool, error) {
	id, ok := reqctx.FromContext(ctx)
	r := transport(ctx)
	if !ok || r == nil {
		return nil, failure(connect.CodeUnauthenticated, "authentication required")
	}
	ctx, err := s.pinPolicy(ctx)
	if err != nil {
		return nil, err
	}
	current := ctx.Value(pinnedPolicyKey{}).(*policyState)
	allowed := map[string]bool{}
	hosts, err := s.hostsWhere(ctx, s.Store.Pool, " AND h.hostname = $2", false, hostname)
	if err != nil {
		return nil, err
	}
	if len(hosts) != 1 {
		return allowed, nil
	}
	host := hostAttributes(hosts[0])
	visible, err := s.can(ctx, authz.ViewHosts, authz.Action{}, host)
	if err != nil || !visible {
		return allowed, err
	}
	env := authz.Environment{TimeNS: time.Now().UnixNano(), SourceIP: r.ip}
	for _, action := range actions {
		result, _, err := evaluate(ctx, current.engine, authz.Input{Subject: id.Subject, Operation: authz.ExecuteAction, Action: action, Host: host, Env: env})
		if err != nil {
			return nil, err
		}
		r.policyVersion = current.version
		r.matchedRules = unique(append(r.matchedRules, result.RuleIDs...))
		if result.Decision == "allow" {
			allowed[action.Name] = true
		}
	}
	return allowed, nil
}
