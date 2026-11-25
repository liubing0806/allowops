package api

import (
	"context"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
)

// AllowedActionsOnHost returns the execution decisions for candidate actions
// that are allowed or require approval on one active host. It is a display
// precheck for actions_search; the job service still authorizes every call.
//
// A missing host, a host the caller may not view and a host without
// authorization labels all return an empty map, so the result does not reveal
// whether a hostname exists. All decisions use one pinned policy snapshot, and
// matched rule IDs are added to the request audit metadata as can does.
func (s *Service) AllowedActionsOnHost(ctx context.Context, hostname string, actions []authz.Action) (map[string]string, error) {
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
	allowed := map[string]string{}
	hosts, err := s.hostsWhere(ctx, s.Store.Pool, " AND h.hostname = $2", false, hostname)
	if err != nil {
		return nil, err
	}
	if len(hosts) != 1 {
		return allowed, nil
	}
	if !r.transportChecked && id.Client == v1.LoginClient_LOGIN_CLIENT_CONSOLE {
		if err := s.checkCSRF(ctx); err != nil {
			return nil, err
		}
	}
	host := hostAttributes(hosts[0])
	env := authz.Environment{TimeNS: time.Now().UnixNano(), SourceIP: r.ip}
	viewResult, _, err := evaluate(ctx, current.engine, authz.Input{Subject: id.Subject, Operation: authz.ViewHosts, Host: host, Env: env})
	if err != nil {
		return nil, err
	}
	r.policyVersion = current.version
	r.matchedRules = unique(append(r.matchedRules, viewResult.RuleIDs...))
	if viewResult.Decision != "allow" {
		return allowed, nil
	}
	for _, action := range actions {
		result, _, err := evaluate(ctx, current.engine, authz.Input{Subject: id.Subject, Operation: authz.ExecuteAction, Action: action, Host: host, Env: env})
		if err != nil {
			return nil, err
		}
		r.policyVersion = current.version
		r.matchedRules = unique(append(r.matchedRules, result.RuleIDs...))
		if result.Decision == "allow" || result.Decision == "require_approval" {
			allowed[action.Name] = result.Decision
		}
	}
	return allowed, nil
}
