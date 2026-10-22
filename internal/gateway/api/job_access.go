package api

import (
	"context"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
)

// CheckRequest exposes the existing transport checks to in-process services.
// It does not authorize an operation or append audit; the service does both.
func (s *Service) CheckRequest(ctx context.Context, write bool) error {
	t := transport(ctx)
	if t != nil && t.tls && t.err != nil && connect.CodeOf(t.err) == connect.CodeUnavailable {
		return t.err
	}
	if t == nil || !t.tls || t.err != nil || t.identity == nil {
		return failure(connect.CodeUnauthenticated, "authentication required")
	}
	if write {
		if origin := t.header.Get("Origin"); origin != "" && origin != s.Config.Origin {
			return failure(connect.CodePermissionDenied, "origin rejected")
		}
		if t.identity.Client == v1.LoginClient_LOGIN_CLIENT_CONSOLE {
			if err := s.checkCSRF(ctx); err != nil {
				return err
			}
		}
	}
	t.transportChecked = true
	return nil
}

// RequireBatch uses one current policy snapshot and one request environment.
// Unlabeled execution targets always deny, including bootstrap administrators.
func (s *Service) RequireBatch(ctx context.Context, op authz.Operation, action authz.Action, hosts []authz.Host) ([]authz.HostResult, uint64, error) {
	if err := s.CheckRequest(ctx, op == authz.ExecuteAction); err != nil {
		return nil, 0, err
	}
	if err := s.refresh(ctx); err != nil {
		return nil, 0, failure(connect.CodeUnavailable, "policy unavailable")
	}
	current := s.state.Load()
	t := transport(ctx)
	results := current.engine.EvaluateBatch(ctx, authz.Input{Subject: t.identity.Subject, Operation: op, Action: action, Env: authz.Environment{TimeNS: time.Now().UnixNano(), SourceIP: t.ip}}, hosts)
	for i, host := range hosts {
		if op == authz.ExecuteAction && len(host.Labels) == 0 {
			results[i].Result = authz.Result{Decision: "deny", RuleIDs: []string{"HOST_UNLABELED"}}
		}
		t.matchedRules = unique(append(t.matchedRules, results[i].Result.RuleIDs...))
	}
	t.policyVersion = current.version
	return results, current.version, nil
}

// RequestInfo contains gateway-authenticated audit identifiers only.
func RequestInfo(ctx context.Context) (actor, sourceIP string) {
	if t := transport(ctx); t != nil {
		return actorID(ctx), t.ip
	}
	return "", ""
}
