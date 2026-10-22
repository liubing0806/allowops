package api

import (
	"context"
	"slices"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/internal/gateway/authz"
)

// PolicySnapshot supplies detached structured rules for MCP display prechecks.
// It does not authorize execution; Require and the Job service remain authoritative.
func (s *Service) PolicySnapshot(ctx context.Context) (uint64, []authz.Rule, error) {
	if _, ok := FromContext(ctx); !ok {
		return 0, nil, failure(connect.CodeUnauthenticated, "authentication required")
	}
	p, err := loadPolicy(ctx, s.Store.Pool, 0)
	if err != nil {
		return 0, nil, dbError(err)
	}
	rules, err := rulesFromProto(p.Rules)
	if err == nil {
		if t := transport(ctx); t != nil {
			t.policyVersion = p.Version
		}
	}
	return p.Version, rules, err
}

// ForkRequestContext isolates mutable authorization/audit metadata for MCP
// calls sharing an HTTP batch. Authentication and transport values are preserved.
func ForkRequestContext(ctx context.Context) context.Context {
	t := transport(ctx)
	if t == nil {
		return ctx
	}
	copy := *t
	copy.matchedRules = nil
	copy.auditTargets = nil
	copy.auditHostname = ""
	copy.resource = true
	return context.WithValue(ctx, requestKey{}, &copy)
}

// RequestAuditInfo exposes only the existing audit allowlist.
func RequestAuditInfo(ctx context.Context) AuditEvent {
	e := AuditEvent{ActorID: actorID(ctx)}
	if t := transport(ctx); t != nil {
		e.SourceIP = t.ip
		e.PolicyVersion = t.policyVersion
		e.MatchedRules = slices.Clone(t.matchedRules)
	}
	return e
}
