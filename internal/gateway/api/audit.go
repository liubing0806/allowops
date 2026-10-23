package api

import (
	"context"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
)

type auditAdapter struct{ appender audit.Appender }

// AppendResultAudit preserves request identity and values while giving result
// persistence its own bounded lifetime after client cancellation. Authorization
// auditing and the operation itself continue to use the request context.
func (s *Service) AppendResultAudit(ctx context.Context, e AuditEvent) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	t := transport(ctx)
	if t == nil || len(t.auditTargets) == 0 {
		return s.Audit.Append(ctx, e)
	}
	resources, err := resultResources(t.auditTargets)
	if err != nil {
		return err
	}
	e.Hostname = t.auditHostname
	for _, resource := range resources {
		e.Resource = resource
		if err = s.Audit.Append(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// NewAuditor adapts the audit module's real Append without changing its payload or storage (design P7).
// A missing implementation remains nil so New refuses startup.
func NewAuditor(appender audit.Appender) Auditor {
	if appender == nil {
		return nil
	}
	return auditAdapter{appender: appender}
}

func (a auditAdapter) Append(ctx context.Context, e AuditEvent) error {
	_, err := a.appender.Append(ctx, audit.Payload{
		SubjectID: e.ActorID, Operation: e.Operation, Decision: e.Outcome, JobID: e.JobID, Resource: e.Resource, Hostname: e.Hostname,
		Reason: e.Phase, PolicyVersion: e.PolicyVersion, MatchedRules: e.MatchedRules, SourceIP: e.SourceIP,
	})
	return err
}

// Authorize implements the audit module's Access. The shared middleware and interceptor supply
// authentication, per-RPC auditing and CSRF before AuditService invokes it.
func (s *Service) Authorize(ctx context.Context, _ http.Header, operation string) (string, error) {
	if operation != string(authz.ViewAudit) {
		return "", failure(connect.CodePermissionDenied, "operation denied")
	}
	if _, err := s.Require(ctx, authz.ViewAudit, authz.Action{}, authz.Host{}); err != nil {
		return "", err
	}
	return reqctx.ActorID(ctx), nil
}

var _ audit.Access = (*Service)(nil)
