package api

import (
	"context"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store"
)

// PolicySnapshot supplies detached structured rules for MCP display prechecks.
// It does not authorize execution; Require and the Job service remain authoritative.
func (s *Service) PolicySnapshot(ctx context.Context) (uint64, []authz.Rule, error) {
	if _, ok := reqctx.FromContext(ctx); !ok {
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

// Database, AuditConfigured, Origin, MessageBytes and PageSize expose the
// configuration the MCP service reads, without exposing Service fields.
func (s *Service) Database() *store.Store {
	if s == nil {
		return nil
	}
	return s.Store
}

func (s *Service) AuditConfigured() bool { return s != nil && s.Audit != nil }
func (s *Service) Origin() string        { return s.Config.Origin }
func (s *Service) MessageBytes() int     { return s.Config.MessageBytes }
func (s *Service) PageSize() int         { return s.Config.PageSize }
