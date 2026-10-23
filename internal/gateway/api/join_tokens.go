package api

import (
	"context"
	"crypto/rand"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

func (s *Service) CreateJoinToken(ctx context.Context, req *connect.Request[v1.CreateJoinTokenRequest]) (*connect.Response[v1.CreateJoinTokenResponse], error) {
	if s.management.config.CAPin == "" {
		return nil, failure(connect.CodeFailedPrecondition, "gateway TLS CA pin unavailable; configure management.ca_pin")
	}
	if req.Msg.MaxUses == 0 {
		return nil, failure(connect.CodeInvalidArgument, "max_uses must be positive")
	}
	ttl := s.gatewayConfig().SingleJoinTTL
	if req.Msg.MaxUses > 1 {
		ttl = s.gatewayConfig().MultiJoinTTL
	}
	if req.Msg.Ttl != nil {
		if req.Msg.Ttl.CheckValid() != nil {
			return nil, failure(connect.CodeInvalidArgument, "invalid TTL")
		}
		ttl = req.Msg.Ttl.AsDuration()
		if ttl <= 0 {
			return nil, failure(connect.CodeInvalidArgument, "TTL must be positive")
		}
	}
	uses := int64(req.Msg.MaxUses)
	// Keep the helper's token/ID format and insertion semantics, retaining the
	// confirmed ID before the subsequent read can fail or be cancelled.
	raw, id := rand.Text(), rand.Text()
	err := insertJoinToken(ctx, s.Store.Pool, id, hash(raw), uses, time.Now().Add(ttl))
	if err != nil {
		return nil, dbError(err)
	}
	recordAuditTarget(ctx, "join_token", id)
	t, err := joinTokenByHash(ctx, s.Store.Pool, hash(raw))
	if err != nil {
		return nil, dbError(err)
	}
	upstream := s.management.config.Upstream
	if upstream == "" {
		upstream = s.Config.Origin
	}
	return connect.NewResponse(&v1.CreateJoinTokenResponse{Token: t, Secret: raw, Upstream: upstream, CaPin: s.management.config.CAPin}), nil
}
func (s *Service) ListJoinTokens(ctx context.Context, req *connect.Request[v1.ListJoinTokensRequest]) (*connect.Response[v1.ListJoinTokensResponse], error) {
	tokens, err := listJoinTokens(ctx, s.Store.Pool)
	if err != nil {
		return nil, dbError(err)
	}
	tokens, cursor, err := page(ctx, s.Config, "join_tokens", req.Msg.Page, tokens)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.ListJoinTokensResponse{Tokens: tokens, Page: cursor}), nil
}
func (s *Service) RevokeJoinToken(ctx context.Context, req *connect.Request[v1.RevokeJoinTokenRequest]) (*connect.Response[v1.RevokeJoinTokenResponse], error) {
	revoked, err := revokeJoinToken(ctx, s.Store.Pool, req.Msg.TokenId)
	if err != nil {
		return nil, dbError(err)
	}
	if revoked == 0 {
		return nil, failure(connect.CodeNotFound, "join token not found")
	}
	return connect.NewResponse(&v1.RevokeJoinTokenResponse{}), nil
}
