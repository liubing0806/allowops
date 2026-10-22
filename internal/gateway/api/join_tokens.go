package api

import (
	"context"
	"crypto/rand"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

const joinColumns = "token_id,max_uses,used_count,expires_at,created_at,revoked_at"

func scanJoin(row pgx.Row) (*v1.JoinToken, error) {
	t := &v1.JoinToken{}
	var expires time.Time
	var created pgtype.Timestamptz
	var revoked pgtype.Timestamptz
	err := row.Scan(&t.TokenId, &t.MaxUses, &t.UsedCount, &expires, &created, &revoked)
	t.ExpiresAt = stamp(expires)
	t.CreatedAt = nullable(created)
	t.RevokedAt = nullable(revoked)
	return t, err
}
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
	_, err := s.Store.Pool.Exec(ctx, "INSERT INTO join_tokens(token_id,token_hash,max_uses,expires_at) VALUES ($1,$2,$3,$4)", id, hash(raw), uses, time.Now().Add(ttl))
	if err != nil {
		return nil, dbError(err)
	}
	recordAuditTarget(ctx, "join_token", id)
	t, err := scanJoin(s.Store.Pool.QueryRow(ctx, "SELECT "+joinColumns+" FROM join_tokens WHERE token_hash=$1", hash(raw)))
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
	rows, err := s.Store.Pool.Query(ctx, "SELECT "+joinColumns+" FROM join_tokens ORDER BY token_id")
	if err != nil {
		return nil, dbError(err)
	}
	defer rows.Close()
	tokens := []*v1.JoinToken{}
	for rows.Next() {
		t, err := scanJoin(rows)
		if err != nil {
			return nil, dbError(err)
		}
		tokens = append(tokens, t)
	}
	if err = rows.Err(); err != nil {
		return nil, dbError(err)
	}
	tokens, cursor, err := page(ctx, s.Config, "join_tokens", req.Msg.Page, tokens)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.ListJoinTokensResponse{Tokens: tokens, Page: cursor}), nil
}
func (s *Service) RevokeJoinToken(ctx context.Context, req *connect.Request[v1.RevokeJoinTokenRequest]) (*connect.Response[v1.RevokeJoinTokenResponse], error) {
	tag, err := s.Store.Pool.Exec(ctx, "UPDATE join_tokens SET revoked=true,revoked_at=CASE WHEN revoked THEN revoked_at ELSE now() END WHERE token_id=$1", req.Msg.TokenId)
	if err != nil {
		return nil, dbError(err)
	}
	if tag.RowsAffected() == 0 {
		return nil, failure(connect.CodeNotFound, "join token not found")
	}
	return connect.NewResponse(&v1.RevokeJoinTokenResponse{}), nil
}
