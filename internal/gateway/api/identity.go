package api

import (
	"context"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authn"
)

func revision(value string) (int64, error) {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 1 {
		return 0, failure(connect.CodeInvalidArgument, "expected revision required")
	}
	return n, nil
}
func (s *Service) CreateServiceAccount(ctx context.Context, r *connect.Request[v1.CreateServiceAccountRequest]) (*connect.Response[v1.CreateServiceAccountResponse], error) {
	m := r.Msg
	if strings.TrimSpace(m.Name) == "" || m.OwnerUserId == "" {
		return nil, failure(connect.CodeInvalidArgument, "name and owner required")
	}
	a, err := insertAccount(ctx, s.Store.Pool, secret("svc_"), m.Name, m.OwnerUserId, m.Description, nonNil(m.Roles), nonNil(m.Teams))
	return connect.NewResponse(&v1.CreateServiceAccountResponse{Account: a}), dbError(err)
}
func (s *Service) GetServiceAccount(ctx context.Context, r *connect.Request[v1.GetServiceAccountRequest]) (*connect.Response[v1.GetServiceAccountResponse], error) {
	a, err := getAccount(ctx, s.Store.Pool, r.Msg.AccountId)
	return connect.NewResponse(&v1.GetServiceAccountResponse{Account: a}), dbError(err)
}
func (s *Service) ListServiceAccounts(ctx context.Context, r *connect.Request[v1.ListServiceAccountsRequest]) (*connect.Response[v1.ListServiceAccountsResponse], error) {
	items, err := listAccounts(ctx, s.Store.Pool)
	if err != nil {
		return nil, dbError(err)
	}
	items, p, err := page(ctx, s.Config, "accounts", r.Msg.Page, items)
	return connect.NewResponse(&v1.ListServiceAccountsResponse{Accounts: items, Page: p}), err
}
func (s *Service) UpdateServiceAccount(ctx context.Context, r *connect.Request[v1.UpdateServiceAccountRequest]) (*connect.Response[v1.UpdateServiceAccountResponse], error) {
	m := r.Msg
	rev, err := revision(m.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	a, err := updateAccount(ctx, s.Store.Pool, m.AccountId, rev, m.OwnerUserId, m.Description, nonNil(m.Roles), nonNil(m.Teams))
	if err == pgx.ErrNoRows {
		return nil, failure(connect.CodeAborted, "account revision changed")
	}
	return connect.NewResponse(&v1.UpdateServiceAccountResponse{Account: a}), dbError(err)
}
func (s *Service) CreateServiceAccountToken(ctx context.Context, r *connect.Request[v1.CreateServiceAccountTokenRequest]) (*connect.Response[v1.CreateServiceAccountTokenResponse], error) {
	days := 30
	if r.Msg.ValidDays != nil {
		days = int(*r.Msg.ValidDays)
	}
	if days < 1 || days > 365 {
		return nil, failure(connect.CodeInvalidArgument, "valid days must be 1..365")
	}
	raw, record, err := authn.GenerateServiceToken(time.Now(), days)
	if err != nil {
		return nil, failure(connect.CodeInternal, "token generation failed")
	}
	t, err := insertAccountToken(ctx, s.Store.Pool, secret("tok_"), r.Msg.AccountId, record.Hash[:], r.Msg.Description, record.ExpiresAt)
	if err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.CreateServiceAccountTokenResponse{Token: t, Secret: raw}), nil
}
func (s *Service) ListServiceAccountTokens(ctx context.Context, r *connect.Request[v1.ListServiceAccountTokensRequest]) (*connect.Response[v1.ListServiceAccountTokensResponse], error) {
	items, err := listAccountTokens(ctx, s.Store.Pool, r.Msg.AccountId)
	if err != nil {
		return nil, dbError(err)
	}
	items, p, err := page(ctx, s.Config, "tokens:"+r.Msg.AccountId, r.Msg.Page, items)
	return connect.NewResponse(&v1.ListServiceAccountTokensResponse{Tokens: items, Page: p}), err
}
func (s *Service) RevokeServiceAccountToken(ctx context.Context, r *connect.Request[v1.RevokeServiceAccountTokenRequest]) (*connect.Response[v1.RevokeServiceAccountTokenResponse], error) {
	rows, err := revokeAccountToken(ctx, s.Store.Pool, r.Msg.AccountId, r.Msg.TokenId)
	if err == nil && rows == 0 {
		return nil, failure(connect.CodeNotFound, "token not found")
	}
	return connect.NewResponse(&v1.RevokeServiceAccountTokenResponse{}), dbError(err)
}
func allUsers(ctx context.Context, q querier, query string) ([]storedUser, error) {
	items, err := searchUsers(ctx, q, query)
	if err != nil {
		return nil, err
	}
	for _, u := range items {
		if err := mapped(ctx, q, u.user); err != nil {
			return nil, err
		}
	}
	return items, nil
}
func (s *Service) ListUsers(ctx context.Context, r *connect.Request[v1.ListUsersRequest]) (*connect.Response[v1.ListUsersResponse], error) {
	users, err := allUsers(ctx, s.Store.Pool, r.Msg.Query)
	if err != nil {
		return nil, dbError(err)
	}
	items := []*v1.User{}
	for _, u := range users {
		items = append(items, u.user)
	}
	items, p, err := page(ctx, s.Config, "users:"+r.Msg.Query, r.Msg.Page, items)
	return connect.NewResponse(&v1.ListUsersResponse{Users: items, Page: p}), err
}
func (s *Service) GetUser(ctx context.Context, r *connect.Request[v1.GetUserRequest]) (*connect.Response[v1.GetUserResponse], error) {
	u, err := loadUser(ctx, s.Store.Pool, r.Msg.UserId)
	return connect.NewResponse(&v1.GetUserResponse{User: u.user}), dbError(err)
}
func (s *Service) SetUserRoles(ctx context.Context, r *connect.Request[v1.SetUserRolesRequest]) (*connect.Response[v1.SetUserRolesResponse], error) {
	rev, err := revision(r.Msg.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	changed, err := setUserRoles(ctx, s.Store.Pool, r.Msg.UserId, rev, nonNil(r.Msg.ManualRoles))
	if err != nil {
		return nil, dbError(err)
	}
	if changed == 0 {
		return nil, failure(connect.CodeAborted, "user revision changed")
	}
	recordAuditTarget(ctx, "user", r.Msg.UserId)
	u, err := loadUser(ctx, s.Store.Pool, r.Msg.UserId)
	return connect.NewResponse(&v1.SetUserRolesResponse{User: u.user}), dbError(err)
}
func (s *Service) GetRoleMappings(ctx context.Context, _ *connect.Request[v1.GetRoleMappingsRequest]) (*connect.Response[v1.GetRoleMappingsResponse], error) {
	tx, err := s.Store.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	rev, err := mappingRevision(ctx, tx)
	if err != nil {
		return nil, dbError(err)
	}
	items, err := listRoleMappings(ctx, tx)
	if err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.GetRoleMappingsResponse{Mappings: items, Revision: strconv.FormatInt(rev, 10)}), nil
}
func (s *Service) SaveRoleMappings(ctx context.Context, r *connect.Request[v1.SaveRoleMappingsRequest]) (*connect.Response[v1.SaveRoleMappingsResponse], error) {
	rev, err := revision(r.Msg.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	changed, err := bumpMappingRevision(ctx, tx, rev)
	if err != nil {
		return nil, dbError(err)
	}
	if changed == 0 {
		return nil, failure(connect.CodeAborted, "mapping revision changed")
	}
	if err := deleteRoleMappings(ctx, tx); err != nil {
		return nil, dbError(err)
	}
	for _, m := range r.Msg.Mappings {
		if m.ProviderId == "" || m.Group == "" || len(m.Roles) == 0 {
			return nil, failure(connect.CodeInvalidArgument, "provider, group and roles required")
		}
		if err := insertRoleMapping(ctx, tx, m.ProviderId, m.Group, nonNil(m.Roles)); err != nil {
			return nil, dbError(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.SaveRoleMappingsResponse{Revision: strconv.FormatInt(rev+1, 10)}), nil
}
func (s *Service) ListRoles(ctx context.Context, r *connect.Request[v1.ListRolesRequest]) (*connect.Response[v1.ListRolesResponse], error) {
	items, err := listRoleNames(ctx, s.Store.Pool)
	if err != nil {
		return nil, dbError(err)
	}
	items, p, err := page(ctx, s.Config, "roles", r.Msg.Page, items)
	return connect.NewResponse(&v1.ListRolesResponse{Roles: items, Page: p}), err
}
