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
	a, err := scanAccount(s.Store.Pool.QueryRow(ctx, "INSERT INTO service_accounts(account_id,name,owner_user_id,description,roles,teams) VALUES ($1,$2,$3,$4,$5,$6) RETURNING "+accountColumns, secret("svc_"), m.Name, m.OwnerUserId, m.Description, nonNil(m.Roles), nonNil(m.Teams)))
	return connect.NewResponse(&v1.CreateServiceAccountResponse{Account: a}), dbError(err)
}
func (s *Service) GetServiceAccount(ctx context.Context, r *connect.Request[v1.GetServiceAccountRequest]) (*connect.Response[v1.GetServiceAccountResponse], error) {
	a, err := scanAccount(s.Store.Pool.QueryRow(ctx, "SELECT "+accountColumns+" FROM service_accounts WHERE account_id=$1", r.Msg.AccountId))
	return connect.NewResponse(&v1.GetServiceAccountResponse{Account: a}), dbError(err)
}
func (s *Service) ListServiceAccounts(ctx context.Context, r *connect.Request[v1.ListServiceAccountsRequest]) (*connect.Response[v1.ListServiceAccountsResponse], error) {
	rows, err := s.Store.Pool.Query(ctx, "SELECT "+accountColumns+" FROM service_accounts ORDER BY account_id")
	if err != nil {
		return nil, dbError(err)
	}
	defer rows.Close()
	items := []*v1.ServiceAccount{}
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, dbError(err)
		}
		items = append(items, a)
	}
	if err := rows.Err(); err != nil {
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
	a, err := scanAccount(s.Store.Pool.QueryRow(ctx, "UPDATE service_accounts SET owner_user_id=$3,description=$4,roles=$5,teams=$6,revision=revision+1 WHERE account_id=$1 AND revision=$2 RETURNING "+accountColumns, m.AccountId, rev, m.OwnerUserId, m.Description, nonNil(m.Roles), nonNil(m.Teams)))
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
	t, err := scanToken(s.Store.Pool.QueryRow(ctx, "INSERT INTO service_account_tokens(token_id,account_id,token_hash,description,expires_at) VALUES ($1,$2,$3,$4,$5) RETURNING "+tokenColumns, secret("tok_"), r.Msg.AccountId, record.Hash[:], r.Msg.Description, record.ExpiresAt))
	if err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.CreateServiceAccountTokenResponse{Token: t, Secret: raw}), nil
}
func (s *Service) ListServiceAccountTokens(ctx context.Context, r *connect.Request[v1.ListServiceAccountTokensRequest]) (*connect.Response[v1.ListServiceAccountTokensResponse], error) {
	rows, err := s.Store.Pool.Query(ctx, "SELECT "+tokenColumns+" FROM service_account_tokens WHERE account_id=$1 ORDER BY token_id", r.Msg.AccountId)
	if err != nil {
		return nil, dbError(err)
	}
	defer rows.Close()
	items := []*v1.ServiceAccountToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, dbError(err)
		}
		items = append(items, t)
	}
	if err := rows.Err(); err != nil {
		return nil, dbError(err)
	}
	items, p, err := page(ctx, s.Config, "tokens:"+r.Msg.AccountId, r.Msg.Page, items)
	return connect.NewResponse(&v1.ListServiceAccountTokensResponse{Tokens: items, Page: p}), err
}
func (s *Service) RevokeServiceAccountToken(ctx context.Context, r *connect.Request[v1.RevokeServiceAccountTokenRequest]) (*connect.Response[v1.RevokeServiceAccountTokenResponse], error) {
	tag, err := s.Store.Pool.Exec(ctx, "UPDATE service_account_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE account_id=$1 AND token_id=$2", r.Msg.AccountId, r.Msg.TokenId)
	if err == nil && tag.RowsAffected() == 0 {
		return nil, failure(connect.CodeNotFound, "token not found")
	}
	return connect.NewResponse(&v1.RevokeServiceAccountTokenResponse{}), dbError(err)
}
func allUsers(ctx context.Context, q querier, query string) ([]storedUser, error) {
	rows, err := q.Query(ctx, "SELECT "+userColumns+" FROM console_users WHERE $1='' OR position(lower($1) in lower(username||' '||email||' '||display_name))>0 ORDER BY user_id", query)
	if err != nil {
		return nil, err
	}
	items := []storedUser{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, u)
	}
	err = rows.Err()
	rows.Close()
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
	tag, err := s.Store.Pool.Exec(ctx, "UPDATE console_users SET manual_roles=$3,revision=revision+1 WHERE user_id=$1 AND revision=$2", r.Msg.UserId, rev, nonNil(r.Msg.ManualRoles))
	if err != nil {
		return nil, dbError(err)
	}
	if tag.RowsAffected() == 0 {
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
	var rev int64
	if err := tx.QueryRow(ctx, "SELECT revision FROM role_mapping_state").Scan(&rev); err != nil {
		return nil, dbError(err)
	}
	rows, err := tx.Query(ctx, "SELECT provider_id,group_name,roles FROM role_mappings ORDER BY provider_id,group_name")
	if err != nil {
		return nil, dbError(err)
	}
	defer rows.Close()
	items := []*v1.RoleMapping{}
	for rows.Next() {
		m := &v1.RoleMapping{}
		if err := rows.Scan(&m.ProviderId, &m.Group, &m.Roles); err != nil {
			return nil, dbError(err)
		}
		items = append(items, m)
	}
	if err := rows.Err(); err != nil {
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
	tag, err := tx.Exec(ctx, "UPDATE role_mapping_state SET revision=revision+1 WHERE revision=$1", rev)
	if err != nil {
		return nil, dbError(err)
	}
	if tag.RowsAffected() == 0 {
		return nil, failure(connect.CodeAborted, "mapping revision changed")
	}
	if _, err := tx.Exec(ctx, "DELETE FROM role_mappings"); err != nil {
		return nil, dbError(err)
	}
	for _, m := range r.Msg.Mappings {
		if m.ProviderId == "" || m.Group == "" || len(m.Roles) == 0 {
			return nil, failure(connect.CodeInvalidArgument, "provider, group and roles required")
		}
		if _, err := tx.Exec(ctx, "INSERT INTO role_mappings(provider_id,group_name,roles) VALUES ($1,$2,$3)", m.ProviderId, m.Group, nonNil(m.Roles)); err != nil {
			return nil, dbError(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.SaveRoleMappingsResponse{Revision: strconv.FormatInt(rev+1, 10)}), nil
}
func (s *Service) ListRoles(ctx context.Context, r *connect.Request[v1.ListRolesRequest]) (*connect.Response[v1.ListRolesResponse], error) {
	rows, err := s.Store.Pool.Query(ctx, `SELECT DISTINCT name FROM (
      SELECT name FROM roles UNION SELECT unnest(manual_roles) FROM console_users UNION SELECT unnest(roles) FROM service_accounts UNION SELECT unnest(roles) FROM role_mappings
      UNION SELECT jsonb_array_elements_text(rule->'roles') FROM policy_versions p CROSS JOIN LATERAL jsonb_array_elements(p.rules->'rules') rule WHERE p.version=(SELECT max(version) FROM policy_versions)
    ) names WHERE name <> '*' ORDER BY name`)
	if err != nil {
		return nil, dbError(err)
	}
	defer rows.Close()
	items := []*v1.Role{}
	for rows.Next() {
		item := &v1.Role{}
		if err := rows.Scan(&item.Name); err != nil {
			return nil, dbError(err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, dbError(err)
	}
	items, p, err := page(ctx, s.Config, "roles", r.Msg.Page, items)
	return connect.NewResponse(&v1.ListRolesResponse{Roles: items, Page: p}), err
}
