package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type querier interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func dbError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return failure(connect.CodeNotFound, "object not found")
	}
	var p *pgconn.PgError
	if errors.As(err, &p) {
		switch p.Code {
		case "23505":
			return failure(connect.CodeAlreadyExists, "object already exists")
		case "23503", "23514":
			return failure(connect.CodeInvalidArgument, "invalid reference or value")
		case "40001", "40P01":
			return failure(connect.CodeAborted, "state changed; retry")
		}
	}
	return failure(connect.CodeUnavailable, "identity database unavailable")
}

const userColumns = "user_id,provider_id,provider_subject,kind,username,email,display_name,groups,manual_roles,teams,revision"

type storedUser struct {
	user          *v1.User
	kind, subject string
}

func scanUser(row pgx.Row) (storedUser, error) {
	u := &v1.User{}
	var kind, sub string
	var rev int64
	err := row.Scan(&u.UserId, &u.ProviderId, &sub, &kind, &u.Username, &u.Email, &u.DisplayName, &u.Groups, &u.ManualRoles, &u.Teams, &rev)
	u.Revision = strconv.FormatInt(rev, 10)
	return storedUser{u, kind, sub}, err
}
func mapped(ctx context.Context, q querier, u *v1.User) error {
	rows, err := q.Query(ctx, "SELECT roles FROM role_mappings WHERE provider_id=$1 AND group_name=ANY($2) ORDER BY group_name", u.ProviderId, u.Groups)
	if err != nil {
		return err
	}
	defer rows.Close()
	u.MappedRoles = []string{}
	for rows.Next() {
		var roles []string
		if err := rows.Scan(&roles); err != nil {
			return err
		}
		u.MappedRoles = append(u.MappedRoles, roles...)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	u.MappedRoles = unique(u.MappedRoles)
	u.EffectiveRoles = unique(append(append([]string{}, u.ManualRoles...), u.MappedRoles...))
	return nil
}
func loadUser(ctx context.Context, q querier, id string) (storedUser, error) {
	u, err := scanUser(q.QueryRow(ctx, "SELECT "+userColumns+" FROM console_users WHERE user_id=$1", id))
	if err == nil {
		err = mapped(ctx, q, u.user)
	}
	return u, err
}
func subject(u storedUser) authz.Subject {
	return authz.Subject{ID: u.subject, Kind: u.kind, Email: u.user.Email, Roles: u.user.EffectiveRoles, Teams: u.user.Teams}
}

func (s *Service) syncUser(ctx context.Context, provider string, id authn.Identity) (*v1.User, error) {
	var uid string
	_, err := s.Store.Pool.Exec(ctx, `INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username,email,groups) VALUES ($1,$2,$3,$4,$3,$5,$6)
      ON CONFLICT(provider_id,provider_subject) DO UPDATE SET email=EXCLUDED.email,groups=EXCLUDED.groups,revision=console_users.revision+1`, secret("usr_"), provider, id.ID, id.Kind, id.Email, nonNil(id.Groups))
	if err != nil {
		return nil, dbError(err)
	}
	if err := s.Store.Pool.QueryRow(ctx, "SELECT user_id FROM console_users WHERE provider_id=$1 AND provider_subject=$2", provider, id.ID).Scan(&uid); err != nil {
		return nil, dbError(err)
	}
	u, err := loadUser(ctx, s.Store.Pool, uid)
	return u.user, dbError(err)
}
func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return unique(v)
}
func nullable(t pgtype.Timestamptz) *timestamppb.Timestamp {
	if !t.Valid {
		return nil
	}
	return stamp(t.Time)
}

const accountColumns = "account_id,name,owner_user_id,description,roles,teams,revision,created_at"

func scanAccount(row pgx.Row) (*v1.ServiceAccount, error) {
	a := &v1.ServiceAccount{}
	var rev int64
	var created time.Time
	err := row.Scan(&a.AccountId, &a.Name, &a.OwnerUserId, &a.Description, &a.Roles, &a.Teams, &rev, &created)
	a.Revision = strconv.FormatInt(rev, 10)
	a.CreatedAt = stamp(created)
	return a, err
}

const tokenColumns = "token_id,account_id,description,created_at,expires_at,last_used_at,revoked_at"

func scanToken(row pgx.Row) (*v1.ServiceAccountToken, error) {
	t := &v1.ServiceAccountToken{}
	var created, expires time.Time
	var used, revoked pgtype.Timestamptz
	err := row.Scan(&t.TokenId, &t.AccountId, &t.Description, &created, &expires, &used, &revoked)
	t.CreatedAt, t.ExpiresAt, t.LastUsedAt, t.RevokedAt = stamp(created), stamp(expires), nullable(used), nullable(revoked)
	return t, err
}

const sessionColumns = "session_id,user_id,created_at,expires_at,last_used_at,revoked_at"

func scanSession(row pgx.Row) (*v1.CliSession, error) {
	t := &v1.CliSession{}
	var created, expires time.Time
	var used, revoked pgtype.Timestamptz
	err := row.Scan(&t.SessionId, &t.UserId, &created, &expires, &used, &revoked)
	t.CreatedAt, t.ExpiresAt, t.LastUsedAt, t.RevokedAt = stamp(created), stamp(expires), nullable(used), nullable(revoked)
	return t, err
}
func (s *Service) authenticate(ctx context.Context, token string, cookie bool) (*Identity, error) {
	if !cookie && strings.HasPrefix(token, "aops_") && len(token) == len("aops_")+43 {
		// Validate the canonical P5A token format before lookup.
		var h [32]byte
		copy(h[:], hash(token))
		if !authn.VerifyServiceToken(token, authn.TokenRecord{Hash: h, ExpiresAt: time.Now().Add(time.Hour)}, time.Now()) {
			return nil, authn.ErrInvalidCredentials
		}
		var accountID string
		if err := s.Store.Pool.QueryRow(ctx, "UPDATE service_account_tokens SET last_used_at=now() WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>now() RETURNING account_id", hash(token)).Scan(&accountID); err != nil {
			return nil, authn.ErrInvalidCredentials
		}
		a, err := scanAccount(s.Store.Pool.QueryRow(ctx, "SELECT "+accountColumns+" FROM service_accounts WHERE account_id=$1", accountID))
		if err != nil {
			return nil, authn.ErrInvalidCredentials
		}
		return &Identity{Subject: authz.Subject{ID: a.AccountId, Kind: "service_account", Roles: a.Roles, Teams: a.Teams, Owner: a.OwnerUserId}}, nil
	}
	client := "cli"
	prefix := "aops_cli_"
	if cookie {
		client = "console"
		prefix = "aops_web_"
	}
	if !strings.HasPrefix(token, prefix) {
		return nil, authn.ErrInvalidCredentials
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(token, prefix))
	if err != nil || len(b) != 32 {
		return nil, authn.ErrInvalidCredentials
	}
	var sessionID, csrf string
	if err := s.Store.Pool.QueryRow(ctx, "UPDATE identity_sessions SET last_used_at=now() WHERE token_hash=$1 AND client=$2 AND revoked_at IS NULL AND expires_at>now() RETURNING session_id,csrf_token", hash(token), client).Scan(&sessionID, &csrf); err != nil {
		return nil, authn.ErrInvalidCredentials
	}
	sess, err := scanSession(s.Store.Pool.QueryRow(ctx, "SELECT "+sessionColumns+" FROM identity_sessions WHERE session_id=$1", sessionID))
	if err != nil {
		return nil, authn.ErrInvalidCredentials
	}
	u, err := loadUser(ctx, s.Store.Pool, sess.UserId)
	if err != nil {
		return nil, authn.ErrInvalidCredentials
	}
	kind := v1.LoginClient_LOGIN_CLIENT_CLI
	if cookie {
		kind = v1.LoginClient_LOGIN_CLIENT_CONSOLE
	}
	return &Identity{Subject: subject(u), User: u.user, Session: sess, Client: kind, CSRF: csrf}, nil
}
func (s *Service) issueSession(ctx context.Context, q querier, userID string, client v1.LoginClient) (*v1.CliSession, string, error) {
	kind, prefix, ttl, csrf := "cli", "aops_cli_", s.Config.CliTTL, ""
	if client == v1.LoginClient_LOGIN_CLIENT_CONSOLE {
		kind, prefix, ttl, csrf = "console", "aops_web_", s.Config.ConsoleTTL, secret("")
	} else if client != v1.LoginClient_LOGIN_CLIENT_CLI {
		return nil, "", failure(connect.CodeInvalidArgument, "login client required")
	}
	token := secret(prefix)
	sess, err := scanSession(q.QueryRow(ctx, "INSERT INTO identity_sessions(session_id,user_id,token_hash,client,csrf_token,expires_at) VALUES ($1,$2,$3,$4,$5,$6) RETURNING "+sessionColumns, secret("ses_"), userID, hash(token), kind, csrf, time.Now().Add(ttl)))
	return sess, token, dbError(err)
}

func page[T any](ctx context.Context, cfg Config, scope string, req *v1.PageRequest, items []T) ([]T, *v1.PageResponse, error) {
	size, offset := cfg.PageSize, 0
	binding := base64.RawURLEncoding.EncodeToString(hash(scope + ":" + actorID(ctx)))
	if req != nil {
		if req.PageSize > 0 {
			size = int(req.PageSize)
		}
		if size > cfg.MaxPageSize {
			return nil, nil, failure(connect.CodeInvalidArgument, "page size exceeds limit")
		}
		if req.PageToken != "" {
			data, err := base64.RawURLEncoding.Strict().DecodeString(req.PageToken)
			parts := strings.Split(string(data), ":")
			if err != nil || len(parts) != 2 || parts[0] != binding {
				return nil, nil, failure(connect.CodeInvalidArgument, "page cursor scope mismatch")
			}
			offset, err = strconv.Atoi(parts[1])
			if err != nil || offset < 0 || offset > len(items) {
				return nil, nil, failure(connect.CodeInvalidArgument, "invalid page cursor")
			}
		}
	}
	limit := offset + min(size, len(items)-offset)
	end := offset
	for candidate := offset + 1; candidate <= limit; candidate++ {
		p := &v1.PageResponse{}
		if candidate < len(items) {
			p.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(binding + ":" + strconv.Itoa(candidate)))
		}
		message := pageMessage(any(items[offset:candidate]), p)
		if message == nil {
			end = candidate
			continue
		} // Intermediate history version IDs; checked after loading policies.
		b, err := protojson.Marshal(message)
		if err != nil {
			return nil, nil, failure(connect.CodeInternal, "list encoding failed")
		}
		if len(b) <= cfg.MessageBytes {
			end = candidate
		}
	}
	if offset < limit && end == offset {
		return nil, nil, failure(connect.CodeResourceExhausted, "list item exceeds message limit")
	}
	out := &v1.PageResponse{}
	if end < len(items) {
		out.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(binding + ":" + strconv.Itoa(end)))
	}
	return items[offset:end], out, nil
}

// Measure the actual wire envelope, including its continuation cursor. All
// public paged response types are listed here; no object is partially returned.
func pageMessage(items any, p *v1.PageResponse) proto.Message {
	switch v := items.(type) {
	case []*v1.Host:
		return &v1.ListHostsResponse{Hosts: v, Page: p}
	case []*v1.HostImportRow:
		return &v1.GetHostImportPreviewResponse{Rows: v, Page: p}
	case []*v1.JoinToken:
		return &v1.ListJoinTokensResponse{Tokens: v, Page: p}
	case []*v1.CatalogVersion:
		return &v1.ListCatalogsResponse{Catalogs: v, Page: p}
	case []*v1.ActionSummary:
		return &v1.ListActionsResponse{Actions: v, Page: p}
	case []*v1.CatalogDistribution:
		return &v1.GetCatalogDistributionResponse{Versions: v, Page: p}
	case []*v1.GatewayInstance:
		return &v1.ListGatewayInstancesResponse{Instances: v, Page: p}
	case []*v1.AgentVersionCount:
		return &v1.GetAgentVersionDistributionResponse{Versions: v, Page: p}
	case []*v1.ServiceAccount:
		return &v1.ListServiceAccountsResponse{Accounts: v, Page: p}
	case []*v1.ServiceAccountToken:
		return &v1.ListServiceAccountTokensResponse{Tokens: v, Page: p}
	case []*v1.User:
		return &v1.ListUsersResponse{Users: v, Page: p}
	case []*v1.Role:
		return &v1.ListRolesResponse{Roles: v, Page: p}
	case []*v1.CliSession:
		return &v1.ListCliSessionsResponse{Sessions: v, Page: p}
	case []*v1.PolicyChange:
		return &v1.GetPolicyTestChangesResponse{Changes: v, Page: p}
	case []*v1.PolicyVersion:
		return &v1.ListPolicyHistoryResponse{Policies: v, Page: p}
	default:
		return nil
	}
}

func snapshotHash(value any) ([]byte, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return hash(string(b)), nil
}
