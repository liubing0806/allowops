package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/audit"
)

type committedFaultKey struct{}
type tracedSQLKey struct{}
type committedFault struct {
	mode           string
	cancel         context.CancelFunc
	policyInserted bool
}
type committedCancelTracer struct{ observed chan string }

func (tr committedCancelTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, tracedSQLKey{}, data.SQL)
}
func (tr committedCancelTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	f, _ := ctx.Value(committedFaultKey{}).(*committedFault)
	if f == nil || data.Err != nil {
		return
	}
	sql, _ := ctx.Value(tracedSQLKey{}).(string)
	cancel := false
	switch f.mode {
	case "roles":
		cancel = strings.HasPrefix(sql, "UPDATE console_users SET manual_roles=") && data.CommandTag.RowsAffected() == 1
	case "join":
		cancel = strings.HasPrefix(sql, "INSERT INTO join_tokens(") && data.CommandTag.RowsAffected() == 1
	case "policy":
		if strings.HasPrefix(sql, "INSERT INTO policy_versions(") {
			f.policyInserted = true
		}
		cancel = sql == "commit" && f.policyInserted && data.CommandTag.String() == "COMMIT"
	}
	if cancel {
		f.mode = ""
		f.cancel()
		tr.observed <- sql
	}
}
func committedFaultFixture(t *testing.T) (*fixture, <-chan string) {
	t.Helper()
	f := newFixture(t, func(_ *Service, h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			ctx = context.WithValue(ctx, committedFaultKey{}, &committedFault{mode: r.Header.Get("X-Test-Cancel-After-Commit"), cancel: cancel})
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	observed := make(chan string, 1)
	original := f.db.Pool
	cfg := original.Config()
	cfg.ConnConfig.Tracer = committedCancelTracer{observed: observed}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.db.Pool = pool
	t.Cleanup(original.Close)
	f.service.Audit = NewAuditor(audit.New(pool, audit.Config{}))
	return f, observed
}
func TestCommittedUserRolesAuditTargetSurvivesReloadCancellation(t *testing.T) {
	f, observed := committedFaultFixture(t)
	ctx := context.Background()
	request := connect.NewRequest(&v1.SetUserRolesRequest{UserId: f.viewer.UserId, ExpectedRevision: f.viewer.Revision, ManualRoles: []string{"operator"}})
	request.Header().Set("X-Test-Cancel-After-Commit", "roles")
	_, err := f.users().SetUserRoles(ctx, request)
	code(t, err, connect.CodeUnavailable)
	select {
	case <-observed:
	default:
		t.Fatal("fixture did not cancel after successful PostgreSQL UPDATE")
	}
	var committed bool
	if err = f.db.Pool.QueryRow(ctx, `SELECT revision=2 AND manual_roles=ARRAY['operator'] FROM console_users WHERE user_id=$1`, f.viewer.UserId).Scan(&committed); err != nil {
		t.Fatal(err)
	}
	if !committed {
		t.Fatal("roles update did not actually commit")
	}
	requireTarget(t, persistedTargets(t, f, rpc.UserServiceSetUserRolesProcedure, "deny"), "user", f.viewer.UserId)
	// A revision conflict must not be represented as another committed target.
	_, err = f.users().SetUserRoles(ctx, connect.NewRequest(&v1.SetUserRolesRequest{UserId: f.viewer.UserId, ExpectedRevision: "1", ManualRoles: []string{"admin"}}))
	code(t, err, connect.CodeAborted)
	events := persistedTargets(t, f, rpc.UserServiceSetUserRolesProcedure, "deny")
	if len(events) != 2 || events[1].Resource != "" {
		t.Fatalf("uncommitted revision failure targets=%v; want empty final resource", events)
	}
}
func TestCommittedPolicyAuditTargetSurvivesRefreshCancellation(t *testing.T) {
	f, observed := committedFaultFixture(t)
	ctx := context.Background()
	p := f.policy(f.adminToken)
	tested, err := p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: defaultRules()}}))
	if err != nil {
		t.Fatal(err)
	}
	request := connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: defaultRules(), TestId: tested.Msg.Test.TestId})
	request.Header().Set("X-Test-Cancel-After-Commit", "policy")
	_, err = p.SavePolicy(ctx, request)
	code(t, err, connect.CodeUnavailable)
	select {
	case <-observed:
	default:
		t.Fatal("fixture did not cancel after PostgreSQL COMMIT")
	}
	var version uint64
	var consumed bool
	if err = f.db.Pool.QueryRow(ctx, `SELECT (SELECT max(version) FROM policy_versions),(SELECT consumed FROM policy_tests WHERE test_id=$1)`, tested.Msg.Test.TestId).Scan(&version, &consumed); err != nil {
		t.Fatal(err)
	}
	if version != 2 || !consumed {
		t.Fatalf("persisted version=%d consumed=%t; want 2,true", version, consumed)
	}
	requireTarget(t, persistedTargets(t, f, rpc.PolicyServiceSavePolicyProcedure, "deny"), "policy_version", "2")
	_, err = p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 2, Rules: defaultRules(), TestId: "missing-test"}))
	code(t, err, connect.CodeAborted)
	events := persistedTargets(t, f, rpc.PolicyServiceSavePolicyProcedure, "deny")
	if len(events) != 2 || events[1].Resource != "" {
		t.Fatalf("uncommitted policy failure targets=%v; want empty final resource", events)
	}
}
func TestCommittedJoinTokenAuditTargetSurvivesReloadCancellation(t *testing.T) {
	f, observed := committedFaultFixture(t)
	ctx := context.Background()
	f.service.management.config.CAPin = "sha256:" + strings.Repeat("0", 64)
	request := connect.NewRequest(&v1.CreateJoinTokenRequest{MaxUses: 1})
	request.Header().Set("X-Test-Cancel-After-Commit", "join")
	_, err := joinClient(f, f.adminToken).CreateJoinToken(ctx, request)
	code(t, err, connect.CodeUnavailable)
	select {
	case <-observed:
	default:
		t.Fatal("fixture did not cancel after successful PostgreSQL INSERT")
	}
	var id string
	if err = f.db.Pool.QueryRow(ctx, `SELECT token_id FROM join_tokens`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	requireTarget(t, persistedTargets(t, f, rpc.JoinTokenServiceCreateJoinTokenProcedure, "deny"), "join_token", id)
}
