package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
	"github.com/liubing0806/allowops/internal/testpg"
)

// queryLog records every statement sent through a pool, so tests can assert
// how many reads of a table a request performs.
type queryLog struct {
	mu  sync.Mutex
	sql []string
}

func (l *queryLog) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	l.mu.Lock()
	l.sql = append(l.sql, data.SQL)
	l.mu.Unlock()
	return ctx
}
func (l *queryLog) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// count returns how many recorded statements contain every given fragment.
func (l *queryLog) count(fragments ...string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, q := range l.sql {
		match := true
		for _, f := range fragments {
			match = match && strings.Contains(q, f)
		}
		if match {
			n++
		}
	}
	return n
}

type poolOptions struct {
	maxConns  int32
	realAudit bool
	queries   *queryLog
}

// poolFixture is newFixture with a bounded pool, an optional statement log and
// an optional real audit store on the same pool.
func poolFixture(t *testing.T, o poolOptions) *fixture {
	t.Helper()
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if o.maxConns > 0 {
		cfg.MaxConns = o.maxConns
	}
	if o.queries != nil {
		cfg.ConnConfig.Tracer = o.queries
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	database := &store.Store{Pool: pool, Queries: db.New(pool)}
	t.Cleanup(database.Close)
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	fx := &auditFixture{}
	var auditor Auditor = fx
	if o.realAudit {
		auditor = NewAuditor(audit.New(pool, audit.Config{}))
	}
	s, err := New(ctx, database, Config{Origin: origin, RoleMappings: []RoleMappingConfig{{ProviderID: "test", Group: "ops", Roles: []string{"admin"}}, {ProviderID: "test", Group: "readers", Roles: []string{"viewer"}}}}, auditor)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = s.Handler()
	server.StartTLS()
	t.Cleanup(server.Close)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	admin, err := s.syncUser(ctx, "test", authn.Identity{ID: "admin", Kind: "oidc", Email: "admin@example.org", Groups: []string{"ops"}})
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := s.syncUser(ctx, "test", authn.Identity{ID: "viewer", Kind: "oidc", Groups: []string{"readers"}})
	if err != nil {
		t.Fatal(err)
	}
	_, at, err := s.issueSession(ctx, pool, admin.UserId, v1.LoginClient_LOGIN_CLIENT_CLI)
	if err != nil {
		t.Fatal(err)
	}
	_, vt, err := s.issueSession(ctx, pool, viewer.UserId, v1.LoginClient_LOGIN_CLIENT_CLI)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{s, database, server, fx, admin, viewer, at, vt}
}

// listHostsOnce issues one ListHosts request as the given caller.
func listHostsOnce(f *fixture, token, hostname string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := hostClient(f, token).ListHosts(ctx, connect.NewRequest(&v1.ListHostsRequest{Query: &v1.HostQuery{Hostname: hostname}}))
	return err
}
