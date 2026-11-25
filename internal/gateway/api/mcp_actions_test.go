package api

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
)

type cancelAfterHostQueryTracer struct {
	cancel context.CancelFunc
}

type cancelAfterHostKey struct{}

func (c *cancelAfterHostQueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "FROM hosts") {
		return context.WithValue(ctx, cancelAfterHostKey{}, true)
	}
	return ctx
}

func (c *cancelAfterHostQueryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	if ctx.Value(cancelAfterHostKey{}) != nil {
		c.cancel()
	}
}

func TestAllowedActionsOnHost(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, host := range []struct{ name, labels string }{
		{"prod-01", `{"env":"prod"}`},
		{"secret-01", `{"env":"secret"}`},
		{"bare-01", `{}`},
		{"deleted-01", `{"env":"prod"}`},
	} {
		if _, err := f.db.Pool.Exec(ctx, `INSERT INTO hosts(host_id,hostname,authorization_labels,certificate_serial,certificate_expires_at) VALUES ($1,$1,$2,'fixture',now()+interval '1 hour')`, host.name, host.labels); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.db.Pool.Exec(ctx, `UPDATE hosts SET certificate_status='deleted' WHERE hostname='deleted-01'`); err != nil {
		t.Fatal(err)
	}
	// The closed hours window never contains the current UTC hour.
	closed := &v1.PolicyHours{From: 12, To: 24, Timezone: "UTC"}
	if time.Now().UTC().Hour() >= 12 {
		closed = &v1.PolicyHours{From: 0, To: 12, Timezone: "UTC"}
	}
	allow, deny := v1.PolicyEffect_POLICY_EFFECT_ALLOW, v1.PolicyEffect_POLICY_EFFECT_DENY
	rules := defaultRules()
	rules.Rules = append(rules.Rules,
		&v1.PolicyRule{Name: "ops-view", Roles: []string{"ops"}, Operations: []string{"view_hosts"}, HostLabels: map[string]string{"env": "prod"}, Effect: allow},
		&v1.PolicyRule{Name: "ops-run", Roles: []string{"ops"}, Operations: []string{"execute_action"}, Risks: []string{"read", "write"}, HostLabels: map[string]string{"env": "prod"}, Effect: allow},
		&v1.PolicyRule{Name: "reload-approval", Roles: []string{"admin", "ops"}, Operations: []string{"execute_action"}, Actions: []string{"svc_reload"}, Effect: v1.PolicyEffect_POLICY_EFFECT_REQUIRE_APPROVAL, Approval: &v1.PolicyApprovalConfig{MinApprovals: 1}},
		&v1.PolicyRule{Name: "ops-no-restart", Roles: []string{"ops"}, Operations: []string{"execute_action"}, Actions: []string{"svc_restart"}, Effect: deny},
		&v1.PolicyRule{Name: "ops-office-ip", Roles: []string{"ops"}, Operations: []string{"execute_action"}, Actions: []string{"office_read"}, SourceCidrs: []string{"10.0.0.0/8"}, Effect: allow},
		&v1.PolicyRule{Name: "ops-always", Roles: []string{"ops"}, Operations: []string{"execute_action"}, Actions: []string{"anytime_purge"}, Hours: &v1.PolicyHours{From: 0, To: 24, Timezone: "UTC"}, Effect: allow},
		&v1.PolicyRule{Name: "ops-closed", Roles: []string{"ops"}, Operations: []string{"execute_action"}, Actions: []string{"night_purge"}, Hours: closed, Effect: allow},
	)
	raw, err := encode(rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(ctx, `INSERT INTO policy_versions(version,rules,created_by) VALUES (2,$1,'fixture')`, raw); err != nil {
		t.Fatal(err)
	}
	candidates := []authz.Action{
		{Name: "disk_usage", Risk: "read"},
		{Name: "svc_restart", Risk: "write"},
		{Name: "svc_reload", Risk: "write"},
		{Name: "data_purge", Risk: "dangerous"},
		{Name: "office_read", Risk: "dangerous"},
		{Name: "anytime_purge", Risk: "dangerous"},
		{Name: "night_purge", Risk: "dangerous"},
	}
	caller := func(role, ip string) (context.Context, *requestState) {
		state := &requestState{identity: &Identity{Subject: authz.Subject{ID: role, Roles: []string{role}}}, transportChecked: true, ip: ip, matchedRules: []string{"earlier"}}
		return reqctx.With(ctx, state), state
	}
	for _, tc := range []struct {
		name, role, ip, host string
		want                 map[string]string
	}{
		{"admin labeled host", "admin", "192.0.2.1", "prod-01", map[string]string{"disk_usage": "allow", "svc_restart": "allow", "svc_reload": "require_approval", "data_purge": "allow", "office_read": "allow", "anytime_purge": "allow", "night_purge": "allow"}},
		{"admin unlabeled host", "admin", "192.0.2.1", "bare-01", map[string]string{}},
		{"admin missing host", "admin", "192.0.2.1", "missing-01", map[string]string{}},
		{"admin deleted host", "admin", "192.0.2.1", "deleted-01", map[string]string{}},
		{"ops office address", "ops", "10.1.2.3", "prod-01", map[string]string{"disk_usage": "allow", "svc_reload": "require_approval", "office_read": "allow", "anytime_purge": "allow"}},
		{"ops other address", "ops", "192.0.2.1", "prod-01", map[string]string{"disk_usage": "allow", "svc_reload": "require_approval", "anytime_purge": "allow"}},
		{"ops hidden host", "ops", "10.1.2.3", "secret-01", map[string]string{}},
		{"ops unlabeled host", "ops", "10.1.2.3", "bare-01", map[string]string{}},
		{"viewer labeled host", "viewer", "10.1.2.3", "prod-01", map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, state := caller(tc.role, tc.ip)
			got, err := f.service.AllowedActionsOnHost(ctx, tc.host, candidates)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("allowed=%v error=%v want=%v", got, err, tc.want)
			}
			if !slices.Contains(state.matchedRules, "earlier") {
				t.Fatalf("matched rules replaced: %v", state.matchedRules)
			}
		})
	}
	ctx, state := caller("ops", "10.1.2.3")
	if _, err := f.service.AllowedActionsOnHost(ctx, "prod-01", candidates); err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{"earlier", "ops-view", "ops-run", "reload-approval", "ops-no-restart", "ops-office-ip", "ops-always"} {
		if !slices.Contains(state.matchedRules, rule) {
			t.Fatalf("matched rules=%v missing %s", state.matchedRules, rule)
		}
	}
	if state.policyVersion != 2 {
		t.Fatalf("policy version=%d", state.policyVersion)
	}
	if _, err := f.service.AllowedActionsOnHost(context.Background(), "prod-01", candidates); err == nil {
		t.Fatal("unauthenticated precheck succeeded")
	}
	// A cancellation occurring AFTER the host query succeeds (during ViewHosts
	// OPA evaluation) must propagate an error instead of returning an empty allow set.
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cfg := f.db.Pool.Config()
	cfg.ConnConfig.Tracer = &cancelAfterHostQueryTracer{cancel: cancel}
	tracedPool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tracedPool.Close)
	origStore := f.service.Store
	f.service.Store = &store.Store{Pool: tracedPool, Queries: db.New(tracedPool)}
	defer func() { f.service.Store = origStore }()
	if _, err := f.service.AllowedActionsOnHost(cancelCtx, "prod-01", candidates); err == nil {
		t.Fatal("post-host-query cancellation during ViewHosts evaluation succeeded")
	}
}
