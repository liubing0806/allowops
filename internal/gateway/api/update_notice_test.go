package api

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
)

func storeUpdateCheck(t *testing.T, f *fixture, latest string, errText string) {
	t.Helper()
	if _, err := f.db.Pool.Exec(context.Background(), "INSERT INTO gateway_update_check(id,latest_version,published_at,checked_at,last_error) VALUES (true,$1,'2026-10-20T08:00:00Z','2026-10-22T08:00:00Z',$2) ON CONFLICT (id) DO UPDATE SET latest_version=EXCLUDED.latest_version,published_at=EXCLUDED.published_at,checked_at=EXCLUDED.checked_at,last_error=EXCLUDED.last_error", latest, errText); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayUpdateInCurrentSession(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	session := func() *v1.GetCurrentSessionResponse {
		r, err := f.auth(f.viewerToken).GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg
	}
	f.service.Config.Version = "0.4.0"
	f.service.Config.UpdateCheckEnabled = true
	if session().GatewayUpdate != nil {
		t.Fatal("update reported before the first check")
	}
	storeUpdateCheck(t, f, "0.5.0", "")
	u := session().GatewayUpdate
	if u == nil || u.LatestVersion != "0.5.0" || u.PublishedAt.AsTime().Format(time.RFC3339) != "2026-10-20T08:00:00Z" || u.CheckedAt.AsTime().Format(time.RFC3339) != "2026-10-22T08:00:00Z" {
		t.Fatalf("update %v", u)
	}
	for _, latest := range []string{"0.4.0", "0.3.9", ""} {
		storeUpdateCheck(t, f, latest, "")
		if session().GatewayUpdate != nil {
			t.Fatalf("latest %q is not newer than 0.4.0", latest)
		}
	}
	storeUpdateCheck(t, f, "0.5.0", "request failed")
	if session().GatewayUpdate == nil {
		t.Fatal("previous latest version must stay visible after a failed check")
	}
	f.service.Config.UpdateCheckEnabled = false
	if session().GatewayUpdate != nil {
		t.Fatal("update reported while the check is disabled")
	}
	f.service.Config.UpdateCheckEnabled = true
	f.service.Config.Version = ""
	if r := session(); r.GatewayVersion != "dev" || r.GatewayUpdate != nil {
		t.Fatal("dev builds must not get an update")
	}
	f.service.Config.Version = "0.6.0-rc.1"
	storeUpdateCheck(t, f, "0.6.0", "")
	if session().GatewayUpdate == nil {
		t.Fatal("release must be newer than its prerelease")
	}
}

func TestSystemStatusUpdateFields(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for name, version := range map[string]string{"old": "0.0.9", "older": "0.0.1", "same": "0.1.0", "newer": "0.2.0", "garbage": "banana", "unreported": ""} {
		id := addHost(t, f, name)
		if _, err := f.db.Pool.Exec(ctx, "UPDATE hosts SET agent_version=$1 WHERE host_id=$2", version, id); err != nil {
			t.Fatal(err)
		}
	}
	admin := rpc.NewSystemServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(f.adminToken)))
	status := func() *v1.GetSystemStatusResponse {
		r, err := admin.GetSystemStatus(ctx, connect.NewRequest(&v1.GetSystemStatusRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg
	}
	f.service.Config.Version = "0.4.0"
	r := status()
	if r.UpdateCheckEnabled || r.GatewayVersion != "0.4.0" || r.GatewayUpdate != nil || r.UpdateCheckedAt != nil || r.UpdateCheckError != "" {
		t.Fatalf("disabled: %v", r)
	}
	if r.HostsBelowGatewayVersion != 2 {
		t.Fatalf("hosts below gateway version=%d, want 2", r.HostsBelowGatewayVersion)
	}
	f.service.Config.UpdateCheckEnabled = true
	if r = status(); !r.UpdateCheckEnabled || r.GatewayUpdate != nil || r.UpdateCheckedAt != nil {
		t.Fatalf("not checked yet: %v", r)
	}
	storeUpdateCheck(t, f, "0.5.0", "request failed")
	r = status()
	if r.GatewayUpdate.GetLatestVersion() != "0.5.0" || r.UpdateCheckedAt.AsTime().Format(time.RFC3339) != "2026-10-22T08:00:00Z" || r.UpdateCheckError != "request failed" {
		t.Fatalf("checked: %v", r)
	}
	f.service.Config.Version = ""
	if r = status(); r.GatewayVersion != "dev" || r.GatewayUpdate != nil || r.UpdateCheckError != "request failed" {
		t.Fatalf("dev build: %v", r)
	}
	// A view_system-only subject has no host permission, so it counts no hosts.
	rules := defaultRules()
	rules.Rules = append(rules.Rules, &v1.PolicyRule{Name: "system-only", Roles: []string{"system-only"}, Operations: []string{"view_system"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW})
	b, err := encode(rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Pool.Exec(ctx, "INSERT INTO policy_versions(version,rules,created_by,reason) VALUES (2,$1,'fixture','fixture')", b); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Pool.Exec(ctx, "DELETE FROM role_mappings WHERE group_name='readers'"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Pool.Exec(ctx, "UPDATE console_users SET manual_roles=ARRAY['system-only'] WHERE user_id=$1", f.viewer.UserId); err != nil {
		t.Fatal(err)
	}
	viewer := rpc.NewSystemServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(f.viewerToken)))
	v, err := viewer.GetSystemStatus(ctx, connect.NewRequest(&v1.GetSystemStatusRequest{}))
	if err != nil || v.Msg.HostsBelowGatewayVersion != 0 {
		t.Fatal("host count exposed unauthorized hosts", err)
	}
}
