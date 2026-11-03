package api

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestVisibleHostnames(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, name := range []string{"allowed", "denied", "deleted"} {
		if _, err := f.db.Pool.Exec(ctx, `INSERT INTO hosts(host_id,hostname,authorization_labels,certificate_serial,certificate_expires_at) VALUES ($1,$1,jsonb_build_object('scope',$1::text),'fixture',now()+interval '1 hour')`, name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.db.Pool.Exec(ctx, `UPDATE hosts SET certificate_status='deleted' WHERE hostname='deleted'`); err != nil {
		t.Fatal(err)
	}
	engine, err := authz.New(ctx, viewRuleSource{{ID: "visible", Effect: "allow", Roles: []string{"viewer"}, Operations: []authz.Operation{authz.ViewHosts}, HostLabels: map[string]string{"scope": "allowed"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx = reqctx.With(ctx, &requestState{identity: &Identity{Subject: authz.Subject{ID: "viewer", Roles: []string{"viewer"}}}, transportChecked: true})
	ctx = context.WithValue(ctx, pinnedPolicyKey{}, &policyState{engine: engine, version: 1})
	for _, test := range []struct {
		names []string
		want  map[string]bool
	}{
		{[]string{"allowed", "denied", "deleted", "missing"}, map[string]bool{"allowed": true}},
		{[]string{"denied", "missing"}, map[string]bool{}}, {nil, map[string]bool{}},
	} {
		got, err := f.service.VisibleHostnames(ctx, test.names)
		if err != nil || !reflect.DeepEqual(got, test.want) {
			t.Fatalf("visible=%v error=%v want=%v", got, err, test.want)
		}
	}
}

func TestPluginSystemHealth(t *testing.T) {
	f := newFixture(t, func(s *Service, h http.Handler) http.Handler {
		s.ConfigurePluginHealth(func() []pluginhost.Health {
			return []pluginhost.Health{{ID: "ready", Module: "inventory.static", OK: true}, {ID: "failed", Module: "inventory.static"}}
		})
		s.ConfigureJobDependencies(statisticsFixture{}, storageHealthFixture{})
		return h
	})
	client := rpc.NewSystemServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(f.adminToken)))
	response, err := client.GetSystemStatus(context.Background(), connect.NewRequest(&v1.GetSystemStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	deps := response.Msg.Dependencies
	if len(deps) != 5 || deps[3].Name != "plugin:ready" || deps[3].Status != v1.HealthStatus_HEALTH_STATUS_HEALTHY || deps[4].Name != "plugin:failed" || deps[4].Status != v1.HealthStatus_HEALTH_STATUS_UNAVAILABLE || deps[4].Reason != "provision failed" || response.Msg.Status != v1.HealthStatus_HEALTH_STATUS_DEGRADED {
		t.Fatal(response.Msg)
	}
}

func TestExistingPolicyDoesNotGainInventoryAccess(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	old := defaultRules()
	for _, r := range old.Rules {
		var ops []string
		for _, op := range r.Operations {
			if op != "view_inventory" {
				ops = append(ops, op)
			}
		}
		r.Operations = ops
	}
	raw, err := protojson.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(ctx, `UPDATE policy_versions SET rules=$1 WHERE version=1`, raw); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(ctx, f.db, f.service.Config, f.audit)
	if err != nil {
		t.Fatal(err)
	}
	ctx = reqctx.With(ctx, &requestState{identity: &Identity{Subject: authz.Subject{ID: "viewer", Roles: []string{"viewer"}}}, transportChecked: true})
	if _, err := restarted.Require(ctx, authz.ViewInventory, authz.Action{}, authz.Host{}); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("existing viewer inventory: %v", err)
	}
	_, rules, err := restarted.PolicySnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		for _, op := range r.Operations {
			if op == authz.ViewInventory {
				t.Fatal("existing policy modified")
			}
		}
	}
}
