package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/testseaweedfs"
)

func TestSDKConditionalDenyDiscoveryAndRealP6Call(t *testing.T) {
	f := newTransportFixture(t)
	ctx := context.Background()
	router, err := hostconn.New(f.db, nil, hostconn.DefaultConfig(), hostconn.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err = router.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(router.Close)
	objects := testseaweedfs.Start(t)
	jobs, err := job.New(f.db, f.identity, router, objects, audit.New(f.db.Pool, audit.Config{}), f.catalogs.Trusted, job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jobs.Close)
	f.service.jobs = jobs
	c, _ := f.client(t, f.viewer, nil)
	policy, err := f.identity.GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	base := policy.Msg.Policy.Rules
	// Put the inactive hour twelve hours ahead. It remains inactive across an
	// hour boundary throughout this bounded test; active hours cover the full day.
	inactive := uint32((time.Now().UTC().Hour() + 12) % 24)
	for i, tc := range []struct {
		name           string
		cidrs          []string
		hours          *v1.PolicyHours
		labels         map[string]string
		active, hidden bool
	}{
		{name: "inactive_ip", cidrs: []string{"192.0.2.0/24"}},
		{name: "active_ip", cidrs: []string{"127.0.0.0/8", "::1/128"}, active: true},
		{name: "inactive_hours", hours: &v1.PolicyHours{From: inactive, To: inactive + 1, Timezone: "UTC"}},
		{name: "active_hours", hours: &v1.PolicyHours{From: 0, To: 24, Timezone: "UTC"}, active: true},
		{name: "inactive_host", labels: map[string]string{"env": "prod"}},
		{name: "unconditional", active: true, hidden: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := &v1.PolicyRules{Rules: append(append([]*v1.PolicyRule{}, base.Rules...),
				&v1.PolicyRule{Name: "viewer-allow", Roles: []string{"viewer"}, Operations: []string{"execute_action"}, Actions: []string{"logs_read"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW},
				&v1.PolicyRule{Name: "viewer-deny", Roles: []string{"viewer"}, Operations: []string{"execute_action"}, Actions: []string{"logs_read"}, SourceCidrs: tc.cidrs, Hours: tc.hours, HostLabels: tc.labels, Effect: v1.PolicyEffect_POLICY_EFFECT_DENY})}
			raw, err := json.Marshal(rules)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.db.Pool.Exec(ctx, `INSERT INTO policy_versions(version,rules,created_by) VALUES ($1,$2,'fixture')`, i+2, raw); err != nil {
				t.Fatal(err)
			}
			listed, err := c.ListTools(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, tool := range listed.Tools {
				if tool.Name == "logs_read" {
					found = true
				}
			}
			if found == tc.hidden {
				t.Errorf("logs_read discoverable=%t; want %t", found, !tc.hidden)
			}
			var tasksBefore, tasksAfter, authorized int
			if err = f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM tasks`).Scan(&tasksBefore); err != nil {
				t.Fatal(err)
			}
			result := call(t, c, "logs_read", actionArgs())
			data := content(t, result)
			if !tc.active {
				if result.IsError || data["job_id"] == nil {
					t.Errorf("inactive deny blocked real tools/call: %v", data)
				}
				if err = f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM tasks`).Scan(&tasksAfter); err != nil {
					t.Fatal(err)
				}
				if tasksAfter != tasksBefore+1 {
					t.Errorf("real P6 task count=%d; want %d", tasksAfter, tasksBefore+1)
				}
			} else {
				if !result.IsError {
					t.Fatalf("active deny allowed tools/call: %v", data)
				}
				if err = f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM tasks`).Scan(&tasksAfter); err != nil {
					t.Fatal(err)
				}
				if tasksAfter != tasksBefore {
					t.Errorf("deny created tasks: before=%d after=%d", tasksBefore, tasksAfter)
				}
				if !tc.hidden {
					if data["reason"] != "JOB_DENIED" {
						t.Errorf("active condition did not reach full P6 ABAC: %v", data)
					}
					if err = f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE operation='run_job' AND reason='authorized' AND decision='deny' AND policy_version=$1`, i+2).Scan(&authorized); err != nil {
						t.Fatal(err)
					}
					if authorized != 1 {
						t.Errorf("P6 deny authorized audits=%d; want 1", authorized)
					}
				}
			}
		})
	}
}
