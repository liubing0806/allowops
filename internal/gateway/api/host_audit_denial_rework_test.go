package api

import (
	"context"
	"fmt"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/audit"
)

func TestSetHostLabelsUnauthorisedLargeSelectorHasNoAuditTargets(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.service.Audit = NewAuditor(audit.New(f.db.Pool, audit.Config{}))
	const count = 5000
	if _, err := f.db.Pool.Exec(ctx, `INSERT INTO hosts(host_id,hostname,authorization_labels,certificate_serial,certificate_expires_at) SELECT 'id-'||lpad(n::text,40,'0'),'host-'||lpad(n::text,4,'0'),jsonb_build_object('env','prod','scope',CASE WHEN n=1 THEN 'allowed' ELSE 'denied' END),'fixture',now()+interval '1 hour' FROM generate_series(1,$1::int) n`, count); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(ctx, `UPDATE console_users SET manual_roles=ARRAY['limited'] WHERE user_id=$1`, f.viewer.UserId); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(ctx, `DELETE FROM role_mappings WHERE group_name='readers'`); err != nil {
		t.Fatal(err)
	}
	rules := defaultRules()
	rules.Rules = append(rules.Rules, &v1.PolicyRule{Name: "one-host-only", Roles: []string{"limited"}, Operations: []string{"manage_hosts"}, HostLabels: map[string]string{"scope": "allowed"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW})
	raw, err := encode(rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Pool.Exec(ctx, `INSERT INTO policy_versions(version,rules,created_by) VALUES (2,$1,'fixture')`, raw); err != nil {
		t.Fatal(err)
	}
	revisions := make([]*v1.HostRevision, count)
	for i := range revisions {
		revisions[i] = &v1.HostRevision{HostId: fmt.Sprintf("id-%040d", i+1), Revision: "1"}
	}
	client := hostClient(f, f.viewerToken)
	for _, tc := range []struct {
		name     string
		expected uint64
		code     connect.Code
	}{
		{name: "count_mismatch_before_authorisation", expected: count - 1, code: connect.CodeAborted},
		{name: "second_target_denied_after_first_allowed", expected: count, code: connect.CodePermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var before uint64
			if err := f.db.Pool.QueryRow(ctx, `SELECT coalesce(max(seq),0) FROM audit_events`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			_, err := client.SetHostLabels(ctx, connect.NewRequest(&v1.SetHostLabelsRequest{Targets: &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "env=prod"}}, ExpectedCount: tc.expected, ExpectedRevisions: revisions, Changes: &v1.LabelChanges{Set: map[string]string{"owner": "must-not-write"}}}))
			code(t, err, tc.code)
			var results, targets, authorised, changed int
			if err := f.db.Pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE reason='result' AND decision='deny'),count(*) FILTER(WHERE resource<>''),count(*) FILTER(WHERE reason='authorized') FROM audit_events WHERE seq>$1 AND operation=$2`, before, rpc.HostServiceSetHostLabelsProcedure).Scan(&results, &targets, &authorised); err != nil {
				t.Fatal(err)
			}
			if results != 1 || targets != 0 || authorised != 0 {
				t.Errorf("denied audit: result events=%d target-bearing events=%d authorised events=%d; want 1,0,0", results, targets, authorised)
			}
			if err := f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM hosts WHERE revision<>1 OR authorization_labels ? 'owner'`).Scan(&changed); err != nil {
				t.Fatal(err)
			}
			if changed != 0 {
				t.Errorf("denied operation changed hosts=%d; want 0", changed)
			}
		})
	}
}
