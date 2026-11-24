package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func populateResources(t *testing.T, f *fixture) {
	t.Helper()
	ctx := context.Background()
	join, err := f.db.CreateJoinToken(ctx, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.db.Register(ctx, join, "host-a", func(string) (string, time.Time, error) { return "fixture-serial", time.Now().Add(time.Hour), nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(ctx, "UPDATE hosts SET authorization_labels=$2 WHERE host_id=$1", id, `{"env":"test"}`); err != nil {
		t.Fatal(err)
	}
	publishPolicyTestCatalog(t, f, []string{"restart"})
}

func publishPolicyTestCatalog(t *testing.T, f *fixture, names []string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actions := make(map[string]catalog.Action, len(names))
	for _, name := range names {
		actions[name] = catalog.Action{Name: name, Description: "fixture", Risk: "dangerous", Exec: []any{"/usr/bin/true"}, Timeout: "1s", MaxOutput: 1024}
	}
	p, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: "test"}, Actions: actions}, catalog.BuildOptions{Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := catalog.CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := catalog.Sign(raw, catalog.SigningKey{PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Publish(context.Background(), db.InsertCatalogParams{CatalogID: "test", Version: int64(p.Version), Dsse: raw, Digest: hash(string(raw)), ExpiresAt: store.Timestamp(time.Now().Add(time.Hour)), ActionNames: names}); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyTrialAndSaveWithManyHostsSharingLabels(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const hostCount, actionCount = 200, 90
	if _, err := f.db.Pool.Exec(ctx, `INSERT INTO hosts(host_id,hostname,authorization_labels,certificate_serial,certificate_expires_at)
		SELECT name,name,CASE WHEN n=$1 THEN '{}'::jsonb WHEN n%2=1 THEN '{"env":"prod"}'::jsonb ELSE '{"env":"dev"}'::jsonb END,name,now()+interval '1 hour'
		FROM generate_series(1,$1::int) AS n CROSS JOIN LATERAL (SELECT 'host-'||lpad(n::text,3,'0') AS name) AS h`, hostCount); err != nil {
		t.Fatal(err)
	}
	names := make([]string, actionCount)
	for i := range names {
		names[i] = fmt.Sprintf("action_%02d", i)
	}
	publishPolicyTestCatalog(t, f, names)
	rules := defaultRules()
	rules.Rules = append(rules.Rules, &v1.PolicyRule{
		Name: "viewer-prod-action", Roles: []string{"viewer"}, Operations: []string{"execute_action"},
		Actions: names[:1], HostLabels: map[string]string{"env": "prod"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW,
	})
	p := f.policy(f.adminToken)
	tested, err := p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: rules}}))
	if err != nil {
		t.Fatal(err)
	}
	const evaluated = 2 * (12 + 2*hostCount + 3*actionCount + 3*actionCount*hostCount)
	if tested.Msg.Test.EvaluatedCount != evaluated || tested.Msg.Test.ChangedCount != hostCount/2 {
		t.Fatalf("trial=%v; want evaluated=%d changed=%d", tested.Msg.Test, evaluated, hostCount/2)
	}
	seen := map[string]bool{}
	var diagnostics int
	var previousIndex uint32
	page := &v1.PageRequest{}
	for {
		changes, err := p.GetPolicyTestChanges(ctx, connect.NewRequest(&v1.GetPolicyTestChangesRequest{TestId: tested.Msg.Test.TestId, Page: page}))
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range changes.Msg.Changes {
			if change.CaseIndex <= previousIndex {
				t.Fatalf("case indices out of order: %d after %d", change.CaseIndex, previousIndex)
			}
			previousIndex = change.CaseIndex
			if change.Host == "host-200" {
				if change.Before.ErrorReason != "HOST_UNLABELED" || change.After.ErrorReason != "HOST_UNLABELED" ||
					change.Before.Effect != v1.PolicyEffect_POLICY_EFFECT_DENY || change.After.Effect != v1.PolicyEffect_POLICY_EFFECT_DENY {
					t.Fatalf("unlabeled host diagnostic=%v", change)
				}
				diagnostics++
				continue
			}
			if seen[change.Host] || change.Before.Effect != v1.PolicyEffect_POLICY_EFFECT_DENY || change.After.Effect != v1.PolicyEffect_POLICY_EFFECT_ALLOW {
				t.Fatalf("unexpected host change=%v", change)
			}
			seen[change.Host] = true
		}
		page.PageToken = changes.Msg.GetPage().GetNextPageToken()
		if page.PageToken == "" {
			break
		}
	}
	for n := 1; n < hostCount; n++ {
		name := fmt.Sprintf("host-%03d", n)
		if seen[name] != (n%2 == 1) {
			t.Errorf("changed hosts contain %s: %t", name, seen[name])
		}
	}
	if len(seen) != hostCount/2 || diagnostics != 2*actionCount {
		t.Errorf("changed hosts=%d diagnostics=%d; want %d and %d", len(seen), diagnostics, hostCount/2, 2*actionCount)
	}
	// Three label sets (prod, dev and empty), including the global empty target
	// in host permissions and per-action job/output checks.
	const groupedEvaluations = 2 * (12 + 2*2 + actionCount + 3*actionCount*3)
	f.service.Config.MaxTestEvaluations = groupedEvaluations
	saved, err := p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: rules, TestId: tested.Msg.Test.TestId}))
	if err != nil || saved.Msg.Policy.Version != 2 {
		t.Fatalf("save=%v error=%v; want version 2", saved, err)
	}
}

func TestSavePolicyWithExplicitHostTargets(t *testing.T) {
	f := newFixture(t)
	populateResources(t, f)
	ctx := context.Background()
	p := f.policy(f.adminToken)
	rules := defaultRules()
	now := time.Now().UTC()
	hour := (now.Hour() + 2) % 24
	at := time.Date(now.Year(), now.Month(), now.Day(), hour, 30, 0, 0, time.UTC)
	rules.Rules = append(rules.Rules, &v1.PolicyRule{
		Name: "viewer-window", Roles: []string{"viewer"}, Operations: []string{"execute_action"},
		Hours:       &v1.PolicyHours{From: uint32(hour), To: uint32(hour + 1), Timezone: "UTC"},
		SourceCidrs: []string{"192.0.2.0/24"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW,
	})
	tested, err := p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{
		BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: rules},
		Cases: []*v1.PolicyTestCase{
			{SubjectId: f.viewer.UserId, Operation: "execute_action", Action: "restart", Targets: hostNames("host-a"), At: timestamppb.New(at), SourceIp: "192.0.2.1"},
			{SubjectId: f.viewer.UserId, Operation: "view_jobs", Action: "restart", Targets: &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "env=test"}}},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if tested.Msg.Test.EvaluatedCount != 2 || tested.Msg.Test.ChangedCount != 1 {
		t.Fatalf("explicit trial=%v; want evaluated=2 changed=1", tested.Msg.Test)
	}
	// Simulate a different trial hour. The explicit timestamp must still apply
	// in both environments when saving.
	if _, err := f.db.Pool.Exec(ctx, "UPDATE policy_tests SET environment=jsonb_set(environment,'{time_ns}',to_jsonb($2::bigint)) WHERE test_id=$1", tested.Msg.Test.TestId, at.UnixNano()); err != nil {
		t.Fatal(err)
	}
	// Revalidation must use the two saved cases instead of the default matrix.
	f.service.Config.MaxTestEvaluations = 2
	saved, err := p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: rules, TestId: tested.Msg.Test.TestId}))
	if err != nil || saved.Msg.Policy.Version != 2 {
		t.Fatalf("save=%v error=%v; want version 2", saved, err)
	}
}

func TestPolicyHistoryRespectsWireBudgetAndRealCursor(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := f.policy(f.adminToken)
	current, err := p.GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for n := 2; n <= 4; n++ {
		if _, err := f.db.Pool.Exec(ctx, "INSERT INTO policy_versions(version,rules,created_by,reason) SELECT $1,rules,'fixture','fixture' FROM policy_versions WHERE version=1", n); err != nil {
			t.Fatal(err)
		}
	}
	one, _ := protojson.Marshal(&v1.ListPolicyHistoryResponse{Policies: []*v1.PolicyVersion{current.Msg.Policy}, Page: &v1.PageResponse{NextPageToken: strings.Repeat("x", 128)}})
	f.service.refreshMu.Lock()
	f.service.Config.MessageBytes = len(one)
	f.service.refreshMu.Unlock()
	cursor := ""
	seen := []uint64{}
	for {
		response, err := p.ListPolicyHistory(ctx, connect.NewRequest(&v1.ListPolicyHistoryRequest{Page: &v1.PageRequest{PageToken: cursor}}))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := protojson.Marshal(response.Msg)
		if len(b) > len(one) {
			t.Fatalf("history bytes=%d limit=%d", len(b), len(one))
		}
		if len(response.Msg.Policies) != 1 {
			t.Fatalf("history page items=%d; want 1", len(response.Msg.Policies))
		}
		seen = append(seen, response.Msg.Policies[0].Version)
		cursor = response.Msg.Page.NextPageToken
		if cursor == "" {
			break
		}
		if len(seen) > 4 {
			t.Fatal("history cursor failed to advance")
		}
	}
	if !reflect.DeepEqual(seen, []uint64{4, 3, 2, 1}) {
		t.Fatalf("history versions=%v", seen)
	}
}

func TestExistingHostsSimulationAndActionAuthorization(t *testing.T) {
	f := newFixture(t)
	populateResources(t, f)
	ctx := context.Background()
	p := f.policy(f.adminToken)
	// Exercise the same HTTP authentication and Require boundary P4B/MCP use.
	endpoint := httptest.NewTLSServer(f.service.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := f.service.Require(r.Context(), authz.ExecuteAction, authz.Action{Name: "restart", Risk: "dangerous"}, authz.Host{ID: "host-a", Labels: map[string]string{"env": "test"}})
		if err != nil {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})))
	defer endpoint.Close()
	for _, tt := range []struct {
		token  string
		status int
	}{{f.adminToken, 200}, {f.viewerToken, 403}} {
		r, _ := http.NewRequest("POST", endpoint.URL, nil)
		r.Header.Set("Authorization", "Bearer "+tt.token)
		response, err := endpoint.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tt.status {
			t.Fatalf("dangerous authorization=%d; want %d", response.StatusCode, tt.status)
		}
	}
	rules := defaultRules()
	rules.Rules = append(rules.Rules, &v1.PolicyRule{Name: "viewer-exec", Roles: []string{"viewer"}, Operations: []string{string(authz.ExecuteAction)}, HostLabels: map[string]string{"env": "test"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW})
	tested, err := p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: rules}}))
	if err != nil {
		t.Fatal(err)
	}
	// S=2, A=1, H=1: S*(13+2H+3A+3AH); view_jobs/view_output add an empty-host input per action (RR-b-01).
	if tested.Msg.Test.EvaluatedCount != 42 || tested.Msg.Test.ChangedCount != 1 {
		t.Fatalf("existing-host trial=%v; want evaluated=42 changed=1", tested.Msg.Test)
	}
	changes, err := p.GetPolicyTestChanges(ctx, connect.NewRequest(&v1.GetPolicyTestChangesRequest{TestId: tested.Msg.Test.TestId}))
	if err != nil {
		t.Fatal(err)
	}
	if changes.Msg.Changes[0].Host != "host-a" || changes.Msg.Changes[0].After.Effect != v1.PolicyEffect_POLICY_EFFECT_ALLOW {
		t.Fatalf("host change=%v", changes.Msg.Changes)
	}
	explicit, err := p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: rules}, Cases: []*v1.PolicyTestCase{{SubjectId: f.viewer.UserId, Operation: string(authz.ExecuteAction), Action: "restart", Targets: &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"host-a"}}}}}}}))
	if err != nil {
		t.Fatal(err)
	}
	if explicit.Msg.Test.EvaluatedCount != 1 || explicit.Msg.Test.ChangedCount != 1 {
		t.Fatalf("explicit trial=%v", explicit.Msg.Test)
	}
	if _, err := f.db.Pool.Exec(ctx, "UPDATE hosts SET authorization_labels=$1", `{"env":"prod"}`); err != nil {
		t.Fatal(err)
	}
	_, err = p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: rules, TestId: tested.Msg.Test.TestId}))
	code(t, err, connect.CodeAborted)
}

func TestPolicyCandidateExpiryIdentityAndEnvironment(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := f.policy(f.adminToken)
	rules := defaultRules()
	test := func() *v1.PolicyTest {
		t.Helper()
		r, err := p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: rules}}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.Test
	}
	tested := test()
	changed := proto.Clone(rules).(*v1.PolicyRules)
	changed.Rules[0].Name = "changed"
	_, err := p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: changed, TestId: tested.TestId}))
	code(t, err, connect.CodeAborted)
	if _, err := f.db.Pool.Exec(ctx, "UPDATE policy_tests SET expires_at=now()-interval '1 second' WHERE test_id=$1", tested.TestId); err != nil {
		t.Fatal(err)
	}
	_, err = p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: rules, TestId: tested.TestId}))
	code(t, err, connect.CodeAborted)
	// A preview made at a different hour is invalid if time-dependent decisions
	// differ, even while the database snapshot and candidate hash still match.
	now := time.Now().UTC().Hour()
	other := (now + 2) % 24
	rules.Rules = append(rules.Rules, &v1.PolicyRule{Name: "viewer-hour", Roles: []string{"viewer"}, Operations: []string{string(authz.ViewAudit)}, Hours: &v1.PolicyHours{From: uint32(other), To: uint32(other + 1), Timezone: "UTC"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW})
	tested = test()
	old := time.Now().UTC()
	old = time.Date(old.Year(), old.Month(), old.Day(), other, 30, 0, 0, time.UTC)
	if _, err := f.db.Pool.Exec(ctx, "UPDATE policy_tests SET environment=jsonb_set(environment,'{time_ns}',to_jsonb($2::bigint)) WHERE test_id=$1", tested.TestId, old.UnixNano()); err != nil {
		t.Fatal(err)
	}
	_, err = p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: rules, TestId: tested.TestId}))
	code(t, err, connect.CodeAborted)
}
