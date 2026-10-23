package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: "test"}, Actions: map[string]catalog.Action{"restart": {Name: "restart", Description: "fixture", Risk: "dangerous", Exec: []any{"/usr/bin/true"}, Timeout: "1s", MaxOutput: 1024}}}, catalog.BuildOptions{Now: time.Now()})
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
	if err := f.db.Publish(ctx, db.InsertCatalogParams{CatalogID: "test", Version: int64(p.Version), Dsse: raw, Digest: hash(string(raw)), ExpiresAt: store.Timestamp(time.Now().Add(time.Hour)), ActionNames: []string{"restart"}}); err != nil {
		t.Fatal(err)
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
	// S=2, A=1, H=1: S*(12+2H+3A+3AH); view_jobs/view_output add an empty-host input per action (RR-b-01).
	if tested.Msg.Test.EvaluatedCount != 40 || tested.Msg.Test.ChangedCount != 1 {
		t.Fatalf("existing-host trial=%v; want evaluated=40 changed=1", tested.Msg.Test)
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
