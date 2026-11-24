package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authn"
)

func publishExampleCatalogForTrial(t *testing.T) (*fixture, []string) {
	t.Helper()
	example, err := catalog.Load("../../../examples/catalog")
	if err != nil {
		t.Fatal(err)
	}
	if len(example.Actions) < 50 {
		t.Fatalf("example catalog has %d actions; want at least 50", len(example.Actions))
	}
	pkg, err := catalog.Build(example, catalog.BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := catalog.CanonicalJSON(pkg)
	if err != nil {
		t.Fatal(err)
	}
	f, key := catalogFixture(t)
	envelope, err := catalog.Sign(payload, catalog.SigningKey{PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	client := catalogClient(f, f.adminToken)
	upload := uploadTestCatalog(t, client, raw)
	if _, err := client.PublishCatalog(t.Context(), connect.NewRequest(&v1.PublishCatalogRequest{UploadId: upload})); err != nil {
		t.Fatal(err)
	}
	return f, slices.Sorted(maps.Keys(example.Actions))
}

func addTrialReaders(t *testing.T, f *fixture, from, to int) {
	t.Helper()
	for i := from; i < to; i++ {
		id := authn.Identity{ID: fmt.Sprintf("reader-%02d", i), Kind: "oidc", Groups: []string{"readers"}}
		if _, err := syncUser(t.Context(), f.db.Pool, "test", id); err != nil {
			t.Fatal(err)
		}
	}
}

func addTrialHosts(t *testing.T, f *fixture, hosts int) {
	t.Helper()
	for i := range hosts {
		tier := "web"
		if i%2 == 1 {
			tier = "db"
		}
		addHost(t, f, fmt.Sprintf("%s-%02d", tier, i))
	}
	if _, err := f.db.Pool.Exec(t.Context(), `UPDATE hosts SET authorization_labels=jsonb_build_object('tier',split_part(hostname,'-',1))`); err != nil {
		t.Fatal(err)
	}
}

func defaultTrialEvaluations(subjects, hosts, actions int) int {
	// For each subject: 12 global checks, view/manage per host, catalog per
	// action, jobs/output per action on the empty and real hosts, execute per pair.
	return subjects * (len(consoleOperations) + 2*hosts + actions + 2*actions*(1+hosts) + actions*hosts)
}

func scaleTrialRequest(cases ...*v1.PolicyTestCase) *connect.Request[v1.TestPolicyRequest] {
	return connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: defaultRules()}, Cases: cases})
}

func TestPolicyTrialWithRealExampleCatalogWithinBudget(t *testing.T) {
	const subjects, hosts = 5, 15
	f, actions := publishExampleCatalogForTrial(t)
	addTrialReaders(t, f, 2, subjects) // fixture already contains admin and viewer
	addTrialHosts(t, f, hosts)
	client := f.policy(f.adminToken)
	ctx, cancel := context.WithTimeout(t.Context(), fullPolicyTrialBudget)
	defer cancel()
	start := time.Now()
	resp, err := client.TestPolicy(ctx, scaleTrialRequest())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("default trial with %d actions, %d subjects and %d hosts after %s: %v", len(actions), subjects, hosts, elapsed, err)
	}
	got := resp.Msg.GetTest().GetEvaluatedCount()
	t.Logf("actions=%d subjects=%d hosts=%d evaluations=%d elapsed=%s budget=%s", len(actions), subjects, hosts, got, elapsed, fullPolicyTrialBudget)
	if want := defaultTrialEvaluations(subjects, hosts, len(actions)); got != uint64(want) {
		t.Errorf("evaluated_count=%d; want %d", got, want)
	}
	if elapsed > fullPolicyTrialBudget {
		t.Errorf("default trial took %s; budget %s", elapsed, fullPolicyTrialBudget)
	}
}

func TestPolicyExplicitCasesScaleWithRealCatalog(t *testing.T) {
	const hosts, limit = 40, 100_000
	f, actions := publishExampleCatalogForTrial(t)
	if got := f.service.Config.MaxTestEvaluations; got != limit {
		t.Fatalf("default MaxTestEvaluations=%d; want %d", got, limit)
	}
	perSubject := defaultTrialEvaluations(1, hosts, len(actions))
	maxSubjects := limit / perSubject
	subjects := max(15, maxSubjects+1)
	addTrialHosts(t, f, hosts)
	addTrialReaders(t, f, 2, subjects)
	client := f.policy(f.adminToken)

	// Shared authorization label tiers (web/db) collapse 40 hosts into 2 groups,
	// so the full default trial succeeds well within the grouped limit.
	ctx, cancel := context.WithTimeout(t.Context(), fullPolicyTrialBudget)
	start := time.Now()
	groupedResp, err := client.TestPolicy(ctx, scaleTrialRequest())
	groupedElapsed := time.Since(start)
	cancel()
	if err != nil {
		t.Fatalf("grouped default trial at %d subjects x %d hosts: %v", subjects, hosts, err)
	}
	t.Logf("grouped_default actions=%d subjects=%d hosts=%d logical_evaluations=%d elapsed=%s",
		len(actions), subjects, hosts, groupedResp.Msg.GetTest().GetEvaluatedCount(), groupedElapsed)
	if want := defaultTrialEvaluations(subjects, hosts, len(actions)); groupedResp.Msg.GetTest().GetEvaluatedCount() != uint64(want) {
		t.Fatalf("grouped evaluated_count=%d; want %d", groupedResp.Msg.GetTest().GetEvaluatedCount(), want)
	}

	// Distinct authorization label sets per host defeat grouping and hit the
	// grouped evaluation limit; explicit cases must still scale linearly.
	if _, err := f.db.Pool.Exec(t.Context(), `UPDATE hosts SET authorization_labels=jsonb_build_object('tier',split_part(hostname,'-',1),'shard',hostname)`); err != nil {
		t.Fatal(err)
	}
	t.Logf("default_limit=%d actions=%d unique_host_groups=%d evaluations_per_subject=%d last_allowed_subjects=%d first_rejected_subjects=%d",
		limit, len(actions), hosts, perSubject, maxSubjects, maxSubjects+1)
	ctx, cancel = context.WithTimeout(t.Context(), 15*time.Second)
	_, err = client.TestPolicy(ctx, scaleTrialRequest())
	cancel()
	var rpcErr *connect.Error
	if !errors.As(err, &rpcErr) || rpcErr.Code() != connect.CodeResourceExhausted {
		t.Fatalf("ungrouped default trial at %d subjects x %d unique hosts: got %v; want resource_exhausted", subjects, hosts, err)
	}
	t.Logf("subjects=%d unique_hosts=%d requested_evaluations=%d error=%v", subjects, hosts, subjects*perSubject, err)

	web := &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "tier=web"}}
	cases := []*v1.PolicyTestCase{
		{SubjectId: f.admin.UserId, Operation: "execute_action", Action: actions[0], Targets: web},
		{SubjectId: f.viewer.UserId, Operation: "view_jobs", Action: actions[1], Targets: web},
		{SubjectId: f.viewer.UserId, Operation: "view_output", Action: actions[2], Targets: web},
	}
	for _, n := range []int{1, len(cases)} {
		const budget = 5 * time.Second
		ctx, cancel := context.WithTimeout(t.Context(), budget)
		start := time.Now()
		resp, err := client.TestPolicy(ctx, scaleTrialRequest(cases[:n]...))
		elapsed := time.Since(start)
		cancel()
		if err != nil {
			t.Fatalf("%d explicit cases after %s: %v", n, elapsed, err)
		}
		got := resp.Msg.GetTest().GetEvaluatedCount()
		t.Logf("actions=%d subjects=%d hosts=%d cases=%d matched_hosts=%d evaluations=%d elapsed=%s budget=%s", len(actions), subjects, hosts, n, hosts/2, got, elapsed, budget)
		if want := n * (hosts / 2); got != uint64(want) {
			t.Fatalf("evaluated_count=%d; want %d", got, want)
		}
	}
}
