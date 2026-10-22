package job_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// statementCounter counts every statement sent through the traced pool.
type statementCounter struct {
	mu  sync.Mutex
	sql []string
}

func (c *statementCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sql = append(c.sql, data.SQL)
	return ctx
}
func (*statementCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (c *statementCounter) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sql = nil
}
func (c *statementCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sql)
}
func (c *statementCounter) summary() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	byPrefix := map[string]int{}
	for _, q := range c.sql {
		byPrefix[q[:min(len(q), 60)]]++
	}
	return fmt.Sprint(byPrefix)
}

type listSpec struct {
	id, subject, action, host, reason string
	created                           time.Time
}

type listEnv struct {
	svc        *job.Service
	counter    *statementCounter
	viewer, sa string
}

const listBase = "2026-01-01T00:00:00Z"

// sortedSpecs orders like the query: created_at DESC, job_id DESC.
func sortedSpecs(specs []listSpec) []listSpec {
	out := slices.Clone(specs)
	slices.SortFunc(out, func(a, b listSpec) int {
		if c := b.created.Compare(a.created); c != 0 {
			return c
		}
		return strings.Compare(b.id, a.id)
	})
	return out
}

// listFixture starts a disposable PostgreSQL, inserts the given jobs (one task
// each) and returns a job service with two callers: a viewer user whose policy
// denies view_jobs for jobs on hosts labelled env=secret, and a service account
// that owns the jobs with subject "sa".
func listFixture(t *testing.T, specs []listSpec) *listEnv {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	counter := &statementCounter{}
	traced := tracedJobStore(t, db, counter)
	if _, err := db.Pool.Exec(ctx, `INSERT INTO gateway_instances(instance_id) VALUES ('fixture');
 INSERT INTO hosts(host_id,hostname,certificate_serial,certificate_expires_at,authorization_labels) VALUES
  ('h-pub','h-pub','serial-pub',now()+interval '1 hour','{"env":"pub"}'),
  ('h-secret','h-secret','serial-secret',now()+interval '1 hour','{"env":"secret"}');
 CREATE TABLE tasks_fixture PARTITION OF tasks DEFAULT;
 INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username,manual_roles) VALUES
  ('owner','fixture','owner','oidc','owner','{admin}'),('viewer','fixture','viewer','oidc','viewer','{viewer}');
 INSERT INTO service_accounts(account_id,name,owner_user_id,roles) VALUES ('sa','fixture','owner','{admin}')`); err != nil {
		t.Fatal(err)
	}
	rules := &v1.PolicyRules{Rules: []*v1.PolicyRule{
		{Name: "allow-view", Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW, Roles: []string{"viewer", "admin"}, Operations: []string{"view_jobs"}},
		{Name: "hide-secret", Effect: v1.PolicyEffect_POLICY_EFFECT_DENY, Roles: []string{"viewer"}, Operations: []string{"view_jobs"}, HostLabels: map[string]string{"env": "secret"}},
	}}
	raw, err := protojson.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	auditor := audit.New(db.Pool, audit.Config{})
	// api.New seeds policy version 1; version 2 is the policy under test.
	access, err := api.New(ctx, traced, api.Config{Origin: "https://127.0.0.1:443"}, api.NewAuditor(auditor))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, "INSERT INTO policy_versions(version,rules,created_by,reason) VALUES (2,$1,'fixture','fixture')", raw); err != nil {
		t.Fatal(err)
	}
	sa, record, err := authn.GenerateServiceToken(time.Now(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, "INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES ('token','sa',$1,now()+interval '1 hour')", record.Hash[:]); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	viewer := "aops_cli_" + base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256([]byte(viewer))
	if _, err := db.Pool.Exec(ctx, "INSERT INTO identity_sessions(session_id,user_id,token_hash,client,expires_at) VALUES ('session','viewer',$1,'cli',now()+interval '1 hour')", digest[:]); err != nil {
		t.Fatal(err)
	}
	batch := &pgx.Batch{}
	for _, s := range specs {
		batch.Queue(`INSERT INTO jobs(job_id,created_at,subject_id,origin_instance,action,action_definition,catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures)
 VALUES ($1,$2,$3,'fixture',$4,convert_to('{}','UTF8'),'catalog',1,decode(repeat('00',32),'hex'),1,$5,3,20,5)`, s.id, s.created, s.subject, s.action, s.reason)
		batch.Queue(`INSERT INTO tasks(job_id,task_id,created_at,host_id,hostname,position,status,result)
 VALUES ($1,'task',$2,$3,$3,0,3,decode('0803','hex'))`, s.id, s.created, s.host)
	}
	results := db.Pool.SendBatch(ctx, batch)
	for range specs {
		for range 2 {
			if _, err := results.Exec(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := results.Close(); err != nil {
		t.Fatal(err)
	}
	return &listEnv{svc: &job.Service{Store: traced, Access: access, Audit: auditor}, counter: counter, viewer: viewer, sa: sa}
}

func (e *listEnv) list(token string, r *v1.ListJobsRequest) (*v1.ListJobsResponse, error) {
	var response *v1.ListJobsResponse
	var err error
	req := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:443/mcp", nil)
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Authorization", "Bearer "+token)
	e.svc.Access.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		response, err = e.svc.ListJobs(req.Context(), r)
	})).ServeHTTP(httptest.NewRecorder(), req)
	return response, err
}

// walk follows next_page_token until it is empty and returns all job IDs, the
// SQL statement count of every page and the sizes of the pages.
func (e *listEnv) walk(t *testing.T, token string, r *v1.ListJobsRequest, size uint32) (ids []string, statements, sizes []int) {
	t.Helper()
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 1000 {
			t.Fatal("pagination did not terminate")
		}
		r.Page = &v1.PageRequest{PageSize: size, PageToken: cursor}
		e.counter.reset()
		response, err := e.list(token, r)
		statements = append(statements, e.counter.count())
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		for _, j := range response.Jobs {
			ids = append(ids, j.JobId)
		}
		sizes = append(sizes, len(response.Jobs))
		cursor = response.Page.NextPageToken
		if cursor == "" {
			return ids, statements, sizes
		}
	}
}

func jobIDs(specs []listSpec, keep func(listSpec) bool) []string {
	ids := []string{}
	for _, s := range sortedSpecs(specs) {
		if keep(s) {
			ids = append(ids, s.id)
		}
	}
	return ids
}

// listHistory builds 340 jobs, two per timestamp so that the job_id tie-break
// matters. By query order the newest 30 and the oldest 10 are on the secret
// host, which the viewer must not see; the 300 between are public. Every tenth
// job belongs to another subject than the service account.
func listHistory() []listSpec {
	base, _ := time.Parse(time.RFC3339, listBase)
	specs := make([]listSpec, 340)
	for i := range specs {
		specs[i] = listSpec{id: fmt.Sprintf("job-%04d", i), created: base.Add(time.Duration(i/2) * time.Second), subject: "sa", action: "act-pub", host: "h-pub"}
	}
	position := map[string]int{}
	for rank, s := range sortedSpecs(specs) {
		position[s.id] = rank
	}
	for i := range specs {
		rank := position[specs[i].id]
		if rank < 30 || rank >= 330 {
			specs[i].action, specs[i].host = "act-secret", "h-secret"
		}
		if rank%10 == 9 {
			specs[i].subject = "other"
		}
	}
	return specs
}

func TestListJobsKeysetPagination(t *testing.T) {
	specs := listHistory()
	e := listFixture(t, specs)
	visible := func(s listSpec) bool { return s.host == "h-pub" }
	t.Run("walk_returns_every_visible_job_once_in_order", func(t *testing.T) {
		want := jobIDs(specs, visible)
		for _, size := range []uint32{1, 7, 50, 200} {
			got, _, sizes := e.walk(t, e.viewer, &v1.ListJobsRequest{}, size)
			if !slices.Equal(got, want) {
				t.Fatalf("size %d: got %d jobs, want %d in order; first difference at %d", size, len(got), len(want), firstDifference(got, want))
			}
			// Hidden jobs (30 at the head, 10 at the tail) must not cause short
			// or empty pages before the last one. Size 200 is cut by the
			// response byte limit instead.
			for i, n := range sizes[:len(sizes)-1] {
				if size <= 50 && n != int(size) {
					t.Fatalf("size %d: page %d has %d jobs; want a full page", size, i, n)
				}
			}
		}
	})
	t.Run("last_page_has_no_token_when_only_hidden_jobs_remain", func(t *testing.T) {
		// 300 visible jobs fill 6 pages of 50 exactly; the 10 hidden jobs after
		// them must not produce a seventh page.
		_, _, sizes := e.walk(t, e.viewer, &v1.ListJobsRequest{}, 50)
		if len(sizes) != 6 {
			t.Fatalf("pages=%v; want 6 pages of 50", sizes)
		}
	})
	t.Run("filters_and_service_account_scope", func(t *testing.T) {
		owned := jobIDs(specs, func(s listSpec) bool { return s.subject == "sa" })
		got, _, _ := e.walk(t, e.sa, &v1.ListJobsRequest{}, 25)
		if !slices.Equal(got, owned) {
			t.Fatalf("service account walk: got %d jobs, want %d; first difference at %d", len(got), len(owned), firstDifference(got, owned))
		}
		want := jobIDs(specs, func(s listSpec) bool { return s.action == "act-pub" && s.subject == "other" })
		got, _, _ = e.walk(t, e.viewer, &v1.ListJobsRequest{Action: "act-pub", SubjectId: "other"}, 4)
		if !slices.Equal(got, want) {
			t.Fatalf("subject filter walk: got %v, want %v", got, want)
		}
		base, _ := time.Parse(time.RFC3339, listBase)
		from, to := base.Add(100*time.Second), base.Add(120*time.Second)
		want = jobIDs(specs, func(s listSpec) bool { return s.host == "h-pub" && !s.created.Before(from) && s.created.Before(to) })
		got, _, _ = e.walk(t, e.viewer, &v1.ListJobsRequest{Created: &v1.TimeRange{From: timestamppb.New(from), To: timestamppb.New(to)}}, 6)
		if !slices.Equal(got, want) || len(want) != 40 {
			t.Fatalf("time range walk: got %d jobs, want %d (expect 40)", len(got), len(want))
		}
		got, _, _ = e.walk(t, e.viewer, &v1.ListJobsRequest{Statuses: []v1.JobStatus{v1.JobStatus_JOB_STATUS_FAILED}}, 6)
		if len(got) != 0 {
			t.Fatalf("status filter walk: got %v; want none", got)
		}
	})
	t.Run("page_size_limits", func(t *testing.T) {
		_, err := e.list(e.viewer, &v1.ListJobsRequest{Page: &v1.PageRequest{PageSize: 201}})
		if err == nil || !strings.Contains(err.Error(), "PAGE_SIZE_EXCEEDED") {
			t.Fatalf("page size 201 error=%v; want PAGE_SIZE_EXCEEDED", err)
		}
		response, err := e.list(e.viewer, &v1.ListJobsRequest{})
		if err != nil || len(response.Jobs) != 50 || response.Page.NextPageToken == "" {
			t.Fatalf("default page: jobs=%d err=%v; want 50 jobs and a token", len(response.GetJobs()), err)
		}
	})
	t.Run("invalid_tokens", func(t *testing.T) {
		first, err := e.list(e.viewer, &v1.ListJobsRequest{Action: "act-pub", Page: &v1.PageRequest{PageSize: 5}})
		if err != nil {
			t.Fatal(err)
		}
		token := first.Page.NextPageToken
		flipped := []byte(token)
		flipped[0] = 'A' + (flipped[0]-'A'+1)%26
		for name, tc := range map[string]struct {
			as  string
			req *v1.ListJobsRequest
			tok string
		}{
			"garbage":         {e.viewer, &v1.ListJobsRequest{Action: "act-pub"}, "!!not-base64!!"},
			"truncated":       {e.viewer, &v1.ListJobsRequest{Action: "act-pub"}, token[:len(token)/2]},
			"binding_altered": {e.viewer, &v1.ListJobsRequest{Action: "act-pub"}, string(flipped)},
			"other_action":    {e.viewer, &v1.ListJobsRequest{Action: "act-secret"}, token},
			"no_action":       {e.viewer, &v1.ListJobsRequest{}, token},
			"other_subject":   {e.viewer, &v1.ListJobsRequest{Action: "act-pub", SubjectId: "sa"}, token},
			"other_actor":     {e.sa, &v1.ListJobsRequest{Action: "act-pub"}, token},
		} {
			t.Run(name, func(t *testing.T) {
				tc.req.Page = &v1.PageRequest{PageSize: 5, PageToken: tc.tok}
				_, err := e.list(tc.as, tc.req)
				if err == nil || !strings.Contains(err.Error(), "INVALID_PAGE_TOKEN") {
					t.Fatalf("error=%v; want INVALID_PAGE_TOKEN", err)
				}
			})
		}
		// The unmodified token still works with the filters it was issued for.
		if _, err := e.list(e.viewer, &v1.ListJobsRequest{Action: "act-pub", Page: &v1.PageRequest{PageSize: 5, PageToken: token}}); err != nil {
			t.Fatalf("valid token rejected: %v", err)
		}
	})
}

// The per-page cost must depend on the page size, not on how many jobs exist.
func TestListJobsPageCostIsBounded(t *testing.T) {
	specs := listHistory()
	e := listFixture(t, specs)
	const size = 5
	// Per job, get and authorize issue a fixed number of statements; one extra
	// job decides whether a next page exists. The overhead covers policy
	// refresh, candidate batches and request checks.
	const perJob, overhead = 5, 10
	bound := perJob*(size+1) + overhead
	ids, statements, _ := e.walk(t, e.viewer, &v1.ListJobsRequest{Action: "act-pub"}, size)
	if len(ids) != 300 {
		t.Fatalf("walk returned %d jobs; want 300", len(ids))
	}
	for page, n := range statements {
		if n > bound {
			t.Fatalf("page %d of %d used %d SQL statements for page_size=%d over %d jobs; want at most %d (O(page_size)); statements by prefix: %s", page, len(statements), n, size, len(ids), bound, e.counter.summary())
		}
	}
}

// A page is cut at the response byte limit; the cursor must resume after the
// last job that was returned.
func TestListJobsResponseByteLimit(t *testing.T) {
	base, _ := time.Parse(time.RFC3339, listBase)
	specs := []listSpec{}
	for i := range 5 {
		specs = append(specs, listSpec{id: fmt.Sprintf("big-%d", i), created: base.Add(time.Duration(i) * time.Second), subject: "sa", action: "act-big", host: "h-pub", reason: strings.Repeat("x", 12000)})
	}
	specs = append(specs, listSpec{id: "huge", created: base.Add(time.Hour), subject: "sa", action: "act-huge", host: "h-pub", reason: strings.Repeat("x", job.ResponseBytes)})
	e := listFixture(t, specs)
	want := jobIDs(specs, func(s listSpec) bool { return s.action == "act-big" })
	got, _, sizes := e.walk(t, e.viewer, &v1.ListJobsRequest{Action: "act-big"}, 5)
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if len(sizes) < 2 || sizes[0] >= 5 {
		t.Fatalf("page sizes=%v; want the first page cut by the response byte limit", sizes)
	}
	_, err := e.list(e.viewer, &v1.ListJobsRequest{Action: "act-huge"})
	if err == nil || !strings.Contains(err.Error(), "JOB_RESPONSE_LIMIT") {
		t.Fatalf("oversized single job error=%v; want JOB_RESPONSE_LIMIT", err)
	}
}

func firstDifference(a, b []string) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}
