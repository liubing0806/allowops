package mcp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
)

type toolAudit struct {
	delegate api.Auditor
	mu       sync.Mutex
	events   []api.AuditEvent
	fail     bool
}

func (a *toolAudit) Append(ctx context.Context, e api.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("fixture audit unavailable")
	}
	if a.delegate != nil {
		if err := a.delegate.Append(ctx, e); err != nil {
			return err
		}
	}
	a.events = append(a.events, e)
	return nil
}
func (a *toolAudit) snapshot() []api.AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]api.AuditEvent(nil), a.events...)
}

type transportFixture struct {
	db            *store.Store
	identity      *api.Service
	service       *Service
	gateway       *httptest.Server
	catalogs      *catalogsvc.Service
	key           ed25519.PrivateKey
	audit         *toolAudit
	jobs          *testJobs
	admin, viewer string
}

func newTransportFixture(t *testing.T) *transportFixture {
	t.Helper()
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	gateway := httptest.NewUnstartedServer(nil)
	auditor := &toolAudit{delegate: api.NewAuditor(audit.New(db.Pool, audit.Config{}))}
	identity, err := api.New(ctx, db, api.Config{Origin: "https://" + gateway.Listener.Addr().String()}, auditor)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	catalogs := &catalogsvc.Service{Store: db, Trusted: map[string]ed25519.PublicKey{catalog.KeyID(pub): pub}, MaxEnvelopeBytes: 1 << 20, MaxActionBytes: 256 << 10}
	if err := identity.ConfigureManagement(api.ManagementConfig{}, nil, catalogs); err != nil {
		t.Fatal(err)
	}
	f := &transportFixture{db: db, identity: identity, gateway: gateway, catalogs: catalogs, key: key, audit: auditor}
	f.jobs = &testJobs{identity: identity, audit: auditor, jobs: map[string]*v1.Job{}, outputs: map[string]string{}}
	f.service, err = New(identity, catalogs, f.jobs, Config{CacheEntries: 2, ProgressInterval: 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	gateway.Config.Handler = f.service.Handler()
	gateway.StartTLS()
	t.Cleanup(gateway.Close)
	if _, err := db.Pool.Exec(ctx, `INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username,manual_roles) VALUES ('owner','test','owner','ldap','owner',ARRAY['admin'])`); err != nil {
		t.Fatal(err)
	}
	mint := func(id, role string) string {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `INSERT INTO service_accounts(account_id,name,owner_user_id,roles) VALUES ($1,$1,'owner',$2)`, id, []string{role}); err != nil {
			t.Fatal(err)
		}
		token, record, err := authn.GenerateServiceToken(time.Now(), 30)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Pool.Exec(ctx, `INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES ($1,$1,$2,$3)`, id, record.Hash[:], record.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		return token
	}
	f.admin = mint("admin", "admin")
	f.viewer = mint("viewer", "viewer")
	for _, name := range []string{"web-01", "web-02"} {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO hosts(host_id,hostname,authorization_labels,certificate_serial,certificate_expires_at) VALUES ($1,$1,'{"env":"test"}','fixture',now()+interval '1 hour')`, name); err != nil {
			t.Fatal(err)
		}
	}
	f.publish(t, 0)
	return f
}
func (f *transportFixture) publish(t *testing.T, offset time.Duration) {
	t.Helper()
	c := &catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: "fixture"}, Actions: map[string]catalog.Action{"logs_read": testAction()}}
	p, err := catalog.Build(c, catalog.BuildOptions{Now: time.Now().Add(offset)})
	if err != nil {
		t.Fatal(err)
	}
	data, err := catalog.CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	env, err := catalog.Sign(data, catalog.SigningKey{PrivateKey: f.key})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.catalogs.Publish(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
}

type bearerTransport struct {
	base          http.RoundTripper
	token         string
	mu            sync.Mutex
	sessionHeader bool
	sse           bool
}

func (b *bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	r.Header.Set("Mcp-Session-Id", "ignored-session")
	response, err := b.base.RoundTrip(r)
	if err == nil {
		b.mu.Lock()
		b.sessionHeader = b.sessionHeader || response.Header.Get("Mcp-Session-Id") != ""
		b.sse = b.sse || strings.Contains(response.Header.Get("Content-Type"), "text/event-stream")
		b.mu.Unlock()
	}
	return response, err
}
func (f *transportFixture) client(t *testing.T, token string, progress func(context.Context, *sdk.ProgressNotificationClientRequest)) (*sdk.ClientSession, *bearerTransport) {
	t.Helper()
	transport := &bearerTransport{base: f.gateway.Client().Transport, token: token}
	client := sdk.NewClient(&sdk.Implementation{Name: "allowops-test", Version: "1"}, &sdk.ClientOptions{ProgressNotificationHandler: progress})
	session, err := client.Connect(context.Background(), &sdk.StreamableClientTransport{Endpoint: f.gateway.URL + "/mcp", HTTPClient: &http.Client{Transport: transport}, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, transport
}
func call(t *testing.T, c *sdk.ClientSession, name string, args any) *sdk.CallToolResult {
	t.Helper()
	r, err := c.CallTool(context.Background(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func content(t *testing.T, r *sdk.CallToolResult) map[string]any {
	t.Helper()
	b, err := json.Marshal(r.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
func actionArgs() map[string]any {
	return map[string]any{"targets": map[string]any{"hosts": []string{"web-01"}}, "params": map[string]any{"mode": "recent"}, "reason": "inspect", "wait_seconds": 0}
}

func TestSDKToolFilteringCacheInvalidationAndRevocation(t *testing.T) {
	f := newTransportFixture(t)
	admin, _ := f.client(t, f.admin, nil)
	viewer, _ := f.client(t, f.viewer, nil)
	list, err := viewer.ListTools(context.Background(), nil)
	if err != nil || len(list.Tools) != 4 {
		t.Fatalf("viewer=%v error=%v", list, err)
	}
	if _, err := admin.ListTools(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	old := f.latestServer()
	if _, err := admin.ListTools(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if f.latestServer() != old {
		t.Fatal("unchanged snapshot missed cache")
	}
	f.publish(t, time.Second)
	if _, err := admin.ListTools(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if f.latestServer() == old {
		t.Fatal("catalog update reused old cache")
	}
	old = f.latestServer()
	if _, err := f.db.Pool.Exec(context.Background(), `INSERT INTO policy_versions(version,rules,created_by) SELECT 2,rules,'fixture' FROM policy_versions WHERE version=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ListTools(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if f.latestServer() == old {
		t.Fatal("policy update reused old cache")
	}
	if _, err := f.db.Pool.Exec(context.Background(), `UPDATE service_accounts SET roles=ARRAY['viewer'] WHERE account_id='admin'`); err != nil {
		t.Fatal(err)
	}
	list, err = admin.ListTools(context.Background(), nil)
	if err != nil || len(list.Tools) != 4 {
		t.Fatalf("changed identity=%v error=%v", list, err)
	}
	f.service.mu.Lock()
	entries := f.service.lru.Len()
	f.service.mu.Unlock()
	if entries > 2 {
		t.Fatalf("cache entries=%d", entries)
	}
	if _, err := f.db.Pool.Exec(context.Background(), `UPDATE service_account_tokens SET revoked_at=now() WHERE token_id='admin'`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ListTools(context.Background(), nil); err == nil {
		t.Fatal("revoked token reached cached tools")
	}
}
func TestSDKParameterErrorsUnknownToolAndJobDenial(t *testing.T) {
	f := newTransportFixture(t)
	c, _ := f.client(t, f.admin, nil)
	args := actionArgs()
	args["params"] = map[string]any{"mode": "invalid"}
	r := call(t, c, "logs_read", args)
	if !r.IsError || !strings.Contains(r.Content[0].(*sdk.TextContent).Text, "recent") {
		t.Fatalf("parameter result=%+v", r)
	}
	r = call(t, c, "removed_action", map[string]any{})
	if !r.IsError {
		t.Fatal("unknown tool was not a tool error")
	}
	args = actionArgs()
	args["targets"] = map[string]any{"selector": "env=test"}
	args["expected_count"] = 1
	r = call(t, c, "logs_read", args)
	if !r.IsError || content(t, r)["actual_count"] != float64(2) {
		t.Fatalf("count mismatch=%+v", r)
	}
	policy, err := f.identity.GetPolicy(context.Background(), connect.NewRequest(&v1.GetPolicyRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	rules := policy.Msg.Policy.Rules
	rules.Rules = append(rules.Rules, &v1.PolicyRule{Name: "deny-test", Roles: []string{"admin"}, Operations: []string{"execute_action"}, HostLabels: map[string]string{"env": "test"}, Effect: v1.PolicyEffect_POLICY_EFFECT_DENY})
	data, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(context.Background(), `INSERT INTO policy_versions(version,rules,created_by) VALUES (2,$1,'fixture')`, data); err != nil {
		t.Fatal(err)
	}
	r = call(t, c, "logs_read", actionArgs())
	if !r.IsError || !strings.Contains(r.Content[0].(*sdk.TextContent).Text, "web-01") {
		t.Fatalf("denial=%+v", r)
	}
	unknownEvent := false
	for _, e := range f.audit.snapshot() {
		if e.Operation == "mcp/unknown_tool" && e.Outcome == "deny" {
			unknownEvent = true
		}
	}
	if !unknownEvent {
		t.Fatal("unknown tool was not audited")
	}
	denied, authorized := 0, 0
	for _, e := range f.audit.snapshot() {
		if e.Operation == "mcp/logs_read" && e.Outcome == "deny" {
			denied++
			if e.PolicyVersion == 0 {
				t.Fatal("denied tool audit has no policy version")
			}
		}
		if e.Phase == "authorized" {
			authorized++
		}
	}
	if denied != 3 || authorized != 0 {
		t.Fatalf("error audits=%d authorized=%d", denied, authorized)
	}
}
func TestSDKBearerRequiredAndQueryRejected(t *testing.T) {
	f := newTransportFixture(t)
	for _, tc := range []struct {
		query, token string
		want         int
	}{{"", "", 401}, {"?token=forbidden", f.admin, 400}, {"?access_token=forbidden", "", 400}} {
		req, err := http.NewRequest(http.MethodPost, f.gateway.URL+"/mcp"+tc.query, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		response, err := f.gateway.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.want {
			t.Fatalf("status=%d want=%d", response.StatusCode, tc.want)
		}
	}
}
func TestSDKProgressAndTimeout(t *testing.T) {
	f := newTransportFixture(t)
	f.jobs.delay = time.Second
	notices := make(chan *sdk.ProgressNotificationParams, 64)
	c, _ := f.client(t, f.admin, func(_ context.Context, r *sdk.ProgressNotificationClientRequest) { notices <- r.Params })
	args := actionArgs()
	args["wait_seconds"] = 1
	p := &sdk.CallToolParams{Name: "logs_read", Arguments: args}
	p.SetProgressToken("progress-test")
	r, err := c.CallTool(context.Background(), p)
	if err != nil || r.IsError {
		t.Fatalf("result=%v error=%v", r, err)
	}
	if content(t, r)["job_id"] == "" || content(t, r)["status"] != "running" {
		t.Fatalf("timeout=%v", content(t, r))
	}
	select {
	case n := <-notices:
		if n.ProgressToken != "progress-test" {
			t.Fatalf("token=%v", n.ProgressToken)
		}
	default:
		t.Fatal("no SSE progress notification")
	}
}
func TestSDKCommentHeartbeatWithoutProgressToken(t *testing.T) {
	f := newTransportFixture(t)
	f.jobs.delay = 250 * time.Millisecond
	args := actionArgs()
	args["wait_seconds"] = 1
	data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{"name": "logs_read", "arguments": args}})
	request, err := http.NewRequest(http.MethodPost, f.gateway.URL+"/mcp", strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+f.admin)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := f.gateway.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(body), ": keepalive\n\n") < 2 || strings.Contains(string(body), "notifications/progress") || strings.Index(string(body), ": keepalive") > strings.Index(string(body), "data:") {
		t.Fatalf("missing heartbeat or invented progress: %s", body)
	}
}

// Implements the same in-process G28 contract as P6, with local fixture data.
type testJobs struct {
	identity *api.Service
	audit    *toolAudit
	mu       sync.Mutex
	jobs     map[string]*v1.Job
	outputs  map[string]string
	delay    time.Duration
	sequence int
}

func (j *testJobs) RunJob(ctx context.Context, r *v1.RunJobRequest) (*v1.RunJobResponse, error) {
	var names []string
	if h := r.Targets.GetHosts(); h != nil {
		names = h.Names
	} else {
		names = []string{"web-01", "web-02"}
	}
	if r.ExpectedCount != nil && *r.ExpectedCount != uint64(len(names)) {
		detail, _ := connect.NewErrorDetail(&v1.ErrorDetail{Reason: "EXPECTED_COUNT_MISMATCH", ActualCount: proto.Uint64(uint64(len(names)))})
		e := connect.NewError(connect.CodeFailedPrecondition, errors.New("count mismatch"))
		e.AddDetail(detail)
		return nil, e
	}
	for _, name := range names {
		result, err := j.identity.Require(ctx, authz.ExecuteAction, authz.Action{Name: r.Action, Risk: "read"}, authz.Host{ID: name, Labels: map[string]string{"env": "test"}})
		if err != nil {
			detail, _ := connect.NewErrorDetail(&v1.ErrorDetail{Reason: "JOB_DENIED", DeniedHosts: []*v1.HostDenial{{Host: name, Rules: result.RuleIDs}}})
			e := connect.NewError(connect.CodePermissionDenied, errors.New("denied"))
			e.AddDetail(detail)
			return nil, e
		}
	}
	id, _ := reqctx.FromContext(ctx)
	if err := j.audit.Append(ctx, api.AuditEvent{ActorID: id.Subject.ID, Operation: "run_job", Phase: "authorized", Outcome: "allow"}); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("authorization audit unavailable"))
	}
	j.mu.Lock()
	j.sequence++
	job := &v1.Job{JobId: fmt.Sprintf("job-20261014-%04d", j.sequence), Action: r.Action, SubjectId: id.Subject.ID, Status: v1.JobStatus_JOB_STATUS_SUCCEEDED, TotalTasks: 1, Counts: []*v1.TaskCount{{Status: v1.TaskStatus_TASK_STATUS_SUCCEEDED, Count: 1}}}
	if j.delay > 0 {
		job.Status = v1.JobStatus_JOB_STATUS_RUNNING
	}
	j.jobs[job.JobId] = job
	j.outputs[job.JobId] = "fixture stdout"
	j.mu.Unlock()
	if j.delay > 0 {
		timer := time.NewTimer(j.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &v1.RunJobResponse{Job: proto.Clone(job).(*v1.Job), Summary: fixtureSummary()}, nil
}
func (j *testJobs) GetJob(ctx context.Context, r *v1.GetJobRequest) (*v1.GetJobResponse, error) {
	j.mu.Lock()
	job := j.jobs[r.JobId]
	j.mu.Unlock()
	if job == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("job not found"))
	}
	id, ok := reqctx.FromContext(ctx)
	if !ok || id.Subject.Kind == "service_account" && id.Subject.ID != job.SubjectId {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("owner required"))
	}
	if _, err := j.identity.Require(ctx, authz.ViewJobs, authz.Action{}, authz.Host{ID: "web-01", Labels: map[string]string{"env": "test"}}); err != nil {
		return nil, err
	}
	return &v1.GetJobResponse{Job: proto.Clone(job).(*v1.Job), Summary: fixtureSummary()}, nil
}
func (j *testJobs) ListJobs(ctx context.Context, r *v1.ListJobsRequest) (*v1.ListJobsResponse, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := &v1.ListJobsResponse{}
	for _, job := range j.jobs {
		if job.SubjectId == r.SubjectId {
			out.Jobs = append(out.Jobs, proto.Clone(job).(*v1.Job))
		}
	}
	return out, nil
}
func (j *testJobs) ListTasks(context.Context, *v1.ListTasksRequest) (*v1.ListTasksResponse, error) {
	return &v1.ListTasksResponse{}, nil
}
func (j *testJobs) CancelJob(ctx context.Context, r *v1.CancelJobRequest) (*v1.CancelJobResponse, error) {
	response, err := j.GetJob(ctx, &v1.GetJobRequest{JobId: r.JobId})
	if err != nil {
		return nil, err
	}
	return &v1.CancelJobResponse{Job: response.Job}, nil
}
func (j *testJobs) GetJobOutput(ctx context.Context, r *v1.GetJobOutputRequest) (*v1.GetJobOutputResponse, error) {
	if _, err := j.GetJob(ctx, &v1.GetJobRequest{JobId: r.JobId}); err != nil {
		return nil, err
	}
	if _, err := j.identity.Require(ctx, authz.ViewOutput, authz.Action{}, authz.Host{ID: r.Hostname, Labels: map[string]string{"env": "test"}}); err != nil {
		return nil, err
	}
	data := []byte("fixture stdout")
	if r.Stream == v1.OutputStream_OUTPUT_STREAM_STDERR {
		data = nil
	}
	if r.Offset > uint64(len(data)) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("offset out of range"))
	}
	end := min(uint64(len(data)), r.Offset+uint64(r.LimitBytes))
	return &v1.GetJobOutputResponse{Data: data[r.Offset:end], NextOffset: end, Eof: end == uint64(len(data)), OutputStored: true}, nil
}

func (f *transportFixture) latestServer() *sdk.Server {
	f.service.mu.Lock()
	defer f.service.mu.Unlock()
	return f.service.lru.Front().Value.(*cacheEntry).server
}

// Protocol-boundary and timer tests keep deterministic responses; real scheduling
// and object output are covered by TestSDKRealJobBackendAgentsAndSeaweedFS.
func fixtureSummary() *v1.JobSummary {
	return &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED, Groups: []*v1.OutputGroup{{ExitCode: proto.Int32(0), HostCount: 1, Hosts: []string{"web-01"}, Stdout: "fixture stdout"}}}
}
