package job_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type auditSpy struct {
	audit.Appender
	AuthFail, ResultFail atomic.Bool
	ResultCalls          atomic.Int64
	mu                   sync.Mutex
	events               []audit.Payload
}

func (a *auditSpy) Append(ctx context.Context, p audit.Payload) (audit.Event, error) {
	if p.Reason == "authorized" && a.AuthFail.Load() {
		return audit.Event{}, errors.New("fixture authorized audit failure")
	}
	if p.Reason == "result" {
		a.ResultCalls.Add(1)
		if a.ResultFail.Load() {
			return audit.Event{}, errors.New("fixture result audit failure")
		}
	}
	a.mu.Lock()
	a.events = append(a.events, p)
	a.mu.Unlock()
	return a.Appender.Append(ctx, p)
}

func TestNativeClientUsesAuthenticationAuthorizationAndG28(t *testing.T) {
	f := setup(t)
	spy := &auditSpy{Appender: f.A.Job.Audit}
	f.A.Job.Audit = spy
	var client job.Client = f.A.Job
	if _, err := client.RunJob(context.Background(), request("stable")); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("unauthenticated native call=%v", err)
	}
	invoke := func(r *v1.RunJobRequest) (result *v1.RunJobResponse, err error) {
		req := httptest.NewRequest(http.MethodPost, "https://localhost/mcp", nil)
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("Authorization", "Bearer "+f.Token)
		f.A.Job.Access.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) { result, err = client.RunJob(req.Context(), r) })).ServeHTTP(httptest.NewRecorder(), req)
		return
	}
	var before int
	f.DB.Pool.QueryRow(context.Background(), "SELECT count(*) FROM jobs").Scan(&before)
	spy.AuthFail.Store(true)
	calls := spy.ResultCalls.Load()
	_, err := invoke(request("stable"))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("authorization audit failure=%v", err)
	}
	var after int
	f.DB.Pool.QueryRow(context.Background(), "SELECT count(*) FROM jobs").Scan(&after)
	if after != before || spy.ResultCalls.Load() != calls {
		t.Fatalf("write or result audit after failed authorization audit: jobs %d -> %d; result audits %d -> %d", before, after, calls, spy.ResultCalls.Load())
	}
	spy.AuthFail.Store(false)
	r := request("typed")
	r.Params = &v1.Parameters{Json: []byte(`{"number":2,"flag":true,"items":["private_marker"]}`)}
	result, err := invoke(r)
	if err != nil || result.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED {
		t.Fatalf("native execution=%v error=%v", result, err)
	}
	spy.mu.Lock()
	events := append([]audit.Payload(nil), spy.events...)
	spy.mu.Unlock()
	matched := false
	for _, event := range events {
		raw, _ := json.Marshal(event)
		if strings.Contains(string(raw), "private_marker") || strings.Contains(string(raw), "2 true") {
			t.Fatal("audit contains parameters or output")
		}
		if event.Reason == "result" && event.JobID == result.Job.JobId {
			matched = event.PolicyVersion > 0 && len(event.MatchedRules) > 0 && event.SubjectID == "sa"
		}
	}
	if !matched {
		t.Fatal("native result audit missing job, policy or rule attribution")
	}
	read := func() (value *v1.GetJobResponse, err error) {
		req := httptest.NewRequest(http.MethodPost, "https://localhost/mcp", nil)
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("Authorization", "Bearer "+f.Token)
		f.A.Job.Access.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
			value, err = client.GetJob(req.Context(), &v1.GetJobRequest{JobId: result.Job.JobId, WaitSeconds: proto.Uint32(0), ResponseFormat: "detailed"})
		})).ServeHTTP(httptest.NewRecorder(), req)
		return
	}
	previews := f.A.Job.Previews
	fake := previewFixture{}
	for i := 0; i < 30; i++ {
		data := append([]byte(fmt.Sprint(i)), bytes.Repeat([]byte("\"\\\n"), 1300)...)
		sum := sha256.Sum256(data)
		empty := sha256.Sum256(nil)
		fake = append(fake, job.Preview{Task: &v1.Task{Hostname: fmt.Sprintf("budget-host-%02d", i), Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_SUCCEEDED, ExitCode: proto.Int32(0)}}, Stdout: data, StdoutHash: sum[:], StderrHash: empty[:], StdoutSize: uint64(len(data))})
	}
	f.A.Job.Previews = fake
	value, err := read()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := protojson.Marshal(value)
	if len(raw) > 32<<10 || proto.Size(value) > 32<<10 || !value.Summary.Truncated {
		t.Fatalf("escaped summary budget bytes=%d proto=%d truncated=%t", len(raw), proto.Size(value), value.Summary.Truncated)
	}
	f.A.Job.Previews = previews
	if _, err := f.DB.Pool.Exec(context.Background(), "UPDATE service_accounts SET roles='{publisher}' WHERE account_id='sa'"); err != nil {
		t.Fatal(err)
	}
	value, err = read()
	if err != nil || len(value.Summary.Groups) != 0 {
		t.Fatalf("own job without view_jobs must allow metadata and hide output=%v error=%v", value, err)
	}
	if _, err := f.DB.Pool.Exec(context.Background(), "UPDATE service_accounts SET roles='{admin}' WHERE account_id='sa'"); err != nil {
		t.Fatal(err)
	}
	spy.ResultFail.Store(true)
	r = request("stable")
	r.WaitSeconds = proto.Uint32(0)
	_, err = invoke(r)
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("result audit failure=%v", err)
	}
	reason := ""
	for _, d := range err.(*connect.Error).Details() {
		value, _ := d.Value()
		if v, ok := value.(*v1.ErrorDetail); ok {
			reason = v.Reason
		}
	}
	if reason != "AUDIT_RESULT_UNAVAILABLE" {
		t.Fatalf("write ambiguity reason=%s", reason)
	}
	spy.ResultFail.Store(false)
	f.DB.Pool.QueryRow(context.Background(), "SELECT count(*) FROM jobs").Scan(&after)
	if after != before+2 {
		t.Fatalf("committed jobs=%d want %d", after, before+2)
	}
}

type previewFixture []job.Preview

func (p previewFixture) Load(context.Context, string) ([]job.Preview, error) { return p, nil }

func TestA21JobOwnershipConsoleAuthorizationAndOutput(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	r := request("slow")
	r.BatchSize, r.WaitSeconds = proto.Uint32(1), proto.Uint32(0)
	value := run(t, f.A, r)
	id := value.Job.JobId
	other, record, err := authn.GenerateServiceToken(time.Now(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.DB.Pool.Exec(ctx, "INSERT INTO service_accounts(account_id,name,owner_user_id,roles) VALUES ('foreign','foreign','owner','{admin}')"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.DB.Pool.Exec(ctx, "INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES ('foreign','foreign',$1,$2)", record.Hash[:], record.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	foreign := rpc.NewJobServiceClient(f.B.HTTP, "https://"+f.B.Address, connect.WithInterceptors(bearer(other)))
	if _, err = foreign.GetJob(ctx, connect.NewRequest(&v1.GetJobRequest{JobId: id, WaitSeconds: proto.Uint32(0)})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("foreign get=%v", err)
	}
	if _, err = foreign.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: id})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("foreign cancel=%v", err)
	}
	if _, err = foreign.GetJobOutput(ctx, connect.NewRequest(&v1.GetJobOutputRequest{JobId: id, Hostname: "a-host", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("foreign output=%v", err)
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		t.Fatal(err)
	}
	token := "aops_cli_" + base64.RawURLEncoding.EncodeToString(random)
	hash := sha256.Sum256([]byte(token))
	if _, err = f.DB.Pool.Exec(ctx, "INSERT INTO identity_sessions(session_id,user_id,token_hash,client,expires_at) VALUES ('console-job','owner',$1,'cli',now()+interval '1 hour')", hash[:]); err != nil {
		t.Fatal(err)
	}
	console := rpc.NewJobServiceClient(f.B.HTTP, "https://"+f.B.Address, connect.WithInterceptors(bearer(token)))
	for _, role := range []string{"publisher", "viewer"} {
		if _, err = f.DB.Pool.Exec(ctx, "UPDATE console_users SET manual_roles=$1 WHERE user_id='owner'", []string{role}); err != nil {
			t.Fatal(err)
		}
		got, readErr := console.GetJob(ctx, connect.NewRequest(&v1.GetJobRequest{JobId: id, WaitSeconds: proto.Uint32(0)}))
		if role == "publisher" && connect.CodeOf(readErr) != connect.CodePermissionDenied {
			t.Fatalf("console without view_jobs=%v", readErr)
		}
		if role == "viewer" && (readErr != nil || len(got.Msg.Summary.Groups) > 0) {
			t.Fatalf("console metadata=%v error=%v", got, readErr)
		}
		if _, err = console.GetJobOutput(ctx, connect.NewRequest(&v1.GetJobOutputRequest{JobId: id, Hostname: "a-host", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("console without view_output=%v", err)
		}
		if _, err = console.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: id})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("console without execute_action=%v", err)
		}
	}
	if _, err = f.DB.Pool.Exec(ctx, "UPDATE console_users SET manual_roles='{admin}' WHERE user_id='owner'; UPDATE hosts SET authorization_labels='{}' WHERE hostname='c-host'"); err != nil {
		t.Fatal(err)
	}
	if _, err = console.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: id})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("console one host denied=%v", err)
	}
	var cancelled bool
	if err = f.DB.Pool.QueryRow(ctx, "SELECT cancel_requested FROM jobs WHERE job_id=$1", id).Scan(&cancelled); err != nil || cancelled {
		t.Fatalf("denied cancellation changed job: cancelled=%t error=%v", cancelled, err)
	}
	if _, err = f.DB.Pool.Exec(ctx, "UPDATE service_accounts SET roles='{publisher}' WHERE account_id='sa'"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.A.Client.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: id})); err != nil {
		t.Fatalf("owner cancel without execution grants=%v", err)
	}
	get(t, f.A, id)
	if _, err = f.DB.Pool.Exec(ctx, "UPDATE hosts SET authorization_labels='{\"env\":\"test\"}' WHERE hostname='c-host'"); err != nil {
		t.Fatal(err)
	}
	if _, err = console.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: id})); err != nil {
		t.Fatalf("console all hosts allowed=%v", err)
	}
}

func TestImmediateRunKeepsSchedulerJobIndependentFromResponse(t *testing.T) {
	var paused atomic.Bool
	f := setup(t, func(f *fixture) {
		f.BeforeMessage = func(e hostconn.Event) {
			if e.Message.GetTaskStarted() != nil && paused.CompareAndSwap(false, true) {
				// Simulate a scheduling stall in the connection receive loop.
				// No heartbeat replies can be sent until this handler returns.
				time.Sleep(4 * time.Second)
			}
		}
	})
	for i := 0; i < 25; i++ {
		r := request("stable")
		r.WaitSeconds = proto.Uint32(0)
		r.ExpectedCount = nil
		r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"b-host"}}}}
		started := run(t, f.A, r)
		var completed *v1.GetJobResponse
		eventually(t, func() bool {
			response, err := f.B.Client.GetJob(context.Background(), connect.NewRequest(&v1.GetJobRequest{JobId: started.Job.JobId, WaitSeconds: proto.Uint32(0)}))
			if err != nil {
				t.Fatal(err)
			}
			completed = response.Msg
			return completed.Job.Status != v1.JobStatus_JOB_STATUS_QUEUED && completed.Job.Status != v1.JobStatus_JOB_STATUS_RUNNING
		})
		if completed.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED || completed.Job.TotalTasks != 1 {
			t.Fatalf("immediate response changed scheduled job: %v", completed.Job)
		}
	}
}
