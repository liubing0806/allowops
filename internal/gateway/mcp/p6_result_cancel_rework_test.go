package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/store"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type p6CancelRequestKey struct{}

type p6CancelRequest struct {
	ctx    context.Context
	cancel context.CancelFunc
}

type p6CancelResult struct {
	err                                           error
	committed, cancelled, detached, valueRetained bool
	remaining                                     time.Duration
}

type p6CancelAudit struct {
	audit.Appender
	db   *store.Store
	done chan p6CancelResult
}

func (a *p6CancelAudit) Append(ctx context.Context, p audit.Payload) (audit.Event, error) {
	if p.Operation != "cancel_job" || p.Reason != "result" {
		return a.Appender.Append(ctx, p)
	}
	result := p6CancelResult{}
	request, ok := ctx.Value(p6CancelRequestKey{}).(p6CancelRequest)
	result.valueRetained = ok
	control, cancel := context.WithTimeout(context.Background(), time.Second)
	var requested bool
	var status int16
	result.err = a.db.Pool.QueryRow(control, `SELECT j.cancel_requested,t.status FROM jobs j JOIN tasks t USING(job_id) WHERE j.job_id=$1`, p.JobID).Scan(&requested, &status)
	cancel()
	result.committed = result.err == nil && requested && status == 8
	if ok {
		request.cancel()
		result.cancelled = errors.Is(request.ctx.Err(), context.Canceled)
	}
	result.detached = ctx.Err() == nil
	if deadline, ok := ctx.Deadline(); ok {
		result.remaining = time.Until(deadline)
	}
	event, err := a.Appender.Append(ctx, p)
	result.err = errors.Join(result.err, err)
	a.done <- result
	return event, err
}

type p6CancelStorage struct{}

func (p6CancelStorage) Put(context.Context, string, []byte) error {
	return errors.New("unexpected output write in queued cancellation")
}

func (p6CancelStorage) Get(context.Context, string, int64) ([]byte, error) {
	return nil, errors.New("unexpected output read in queued cancellation")
}

// Use an actual SDK request and the real P6 transaction. Cancellation happens
// only after an independent PG read observes the committed cancellation write.
func TestSDKP6CommittedCancellationResultAudit(t *testing.T) {
	f := newTransportFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dir := t.TempDir()
	ca, err := hostconn.OpenCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := hostconn.New(f.db, ca, hostconn.DefaultConfig(), hostconn.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	spy := &p6CancelAudit{Appender: audit.New(f.db.Pool, audit.Config{}), db: f.db, done: make(chan p6CancelResult, 1)}
	jobs, err := job.New(f.db, f.identity, hosts, p6CancelStorage{}, spy, f.catalogs.Trusted, job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	hosts.Hooks = jobs.Hooks()
	if err := hosts.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hosts.Close)
	jobs.Start()
	t.Cleanup(jobs.Close)
	const id = "job-20261021-7001"
	if _, err := f.db.Pool.Exec(ctx, `INSERT INTO jobs(job_id,created_at,subject_id,origin_instance,action,action_definition,catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures)
      VALUES ($1,now(),'admin',$2,'logs_read',convert_to('{}','UTF8'),'fixture',1,decode(repeat('00',32),'hex'),1,'queued cancellation fixture',1,1,0);
      `, id, hosts.InstanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Pool.Exec(ctx, `CREATE TABLE tasks_p6_rework PARTITION OF tasks DEFAULT;
      INSERT INTO tasks(job_id,task_id,created_at,host_id,hostname,position,status,result)
      SELECT job_id,'queued-task',created_at,'web-01','web-01',0,1,decode('0801','hex') FROM jobs WHERE job_id='job-20261021-7001'`); err != nil {
		t.Fatal(err)
	}
	service, err := New(f.identity, f.catalogs, jobs, Config{ProgressInterval: 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	handler := service.Handler()
	gateway := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, cancel := context.WithCancel(r.Context())
		defer cancel()
		request = context.WithValue(request, p6CancelRequestKey{}, p6CancelRequest{request, cancel})
		handler.ServeHTTP(w, r.WithContext(request))
	}))
	gateway.StartTLS()
	t.Cleanup(gateway.Close)
	transport := &bearerTransport{base: gateway.Client().Transport, token: f.admin}
	client := sdk.NewClient(&sdk.Implementation{Name: "p6-write-cancel-rework", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: gateway.URL + "/mcp", HTTPClient: &http.Client{Transport: transport}, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	_, callErr := session.CallTool(ctx, &sdk.CallToolParams{Name: "jobs_cancel", Arguments: map[string]any{"job_id": id}})
	select {
	case result := <-spy.done:
		if result.err != nil || !result.committed || !result.cancelled || !result.detached || !result.valueRetained || result.remaining <= 0 || result.remaining > 5*time.Second {
			t.Fatalf("P6 result err=%v committed=%t request_cancelled=%t detached=%t value_retained=%t remaining=%s", result.err, result.committed, result.cancelled, result.detached, result.valueRetained, result.remaining)
		}
		t.Logf("SDK response error=%v; committed P6 cancellation result appended", callErr)
	case <-ctx.Done():
		t.Fatal("real P6 result boundary not reached")
	}
	for _, phase := range []string{"authorized", "result"} {
		var count int
		if err := f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE operation='cancel_job' AND reason=$1 AND decision='allow' AND job_id=$2 AND subject_id='admin' AND source_ip='127.0.0.1'`, phase, id).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("P6 %s persisted rows=%d; want 1", phase, count)
		}
	}
	var last uint64
	if err := f.db.Pool.QueryRow(ctx, "SELECT max(seq) FROM audit_events").Scan(&last); err != nil {
		t.Fatal(err)
	}
	verified, err := audit.New(f.db.Pool, audit.Config{}).Verify(ctx, audit.VerifyOptions{From: 1, To: last})
	if err != nil || !verified.Valid {
		t.Fatalf("P7 verification=%+v error=%v", verified, err)
	}
}
