package job

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

// A database stall for one task must not hold the output-map mutex for other
// tasks. A trigger gives us a deterministic stall after OnMessage locks its row.
func concurrencyFixture(t *testing.T) *Service {
	t.Helper()
	dsn := testpg.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if _, err := db.Pool.Exec(ctx, `INSERT INTO gateway_instances(instance_id) VALUES ('fixture');
 INSERT INTO hosts(host_id,hostname,certificate_serial,certificate_expires_at) VALUES ('slow','slow','serial-slow',now()+interval '1 hour'),('fast','fast','serial-fast',now()+interval '1 hour');
 INSERT INTO jobs(job_id,created_at,subject_id,origin_instance,action,action_definition,catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures)
 VALUES ('job',now(),'sa','fixture','action',convert_to('{}','UTF8'),'catalog',1,decode(repeat('00',32),'hex'),1,'test',2,20,5);
 CREATE TABLE tasks_fixture PARTITION OF tasks DEFAULT;
 INSERT INTO tasks(job_id,task_id,created_at,host_id,hostname,position,connection_id,dispatched,status,result)
 SELECT job_id,task,created_at,task,task,position,'connection',true,1,decode('0801','hex') FROM jobs CROSS JOIN (VALUES ('slow',0),('fast',1)) AS t(task,position);
 CREATE FUNCTION stall_task() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.task_id='slow' THEN PERFORM pg_advisory_xact_lock(918006); END IF;
 RETURN NEW; END $$;
 CREATE TRIGGER stall_task BEFORE UPDATE ON tasks FOR EACH ROW EXECUTE FUNCTION stall_task();`); err != nil {
		t.Fatal(err)
	}
	return &Service{Store: db, Storage: noopStorage{}, outputs: map[string]*taskOutput{}}
}

func TestTaskEventsProgressIndependently(t *testing.T) {
	s := concurrencyFixture(t)
	db := s.Store
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	blocker, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, "SELECT pg_advisory_xact_lock(918006)"); err != nil {
		t.Fatal(err)
	}
	started := func(id string) error {
		return s.OnMessage(ctx, hostconn.Event{HostID: id, ConnectionID: "connection", Message: &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: id}}}})
	}
	slow := make(chan error, 1)
	go func() { slow <- started("slow") }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=918006 AND NOT granted)").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slow task did not reach controlled SQL stall")
		}
		time.Sleep(10 * time.Millisecond)
	}
	fast := make(chan error, 1)
	go func() { fast <- started("fast") }()
	independent := false
	select {
	case err := <-fast:
		if err != nil {
			t.Error(err)
		}
		independent = true
	case <-time.After(2 * time.Second):
	}
	// Release the controlled stall and join both handlers before closing the pool.
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-slow; err != nil {
		t.Error(err)
	}
	if !independent {
		if err := <-fast; err != nil {
			t.Error(err)
		}
		t.Fatal("fast task blocked behind unrelated slow task SQL; want independent progress")
	}
	// The same task still uses its row lock and rejects a duplicate start.
	if err := started("fast"); err == nil || err.Error() != "DUPLICATE_TASK_START" {
		t.Fatalf("duplicate start error=%v", err)
	}
}

type reservationRouter struct{ sent chan string }

func (r reservationRouter) Send(context.Context, string, *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	return nil, errors.New("unbound dispatch")
}

func (r reservationRouter) SendToConnection(_ context.Context, host, connection string, _ *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	if connection != "connection" {
		return nil, errors.New("unexpected connection generation")
	}
	r.sent <- host
	return nil, nil
}

func TestDispatchReservationsShareJobLock(t *testing.T) {
	s := concurrencyFixture(t)
	db := s.Store
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := db.Pool.Exec(ctx, "UPDATE hosts SET instance_id='fixture',connection_id='connection'; UPDATE tasks SET dispatched=false"); err != nil {
		t.Fatal(err)
	}
	blocker, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err = blocker.Exec(ctx, "SELECT pg_advisory_xact_lock(918006)"); err != nil {
		t.Fatal(err)
	}
	router := reservationRouter{sent: make(chan string, 2)}
	s.Router = router
	dispatch := func(id string) {
		s.dispatch(ctx, &v1.Job{JobId: "job"}, &v1.Task{TaskId: id, HostId: id}, catalog.Action{Timeout: "5s"}, &v1.RunJobRequest{})
	}
	slowDone := make(chan struct{})
	go func() { defer close(slowDone); dispatch("slow") }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=918006 AND NOT granted)").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slow reservation did not reach controlled SQL stall")
		}
		time.Sleep(10 * time.Millisecond)
	}
	fastDone := make(chan struct{})
	go func() { defer close(fastDone); dispatch("fast") }()
	independent := false
	select {
	case host := <-router.sent:
		if host != "fast" {
			t.Errorf("first dispatch=%s want fast", host)
		}
		independent = true
	case <-time.After(2 * time.Second):
	}
	// CancelJob/finish/recovery still need an exclusive lock, which must conflict
	// with the in-flight reservation even when other reservations may proceed.
	cancelTx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cancelTx.Exec(ctx, "SELECT job_id FROM jobs WHERE job_id='job' FOR UPDATE NOWAIT")
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
		t.Errorf("exclusive cancellation lock error=%v want lock_not_available", err)
	}
	cancelTx.Rollback(ctx)
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	<-slowDone
	<-fastDone
	if !independent {
		t.Fatal("fast reservation blocked behind unrelated slow reservation; want concurrent reservations")
	}
	var bound int
	if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM tasks WHERE dispatched AND connection_id='connection'").Scan(&bound); err != nil || bound != 2 {
		t.Fatalf("bound tasks=%d error=%v", bound, err)
	}
	// Once reservations commit, cancellation can take the exclusive lock.
	cancelTx, err = db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelTx.Rollback(ctx)
	if _, err := cancelTx.Exec(ctx, "SELECT job_id FROM jobs WHERE job_id='job' FOR UPDATE NOWAIT"); err != nil {
		t.Fatal(err)
	}
}

type postReservationWindowRouter struct {
	service             *Service
	reserved            chan string
	release             chan struct{}
	wroteTaskAssignment atomic.Bool
	receivedCancel      atomic.Bool
}

func (r *postReservationWindowRouter) Send(context.Context, string, *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	return nil, errors.New("unbound dispatch")
}

func (r *postReservationWindowRouter) SendToConnection(ctx context.Context, host, connection string, m *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	if c := m.GetCancel(); c != nil {
		r.receivedCancel.Store(true)
		return nil, nil
	}
	if task := m.GetTask(); task != nil {
		r.reserved <- host
		<-r.release
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r.wroteTaskAssignment.Store(true)
		_ = r.service.OnMessage(ctx, hostconn.Event{
			HostID:       host,
			ConnectionID: connection,
			Message: &v1.ConnectRequest{
				Message: &v1.ConnectRequest_TaskStarted{
					TaskStarted: &v1.TaskStarted{JobId: task.JobId, TaskId: task.TaskId},
				},
			},
		})
		if r.receivedCancel.Load() {
			return nil, nil
		}
		_ = r.service.OnMessage(ctx, hostconn.Event{
			HostID:       host,
			ConnectionID: connection,
			Message: &v1.ConnectRequest{
				Message: &v1.ConnectRequest_Output{
					Output: &v1.TaskOutputChunk{JobId: task.JobId, TaskId: task.TaskId, Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT, Eof: true},
				},
			},
		})
		_ = r.service.OnMessage(ctx, hostconn.Event{
			HostID:       host,
			ConnectionID: connection,
			Message: &v1.ConnectRequest{
				Message: &v1.ConnectRequest_Output{
					Output: &v1.TaskOutputChunk{JobId: task.JobId, TaskId: task.TaskId, Stream: v1.OutputStream_OUTPUT_STREAM_STDERR, Eof: true},
				},
			},
		})
		empty := sha256.Sum256(nil)
		completed := &v1.TaskCompleted{
			JobId:  task.JobId,
			TaskId: task.TaskId,
			Result: &v1.ExecutionResult{
				Status:   v1.TaskStatus_TASK_STATUS_SUCCEEDED,
				ExitCode: proto.Int32(0),
				Duration: durationpb.New(time.Millisecond),
				Stdout:   &v1.OutputMetadata{Sha256: empty[:]},
				Stderr:   &v1.OutputMetadata{Sha256: empty[:]},
			},
		}
		_ = r.service.OnMessage(ctx, hostconn.Event{
			HostID:       host,
			ConnectionID: connection,
			Message: &v1.ConnectRequest{
				Message: &v1.ConnectRequest_TaskCompleted{TaskCompleted: completed},
			},
		})
		return completed, nil
	}
	return nil, nil
}

func TestCancelJobDuringPostReservationWindow(t *testing.T) {
	s := concurrencyFixture(t)
	db := s.Store
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.Close()
	auditor := audit.New(db.Pool, audit.Config{})
	access, err := api.New(ctx, db, api.Config{Origin: "https://127.0.0.1:443"}, api.NewAuditor(auditor))
	if err != nil {
		t.Fatal(err)
	}
	s.Audit = auditor
	s.Access = access
	s.Previews = &DatabasePreviews{Store: db}

	token, record, err := authn.GenerateServiceToken(time.Now(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `
		DELETE FROM tasks WHERE task_id='slow';
		UPDATE hosts SET instance_id='fixture',connection_id='connection';
		UPDATE tasks SET dispatched=false,status=1 WHERE task_id='fast';
		INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username,manual_roles) VALUES ('owner','fixture','owner','oidc','owner','{admin}');
		INSERT INTO service_accounts(account_id,name,owner_user_id,roles) VALUES ('sa','fixture','owner','{admin}');
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, "INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES ('token','sa',$1,now()+interval '1 hour')", record.Hash[:]); err != nil {
		t.Fatal(err)
	}

	router := &postReservationWindowRouter{
		service:  s,
		reserved: make(chan string, 1),
		release:  make(chan struct{}),
	}
	s.Router = router

	dispatchDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		s.dispatch(ctx, &v1.Job{JobId: "job"}, &v1.Task{TaskId: "fast", HostId: "fast"}, catalog.Action{Timeout: "5s"}, &v1.RunJobRequest{})
	}()

	select {
	case host := <-router.reserved:
		if host != "fast" {
			t.Fatalf("reserved host=%s want fast", host)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch did not enter SendToConnection")
	}

	var cancelErr error
	req := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:443/mcp", nil)
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Authorization", "Bearer "+token)
	s.Access.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, cancelErr = s.CancelJob(r.Context(), &v1.CancelJobRequest{JobId: "job"})
	})).ServeHTTP(httptest.NewRecorder(), req)
	if cancelErr != nil {
		t.Fatalf("CancelJob error=%v", cancelErr)
	}

	close(router.release)
	<-dispatchDone
	s.wg.Wait()

	if router.wroteTaskAssignment.Load() {
		t.Errorf("TaskAssignment was still sent to host after CancelJob committed")
	}
	var taskStatus, jobStatus int16
	if err := db.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE job_id='job' AND task_id='fast'").Scan(&taskStatus); err != nil {
		t.Fatal(err)
	}
	if taskStatus != int16(v1.TaskStatus_TASK_STATUS_CANCELLED) {
		t.Errorf("task status=%d want %d (TASK_STATUS_CANCELLED)", taskStatus, v1.TaskStatus_TASK_STATUS_CANCELLED)
	}
	if err := db.Pool.QueryRow(ctx, "SELECT status FROM jobs WHERE job_id='job'").Scan(&jobStatus); err != nil {
		t.Fatal(err)
	}
	if jobStatus != int16(v1.JobStatus_JOB_STATUS_CANCELLED) {
		t.Errorf("job status=%d want %d (JOB_STATUS_CANCELLED)", jobStatus, v1.JobStatus_JOB_STATUS_CANCELLED)
	}
}

func TestRecoverLostInstancesDuringPostReservationWindow(t *testing.T) {
	s := concurrencyFixture(t)
	db := s.Store
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.Close()
	s.Audit = audit.New(db.Pool, audit.Config{})
	s.instanceID = "survivor"
	s.lostAfter = 10 * time.Second

	if _, err := db.Pool.Exec(ctx, `
		DELETE FROM tasks WHERE task_id='slow';
		UPDATE hosts SET instance_id='fixture',connection_id='connection';
		UPDATE tasks SET dispatched=false,status=1 WHERE task_id='fast';
	`); err != nil {
		t.Fatal(err)
	}

	router := &postReservationWindowRouter{
		service:  s,
		reserved: make(chan string, 1),
		release:  make(chan struct{}),
	}
	s.Router = router

	dispatchDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		s.dispatch(ctx, &v1.Job{JobId: "job"}, &v1.Task{TaskId: "fast", HostId: "fast"}, catalog.Action{Timeout: "5s"}, &v1.RunJobRequest{})
	}()

	select {
	case <-router.reserved:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch did not enter SendToConnection")
	}

	if _, err := db.Pool.Exec(ctx, "UPDATE gateway_instances SET last_seen=now()-interval '1 minute' WHERE instance_id='fixture'"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverLostInstances(ctx); err != nil {
		t.Fatalf("RecoverLostInstances error=%v", err)
	}

	close(router.release)
	<-dispatchDone

	if router.wroteTaskAssignment.Load() {
		t.Errorf("in-flight dispatch wrote TaskAssignment after RecoverLostInstances finished job")
	}

	// Also verify that if a late TaskStarted arrives for a recovered/terminal task,
	// OnMessage actively sends CancelTask to terminate the orphan process on the host.
	if err := s.OnMessage(ctx, hostconn.Event{
		HostID:       "fast",
		ConnectionID: "connection",
		Message: &v1.ConnectRequest{
			Message: &v1.ConnectRequest_TaskStarted{
				TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: "fast"},
			},
		},
	}); err != nil {
		t.Fatalf("late TaskStarted error=%v", err)
	}
	s.wg.Wait()
	if !router.receivedCancel.Load() {
		t.Errorf("expected CancelTask to be sent when TaskStarted arrives for terminal task")
	}

	var taskStatus, jobStatus int16
	if err := db.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE job_id='job' AND task_id='fast'").Scan(&taskStatus); err != nil {
		t.Fatal(err)
	}
	if taskStatus != int16(v1.TaskStatus_TASK_STATUS_SKIPPED) {
		t.Errorf("task status=%d want %d (TASK_STATUS_SKIPPED)", taskStatus, v1.TaskStatus_TASK_STATUS_SKIPPED)
	}
	if err := db.Pool.QueryRow(ctx, "SELECT status FROM jobs WHERE job_id='job'").Scan(&jobStatus); err != nil {
		t.Fatal(err)
	}
	if jobStatus != int16(v1.JobStatus_JOB_STATUS_FAILED) {
		t.Errorf("job status=%d want %d (JOB_STATUS_FAILED)", jobStatus, v1.JobStatus_JOB_STATUS_FAILED)
	}
}

func TestOnMessageRollbackPreservesInMemoryOutputState(t *testing.T) {
	s := concurrencyFixture(t)
	db := s.Store
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	actionDef, err := json.Marshal(catalog.Action{
		Name:      "action",
		MaxOutput: 1024,
		Steps:     []catalog.Step{{Name: "first", Exec: []any{"/usr/bin/true"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, "UPDATE jobs SET action_definition=$1 WHERE job_id='job'", actionDef); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `
		DELETE FROM tasks WHERE task_id='slow';
		CREATE TABLE commit_fail(fail boolean NOT NULL);
		INSERT INTO commit_fail VALUES (false);
		CREATE FUNCTION check_commit_fail() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF (SELECT fail FROM commit_fail LIMIT 1) THEN
				RAISE EXCEPTION 'simulated deferred commit failure';
			END IF;
			RETURN NULL;
		END $$;
		CREATE CONSTRAINT TRIGGER fail_tasks_commit AFTER INSERT OR UPDATE ON tasks DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_commit_fail();
		CREATE CONSTRAINT TRIGGER fail_steps_commit AFTER INSERT OR UPDATE ON task_steps DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_commit_fail();
	`); err != nil {
		t.Fatal(err)
	}

	// 1. Pre-validation failure (output chunk before TaskStarted) must not leave an entry in s.outputs.
	stepIdx := uint32(0)
	chunkEvent := hostconn.Event{
		HostID:       "fast",
		ConnectionID: "connection",
		Message: &v1.ConnectRequest{
			Message: &v1.ConnectRequest_Output{
				Output: &v1.TaskOutputChunk{
					JobId:     "job",
					TaskId:    "fast",
					StepIndex: &stepIdx,
					Stream:    v1.OutputStream_OUTPUT_STREAM_STDOUT,
					Offset:    0,
					Data:      []byte("hello"),
					Eof:       true,
				},
			},
		},
	}
	if err := s.OnMessage(ctx, chunkEvent); err == nil {
		t.Fatal("expected error for output chunk before TaskStarted")
	}
	s.mu.Lock()
	outputsCount := len(s.outputs)
	s.mu.Unlock()
	if outputsCount != 0 {
		t.Errorf("s.outputs count=%d after failed validation; want 0", outputsCount)
	}

	// Start task normally.
	if err := s.OnMessage(ctx, hostconn.Event{
		HostID:       "fast",
		ConnectionID: "connection",
		Message: &v1.ConnectRequest{
			Message: &v1.ConnectRequest_TaskStarted{
				TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: "fast"},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// 2. TaskOutputChunk commit failure must not pollute out.Streams or out.Bytes.
	key := outputID("job", "fast")
	s.mu.Lock()
	out := s.outputs[key]
	if out == nil {
		out = &taskOutput{Streams: map[streamKey]*streamOutput{}}
		s.outputs[key] = out
	}
	s.mu.Unlock()

	out.mu.Lock()
	chunkCtx, cancelChunk := context.WithCancel(ctx)
	chunkErrCh := make(chan error, 1)
	go func() {
		chunkErrCh <- s.OnMessage(chunkCtx, chunkEvent)
	}()
	// Wait until OnMessage has acquired the task row lock and is waiting for out.mu.
	deadline := time.Now().Add(5 * time.Second)
	for {
		probeTx, err := db.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = probeTx.Exec(ctx, "SELECT 1 FROM tasks WHERE job_id='job' AND task_id='fast' FOR UPDATE NOWAIT")
		_ = probeTx.Rollback(ctx)
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) && pgerr.Code == "55P03" {
			break
		}
		if time.Now().After(deadline) {
			out.mu.Unlock()
			cancelChunk()
			t.Fatal("chunk handler did not acquire task row lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancelChunk()
	out.mu.Unlock()
	if err := <-chunkErrCh; err == nil {
		t.Fatal("expected TaskOutputChunk commit to fail when context is cancelled before commit")
	}
	out.mu.Lock()
	bytesAfterRollback := out.Bytes
	streamAfterRollback := out.Streams[streamKey{0, v1.OutputStream_OUTPUT_STREAM_STDOUT}]
	if bytesAfterRollback != 0 || (streamAfterRollback != nil && (len(streamAfterRollback.Data) != 0 || streamAfterRollback.EOF)) {
		t.Errorf("in-memory output modified despite rollback: bytes=%d stream=%+v", bytesAfterRollback, streamAfterRollback)
		// Reset so subsequent test steps can proceed.
		out.Bytes = 0
		delete(out.Streams, streamKey{0, v1.OutputStream_OUTPUT_STREAM_STDOUT})
	}
	out.mu.Unlock()

	// Retrying the same chunk with a valid context must succeed.
	if err := s.OnMessage(ctx, chunkEvent); err != nil {
		t.Fatalf("retry TaskOutputChunk after rollback failed: %v", err)
	}
	if err := s.OnMessage(ctx, hostconn.Event{
		HostID:       "fast",
		ConnectionID: "connection",
		Message: &v1.ConnectRequest{
			Message: &v1.ConnectRequest_Output{
				Output: &v1.TaskOutputChunk{
					JobId:     "job",
					TaskId:    "fast",
					StepIndex: &stepIdx,
					Stream:    v1.OutputStream_OUTPUT_STREAM_STDERR,
					Offset:    0,
					Eof:       true,
				},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// 3. StepCompleted commit failure via deferred constraint trigger must keep out.Steps in sync with DB task_steps.
	if _, err := db.Pool.Exec(ctx, "UPDATE commit_fail SET fail=true"); err != nil {
		t.Fatal(err)
	}
	helloSum := sha256.Sum256([]byte("hello"))
	emptySum := sha256.Sum256(nil)
	stepEvent := hostconn.Event{
		HostID:       "fast",
		ConnectionID: "connection",
		Message: &v1.ConnectRequest{
			Message: &v1.ConnectRequest_StepCompleted{
				StepCompleted: &v1.StepCompleted{
					JobId:     "job",
					TaskId:    "fast",
					StepIndex: 0,
					StepName:  "first",
					Result: &v1.ExecutionResult{
						Status:   v1.TaskStatus_TASK_STATUS_SUCCEEDED,
						ExitCode: proto.Int32(0),
						Duration: durationpb.New(time.Millisecond),
						Stdout:   &v1.OutputMetadata{SizeBytes: 5, Sha256: helloSum[:]},
						Stderr:   &v1.OutputMetadata{SizeBytes: 0, Sha256: emptySum[:]},
					},
				},
			},
		},
	}
	if err := s.OnMessage(ctx, stepEvent); err == nil {
		t.Fatal("expected StepCompleted commit to fail via deferred constraint trigger")
	}
	var dbSteps int
	if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM task_steps WHERE job_id='job' AND task_id='fast'").Scan(&dbSteps); err != nil {
		t.Fatal(err)
	}
	out.mu.Lock()
	memSteps := len(out.Steps)
	out.mu.Unlock()
	if dbSteps != 0 || memSteps != 0 {
		t.Fatalf("after StepCompleted commit failure: dbSteps=%d memSteps=%d; want both 0", dbSteps, memSteps)
	}

	// Re-enable commits and verify StepCompleted retry succeeds.
	if _, err := db.Pool.Exec(ctx, "UPDATE commit_fail SET fail=false"); err != nil {
		t.Fatal(err)
	}
	if err := s.OnMessage(ctx, stepEvent); err != nil {
		t.Fatalf("retry StepCompleted after rollback failed: %v", err)
	}
}

func TestDispatchReservationFailureDoesNotLeaveJobStuckRunning(t *testing.T) {
	s := concurrencyFixture(t)
	db := s.Store
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := db.Pool.Exec(ctx, `
		DELETE FROM tasks WHERE task_id='slow';
		UPDATE hosts SET instance_id='fixture',connection_id='connection';
		UPDATE tasks SET dispatched=false,status=1 WHERE task_id='fast';
	`); err != nil {
		t.Fatal(err)
	}

	// 1. Verify P6: duplicate reservation for an already-dispatched status=1 task must be rejected by AND NOT dispatched.
	router := reservationRouter{sent: make(chan string, 2)}
	s.Router = router
	s.dispatch(ctx, &v1.Job{JobId: "job"}, &v1.Task{TaskId: "fast", HostId: "fast"}, catalog.Action{Timeout: "5s"}, &v1.RunJobRequest{})
	if len(router.sent) != 1 {
		t.Fatalf("initial dispatch count=%d want 1", len(router.sent))
	}
	if _, err := db.Pool.Exec(ctx, "UPDATE hosts SET connection_id='connection-2' WHERE host_id='fast'"); err != nil {
		t.Fatal(err)
	}
	s.dispatch(ctx, &v1.Job{JobId: "job"}, &v1.Task{TaskId: "fast", HostId: "fast"}, catalog.Action{Timeout: "5s"}, &v1.RunJobRequest{})
	if len(router.sent) != 1 {
		t.Errorf("duplicate dispatch sent %d times; want 1 (blocked by AND NOT dispatched)", len(router.sent))
	}
	var connID string
	if err := db.Pool.QueryRow(ctx, "SELECT connection_id FROM tasks WHERE job_id='job' AND task_id='fast'").Scan(&connID); err != nil {
		t.Fatal(err)
	}
	if connID != "connection" {
		t.Errorf("task connection_id overwritten to %s; want connection", connID)
	}

	// 2. Verify P5 (if cancel branch): dispatch rolls back tx before calling setTerminal so it does not require 2 pool connections simultaneously.
	if _, err := db.Pool.Exec(ctx, "UPDATE jobs SET cancel_requested=true WHERE job_id='job'; UPDATE tasks SET dispatched=false,status=1 WHERE task_id='fast'"); err != nil {
		t.Fatal(err)
	}
	maxConns := int(db.Pool.Config().MaxConns)
	txs := make([]interface{ Rollback(context.Context) error }, 0, maxConns-1)
	for i := 0; i < maxConns-1; i++ {
		tx, err := db.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		txs = append(txs, tx)
	}
	cancelCtx, cancelDone := context.WithTimeout(ctx, 500*time.Millisecond)
	s.dispatch(cancelCtx, &v1.Job{JobId: "job"}, &v1.Task{TaskId: "fast", HostId: "fast"}, catalog.Action{Timeout: "5s"}, &v1.RunJobRequest{})
	cancelDone()
	for _, tx := range txs {
		_ = tx.Rollback(ctx)
	}
	var cancelledTaskStatus int16
	if err := db.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE job_id='job' AND task_id='fast'").Scan(&cancelledTaskStatus); err != nil {
		t.Fatal(err)
	}
	if cancelledTaskStatus != int16(v1.TaskStatus_TASK_STATUS_CANCELLED) {
		t.Errorf("if-cancel task status=%d want %d (TASK_STATUS_CANCELLED)", cancelledTaskStatus, v1.TaskStatus_TASK_STATUS_CANCELLED)
	}

	// 3. Verify P5 (reservation tx failure): if reservation UPDATE fails, schedule still marks task and job terminal instead of leaving them PENDING / RUNNING.
	if _, err := db.Pool.Exec(ctx, `
		UPDATE jobs SET cancel_requested=false,status=2 WHERE job_id='job';
		UPDATE tasks SET dispatched=false,status=1 WHERE task_id='fast';
		CREATE FUNCTION fail_reservation_update() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.dispatched AND NEW.status=1 THEN
				RAISE EXCEPTION 'simulated reservation failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER fail_reservation_update BEFORE UPDATE ON tasks FOR EACH ROW EXECUTE FUNCTION fail_reservation_update();
	`); err != nil {
		t.Fatal(err)
	}
	if err := s.schedule(ctx, &v1.Job{JobId: "job"}, catalog.Action{Timeout: "5s"}, &v1.RunJobRequest{}, 20, 5); err != nil {
		t.Fatalf("schedule error=%v", err)
	}
	var finalTaskStatus, finalJobStatus int16
	if err := db.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE job_id='job' AND task_id='fast'").Scan(&finalTaskStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, "SELECT status FROM jobs WHERE job_id='job'").Scan(&finalJobStatus); err != nil {
		t.Fatal(err)
	}
	if finalTaskStatus <= 2 || finalJobStatus <= 2 {
		t.Errorf("after reservation failure: taskStatus=%d jobStatus=%d; want both terminal (>2)", finalTaskStatus, finalJobStatus)
	}
}
