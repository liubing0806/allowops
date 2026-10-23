package job

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"google.golang.org/protobuf/proto"
)

type vfx6PauseCommit struct{}
type vfx6SQL struct{}

type vfx6Tracer struct {
	committed chan struct{}
	release   chan struct{}
}

func (p *vfx6Tracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if ctx.Value(vfx6PauseCommit{}) != nil && d.SQL == "commit" {
		return context.WithValue(ctx, vfx6SQL{}, true)
	}
	return ctx
}

func (p *vfx6Tracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if ctx.Value(vfx6SQL{}) == true && d.Err == nil {
		close(p.committed)
		<-p.release
	}
}

func TestVFX6TaskStartedAfterTerminalCleanupLeaksBuffer(t *testing.T) {
	s := concurrencyFixture(t)
	ctx := context.Background()
	tracer := &vfx6Tracer{committed: make(chan struct{}), release: make(chan struct{})}
	cfg := s.Store.Pool.Config()
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	traced := *s.Store
	traced.Pool = pool
	s.Store = &traced
	done := make(chan error, 1)
	go func() {
		done <- s.OnMessage(context.WithValue(ctx, vfx6PauseCommit{}, true), hostconn.Event{HostID: "fast", ConnectionID: "connection", Message: &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: "fast"}}}})
	}()
	<-tracer.committed
	if err := s.setTerminal(ctx, "job", "fast", &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_OFFLINE, Reason: "OFFLINE"}); err != nil {
		t.Fatal(err)
	}
	close(tracer.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var state int16
	if err := pool.QueryRow(ctx, "SELECT status FROM tasks WHERE task_id='fast'").Scan(&state); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	n := len(s.outputs)
	s.mu.Unlock()
	t.Logf("terminal status=%d outputs entries=%d after TaskStarted resumed following terminal cleanup", state, n)
	if n != 0 {
		t.Errorf("terminal task recreated %d output buffer(s) after cleanup; want 0", n)
	}
}

func TestVFX6FailedSetTerminalPreservesLiveOutput(t *testing.T) {
	s := concurrencyFixture(t)
	ctx := context.Background()
	if _, err := s.Store.Pool.Exec(ctx, `UPDATE jobs SET action_definition=convert_to('{"max_output":1024}','UTF8') WHERE job_id='job'`); err != nil {
		t.Fatal(err)
	}
	started := hostconn.Event{HostID: "fast", ConnectionID: "connection", Message: &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: "fast"}}}}
	if err := s.OnMessage(ctx, started); err != nil {
		t.Fatal(err)
	}
	chunk := hostconn.Event{HostID: "fast", ConnectionID: "connection", Message: &v1.ConnectRequest{Message: &v1.ConnectRequest_Output{Output: &v1.TaskOutputChunk{JobId: "job", TaskId: "fast", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT, Data: []byte("hello")}}}}
	if err := s.OnMessage(ctx, chunk); err != nil {
		t.Fatal(err)
	}
	dead, cancel := context.WithCancel(ctx)
	cancel()
	err := s.setTerminal(dead, "job", "fast", &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_OFFLINE, Reason: "OFFLINE"})
	if err == nil {
		t.Fatal("expected canceled database update to fail")
	}
	var state int16
	if e := s.Store.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE task_id='fast'").Scan(&state); e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	n := len(s.outputs)
	s.mu.Unlock()
	chunk.Message.GetOutput().Offset = 5
	nextErr := s.OnMessage(ctx, chunk)
	t.Logf("setTerminal error=%v task status=%d buffer count=%d next chunk error=%v", err, state, n, nextErr)
	if state != 2 || n != 1 || nextErr != nil {
		t.Errorf("failed terminal update lost running task output: status=%d buffers=%d next chunk=%v; want 2,1,nil", state, n, nextErr)
	}
	// A server-side SQL failure must preserve the same live state as a canceled
	// client context. Continue at the offset of all previously accepted bytes.
	if _, err := s.Store.Pool.Exec(ctx, `CREATE FUNCTION reject_terminal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
	 IF NEW.task_id='fast' AND NEW.status=6 THEN RAISE EXCEPTION 'fixture terminal write rejected'; END IF;
	 RETURN NEW; END $$;
	 CREATE TRIGGER reject_terminal BEFORE UPDATE ON tasks FOR EACH ROW EXECUTE FUNCTION reject_terminal();`); err != nil {
		t.Fatal(err)
	}
	if err := s.setTerminal(ctx, "job", "fast", &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_OFFLINE}); err == nil {
		t.Fatal("expected fixture terminal write rejection")
	}
	chunk.Message.GetOutput().Offset = 10
	if err := s.OnMessage(ctx, chunk); err != nil {
		t.Errorf("server-side failed terminal update lost live output: %v", err)
	}

}

func TestVFX6CloseContextBeforeReservationPreservesPending(t *testing.T) {
	s := concurrencyFixture(t)
	ctx := context.Background()
	if _, err := s.Store.Pool.Exec(ctx, "DELETE FROM tasks WHERE task_id='slow'; UPDATE tasks SET dispatched=false WHERE task_id='fast'"); err != nil {
		t.Fatal(err)
	}
	dead, cancel := context.WithCancel(ctx)
	cancel()
	s.dispatch(dead, &v1.Job{JobId: "job"}, &v1.Task{TaskId: "fast", HostId: "fast"}, catalog.Action{Timeout: "5s"}, &v1.RunJobRequest{})
	var status int16
	var raw []byte
	if err := s.Store.Pool.QueryRow(ctx, "SELECT status,result FROM tasks WHERE task_id='fast'").Scan(&status, &raw); err != nil {
		t.Fatal(err)
	}
	r := &v1.ExecutionResult{}
	if err := proto.Unmarshal(raw, r); err != nil {
		t.Fatal(err)
	}
	t.Logf("already cancelled service context before reservation: task status=%d reason=%s", status, r.Reason)
	if status != 1 || r.Reason != "" {
		t.Errorf("pre-reservation shutdown changed pending task: %d %s; want 1 and empty reason", status, r.Reason)
	}
	if _, err := s.Store.Pool.Exec(ctx, "UPDATE gateway_instances SET last_seen=now()-interval '1 minute'"); err != nil {
		t.Fatal(err)
	}
	survivor := &Service{Store: s.Store, Audit: audit.New(s.Store.Pool, audit.Config{}), instanceID: "survivor", lostAfter: 10 * time.Second}
	if err := survivor.RecoverLostInstances(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.Pool.QueryRow(ctx, "SELECT status,result FROM tasks WHERE task_id='fast'").Scan(&status, &raw); err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(raw, r); err != nil {
		t.Fatal(err)
	}
	if status != int16(v1.TaskStatus_TASK_STATUS_SKIPPED) || r.Reason != "GATEWAY_INSTANCE_LOST" {
		t.Errorf("survivor recovered task as %d %s; want SKIPPED/GATEWAY_INSTANCE_LOST", status, r.Reason)
	}

}

func TestVFX6RemoteRecoveryReleasesOriginalOwnerOutput(t *testing.T) {
	s := concurrencyFixture(t)
	ctx := context.Background()
	if _, err := s.Store.Pool.Exec(ctx, `UPDATE jobs SET action_definition=convert_to('{"max_output":1024}','UTF8');UPDATE gateway_instances SET last_seen=now()-interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	for _, message := range []*v1.ConnectRequest{
		{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: "fast"}}},
		{Message: &v1.ConnectRequest_Output{Output: &v1.TaskOutputChunk{JobId: "job", TaskId: "fast", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT, Data: []byte("hello")}}},
	} {
		if err := s.OnMessage(ctx, hostconn.Event{HostID: "fast", ConnectionID: "connection", Message: message}); err != nil {
			t.Fatal(err)
		}
	}
	survivor := &Service{Store: s.Store, Audit: audit.New(s.Store.Pool, audit.Config{}), instanceID: "survivor", lostAfter: 10 * time.Second, outputs: map[string]*taskOutput{}}
	if err := survivor.RecoverLostInstances(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.Pool.Exec(ctx, `INSERT INTO tasks(job_id,task_id,created_at,host_id,hostname,position,connection_id,dispatched,status,result)
	 SELECT job_id,'replacement',created_at,'fast','fast',2,'new-connection',true,2,decode('0802','hex') FROM jobs WHERE job_id='job'`); err != nil {
		t.Fatal(err)
	}
	if err := s.OnMessage(ctx, hostconn.Event{HostID: "fast", ConnectionID: "new-connection", Message: &v1.ConnectRequest{Message: &v1.ConnectRequest_Output{Output: &v1.TaskOutputChunk{JobId: "job", TaskId: "replacement", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT, Data: []byte("new")}}}}); err != nil {
		t.Fatal(err)
	}

	s.OnDisconnect(hostconn.Event{HostID: "fast", ConnectionID: "connection"})
	s.mu.Lock()
	n := len(s.outputs)
	var bytes int64
	for _, out := range s.outputs {
		out.mu.Lock()
		bytes += out.Bytes
		out.mu.Unlock()
	}
	s.mu.Unlock()
	t.Logf("original owner after remote recovery + OnDisconnect: buffers=%d retained bytes=%d", n, bytes)
	if n != 1 || bytes != 3 {
		t.Errorf("disconnect retained buffers=%d bytes=%d; want only replacement generation: 1 buffer, 3 bytes", n, bytes)
	}
	s.OnDisconnect(hostconn.Event{HostID: "fast", ConnectionID: "new-connection"})
	if len(s.outputs) != 0 {
		t.Errorf("replacement disconnect retained %d output buffers", len(s.outputs))
	}
}

func TestVFX6FirstTerminalWinsAndLateCompletionIgnored(t *testing.T) {
	s := concurrencyFixture(t)
	ctx := context.Background()
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.Close()
	router := &postReservationWindowRouter{}
	s.Router = router
	for _, terminal := range []v1.TaskStatus{v1.TaskStatus_TASK_STATUS_SUCCEEDED, v1.TaskStatus_TASK_STATUS_CANCELLED} {
		router.receivedCancel.Store(false)
		if _, err := s.Store.Pool.Exec(ctx, "UPDATE tasks SET status=$1,result=$2 WHERE task_id='fast'", int16(terminal), pendingResult(terminal, "")); err != nil {
			t.Fatal(err)
		}
		completed := &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskCompleted{TaskCompleted: &v1.TaskCompleted{JobId: "job", TaskId: "fast", Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_SUCCEEDED}}}}
		if err := s.OnMessage(ctx, hostconn.Event{HostID: "fast", ConnectionID: "connection", Message: completed}); err != nil {
			t.Fatal(err)
		}
		if router.receivedCancel.Load() {
			t.Errorf("late TaskCompleted triggered CancelTask")
		}
		if err := s.setTerminal(ctx, "job", "fast", &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_CANCELLED, Reason: "CANCELLED"}); err != nil {
			t.Fatal(err)
		}
		var actual int16
		if err := s.Store.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE task_id='fast'").Scan(&actual); err != nil {
			t.Fatal(err)
		}
		if actual != int16(terminal) {
			t.Errorf("first terminal=%d overwritten by=%d", terminal, actual)
		}
		started := &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: "fast"}}}
		if err := s.OnMessage(ctx, hostconn.Event{HostID: "fast", ConnectionID: "connection", Message: started}); err != nil {
			t.Fatal(err)
		}
		s.wg.Wait()
		t.Logf("first terminal=%s unchanged=%d; late TaskCompleted cancel=false; late TaskStarted cancel=%t", terminal, actual, router.receivedCancel.Load())
	}
}

func TestVFX6CloseWaitsForUnboundedTerminalWriteBeforeReservation(t *testing.T) {
	s := concurrencyFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.Store.Pool.Exec(ctx, "UPDATE tasks SET dispatched=false WHERE task_id='fast'"); err != nil {
		t.Fatal(err)
	}
	blocker, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, "SELECT 1 FROM tasks WHERE task_id='fast' FOR UPDATE"); err != nil {
		t.Fatal(err)
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.cancel()
	dispatchDone := make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(dispatchDone)
		s.dispatch(s.ctx, &v1.Job{JobId: "job"}, &v1.Task{TaskId: "fast", HostId: "fast"}, catalog.Action{Timeout: "5s"}, &v1.RunJobRequest{})
	}()
	// Detect the production UPDATE blocked on the task row; no sleep guesses at entry.
	for {
		select {
		case <-dispatchDone:
			s.Close()
			t.Log("cancelled pre-reservation dispatch returned without a terminal database write")
			return
		default:
		}
		var blocked bool
		if err := s.Store.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE tasks SET status=%')").Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	closeDone := make(chan struct{})
	go func() { s.Close(); close(closeDone) }()
	select {
	case <-closeDone:
		t.Log("Close returned while a terminal write remained blocked")
	case <-time.After(200 * time.Millisecond):
		t.Errorf("Close still blocked on terminal UPDATE after service context was already cancelled before reservation; write context has no deadline")
	}
	// Always release the local fixture lock and join both goroutines.
	if err := blocker.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-closeDone
}

// After a committed reservation, cancellation of the service must not prevent
// the required terminal write; that write must have its own short deadline.
type fx6CancelRouter struct{ cancel context.CancelFunc }

func (r fx6CancelRouter) Send(context.Context, string, *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	r.cancel()
	return nil, context.Canceled
}

type fx6DeadlineTracer struct{ deadlines chan time.Duration }

func (p fx6DeadlineTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(d.SQL, "UPDATE tasks SET status=$3,result=$4,finished_at=") {
		remaining := time.Duration(-1)
		if deadline, ok := ctx.Deadline(); ok {
			remaining = time.Until(deadline)
		}
		p.deadlines <- remaining
	}
	return ctx
}

func (fx6DeadlineTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestVFX6CancelledReservedDispatchBoundsTerminalWrite(t *testing.T) {
	s := concurrencyFixture(t)
	ctx := context.Background()
	if _, err := s.Store.Pool.Exec(ctx, "UPDATE hosts SET instance_id='fixture',connection_id='connection'; UPDATE tasks SET dispatched=false WHERE task_id='fast'"); err != nil {
		t.Fatal(err)
	}
	tracer := fx6DeadlineTracer{deadlines: make(chan time.Duration, 1)}
	cfg := s.Store.Pool.Config()
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	db := *s.Store
	db.Pool = pool
	s.Store = &db
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.Close()
	s.Router = fx6CancelRouter{cancel: s.cancel}
	s.dispatch(s.ctx, &v1.Job{JobId: "job"}, &v1.Task{TaskId: "fast", HostId: "fast"}, catalog.Action{Timeout: "5s"}, &v1.RunJobRequest{})
	select {
	case remaining := <-tracer.deadlines:
		if remaining <= 0 || remaining > 5*time.Second {
			t.Errorf("terminal write deadline remaining=%s; want independent deadline within 5s", remaining)
		}
	default:
		t.Error("reserved dispatch did not attempt terminal write")
	}
	var status int16
	if err := pool.QueryRow(ctx, "SELECT status FROM tasks WHERE task_id='fast'").Scan(&status); err != nil || status != int16(v1.TaskStatus_TASK_STATUS_OFFLINE) {
		t.Errorf("reserved dispatch terminal status=%d error=%v; want OFFLINE", status, err)
	}
}

type fx6WaitingCancelRouter struct {
	started  chan string
	canceled chan struct{}
	release  chan struct{}
	deadline chan time.Duration
}

func (r fx6WaitingCancelRouter) Send(context.Context, string, *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	return nil, errors.New("cancellation must remain generation-bound")
}

func (r fx6WaitingCancelRouter) SendToConnection(ctx context.Context, _, connection string, _ *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	deadline, ok := ctx.Deadline()
	remaining := time.Duration(-1)
	if ok {
		remaining = time.Until(deadline)
	}
	r.deadline <- remaining
	r.started <- connection
	<-ctx.Done()
	close(r.canceled)
	<-r.release
	return nil, ctx.Err()
}

func TestVFX6CloseJoinsLateStartCancellation(t *testing.T) {
	s := concurrencyFixture(t)
	ctx := context.Background()
	s.ctx, s.cancel = context.WithCancel(ctx)
	router := fx6WaitingCancelRouter{started: make(chan string, 1), canceled: make(chan struct{}), release: make(chan struct{}), deadline: make(chan time.Duration, 1)}
	s.Router = router
	var release sync.Once
	defer s.Close()
	defer release.Do(func() { close(router.release) })
	if err := s.setTerminal(ctx, "job", "fast", &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_CANCELLED, Reason: "CANCELLED"}); err != nil {
		t.Fatal(err)
	}
	handled := make(chan error, 1)
	go func() {
		handled <- s.OnMessage(ctx, hostconn.Event{HostID: "fast", ConnectionID: "connection", Message: &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: "fast"}}}})
	}()
	select {
	case err := <-handled:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnMessage waited for cancellation result in owner loop")
	}
	select {
	case connection := <-router.started:
		if connection != "connection" {
			t.Errorf("cancellation connection=%s want original connection", connection)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation worker did not start")
	}
	if remaining := <-router.deadline; remaining <= 0 || remaining > 10*time.Second {
		t.Errorf("late cancellation deadline=%s want within 10s", remaining)
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-router.canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel late-start worker context")
	}
	select {
	case <-closed:
		t.Error("Close returned before cancellation worker exited")
	default:
	}
	release.Do(func() { close(router.release) })
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not join cancellation worker")
	}
	// A late database result after Close must not admit another worker.
	late := fx6WaitingCancelRouter{started: make(chan string, 1), canceled: make(chan struct{}), release: make(chan struct{}), deadline: make(chan time.Duration, 1)}
	close(late.release)
	s.Router = late
	if err := s.OnMessage(ctx, hostconn.Event{HostID: "fast", ConnectionID: "connection", Message: &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: "fast"}}}}); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if len(late.started) != 0 {
		t.Error("closed service admitted another cancellation worker")
	}

}
