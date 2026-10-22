package job

import (
	"context"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
)

type noopStorage struct{}

func (noopStorage) Put(context.Context, string, []byte) error          { return nil }
func (noopStorage) Get(context.Context, string, int64) ([]byte, error) { return nil, nil }

func TestAbandonedTaskOutputBuffersAreReleased(t *testing.T) {
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO gateway_instances(instance_id) VALUES ('fixture');
 INSERT INTO hosts(host_id,hostname,certificate_serial,certificate_expires_at) VALUES ('host','host','serial',now()+interval '1 hour');
 INSERT INTO jobs(job_id,created_at,subject_id,origin_instance,action,action_definition,catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures)
 VALUES ('job',now(),'sa','fixture','action',convert_to('{}','UTF8'),'catalog',1,decode(repeat('00',32),'hex'),1,'test',2,1,0);
 CREATE TABLE tasks_fixture PARTITION OF tasks DEFAULT;
 INSERT INTO tasks(job_id,task_id,created_at,host_id,hostname,position,connection_id,dispatched,status,result)
 SELECT job_id,'task',created_at,'host','host',0,'connection',true,2,decode('0802','hex') FROM jobs WHERE job_id='job';`); err != nil {
		t.Fatal(err)
	}
	s := &Service{Store: db}
	event := hostconn.Event{HostID: "host", ConnectionID: "connection"}
	for _, disconnected := range []bool{true, false} {
		status := v1.TaskStatus_TASK_STATUS_RUNNING
		if !disconnected {
			status = v1.TaskStatus_TASK_STATUS_FAILED
		}
		if _, err := db.Pool.Exec(ctx, "UPDATE tasks SET status=$1,result=$2", int16(status), pendingResult(status, "")); err != nil {
			t.Fatal(err)
		}
		s.outputs = map[string]*taskOutput{outputID("job", "task"): {Streams: map[streamKey]*streamOutput{{-1, v1.OutputStream_OUTPUT_STREAM_STDOUT}: {Data: []byte("retained partial output")}}}}
		if disconnected {
			s.OnDisconnect(event)
			status = v1.TaskStatus_TASK_STATUS_OFFLINE
		} else {
			event.Message = &v1.ConnectRequest{Message: &v1.ConnectRequest_Output{Output: &v1.TaskOutputChunk{JobId: "job", TaskId: "task", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT, Eof: true}}}
			if err := s.OnMessage(ctx, event); err != nil {
				t.Fatal(err)
			}
		}
		if len(s.outputs) != 0 {
			t.Fatalf("disconnected=%t retained %d terminal task output buffers", disconnected, len(s.outputs))
		}
		var got int16
		if err := db.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE task_id='task'").Scan(&got); err != nil || got != int16(status) {
			t.Fatalf("terminal status=%d want=%d error=%v", got, status, err)
		}
	}
}

func TestTaskOutputBuffersReleasedAfterSetTerminalAndRecovery(t *testing.T) {
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO gateway_instances(instance_id) VALUES ('fixture');
 INSERT INTO hosts(host_id,hostname,certificate_serial,certificate_expires_at) VALUES ('host','host','serial',now()+interval '1 hour');
 INSERT INTO jobs(job_id,created_at,subject_id,origin_instance,action,action_definition,catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures)
 VALUES ('job',now(),'sa','fixture','action',convert_to('{"max_output":1024}','UTF8'),'catalog',1,decode(repeat('00',32),'hex'),1,'test',2,1,0);
 CREATE TABLE tasks_fixture PARTITION OF tasks DEFAULT;
 INSERT INTO tasks(job_id,task_id,created_at,host_id,hostname,position,connection_id,dispatched,status,result)
 SELECT job_id,'task',created_at,'host','host',0,'connection',true,1,decode('0801','hex') FROM jobs WHERE job_id='job';`); err != nil {
		t.Fatal(err)
	}

	s := &Service{
		Store:      db,
		Audit:      audit.New(db.Pool, audit.Config{}),
		Storage:    noopStorage{},
		outputs:    map[string]*taskOutput{},
		instanceID: "survivor",
		lostAfter:  10 * time.Second,
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.Close()

	// 1. Task starts, produces output, then terminates via setTerminal (e.g. failed cancelTasks) followed by OnDisconnect.
	if err := s.OnMessage(ctx, hostconn.Event{
		HostID:       "host",
		ConnectionID: "connection",
		Message:      &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: "task"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.OnMessage(ctx, hostconn.Event{
		HostID:       "host",
		ConnectionID: "connection",
		Message:      &v1.ConnectRequest{Message: &v1.ConnectRequest_Output{Output: &v1.TaskOutputChunk{JobId: "job", TaskId: "task", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT, Data: []byte("chunk"), Eof: true}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.setTerminal(ctx, "job", "task", &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_OFFLINE, Reason: "OFFLINE"}); err != nil {
		t.Fatal(err)
	}
	s.OnDisconnect(hostconn.Event{HostID: "host", ConnectionID: "connection"})
	s.mu.Lock()
	afterSetTerminal := len(s.outputs)
	s.mu.Unlock()
	if afterSetTerminal != 0 {
		t.Errorf("s.outputs retained %d entries after setTerminal + OnDisconnect; want 0", afterSetTerminal)
		s.mu.Lock()
		s.outputs = map[string]*taskOutput{}
		s.mu.Unlock()
	}

	// 2. Task starts, produces output, then terminates via RecoverLostInstances followed by OnDisconnect.
	if _, err := db.Pool.Exec(ctx, "UPDATE jobs SET status=2 WHERE job_id='job'"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, "UPDATE tasks SET status=1,result=$1 WHERE task_id='task'", pendingResult(v1.TaskStatus_TASK_STATUS_PENDING, "")); err != nil {
		t.Fatal(err)
	}
	if err := s.OnMessage(ctx, hostconn.Event{
		HostID:       "host",
		ConnectionID: "connection",
		Message:      &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: "task"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.OnMessage(ctx, hostconn.Event{
		HostID:       "host",
		ConnectionID: "connection",
		Message:      &v1.ConnectRequest{Message: &v1.ConnectRequest_Output{Output: &v1.TaskOutputChunk{JobId: "job", TaskId: "task", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT, Data: []byte("chunk"), Eof: true}}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, "UPDATE gateway_instances SET last_seen=now()-interval '1 minute' WHERE instance_id='fixture'"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverLostInstances(ctx); err != nil {
		t.Fatal(err)
	}
	s.OnDisconnect(hostconn.Event{HostID: "host", ConnectionID: "connection"})
	s.mu.Lock()
	afterRecovery := len(s.outputs)
	s.mu.Unlock()
	if afterRecovery != 0 {
		t.Errorf("s.outputs retained %d entries after RecoverLostInstances + OnDisconnect; want 0", afterRecovery)
		s.mu.Lock()
		s.outputs = map[string]*taskOutput{}
		s.mu.Unlock()
	}

	// 3. persist must acquire out.mu before reading out.Streams (detected under -race if unlocked).
	out := &taskOutput{Streams: map[streamKey]*streamOutput{}}
	s.mu.Lock()
	s.outputs[outputID("job", "task")] = out
	s.mu.Unlock()
	out.mu.Lock()
	persistDone := make(chan struct{})
	go func() {
		defer close(persistDone)
		s.persist("job", "task", "host", "host", "sa", "action", time.Now().UTC(), 1, out)
	}()
	time.Sleep(20 * time.Millisecond)
	out.Streams[streamKey{-1, v1.OutputStream_OUTPUT_STREAM_STDOUT}] = &streamOutput{Data: []byte("ok"), EOF: true}
	out.mu.Unlock()
	<-persistDone
	s.mu.Lock()
	afterPersist := len(s.outputs)
	s.mu.Unlock()
	if afterPersist != 0 {
		t.Errorf("s.outputs retained %d entries after persist; want 0", afterPersist)
	}
}
