package job

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

// sendOnlyRouter implements only hostconn.Router, so OnMessage must use Send
// instead of SendToConnection when it cancels a late TaskStarted.
type sendOnlyRouter struct{ cancels atomic.Int32 }

func (r *sendOnlyRouter) Send(_ context.Context, _ string, m *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	if m.GetCancel() != nil {
		r.cancels.Add(1)
	}
	return nil, nil
}

func onMessageReq(m any) *v1.ConnectRequest {
	switch m := m.(type) {
	case *v1.TaskStarted:
		return &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: m}}
	case *v1.TaskOutputChunk:
		return &v1.ConnectRequest{Message: &v1.ConnectRequest_Output{Output: m}}
	case *v1.StepCompleted:
		return &v1.ConnectRequest{Message: &v1.ConnectRequest_StepCompleted{StepCompleted: m}}
	case *v1.TaskCompleted:
		return &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskCompleted{TaskCompleted: m}}
	}
	return &v1.ConnectRequest{}
}

// TestOnMessageRejections fixes the validation order and the error text of
// OnMessage for each message type. Every case starts from a reset task row and
// replays optional prefix messages that must succeed.
func TestOnMessageRejections(t *testing.T) {
	s := concurrencyFixture(t)
	ctx := context.Background()
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.Close()
	s.Audit = audit.New(s.Store.Pool, audit.Config{})
	if _, err := s.Store.Pool.Exec(ctx, `CREATE TABLE test_fail(tbl text);
 CREATE FUNCTION test_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF EXISTS(SELECT 1 FROM test_fail WHERE tbl=TG_TABLE_NAME) THEN RAISE EXCEPTION 'test failure' USING ERRCODE='XX001'; END IF;
 RETURN NEW; END $$;
 CREATE TRIGGER test_fail BEFORE UPDATE ON tasks FOR EACH ROW EXECUTE FUNCTION test_fail();
 CREATE TRIGGER test_fail BEFORE INSERT ON task_steps FOR EACH ROW EXECUTE FUNCTION test_fail();`); err != nil {
		t.Fatal(err)
	}
	reset := func(t *testing.T, definition string, state v1.TaskStatus, result string) {
		t.Helper()
		s.outputs = map[string]*taskOutput{}
		if result == "" {
			result = "0801"
		}
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{"DELETE FROM test_fail", nil},
			{"DELETE FROM task_steps", nil},
			{"UPDATE jobs SET action_definition=convert_to($1,'UTF8')", []any{definition}},
			{"UPDATE tasks SET status=$1,result=decode($2,'hex'),dispatched=true,connection_id='connection',started_at=NULL,finished_at=NULL WHERE task_id='fast'", []any{int16(state), result}},
		} {
			if _, err := s.Store.Pool.Exec(ctx, q.sql, q.args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	const one = `{"max_output":1024,"steps":[{"name":"a"}]}`
	const two = `{"max_output":1024,"steps":[{"name":"a"},{"name":"b"}]}`
	const plain = `{"max_output":1024}`
	ev := func(m any) hostconn.Event {
		return hostconn.Event{HostID: "fast", ConnectionID: "connection", Message: onMessageReq(m)}
	}
	failed := func(exit int32) *v1.ExecutionResult {
		return &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_FAILED, ExitCode: proto.Int32(exit), Duration: durationpb.New(0)}
	}
	step := func(i uint32, name string, r *v1.ExecutionResult) *v1.StepCompleted {
		return &v1.StepCompleted{JobId: "job", TaskId: "fast", StepIndex: i, StepName: name, Result: r}
	}
	chunk := func(stream v1.OutputStream, data string, offset uint64, eof bool) *v1.TaskOutputChunk {
		return &v1.TaskOutputChunk{JobId: "job", TaskId: "fast", Stream: stream, Data: []byte(data), Offset: offset, Eof: eof}
	}
	stdout := v1.OutputStream_OUTPUT_STREAM_STDOUT
	start := &v1.TaskStarted{JobId: "job", TaskId: "fast"}
	cases := []struct {
		name       string
		definition string
		state      v1.TaskStatus
		failTable  string
		prefix     []hostconn.Event
		event      hostconn.Event
		want       string // exact error text; "" means success; "*" means any error
	}{
		{name: "nil message", definition: plain, state: 1, event: hostconn.Event{HostID: "fast", ConnectionID: "connection"}},
		{name: "empty message", definition: plain, state: 1, event: ev(nil)},
		{name: "unknown task", definition: plain, state: 1, event: hostconn.Event{HostID: "fast", ConnectionID: "connection", Message: onMessageReq(&v1.TaskStarted{JobId: "job", TaskId: "nope"})}, want: "UNKNOWN_TASK_EVENT"},
		{name: "host mismatch", definition: plain, state: 1, event: hostconn.Event{HostID: "slow", ConnectionID: "connection", Message: onMessageReq(start)}, want: "TASK_CONNECTION_MISMATCH"},
		{name: "connection mismatch", definition: plain, state: 1, event: hostconn.Event{HostID: "fast", ConnectionID: "old", Message: onMessageReq(start)}, want: "TASK_CONNECTION_MISMATCH"},
		{name: "mismatch wins over terminal state", definition: plain, state: 4, event: hostconn.Event{HostID: "fast", ConnectionID: "old", Message: onMessageReq(start)}, want: "TASK_CONNECTION_MISMATCH"},
		{name: "terminal state wins over invalid definition", definition: "{", state: 4, event: ev(start)},
		{name: "invalid definition", definition: "{", state: 1, event: ev(start), want: "*"},
		{name: "invalid definition wins over duplicate start", definition: "{", state: 2, event: ev(start), want: "*"},
		{name: "invalid definition wins over invalid chunk", definition: "{", state: 1, event: ev(chunk(stdout, "x", 0, false)), want: "*"},
		{name: "duplicate start", definition: plain, state: 2, event: ev(start), want: "DUPLICATE_TASK_START"},
		{name: "start update failure", definition: plain, state: 1, failTable: "tasks_fixture", event: ev(start), want: "*"},
		{name: "start", definition: plain, state: 1, event: ev(start)},
		{name: "chunk before start", definition: plain, state: 1, event: ev(chunk(stdout, "x", 0, false)), want: "INVALID_OUTPUT_CHUNK"},
		{name: "chunk without stream", definition: plain, state: 2, event: ev(chunk(v1.OutputStream_OUTPUT_STREAM_UNSPECIFIED, "x", 0, false)), want: "INVALID_OUTPUT_CHUNK"},
		{name: "empty chunk without eof", definition: plain, state: 2, event: ev(chunk(stdout, "", 0, false)), want: "INVALID_OUTPUT_CHUNK"},
		{name: "chunk step on plain action", definition: plain, state: 2, event: ev(&v1.TaskOutputChunk{JobId: "job", TaskId: "fast", Stream: stdout, Data: []byte("x"), StepIndex: proto.Uint32(0)}), want: "INVALID_OUTPUT_STEP"},
		{name: "chunk without step on step action", definition: one, state: 2, event: ev(chunk(stdout, "x", 0, false)), want: "INVALID_OUTPUT_STEP"},
		{name: "chunk step beyond definition", definition: one, state: 2, event: ev(&v1.TaskOutputChunk{JobId: "job", TaskId: "fast", Stream: stdout, Data: []byte("x"), StepIndex: proto.Uint32(1)}), want: "INVALID_OUTPUT_STEP"},
		{name: "chunk offset", definition: plain, state: 2, event: ev(chunk(stdout, "x", 1, false)), want: "OUTPUT_OFFSET_OR_BUDGET"},
		{name: "chunk after eof", definition: plain, state: 2, prefix: []hostconn.Event{ev(chunk(stdout, "x", 0, true))}, event: ev(chunk(stdout, "y", 1, false)), want: "OUTPUT_OFFSET_OR_BUDGET"},
		{name: "chunk budget", definition: `{"max_output":3}`, state: 2, event: ev(chunk(stdout, "four", 0, false)), want: "OUTPUT_OFFSET_OR_BUDGET"},
		{name: "chunk", definition: plain, state: 2, event: ev(chunk(stdout, "x", 0, true))},
		{name: "step before start", definition: one, state: 1, event: ev(step(0, "a", failed(1))), want: "INVALID_STEP_RESULT"},
		{name: "step on plain action", definition: plain, state: 2, event: ev(step(0, "a", failed(1))), want: "INVALID_STEP_RESULT"},
		{name: "step index beyond definition", definition: one, state: 2, event: ev(step(1, "a", failed(1))), want: "INVALID_STEP_RESULT"},
		{name: "step name", definition: one, state: 2, event: ev(step(0, "b", failed(1))), want: "INVALID_STEP_RESULT"},
		{name: "step out of order", definition: two, state: 2, event: ev(step(1, "b", failed(1))), want: "INVALID_STEP_RESULT"},
		{name: "step without result", definition: one, state: 2, event: ev(step(0, "a", nil)), want: "INVALID_EXECUTION_RESULT"},
		{name: "step result", definition: one, state: 2, event: ev(step(0, "a", &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_FAILED, ExitCode: proto.Int32(0), Duration: durationpb.New(0)})), want: "INVALID_FAILURE_EXIT"},
		{name: "skipped step without failure", definition: two, state: 2, event: ev(step(0, "a", &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_SKIPPED, Duration: durationpb.New(0)})), want: "INVALID_SKIPPED_STEP"},
		{name: "skipped step after failure", definition: two, state: 2, prefix: []hostconn.Event{ev(step(0, "a", failed(1)))}, event: ev(step(1, "b", &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_SKIPPED, Duration: durationpb.New(0)}))},
		{name: "step insert failure", definition: one, state: 2, failTable: "task_steps", event: ev(step(0, "a", failed(1))), want: "*"},
		{name: "step", definition: one, state: 2, event: ev(step(0, "a", failed(1)))},
		{name: "completion without result", definition: plain, state: 2, event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast"}), want: "MISSING_TASK_RESULT"},
		{name: "success before start", definition: plain, state: 1, event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_SUCCEEDED}}), want: "RESULT_BEFORE_START"},
		{name: "step count on plain action", definition: plain, state: 2, event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", CompletedSteps: 1, Result: failed(1)}), want: "INVALID_STEP_COUNT"},
		{name: "plain result", definition: plain, state: 2, event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_SUCCEEDED, ExitCode: proto.Int32(1), Duration: durationpb.New(0)}}), want: "INVALID_SUCCESS_EXIT"},
		{name: "plain completion", definition: plain, state: 2, event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", Result: failed(1)})},
		{name: "step completion with stdout metadata", definition: one, state: 2, event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_FAILED, Stdout: &v1.OutputMetadata{}, Duration: durationpb.New(0)}}), want: "INVALID_STEPS_COMPLETION"},
		{name: "step completion count", definition: one, state: 2, event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", CompletedSteps: 1, Result: failed(1)}), want: "INVALID_STEPS_COMPLETION"},
		{name: "incomplete steps", definition: two, state: 2, prefix: []hostconn.Event{ev(step(0, "a", failed(1)))}, event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", CompletedSteps: 1, Result: failed(1)}), want: "INCOMPLETE_STEPS"},
		{name: "step completion scalars", definition: one, state: 2, prefix: []hostconn.Event{ev(step(0, "a", failed(1)))}, event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", CompletedSteps: 1, Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_FAILED, ExitCode: proto.Int32(1)}}), want: "INVALID_EXECUTION_RESULT"},
		{name: "step completion without duration", definition: one, state: 2, prefix: []hostconn.Event{ev(step(0, "a", failed(1)))}, event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", CompletedSteps: 1, Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_FAILED}}), want: "INVALID_EXECUTION_RESULT"},
		{name: "aggregate status", definition: one, state: 2, prefix: []hostconn.Event{ev(step(0, "a", failed(1)))}, event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", CompletedSteps: 1, Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_TIMEOUT, ExitCode: proto.Int32(1), Duration: durationpb.New(0)}}), want: "INVALID_AGGREGATE_RESULT"},
		{name: "aggregate exit", definition: one, state: 2, prefix: []hostconn.Event{ev(step(0, "a", failed(1)))}, event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", CompletedSteps: 1, Result: failed(2)}), want: "INVALID_AGGREGATE_RESULT"},
		{name: "step completion", definition: one, state: 2, prefix: []hostconn.Event{ev(step(0, "a", failed(1)))}, event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", CompletedSteps: 1, Result: failed(1)})},
		{name: "completion update failure", definition: plain, state: 2, failTable: "tasks_fixture", event: ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", Result: failed(1)}), want: "*"},
		{name: "late start cancels through Send", definition: plain, state: 4, event: ev(start)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			router := &sendOnlyRouter{}
			s.Router = nil
			if c.name == "late start cancels through Send" {
				s.Router = router
				defer func() {
					s.wg.Wait()
					if router.cancels.Load() != 1 {
						t.Errorf("cancel sent through Send %d times; want 1", router.cancels.Load())
					}
				}()
			}
			reset(t, c.definition, c.state, "")
			for _, p := range c.prefix {
				if err := s.OnMessage(ctx, p); err != nil {
					t.Fatalf("prefix message: %v", err)
				}
			}
			if c.failTable != "" {
				if _, err := s.Store.Pool.Exec(ctx, "INSERT INTO test_fail VALUES ($1)", c.failTable); err != nil {
					t.Fatal(err)
				}
			}
			err := s.OnMessage(ctx, c.event)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("error = %v; want success", err)
			case c.want == "*" && err == nil:
				t.Fatal("error = nil; want an error")
			case c.want != "" && c.want != "*" && (err == nil || err.Error() != c.want):
				t.Fatalf("error = %v; want %s", err, c.want)
			}
			// An unsuccessful event must leave the task row as it was.
			var status int16
			if e := s.Store.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE task_id='fast'").Scan(&status); e != nil {
				t.Fatal(e)
			}
			if err != nil && len(c.prefix) == 0 && status != int16(c.state) {
				t.Fatalf("status after rejected event = %d; want %d", status, c.state)
			}
			s.wg.Wait()
		})
	}
	t.Run("completion after service stop", func(t *testing.T) {
		s.Router = nil
		reset(t, plain, v1.TaskStatus_TASK_STATUS_RUNNING, "0802")
		s.cancel()
		err := s.OnMessage(ctx, ev(&v1.TaskCompleted{JobId: "job", TaskId: "fast", Result: failed(1)}))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v; want context canceled", err)
		}
		var status int16
		if err := s.Store.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE task_id='fast'").Scan(&status); err != nil || status != 2 {
			t.Fatalf("status = %d err=%v; want unchanged 2", status, err)
		}
	})
}
