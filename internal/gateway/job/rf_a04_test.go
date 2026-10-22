package job

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestRFA04CompositeCompletion(t *testing.T) {
	s := concurrencyFixture(t)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	defer s.Close()
	s.Audit = audit.New(s.Store.Pool, audit.Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	a := catalog.Action{Name: "action", MaxOutput: 1024, OnError: "continue", Steps: []catalog.Step{{Name: "first", Exec: []any{"/usr/bin/true"}}, {Name: "second", Exec: []any{"/usr/bin/true"}}}}
	definition, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.Pool.Exec(ctx, "UPDATE jobs SET action_definition=$1", definition); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.Pool.Exec(ctx, "DELETE FROM tasks WHERE task_id='slow'"); err != nil {
		t.Fatal(err)
	}
	success := v1.TaskStatus_TASK_STATUS_SUCCEEDED
	failed := v1.TaskStatus_TASK_STATUS_FAILED
	timeout := v1.TaskStatus_TASK_STATUS_TIMEOUT
	cancelled := v1.TaskStatus_TASK_STATUS_CANCELLED
	tests := []struct {
		name     string
		started  bool
		steps    []v1.TaskStatus
		status   v1.TaskStatus
		exit     *int32
		reason   string
		duration *durationpb.Duration
		valid    bool
	}{
		{"zero_steps_after_start", true, nil, success, proto.Int32(0), "", durationpb.New(time.Millisecond), false},
		{"failed_step_reported_success", true, []v1.TaskStatus{failed, success}, success, proto.Int32(1), "", durationpb.New(time.Millisecond), false},
		{"raw_reason", true, []v1.TaskStatus{success, success}, success, proto.Int32(0), "raw error text", durationpb.New(time.Millisecond), false},
		{"missing_duration", true, []v1.TaskStatus{success, success}, success, proto.Int32(0), "", nil, false},
		{"negative_duration", true, []v1.TaskStatus{success, success}, success, proto.Int32(0), "", durationpb.New(-time.Second), false},
		{"invalid_duration", true, []v1.TaskStatus{success, success}, success, proto.Int32(0), "", &durationpb.Duration{Nanos: 1000000000}, false},
		{"all_success", true, []v1.TaskStatus{success, success}, success, proto.Int32(0), "", durationpb.New(time.Millisecond), true},
		{"failure", true, []v1.TaskStatus{failed, success}, failed, proto.Int32(1), "EXECUTION_FAILED", durationpb.New(time.Millisecond), true},
		{"timeout_after_failure", true, []v1.TaskStatus{failed, timeout}, timeout, proto.Int32(1), "TIMEOUT", durationpb.New(time.Millisecond), true},
		{"cancel_after_failure", true, []v1.TaskStatus{failed, cancelled}, cancelled, proto.Int32(1), "CANCELLED", durationpb.New(time.Millisecond), true},
		{"timeout_misreported_failure", true, []v1.TaskStatus{failed, timeout}, failed, proto.Int32(1), "EXECUTION_FAILED", durationpb.New(time.Millisecond), false},
		{"skipped_after_timeout", true, []v1.TaskStatus{timeout, v1.TaskStatus_TASK_STATUS_SKIPPED}, timeout, proto.Int32(1), "TIMEOUT", durationpb.New(time.Millisecond), true},
		{"unsupported_before_start", false, nil, v1.TaskStatus_TASK_STATUS_UNSUPPORTED, nil, "ACTION_UNSUPPORTED", nil, true},
		{"failed_before_start", false, nil, failed, nil, "INVALID_PARAMETERS", nil, true},
	}
	event := func(m *v1.ConnectRequest) error {
		return s.OnMessage(ctx, hostconn.Event{HostID: "fast", ConnectionID: "connection", Message: m})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s.wg.Wait()
			if _, err := s.Store.Pool.Exec(ctx, "UPDATE tasks SET status=1,result=$1,step_count=0,output_state='pending'", pendingResult(v1.TaskStatus_TASK_STATUS_PENDING, "")); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Store.Pool.Exec(ctx, "DELETE FROM task_steps"); err != nil {
				t.Fatal(err)
			}
			s.clearTasks("job", "fast")
			if tc.started {
				if err := event(&v1.ConnectRequest{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: "fast"}}}); err != nil {
					t.Fatal(err)
				}
			}
			for i, status := range tc.steps {
				r := &v1.ExecutionResult{Status: status, Duration: durationpb.New(time.Millisecond)}
				if status != v1.TaskStatus_TASK_STATUS_SKIPPED {
					code := int32(0)
					if status != success {
						code = 1
					}
					r.ExitCode = &code
					empty := sha256.Sum256(nil)
					r.Stdout = &v1.OutputMetadata{Sha256: empty[:]}
					r.Stderr = &v1.OutputMetadata{Sha256: empty[:]}
					for _, stream := range []v1.OutputStream{v1.OutputStream_OUTPUT_STREAM_STDOUT, v1.OutputStream_OUTPUT_STREAM_STDERR} {
						if err := event(&v1.ConnectRequest{Message: &v1.ConnectRequest_Output{Output: &v1.TaskOutputChunk{JobId: "job", TaskId: "fast", StepIndex: proto.Uint32(uint32(i)), Stream: stream, Eof: true}}}); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err := event(&v1.ConnectRequest{Message: &v1.ConnectRequest_StepCompleted{StepCompleted: &v1.StepCompleted{JobId: "job", TaskId: "fast", StepIndex: uint32(i), StepName: a.Steps[i].Name, Result: r}}}); err != nil {
					t.Fatal(err)
				}
			}
			result := &v1.ExecutionResult{Status: tc.status, ExitCode: tc.exit, Reason: tc.reason, Duration: tc.duration}
			err := event(&v1.ConnectRequest{Message: &v1.ConnectRequest_TaskCompleted{TaskCompleted: &v1.TaskCompleted{JobId: "job", TaskId: "fast", CompletedSteps: uint32(len(tc.steps)), Result: result}}})
			s.wg.Wait()
			var status int16
			var count int
			if e := s.Store.Pool.QueryRow(ctx, "SELECT status,step_count FROM tasks WHERE task_id='fast'").Scan(&status, &count); e != nil {
				t.Fatal(e)
			}
			if tc.valid {
				if err != nil || status != int16(tc.status) || count != len(tc.steps) {
					t.Errorf("valid completion error=%v status=%d step_count=%d; want nil,%d,%d", err, status, count, tc.status, len(tc.steps))
				}
			} else if err == nil || status != 2 {
				t.Errorf("invalid completion error=%v status=%d; want rejection and RUNNING(2)", err, status)
			}
		})
	}
}
