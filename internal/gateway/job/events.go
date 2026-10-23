package job

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"google.golang.org/protobuf/proto"
)

type streamKey struct {
	Step   int
	Stream v1.OutputStream
}
type streamOutput struct {
	Data []byte
	EOF  bool
}
type taskOutput struct {
	mu      sync.Mutex
	Streams map[streamKey]*streamOutput
	Steps   []*v1.TaskStep
	Bytes   int64
}

var resultReason = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

func outputID(jobID, taskID string) string { return jobID + "/" + taskID }
func stepValue(step *uint32) int {
	if step == nil {
		return -1
	}
	return int(*step)
}

func (s *Service) Hooks() hostconn.Hooks {
	return hostconn.Hooks{OnMessage: s.OnMessage, OnDisconnect: s.OnDisconnect, Drain: s.Drain}
}

// eventTask returns the job and task that an agent message refers to. Messages
// of other types, and empty messages, have none.
func eventTask(msg *v1.ConnectRequest) (jobID, taskID string, ok bool) {
	switch {
	case msg.GetTaskStarted() != nil:
		m := msg.GetTaskStarted()
		return m.JobId, m.TaskId, true
	case msg.GetOutput() != nil:
		m := msg.GetOutput()
		return m.JobId, m.TaskId, true
	case msg.GetStepCompleted() != nil:
		m := msg.GetStepCompleted()
		return m.JobId, m.TaskId, true
	case msg.GetTaskCompleted() != nil:
		m := msg.GetTaskCompleted()
		return m.JobId, m.TaskId, true
	}
	return "", "", false
}

// taskEventScope is what the handlers of one agent event share. The task row is
// locked by tx until the handler commits or the event is rejected.
type taskEventScope struct {
	tx     pgx.Tx
	jobID  string
	taskID string
	row    taskEvent
	action catalog.Action
	out    *taskOutput
}

// OnMessage applies one agent message to its task inside a transaction that
// holds the task row lock. A rejected event rolls the transaction back.
func (s *Service) OnMessage(ctx context.Context, e hostconn.Event) error {
	if e.Message == nil {
		return nil
	}
	jobID, taskID, ok := eventTask(e.Message)
	if !ok {
		return nil
	}
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	row, err := lockTaskForEvent(ctx, tx, jobID, taskID)
	if err != nil {
		return errors.New("UNKNOWN_TASK_EVENT")
	}
	if row.hostID != e.HostID || row.connection != e.ConnectionID || !row.dispatched {
		return errors.New("TASK_CONNECTION_MISMATCH")
	}
	if row.state > 2 {
		return s.ignoreTerminalTaskEvent(ctx, tx, e, jobID, taskID, row.state)
	} // First terminal result wins; late messages are ignored.
	var a catalog.Action
	if err := json.Unmarshal(row.definition, &a); err != nil {
		return err
	}
	if e.Message.GetTaskStarted() != nil {
		return s.onTaskStarted(ctx, tx, jobID, taskID, row.state)
	}
	if err := checkEventPreconditions(e.Message, row.state, a); err != nil {
		return err
	}
	out := s.eventOutput(jobID, taskID, e.Message.GetTaskCompleted() == nil)
	// The task row lock orders events against cancellation and disconnects.
	// Keep in-memory synchronization per task; SQL must not hold the map lock
	// and serialize results from unrelated hosts.
	out.mu.Lock()
	defer out.mu.Unlock()
	scope := &taskEventScope{tx: tx, jobID: jobID, taskID: taskID, row: row, action: a, out: out}
	switch {
	case e.Message.GetOutput() != nil:
		return s.onOutputChunk(ctx, scope, e.Message.GetOutput())
	case e.Message.GetStepCompleted() != nil:
		return s.onStepCompleted(ctx, scope, e.Message.GetStepCompleted())
	case e.Message.GetTaskCompleted() != nil:
		return s.onTaskCompleted(ctx, scope, e.Message.GetTaskCompleted())
	}
	return tx.Commit(ctx)
}

// ignoreTerminalTaskEvent drops a message for a task that already has a
// terminal result and releases its buffers. A late TaskStarted additionally
// makes the owner cancel the task on the agent.
func (s *Service) ignoreTerminalTaskEvent(ctx context.Context, tx pgx.Tx, e hostconn.Event, jobID, taskID string, state int16) error {
	tx.Rollback(ctx)
	s.clearTasks(jobID, taskID)
	if e.Message.GetTaskStarted() != nil && s.Router != nil {
		s.cancelLateStart(e, jobID, taskID, state)
	}
	return nil
}

func (s *Service) cancelLateStart(e hostconn.Event, jobID, taskID string, state int16) {
	reason := "CANCELLED"
	if v1.TaskStatus(state) == v1.TaskStatus_TASK_STATUS_SKIPPED || v1.TaskStatus(state) == v1.TaskStatus_TASK_STATUS_FAILED {
		reason = "GATEWAY_INSTANCE_LOST"
	}
	// Serialize worker admission with Close, including when the event's
	// database read finishes after the service has already stopped.
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	cancelCtx, done := context.WithTimeout(s.ctx, 10*time.Second)
	m := &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{JobId: jobID, TaskId: taskID, Reason: reason}}}
	// OnMessage runs in the owner's stream loop. Waiting here would
	// prevent that loop from writing this cancellation or its result.
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer done()
		if bound, ok := s.Router.(interface {
			SendToConnection(context.Context, string, string, *v1.ConnectResponse) (*v1.TaskCompleted, error)
		}); ok {
			_, _ = bound.SendToConnection(cancelCtx, e.HostID, e.ConnectionID, m)
		} else {
			_, _ = s.Router.Send(cancelCtx, e.HostID, m)
		}
	}()
}

func (s *Service) onTaskStarted(ctx context.Context, tx pgx.Tx, jobID, taskID string, state int16) error {
	if state != 1 {
		return errors.New("DUPLICATE_TASK_START")
	}
	if err := markTaskStarted(ctx, tx, jobID, taskID, pendingResult(v1.TaskStatus_TASK_STATUS_RUNNING, "")); err != nil {
		return err
	}
	// Output events publish their buffer while holding the task row lock.
	// Do not create an empty entry after COMMIT releases that lock: a
	// terminal writer may already have committed and cleared the task.
	return tx.Commit(ctx)
}

// checkEventPreconditions rejects output, step and completion messages that do
// not fit the task state or the action definition, before any buffer is touched.
func checkEventPreconditions(msg *v1.ConnectRequest, state int16, a catalog.Action) error {
	if chunk := msg.GetOutput(); chunk != nil {
		if state != 2 || (chunk.Stream != v1.OutputStream_OUTPUT_STREAM_STDOUT && chunk.Stream != v1.OutputStream_OUTPUT_STREAM_STDERR) || (len(chunk.Data) == 0 && !chunk.Eof) {
			return errors.New("INVALID_OUTPUT_CHUNK")
		}
	} else if step := msg.GetStepCompleted(); step != nil {
		if state != 2 || a.Steps == nil || int(step.StepIndex) >= len(a.Steps) || step.StepName != a.Steps[step.StepIndex].Name {
			return errors.New("INVALID_STEP_RESULT")
		}
	} else if completed := msg.GetTaskCompleted(); completed != nil {
		if completed.Result == nil {
			return errors.New("MISSING_TASK_RESULT")
		}
		if state == 1 && completed.Result.Status == v1.TaskStatus_TASK_STATUS_SUCCEEDED {
			return errors.New("RESULT_BEFORE_START")
		}
	}
	return nil
}

// eventOutput returns the task's output buffer, creating it when the task has
// none. A new buffer is stored in the map only when register is true; the
// TaskCompleted handler passes false.
func (s *Service) eventOutput(jobID, taskID string, register bool) *taskOutput {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := outputID(jobID, taskID)
	out := s.outputs[key]
	if out == nil {
		out = &taskOutput{Streams: map[streamKey]*streamOutput{}}
		if register {
			s.outputs[key] = out
		}
	}
	return out
}

func (s *Service) onOutputChunk(ctx context.Context, sc *taskEventScope, chunk *v1.TaskOutputChunk) error {
	out, a := sc.out, sc.action
	step := stepValue(chunk.StepIndex)
	if (a.Steps == nil && step != -1) || (a.Steps != nil && (step != len(out.Steps) || step >= len(a.Steps))) {
		return errors.New("INVALID_OUTPUT_STEP")
	}
	k := streamKey{step, chunk.Stream}
	stream := out.Streams[k]
	var size uint64
	var eof bool
	if stream != nil {
		size = uint64(len(stream.Data))
		eof = stream.EOF
	}
	if eof || chunk.Offset != size || out.Bytes+int64(len(chunk.Data)) > int64(a.MaxOutput) {
		return errors.New("OUTPUT_OFFSET_OR_BUDGET")
	}
	if err := sc.tx.Commit(ctx); err != nil {
		return err
	}
	if stream == nil {
		stream = &streamOutput{}
		out.Streams[k] = stream
	}
	stream.Data = append(stream.Data, chunk.Data...)
	stream.EOF = chunk.Eof
	out.Bytes += int64(len(chunk.Data))
	return nil
}

func (s *Service) onStepCompleted(ctx context.Context, sc *taskEventScope, step *v1.StepCompleted) error {
	out := sc.out
	if err := validateStepCompleted(step, out, sc.action); err != nil {
		return err
	}
	raw, err := proto.Marshal(step.Result)
	if err != nil {
		return err
	}
	if err := insertTaskStep(ctx, sc.tx, sc.jobID, sc.taskID, sc.row.created, step.StepIndex, step.StepName, raw); err != nil {
		return err
	}
	if err := sc.tx.Commit(ctx); err != nil {
		return err
	}
	out.Steps = append(out.Steps, &v1.TaskStep{Index: step.StepIndex, Name: step.StepName, Result: proto.Clone(step.Result).(*v1.ExecutionResult)})
	return nil
}

// validateStepCompleted checks a step result against the steps already
// received: its position, its result fields and, for a skipped step, an earlier failure.
func validateStepCompleted(step *v1.StepCompleted, out *taskOutput, a catalog.Action) error {
	if int(step.StepIndex) != len(out.Steps) {
		return errors.New("INVALID_STEP_RESULT")
	}
	if err := validateResult(step.Result, out, int(step.StepIndex), true); err != nil {
		return err
	}
	if step.Result.Status == v1.TaskStatus_TASK_STATUS_SKIPPED {
		failed := false
		for _, prior := range out.Steps {
			if (a.OnError != "continue" && prior.Result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED) || prior.Result.Status == v1.TaskStatus_TASK_STATUS_CANCELLED || prior.Result.Status == v1.TaskStatus_TASK_STATUS_TIMEOUT {
				failed = true
			}
		}
		if !failed {
			return errors.New("INVALID_SKIPPED_STEP")
		}
	}
	return nil
}

func (s *Service) onTaskCompleted(ctx context.Context, sc *taskEventScope, completed *v1.TaskCompleted) error {
	out := sc.out
	if err := validateTaskCompleted(completed, sc.row.state, out, sc.action); err != nil {
		return err
	}
	stdout, stderr := aggregate(out, sc.action)
	stdoutHash, stderrHash := sha256.Sum256(stdout), sha256.Sum256(stderr)
	raw, err := proto.Marshal(completed.Result)
	if err != nil {
		return err
	}
	if err := completeTask(ctx, sc.tx, sc.jobID, sc.taskID, int16(completed.Result.Status), raw, stdout[:min(len(stdout), GroupBytes)], stderr[:min(len(stderr), GroupBytes)], stdoutHash[:], stderrHash[:], len(out.Steps), len(stdout), len(stderr)); err != nil {
		return err
	}
	return s.commitTerminalResult(ctx, sc, completed.Result.Status, raw)
}

// commitTerminalResult commits the terminal result of a task and starts the
// persistence of its output. Persistence is registered before the commit is
// visible, so Drain and Close wait for it.
func (s *Service) commitTerminalResult(ctx context.Context, sc *taskEventScope, status v1.TaskStatus, raw []byte) error {
	// Register accepted persistence before terminal COMMIT is visible to
	// Drain, and serialize worker admission against Close's cancellation.
	s.mu.Lock()
	if err := s.ctx.Err(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.activePersists.Add(1)
	s.wg.Add(1)
	s.mu.Unlock()
	// A COMMIT error is not a rollback: the server can commit and the reply
	// be lost, or the connection context end during the call. Commit outside
	// the connection's cancellation, and when it still reports an error, start
	// persistence if the database holds exactly this terminal result.
	commitCtx, stopCommit := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	err := sc.tx.Commit(commitCtx)
	stopCommit()
	if err != nil && !s.terminalCommitted(ctx, sc.jobID, sc.taskID, status, raw) {
		s.activePersists.Add(-1)
		s.wg.Done()
		return err
	}
	row := sc.row
	go func() {
		defer s.wg.Done()
		defer s.activePersists.Add(-1)
		s.persist(sc.jobID, sc.taskID, row.hostID, row.hostname, row.actor, sc.action.Name, row.created, row.policyVersion, sc.out)
	}()
	return nil
}

// validateTaskCompleted checks a TaskCompleted message against the task state,
// the action definition and the output and steps received so far.
func validateTaskCompleted(completed *v1.TaskCompleted, state int16, out *taskOutput, a catalog.Action) error {
	if a.Steps == nil {
		if completed.CompletedSteps != 0 {
			return errors.New("INVALID_STEP_COUNT")
		}
		return validateResult(completed.Result, out, -1, false)
	}
	if completed.Result.Stdout != nil || completed.Result.Stderr != nil || completed.CompletedSteps != uint32(len(out.Steps)) {
		return errors.New("INVALID_STEPS_COMPLETION")
	}
	if (state == 2 || len(out.Steps) > 0) && len(out.Steps) != len(a.Steps) {
		return errors.New("INCOMPLETE_STEPS")
	}
	if err := validateResultScalars(completed.Result, false); err != nil {
		return err
	}
	if state == 2 && completed.Result.Duration == nil {
		return errors.New("INVALID_EXECUTION_RESULT")
	}
	if len(out.Steps) > 0 {
		if err := validateStepsAggregate(completed.Result, out); err != nil {
			return err
		}
	}
	if !terminalAgentStatus(completed.Result.Status) {
		return errors.New("INVALID_TASK_STATUS")
	}
	return nil
}

// validateStepsAggregate checks that the task result is the aggregate of its
// step results: status, exit code and the truncation flags.
func validateStepsAggregate(result *v1.ExecutionResult, out *taskOutput) error {
	var exit *int32
	truncated, scan := false, false
	for _, step := range out.Steps {
		truncated = truncated || step.Result.Truncated
		scan = scan || step.Result.ScanLimitReached
		if exit == nil && step.Result.Status != v1.TaskStatus_TASK_STATUS_SKIPPED {
			if step.Result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED {
				exit = step.Result.ExitCode
				break
			}
		}
	}
	// Validate all OR flags even when the first failure determines exit.
	for _, step := range out.Steps {
		truncated = truncated || step.Result.Truncated
		scan = scan || step.Result.ScanLimitReached
	}
	allOK := true
	for _, step := range out.Steps {
		if step.Result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED {
			allOK = false
		}
	}
	if allOK {
		exit = proto.Int32(0)
	}
	expected := v1.TaskStatus_TASK_STATUS_SUCCEEDED
	// errors.Join preserves cancellation and timeout from any step.
	// Exit code still comes from the first failing step (design A13).
	for _, step := range out.Steps {
		switch step.Result.Status {
		case v1.TaskStatus_TASK_STATUS_CANCELLED:
			expected = v1.TaskStatus_TASK_STATUS_CANCELLED
		case v1.TaskStatus_TASK_STATUS_TIMEOUT:
			if expected != v1.TaskStatus_TASK_STATUS_CANCELLED {
				expected = v1.TaskStatus_TASK_STATUS_TIMEOUT
			}
		case v1.TaskStatus_TASK_STATUS_FAILED, v1.TaskStatus_TASK_STATUS_UNSUPPORTED:
			if expected == v1.TaskStatus_TASK_STATUS_SUCCEEDED {
				expected = v1.TaskStatus_TASK_STATUS_FAILED
			}
		}
	}
	if result.Status != expected {
		return errors.New("INVALID_AGGREGATE_RESULT")
	}
	if !equalExit(exit, result.ExitCode) || truncated != result.Truncated || scan != result.ScanLimitReached {
		return errors.New("INVALID_AGGREGATE_RESULT")
	}
	return nil
}

// terminalCommitted reports whether the task row already holds this write's
// terminal status and result bytes. It reads with its own bounded context.
func (s *Service) terminalCommitted(ctx context.Context, jobID, taskID string, status v1.TaskStatus, result []byte) bool {
	readCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	stored, raw, err := getTaskStatusResult(readCtx, s.Store.Pool, jobID, taskID)
	return err == nil && stored == int16(status) && bytes.Equal(raw, result)
}

func terminalAgentStatus(status v1.TaskStatus) bool {
	return status == v1.TaskStatus_TASK_STATUS_SUCCEEDED || status == v1.TaskStatus_TASK_STATUS_FAILED || status == v1.TaskStatus_TASK_STATUS_TIMEOUT || status == v1.TaskStatus_TASK_STATUS_CANCELLED || status == v1.TaskStatus_TASK_STATUS_UNSUPPORTED
}
func equalExit(a, b *int32) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }
func validateResultScalars(r *v1.ExecutionResult, isStep bool) error {
	if r == nil || (r.Reason != "" && !resultReason.MatchString(r.Reason)) {
		return errors.New("INVALID_EXECUTION_RESULT")
	}
	noProcess := r.ExitCode == nil && r.Stdout == nil && r.Stderr == nil && (r.Status == v1.TaskStatus_TASK_STATUS_UNSUPPORTED || r.Status == v1.TaskStatus_TASK_STATUS_FAILED)
	if r.Duration == nil {
		if !noProcess {
			return errors.New("INVALID_EXECUTION_RESULT")
		}
	} else if r.Duration.CheckValid() != nil || r.Duration.AsDuration() < 0 {
		return errors.New("INVALID_EXECUTION_RESULT")
	}
	if isStep && r.Status == v1.TaskStatus_TASK_STATUS_SKIPPED {
		return nil
	}
	if !terminalAgentStatus(r.Status) {
		return errors.New("INVALID_TASK_STATUS")
	}
	if r.Status == v1.TaskStatus_TASK_STATUS_SUCCEEDED && (r.ExitCode == nil || *r.ExitCode != 0) {
		return errors.New("INVALID_SUCCESS_EXIT")
	}
	if r.Status == v1.TaskStatus_TASK_STATUS_FAILED && r.ExitCode != nil && *r.ExitCode == 0 {
		return errors.New("INVALID_FAILURE_EXIT")
	}
	return nil
}
func validateResult(r *v1.ExecutionResult, out *taskOutput, step int, isStep bool) error {
	if err := validateResultScalars(r, isStep); err != nil {
		return err
	}
	if isStep && r.Status == v1.TaskStatus_TASK_STATUS_SKIPPED {
		if r.ExitCode != nil || r.Stdout != nil || r.Stderr != nil || out.Streams[streamKey{step, v1.OutputStream_OUTPUT_STREAM_STDOUT}] != nil || out.Streams[streamKey{step, v1.OutputStream_OUTPUT_STREAM_STDERR}] != nil {
			return errors.New("SKIPPED_STEP_OUTPUT")
		}
		return nil
	}
	for _, item := range []struct {
		kind v1.OutputStream
		meta *v1.OutputMetadata
	}{{v1.OutputStream_OUTPUT_STREAM_STDOUT, r.Stdout}, {v1.OutputStream_OUTPUT_STREAM_STDERR, r.Stderr}} {
		stream := out.Streams[streamKey{step, item.kind}]
		if stream == nil && item.meta == nil && r.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED {
			continue
		}
		if stream == nil || !stream.EOF || item.meta == nil {
			return errors.New("OUTPUT_EOF_REQUIRED")
		}
		sum := sha256.Sum256(stream.Data)
		if item.meta.SizeBytes != uint64(len(stream.Data)) || !bytes.Equal(item.meta.Sha256, sum[:]) {
			return errors.New("OUTPUT_METADATA_MISMATCH")
		}
	}
	return nil
}

func aggregate(out *taskOutput, a catalog.Action) ([]byte, []byte) {
	var stdout, stderr []byte
	steps := []int{-1}
	if a.Steps != nil {
		steps = nil
		for i := range a.Steps {
			steps = append(steps, i)
		}
	}
	for _, step := range steps {
		if stream := out.Streams[streamKey{step, v1.OutputStream_OUTPUT_STREAM_STDOUT}]; stream != nil {
			stdout = append(stdout, stream.Data...)
		}
		if stream := out.Streams[streamKey{step, v1.OutputStream_OUTPUT_STREAM_STDERR}]; stream != nil {
			stderr = append(stderr, stream.Data...)
		}
	}
	return stdout, stderr
}

func (s *Service) persist(jobID, taskID, hostID, hostname, actor, action string, created time.Time, version uint64, out *taskOutput) {
	out.mu.Lock()
	defer func() {
		out.mu.Unlock()
		s.mu.Lock()
		delete(s.outputs, outputID(jobID, taskID))
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	stored := true
	paths := []audit.Output{}
	for k, stream := range out.Streams {
		if !stream.EOF {
			stored = false
			continue
		}
		var step *uint32
		if k.Step >= 0 {
			step = proto.Uint32(uint32(k.Step))
		}
		name := "stdout"
		if k.Stream == v1.OutputStream_OUTPUT_STREAM_STDERR {
			name = "stderr"
		}
		key := output.Key(created, jobID, hostID, step, name)
		sum := sha256.Sum256(stream.Data)
		paths = append(paths, audit.Output{ObjectPath: key, SHA256: sum[:], Stream: int32(k.Stream), StepIndex: step})
		if err := s.Storage.Put(ctx, key, stream.Data); err != nil {
			stored = false
		}
	}
	state := "stored"
	decision := "allow"
	if !stored {
		state = "failed"
		decision = "deny"
		slog.Error("output object write failed", "job_id", jobID, "task_id", taskID)
	}
	// Upload exhaustion must not consume the required state-write budget.
	// Keep this worker responsible for retryable writes until service shutdown,
	// then use the existing independent five-second terminal cleanup boundary.
	if err := terminalSQL(s.ctx, jobID, func(ctx context.Context) error {
		return updateOutputState(ctx, s.Store.Pool, jobID, taskID, stored, state)
	}); err != nil {
		logSQLFailure(s.ctx, slog.LevelError, "output storage state update failed", jobID, err, "task_id", taskID)
		return
	}
	// Close cancels s.ctx before the state write above; the audit of that state
	// gets the same independent five-second budget instead of failing at once.
	auditCtx, stopAudit := context.WithTimeout(context.WithoutCancel(s.ctx), 5*time.Second)
	defer stopAudit()
	if _, err := s.Audit.Append(auditCtx, audit.Payload{SubjectID: actor, Operation: "store_output", Resource: hostID, Hostname: hostname, Decision: decision, JobID: jobID, TaskID: taskID, Action: action, PolicyVersion: version, Outputs: paths}); err != nil {
		slog.Error("output storage audit failed", "job_id", jobID, "task_id", taskID)
	}
}

func (s *Service) OnDisconnect(e hostconn.Event) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Remote recovery can have made these tasks terminal without clearing the
	// connection owner's buffers. Include all tasks of this generation.
	pairs, err := disconnectTasks(ctx, s.Store.Pool, e.HostID, e.ConnectionID, pendingResult(v1.TaskStatus_TASK_STATUS_OFFLINE, "OFFLINE"))
	if errors.Is(err, errDisconnectScan) {
		return
	}
	if err != nil {
		slog.Error("task disconnect update failed", "host_id", e.HostID)
		return
	}
	for _, p := range pairs {
		s.clearTasks(p.jobID, p.taskID)
	}
}
