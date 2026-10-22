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

func (s *Service) OnMessage(ctx context.Context, e hostconn.Event) error {
	var jobID, taskID string
	if e.Message == nil {
		return nil
	}
	switch {
	case e.Message.GetTaskStarted() != nil:
		m := e.Message.GetTaskStarted()
		jobID, taskID = m.JobId, m.TaskId
	case e.Message.GetOutput() != nil:
		m := e.Message.GetOutput()
		jobID, taskID = m.JobId, m.TaskId
	case e.Message.GetStepCompleted() != nil:
		m := e.Message.GetStepCompleted()
		jobID, taskID = m.JobId, m.TaskId
	case e.Message.GetTaskCompleted() != nil:
		m := e.Message.GetTaskCompleted()
		jobID, taskID = m.JobId, m.TaskId
	default:
		return nil
	}
	// A database failure is not a protocol violation. Closing the stream would
	// end every running task on the host, so retry the whole transaction while
	// the connection lives. In-memory task state changes only after COMMIT.
	// A failed attempt may still have committed, so later attempts are replays
	// that accept the state an earlier attempt wrote for this same event.
	replay := false
	return retrySQL(ctx, jobID, func(ctx context.Context) error {
		err := s.taskEvent(ctx, e, jobID, taskID, replay)
		replay = true
		return err
	})
}

// commitTaskEvent commits a non-terminal task event. Tests replace it to report
// a lost COMMIT acknowledgement after the server committed.
var commitTaskEvent = func(ctx context.Context, tx pgx.Tx) error { return tx.Commit(ctx) }

func (s *Service) taskEvent(ctx context.Context, e hostconn.Event, jobID, taskID string, replay bool) error {
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var definition []byte
	var state int16
	var created time.Time
	var hostID, hostname, connection, actor string
	var dispatched bool
	var version uint64
	err = tx.QueryRow(ctx, "SELECT j.action_definition,t.status,t.created_at,t.host_id,t.hostname,COALESCE(t.connection_id,''),t.dispatched,j.subject_id,j.policy_version FROM tasks t JOIN jobs j ON j.job_id=t.job_id WHERE t.job_id=$1 AND t.task_id=$2 FOR UPDATE OF t", jobID, taskID).Scan(&definition, &state, &created, &hostID, &hostname, &connection, &dispatched, &actor, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("UNKNOWN_TASK_EVENT")
	}
	if err != nil {
		return err
	}
	if hostID != e.HostID || connection != e.ConnectionID || !dispatched {
		return errors.New("TASK_CONNECTION_MISMATCH")
	}
	if state > 2 {
		tx.Rollback(ctx)
		s.clearTasks(jobID, taskID)
		if e.Message.GetTaskStarted() != nil && s.Router != nil {
			reason := "CANCELLED"
			if v1.TaskStatus(state) == v1.TaskStatus_TASK_STATUS_SKIPPED || v1.TaskStatus(state) == v1.TaskStatus_TASK_STATUS_FAILED {
				reason = "GATEWAY_INSTANCE_LOST"
			}
			// Serialize worker admission with Close, including when the event's
			// database read finishes after the service has already stopped.
			s.mu.Lock()
			if s.ctx.Err() != nil {
				s.mu.Unlock()
				return nil
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
		return nil
	} // First terminal result wins; late messages are ignored.
	var a catalog.Action
	if err := json.Unmarshal(definition, &a); err != nil {
		return err
	}
	if started := e.Message.GetTaskStarted(); started != nil {
		if state == 2 && replay {
			// The host stream is serial, so only this event's earlier attempt
			// can have started the task.
			return nil
		}
		if state != 1 {
			return errors.New("DUPLICATE_TASK_START")
		}
		if _, err := tx.Exec(ctx, "UPDATE tasks SET status=2,result=$3,started_at=now() WHERE job_id=$1 AND task_id=$2", jobID, taskID, pendingResult(v1.TaskStatus_TASK_STATUS_RUNNING, "")); err != nil {
			return err
		}
		// Output events publish their buffer while holding the task row lock.
		// Do not create an empty entry after COMMIT releases that lock: a
		// terminal writer may already have committed and cleared the task.
		return commitTaskEvent(ctx, tx)
	}
	if chunk := e.Message.GetOutput(); chunk != nil {
		if state != 2 || (chunk.Stream != v1.OutputStream_OUTPUT_STREAM_STDOUT && chunk.Stream != v1.OutputStream_OUTPUT_STREAM_STDERR) || (len(chunk.Data) == 0 && !chunk.Eof) {
			return errors.New("INVALID_OUTPUT_CHUNK")
		}
	} else if step := e.Message.GetStepCompleted(); step != nil {
		if state != 2 || a.Steps == nil || int(step.StepIndex) >= len(a.Steps) || step.StepName != a.Steps[step.StepIndex].Name {
			return errors.New("INVALID_STEP_RESULT")
		}
	} else if completed := e.Message.GetTaskCompleted(); completed != nil {
		if completed.Result == nil {
			return errors.New("MISSING_TASK_RESULT")
		}
		if state == 1 && completed.Result.Status == v1.TaskStatus_TASK_STATUS_SUCCEEDED {
			return errors.New("RESULT_BEFORE_START")
		}
	}
	s.mu.Lock()
	key := outputID(jobID, taskID)
	out := s.outputs[key]
	if out == nil {
		out = &taskOutput{Streams: map[streamKey]*streamOutput{}}
		if e.Message.GetTaskCompleted() == nil {
			s.outputs[key] = out
		}
	}
	s.mu.Unlock()
	// The task row lock orders events against cancellation and disconnects.
	// Keep in-memory synchronization per task; SQL must not hold the map lock
	// and serialize results from unrelated hosts.
	out.mu.Lock()
	defer out.mu.Unlock()
	if chunk := e.Message.GetOutput(); chunk != nil {
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
		if err := commitTaskEvent(ctx, tx); err != nil {
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
	} else if step := e.Message.GetStepCompleted(); step != nil {
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
		raw, err := proto.Marshal(step.Result)
		if err != nil {
			return err
		}
		insert := "INSERT INTO task_steps(job_id,task_id,created_at,step_index,name,result) VALUES ($1,$2,$3,$4,$5,$6)"
		if replay {
			// out.Steps changes only after COMMIT, so an existing row for this
			// index was written by this event's earlier attempt.
			insert += " ON CONFLICT DO NOTHING"
		}
		if _, err := tx.Exec(ctx, insert, jobID, taskID, created, step.StepIndex, step.StepName, raw); err != nil {
			return err
		}
		if err := commitTaskEvent(ctx, tx); err != nil {
			return err
		}
		out.Steps = append(out.Steps, &v1.TaskStep{Index: step.StepIndex, Name: step.StepName, Result: proto.Clone(step.Result).(*v1.ExecutionResult)})
		return nil
	} else if completed := e.Message.GetTaskCompleted(); completed != nil {
		if a.Steps == nil {
			if completed.CompletedSteps != 0 {
				return errors.New("INVALID_STEP_COUNT")
			}
			if err := validateResult(completed.Result, out, -1, false); err != nil {
				return err
			}
		} else {
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
			if len(out.Steps) > 0 {
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
				// Exit code still comes from the first failing step (A13).
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
				if completed.Result.Status != expected {
					return errors.New("INVALID_AGGREGATE_RESULT")
				}
				if !equalExit(exit, completed.Result.ExitCode) || truncated != completed.Result.Truncated || scan != completed.Result.ScanLimitReached {
					return errors.New("INVALID_AGGREGATE_RESULT")
				}
			}
			if !terminalAgentStatus(completed.Result.Status) {
				return errors.New("INVALID_TASK_STATUS")
			}
		}
		stdout, stderr := aggregate(out, a)
		stdoutHash, stderrHash := sha256.Sum256(stdout), sha256.Sum256(stderr)
		raw, err := proto.Marshal(completed.Result)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE tasks SET status=$3,result=$4,finished_at=now(),stdout_preview=$5,stderr_preview=$6,stdout_sha256=$7,stderr_sha256=$8,step_count=$9,stdout_size=$10,stderr_size=$11,output_instance=$12 WHERE job_id=$1 AND task_id=$2 AND status IN (1,2)", jobID, taskID, int16(completed.Result.Status), raw, stdout[:min(len(stdout), GroupBytes)], stderr[:min(len(stderr), GroupBytes)], stdoutHash[:], stderrHash[:], len(out.Steps), len(stdout), len(stderr), s.instanceID); err != nil {
			return err
		}
		// output_instance names the process whose persist goroutine moves
		// output_state on; it can differ from jobs.origin_instance. If that
		// process dies first, RecoverLostInstances marks the output unavailable.
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
		err = tx.Commit(commitCtx)
		stopCommit()
		if err != nil && !s.terminalCommitted(ctx, jobID, taskID, completed.Result.Status, raw) {
			s.activePersists.Add(-1)
			s.wg.Done()
			return err
		}
		go func() {
			defer s.wg.Done()
			defer s.activePersists.Add(-1)
			s.persist(jobID, taskID, hostID, hostname, actor, a.Name, created, version, out)
		}()
		return nil
	}
	return tx.Commit(ctx)
}

// terminalCommitted reports whether the task row already holds this write's
// terminal status and result bytes. It reads with its own bounded context.
func (s *Service) terminalCommitted(ctx context.Context, jobID, taskID string, status v1.TaskStatus, result []byte) bool {
	readCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	var stored int16
	var raw []byte
	err := s.Store.Pool.QueryRow(readCtx, "SELECT status,result FROM tasks WHERE job_id=$1 AND task_id=$2", jobID, taskID).Scan(&stored, &raw)
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
		_, err := s.Store.Pool.Exec(ctx, "UPDATE tasks SET output_stored=$3,output_state=$4 WHERE job_id=$1 AND task_id=$2", jobID, taskID, stored, state)
		return err
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
	rows, err := s.Store.Pool.Query(ctx, "WITH disconnected AS (UPDATE tasks SET status=6,result=$3,finished_at=now(),output_state='unavailable' WHERE host_id=$1 AND connection_id=$2 AND status IN (1,2) RETURNING job_id,task_id) SELECT job_id,task_id FROM tasks WHERE host_id=$1 AND connection_id=$2", e.HostID, e.ConnectionID, pendingResult(v1.TaskStatus_TASK_STATUS_OFFLINE, "OFFLINE"))
	if err != nil {
		slog.Error("task disconnect update failed", "host_id", e.HostID)
		return
	}
	type pair struct{ jobID, taskID string }
	pairs := []pair{}
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.jobID, &p.taskID); err != nil {
			rows.Close()
			return
		}
		pairs = append(pairs, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		slog.Error("task disconnect update failed", "host_id", e.HostID)
		return
	}
	for _, p := range pairs {
		s.clearTasks(p.jobID, p.taskID)
	}
}
