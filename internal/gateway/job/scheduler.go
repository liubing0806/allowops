package job

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"sync"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/store"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

// A22: this bit set is the only definition of max_failures accounting.
const failureStatuses uint32 = 1<<v1.TaskStatus_TASK_STATUS_FAILED |
	1<<v1.TaskStatus_TASK_STATUS_TIMEOUT | 1<<v1.TaskStatus_TASK_STATUS_UNSUPPORTED

func failedStatus(status v1.TaskStatus) bool {
	return status >= 0 && status < 32 && failureStatuses&(1<<status) != 0
}

func (s *Service) schedule(ctx context.Context, j *v1.Job, a catalog.Action, r *v1.RunJobRequest, batch, limit uint32) error {
	if err := retrySQL(ctx, j.JobId, func(ctx context.Context) error {
		_, err := s.Store.Pool.Exec(ctx, "UPDATE jobs SET status=2 WHERE job_id=$1 AND status=1", j.JobId)
		return err
	}); err != nil {
		return err
	}
	var tasks []*v1.Task
	if err := retrySQL(ctx, j.JobId, func(ctx context.Context) error { var err error; tasks, err = s.tasks(ctx, j.JobId); return err }); err != nil {
		return err
	}
	for start := 0; start < len(tasks); start += int(batch) {
		var cancel bool
		var failures int
		if err := retrySQL(ctx, j.JobId, func(ctx context.Context) error {
			return s.Store.Pool.QueryRow(ctx, "SELECT cancel_requested FROM jobs WHERE job_id=$1", j.JobId).Scan(&cancel)
		}); err != nil {
			return err
		}
		var current []*v1.Task
		if err := retrySQL(ctx, j.JobId, func(ctx context.Context) error { var err error; current, err = s.tasks(ctx, j.JobId); return err }); err != nil {
			return err
		}
		for _, t := range current {
			if failedStatus(t.Result.Status) {
				failures++
			}
		}
		if cancel || failures > int(limit) || s.draining.Load() {
			status := v1.TaskStatus_TASK_STATUS_SKIPPED
			reason := "MAX_FAILURES"
			if s.draining.Load() {
				reason = "GATEWAY_DRAINING"
			}
			if cancel {
				status = v1.TaskStatus_TASK_STATUS_CANCELLED
				reason = "CANCELLED"
			}
			for _, t := range tasks[start:] {
				if err := retrySQL(ctx, j.JobId, func(ctx context.Context) error {
					return s.setTerminal(ctx, j.JobId, t.TaskId, &v1.ExecutionResult{Status: status, Reason: reason})
				}); err != nil {
					return err
				}
			}
			break
		}
		var wg sync.WaitGroup
		for _, t := range tasks[start:min(start+int(batch), len(tasks))] {
			wg.Add(1)
			go func() { defer wg.Done(); s.dispatch(ctx, j, t, a, r) }()
		}
		wg.Wait()
	}
	return retrySQL(ctx, j.JobId, func(ctx context.Context) error { return s.finishJob(ctx, j.JobId) })
}

func (s *Service) dispatch(ctx context.Context, j *v1.Job, t *v1.Task, a catalog.Action, r *v1.RunJobRequest) {
	// Shared job row locks let independent reservations proceed concurrently.
	// CancelJob's exclusive lock still makes reservation atomic with cancellation.
	// TaskStarted, not reservation, confirms actual execution.
	if ctx.Err() != nil {
		return
	}
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		s.dispatchTerminal(ctx, j.JobId, t.TaskId, &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_OFFLINE, Reason: "OFFLINE"})
		return
	}
	defer tx.Rollback(ctx)
	var cancel bool
	var jobStatus int16
	if err := tx.QueryRow(ctx, "SELECT cancel_requested,status FROM jobs WHERE job_id=$1 FOR SHARE", j.JobId).Scan(&cancel, &jobStatus); err != nil {
		tx.Rollback(ctx)
		if ctx.Err() != nil {
			return
		}
		s.dispatchTerminal(ctx, j.JobId, t.TaskId, &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_OFFLINE, Reason: "OFFLINE"})
		return
	}
	if jobStatus > 2 {
		return
	}
	if cancel {
		tx.Rollback(ctx)
		s.dispatchTerminal(ctx, j.JobId, t.TaskId, &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_CANCELLED, Reason: "CANCELLED"})
		return
	}
	var connection *string
	if err := tx.QueryRow(ctx, "SELECT connection_id FROM hosts WHERE host_id=$1 AND certificate_status='active'", t.HostId).Scan(&connection); err != nil || connection == nil {
		tx.Rollback(ctx)
		s.dispatchTerminal(ctx, j.JobId, t.TaskId, &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_OFFLINE, Reason: "OFFLINE"})
		return
	}
	tag, err := tx.Exec(ctx, "UPDATE tasks SET dispatched=true,connection_id=$3 WHERE job_id=$1 AND task_id=$2 AND status=1 AND NOT dispatched", j.JobId, t.TaskId, *connection)
	if err != nil {
		tx.Rollback(ctx)
		if ctx.Err() != nil {
			return
		}
		s.dispatchTerminal(ctx, j.JobId, t.TaskId, &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_OFFLINE, Reason: "OFFLINE"})
		return
	}
	if tag.RowsAffected() == 0 {
		return
	}
	dispatchCtx, done := context.WithTimeout(ctx, timeout(a)+10*time.Second)
	defer done()
	key := outputID(j.JobId, t.TaskId)
	s.mu.Lock()
	if s.dispatches == nil {
		s.dispatches = map[string]context.CancelFunc{}
	}
	s.dispatches[key] = done
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.dispatches, key)
		s.mu.Unlock()
	}()
	if err := tx.Commit(ctx); err != nil {
		s.dispatchTerminal(ctx, j.JobId, t.TaskId, &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_OFFLINE, Reason: "OFFLINE"})
		return
	}
	params := r.Params
	if params == nil || len(params.Json) == 0 {
		params = &v1.Parameters{Json: []byte("{}")}
	}
	assignment := &v1.TaskAssignment{JobId: j.JobId, TaskId: t.TaskId, Catalog: j.Catalog, Action: j.Action, ActionSha256: j.ActionSha256, Params: params, Timeout: durationpb.New(timeout(a)), Filters: r.Filters}
	message := &v1.ConnectResponse{Message: &v1.ConnectResponse_Task{Task: assignment}}
	var result *v1.TaskCompleted
	if bound, ok := s.Router.(interface {
		SendToConnection(context.Context, string, string, *v1.ConnectResponse) (*v1.TaskCompleted, error)
	}); ok {
		result, err = bound.SendToConnection(dispatchCtx, t.HostId, *connection, message)
	} else {
		result, err = s.Router.Send(dispatchCtx, t.HostId, message)
	}
	if err != nil {
		status, reason := v1.TaskStatus_TASK_STATUS_OFFLINE, "OFFLINE"
		if errors.Is(err, store.ErrCapacity) {
			status, reason = v1.TaskStatus_TASK_STATUS_FAILED, "DISPATCH_CAPACITY"
		}
		s.dispatchTerminal(ctx, j.JobId, t.TaskId, &v1.ExecutionResult{Status: status, Reason: reason})
		return
	}
	// Production owner hooks persist validated results before Router.Send returns.
	// Do not accept unvalidated metadata from an alternate router.
	_ = result
}

// Required terminal writes can outlive a canceled dispatch, but must not keep
// Close waiting on the database without a deadline.
func (s *Service) dispatchTerminal(ctx context.Context, jobID, taskID string, result *v1.ExecutionResult) {
	if err := terminalSQL(ctx, jobID, func(ctx context.Context) error { return s.setTerminal(ctx, jobID, taskID, result) }); err != nil {
		logSQLFailure(ctx, slog.LevelError, "task terminal update failed", jobID, err, "task_id", taskID)
	}
}

func (s *Service) finishJob(ctx context.Context, id string) error {
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.finishJobTx(ctx, tx, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) finishJobTx(ctx context.Context, tx pgx.Tx, id string) error {
	var cancelled bool
	var old int16
	if err := tx.QueryRow(ctx, "SELECT cancel_requested,status FROM jobs WHERE job_id=$1 FOR UPDATE", id).Scan(&cancelled, &old); err != nil {
		return err
	}
	if old > 2 {
		return nil
	}
	rows, err := tx.Query(ctx, "SELECT status,count(*) FROM tasks WHERE job_id=$1 GROUP BY status", id)
	if err != nil {
		return err
	}
	var successes, failures, pending, cancels int
	for rows.Next() {
		var status int16
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			rows.Close()
			return err
		}
		switch v1.TaskStatus(status) {
		case v1.TaskStatus_TASK_STATUS_PENDING, v1.TaskStatus_TASK_STATUS_RUNNING:
			pending += n
		case v1.TaskStatus_TASK_STATUS_SUCCEEDED:
			successes += n
		case v1.TaskStatus_TASK_STATUS_CANCELLED:
			cancels += n
		default:
			failures += n
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if pending > 0 {
		return nil
	}
	status := v1.JobStatus_JOB_STATUS_FAILED
	if failures == 0 && cancels == 0 {
		status = v1.JobStatus_JOB_STATUS_SUCCEEDED
	} else if cancels > 0 && cancelled {
		status = v1.JobStatus_JOB_STATUS_CANCELLED
	} else if successes > 0 {
		status = v1.JobStatus_JOB_STATUS_PARTIALLY_FAILED
	}
	_, err = tx.Exec(ctx, "UPDATE jobs SET status=$2,finished_at=now() WHERE job_id=$1 AND status IN (1,2)", id, int16(status))
	if err != nil {
		return err
	}
	return nil
}

func pendingResult(status v1.TaskStatus, reason string) []byte {
	b, _ := proto.Marshal(&v1.ExecutionResult{Status: status, Reason: reason})
	return b
}
