package job

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/audit"
)

// Start runs recovery only after hostconn has registered this instance.
func (s *Service) Start() {
	if !s.started.CompareAndSwap(false, true) {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		tick := time.NewTicker(s.recoveryInterval)
		defer tick.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-tick.C:
				if err := s.RecoverLostInstances(s.ctx); err != nil && s.ctx.Err() == nil {
					slog.Error("lost gateway recovery failed", "instance_id", s.instanceID)
				}
			}
		}
	}()
}

// Drain stops admission and later batches, then waits for this instance's jobs
// and the tasks on its current host connections. P4 owns deadline disconnects.
func (s *Service) Drain(ctx context.Context) error {
	s.submitMu.Lock()
	s.draining.Store(true)
	s.submitMu.Unlock()
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	for {
		var tasks int
		if err := s.Store.Pool.QueryRow(ctx, "SELECT count(*) FROM tasks t JOIN hosts h ON h.host_id=t.host_id WHERE t.status IN (1,2) AND t.dispatched AND h.instance_id=$1 AND h.connection_id=t.connection_id", s.instanceID).Scan(&tasks); err != nil {
			return err
		}
		if tasks == 0 && s.activeJobs.Load() == 0 && s.activePersists.Load() == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// RecoverLostInstances implements G52. SKIP LOCKED elects one survivor per job;
// task conditions retain any terminal state that won a completion race.
func (s *Service) RecoverLostInstances(ctx context.Context) error {
	for {
		tx, err := s.Store.Pool.Begin(ctx)
		if err != nil {
			return err
		}
		var id, origin string
		var version uint64
		err = tx.QueryRow(ctx, "SELECT j.job_id,j.origin_instance,j.policy_version FROM jobs j JOIN gateway_instances i ON i.instance_id=j.origin_instance WHERE j.status IN (1,2) AND i.last_seen<now()-$1*interval '1 second' ORDER BY j.job_id FOR UPDATE OF j SKIP LOCKED LIMIT 1", s.lostAfter.Seconds()).Scan(&id, &origin, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			tx.Rollback(ctx)
			return s.recoverLostOutputs(ctx)
		}
		if err != nil {
			tx.Rollback(ctx)
			return err
		}
		event := audit.Payload{SubjectID: "gateway:" + s.instanceID, Operation: "recover_job", Resource: origin, JobID: id, PolicyVersion: version, Decision: "allow", Reason: "authorized"}
		if _, err := s.Audit.Append(ctx, event); err != nil {
			tx.Rollback(ctx)
			return err
		}
		var recoveredTasks []string
		for _, spec := range []struct {
			from   int16
			to     int16
			status v1.TaskStatus
		}{
			{1, 7, v1.TaskStatus_TASK_STATUS_SKIPPED},
			{2, 4, v1.TaskStatus_TASK_STATUS_FAILED},
		} {
			rows, err := tx.Query(ctx, "UPDATE tasks SET status=$3,result=$4,finished_at=now(),output_state='unavailable' WHERE job_id=$1 AND status=$2 RETURNING task_id", id, spec.from, spec.to, pendingResult(spec.status, "GATEWAY_INSTANCE_LOST"))
			if err != nil {
				tx.Rollback(ctx)
				return err
			}
			for rows.Next() {
				var taskID string
				if err := rows.Scan(&taskID); err != nil {
					rows.Close()
					tx.Rollback(ctx)
					return err
				}
				recoveredTasks = append(recoveredTasks, taskID)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				tx.Rollback(ctx)
				return err
			}
		}
		if err := s.finishJobTx(ctx, tx, id); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		s.clearTasks(id, recoveredTasks...)
		event.Reason = "result"
		if _, err := s.Audit.Append(ctx, event); err != nil {
			slog.Error("lost gateway recovery result audit failed", "job_id", id)
			return err
		}
	}
}

// recoverLostOutputs ends the pending output of terminal tasks whose receiving
// gateway process is lost by the same last_seen rule as job recovery. That
// process persisted the output from memory and no other process can; without
// this, GetJobOutput would answer OUTPUT_PENDING forever. The audit event is
// the one persist writes for a failed upload. A task whose output_instance is
// NULL (written before the column existed) is not touched.
func (s *Service) recoverLostOutputs(ctx context.Context) error {
	for {
		tx, err := s.Store.Pool.Begin(ctx)
		if err != nil {
			return err
		}
		var jobID, taskID, hostID, hostname, actor, action string
		var version uint64
		err = tx.QueryRow(ctx, "SELECT t.job_id,t.task_id,t.host_id,t.hostname,j.subject_id,j.action,j.policy_version FROM tasks t JOIN jobs j ON j.job_id=t.job_id JOIN gateway_instances i ON i.instance_id=t.output_instance WHERE t.output_state='pending' AND t.status>2 AND i.last_seen<now()-$1*interval '1 second' ORDER BY t.job_id,t.task_id FOR UPDATE OF t SKIP LOCKED LIMIT 1", s.lostAfter.Seconds()).Scan(&jobID, &taskID, &hostID, &hostname, &actor, &action, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			tx.Rollback(ctx)
			return nil
		}
		if err != nil {
			tx.Rollback(ctx)
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE tasks SET output_state='unavailable' WHERE job_id=$1 AND task_id=$2", jobID, taskID); err != nil {
			tx.Rollback(ctx)
			return err
		}
		// Audit before COMMIT: a failed append leaves the task pending for the
		// next pass instead of an unavailable output without a record.
		if _, err := s.Audit.Append(ctx, audit.Payload{SubjectID: actor, Operation: "store_output", Resource: hostID, Hostname: hostname, Decision: "deny", Reason: "OUTPUT_INSTANCE_LOST", JobID: jobID, TaskID: taskID, Action: action, PolicyVersion: version, Outputs: []audit.Output{}}); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
}
