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
		tasks, err := countDrainTasks(ctx, s.Store.Pool, s.instanceID)
		if err != nil {
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
		id, origin, version, err := lockLostInstanceJob(ctx, tx, s.lostAfter.Seconds())
		if errors.Is(err, pgx.ErrNoRows) {
			tx.Rollback(ctx)
			return nil
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
			ids, err := recoverTasks(ctx, tx, id, spec.from, spec.to, pendingResult(spec.status, "GATEWAY_INSTANCE_LOST"))
			if err != nil {
				tx.Rollback(ctx)
				return err
			}
			recoveredTasks = append(recoveredTasks, ids...)
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
