package job

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store/db"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func structCatalogRef(id string, version int64) db.GetCatalogParams {
	return db.GetCatalogParams{CatalogID: id, Version: version}
}

func (s *Service) hosts(ctx context.Context) ([]host, error) {
	return listActiveHosts(ctx, s.Store.Pool)
}

func (s *Service) get(ctx context.Context, id string) (*v1.Job, error) {
	j, err := selectJob(ctx, s.Store.Pool, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, failure(connect.CodeNotFound, "JOB_UNKNOWN")
	}
	if err != nil {
		return nil, failure(connect.CodeUnavailable, "JOB_DATABASE_UNAVAILABLE")
	}
	counts, err := countJobTasksByStatus(ctx, s.Store.Pool, id)
	if err != nil {
		return nil, err
	}
	for _, c := range counts {
		j.Counts = append(j.Counts, c)
		j.TotalTasks += c.Count
	}
	return j, nil
}

func (s *Service) tasks(ctx context.Context, id string) ([]*v1.Task, error) {
	return listJobTasks(ctx, s.Store.Pool, id)
}

func (s *Service) create(ctx context.Context, subject string, p *catalog.Package, a catalog.Action, digest []byte, reason string, targets []host, batch, failures uint32, version uint64, denied bool) (*v1.Job, error) {
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	at := time.Now().UTC().Truncate(time.Microsecond)
	if err := partition(ctx, tx, at); err != nil {
		return nil, err
	}
	if err := lockJobSubject(ctx, tx, subject); err != nil {
		return nil, err
	}
	identity, _ := reqctx.FromContext(ctx)
	if !denied && identity != nil && identity.Subject.Kind == "service_account" {
		n, err := countActiveJobs(ctx, tx, subject)
		if err != nil {
			return nil, err
		}
		if n >= 5 {
			return nil, failure(connect.CodeResourceExhausted, "CONCURRENT_JOB_LIMIT")
		}
	}
	sequence, err := nextJobSequence(ctx, tx, at)
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("job-%s-%04d", at.Format("20060102"), sequence)
	definition, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	status := v1.JobStatus_JOB_STATUS_QUEUED
	var finished *time.Time
	if denied {
		status = v1.JobStatus_JOB_STATUS_DENIED
		finished = &at
	}
	if err := insertJob(ctx, tx, newJob{id: id, at: at, subject: subject, action: a.Name, definition: definition, catalogID: p.CatalogID, catalogVersion: p.Version, digest: digest, policyVersion: version, reason: reason, status: status, batch: batch, failures: failures, finished: finished, origin: s.instanceID}); err != nil {
		return nil, err
	}
	if !denied {
		raw, _ := proto.Marshal(&v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_PENDING})
		for i, h := range targets {
			if err := insertPendingTask(ctx, tx, id, fmt.Sprintf("%s-%d", id, i), at, h, i, raw); err != nil {
				return nil, err
			}
		}
	}
	// A COMMIT error is not a rollback. Commit outside the request's cancellation
	// and, when it still reports an error, keep the job if the database holds it.
	commitCtx, stopCommit := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	err = tx.Commit(commitCtx)
	stopCommit()
	if err != nil && !s.jobCommitted(ctx, id, at, subject) {
		return nil, err
	}
	// Admission must not depend on a request-context read after COMMIT.
	// Response reads can still fail without abandoning the committed scheduler.
	j := &v1.Job{JobId: id, Action: a.Name, Catalog: &v1.CatalogRef{CatalogId: p.CatalogID, Version: uint64(p.Version)}, ActionSha256: digest, SubjectId: subject, Reason: reason, Status: status, CreatedAt: timestamppb.New(at), PolicyVersion: version}
	if finished != nil {
		j.FinishedAt = timestamppb.New(*finished)
	}
	if !denied && len(targets) > 0 {
		j.TotalTasks = uint64(len(targets))
		j.Counts = []*v1.TaskCount{{Status: v1.TaskStatus_TASK_STATUS_PENDING, Count: j.TotalTasks}}
	}
	return j, nil
}

// jobCommitted reports whether this create transaction's job row exists. The job
// ID is built from the per-day counter row in job_sequences, which the same
// transaction updates under a row lock, so two transactions cannot obtain the
// same ID while both are live; a rolled-back transaction releases its counter
// value for reuse. A row with this ID may therefore come from a later transaction
// that reused the value after our rollback. That transaction's created_at is its
// own time.Now() at microsecond precision, and its subject_id is the caller's
// subject, so (job_id, created_at, subject_id) all matching identifies the row as
// ours and not a reused-ID row from another transaction or subject. It reads with
// its own bounded context.
func (s *Service) jobCommitted(ctx context.Context, id string, created time.Time, subject string) bool {
	readCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	found, err := jobCreatedBy(readCtx, s.Store.Pool, id, created, subject)
	return err == nil && found
}

func (s *Service) setTerminal(ctx context.Context, jobID, taskID string, result *v1.ExecutionResult) error {
	raw, err := proto.Marshal(result)
	if err != nil {
		return err
	}
	affected, err := updateTaskTerminal(ctx, s.Store.Pool, jobID, taskID, int16(result.Status), raw)
	if err != nil {
		return err
	}
	if affected == 0 {
		terminal, err := isTaskTerminal(ctx, s.Store.Pool, jobID, taskID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil || !terminal {
			return err
		}
	}
	s.clearTasks(jobID, taskID)
	return nil
}

// Running jobs are counted across all instances. P4B may call CountJobs without
// relying on the current instance's in-memory scheduler.
func (s *Service) CountJobs(ctx context.Context) (uint64, error) {
	running, _, err := s.Statistics(ctx)
	return running, err
}

// Statistics counts only jobs visible through the same A21 authorization used
// by GetJob/ListJobs. Failed includes failed/partially_failed completed in 24h.
func (s *Service) Statistics(ctx context.Context) (running, failed uint64, err error) {
	if err := s.Access.CheckRequest(ctx, false); err != nil {
		return 0, 0, err
	}
	items, err := listStatisticsJobs(ctx, s.Store.Pool)
	if err != nil {
		return 0, 0, err
	}
	for _, v := range items {
		j, err := s.get(ctx, v.id)
		if err != nil {
			return 0, 0, err
		}
		if _, _, err := s.authorize(ctx, j, authz.ViewJobs, false, ""); err != nil {
			if connect.CodeOf(err) == connect.CodePermissionDenied {
				continue
			}
			return 0, 0, err
		}
		if v.status == 1 || v.status == 2 {
			running++
		} else {
			failed++
		}
	}
	return running, failed, nil
}
