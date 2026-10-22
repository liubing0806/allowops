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
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/store/db"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func structCatalogRef(id string, version int64) db.GetCatalogParams {
	return db.GetCatalogParams{CatalogID: id, Version: version}
}

func (s *Service) hosts(ctx context.Context) ([]host, error) {
	rows, err := s.Store.Pool.Query(ctx, "SELECT host_id,hostname,COALESCE(connection_id,''),authorization_labels,reported_labels FROM hosts WHERE certificate_status='active' ORDER BY hostname,host_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	all := []host{}
	for rows.Next() {
		var h host
		var labels, reported []byte
		if err := rows.Scan(&h.ID, &h.Name, &h.Connection, &labels, &reported); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(labels, &h.Labels); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(reported, &h.Reported); err != nil {
			return nil, err
		}
		all = append(all, h)
	}
	return all, rows.Err()
}

const jobColumns = "job_id,action,catalog_id,catalog_version,action_sha256,subject_id,reason,status,created_at,finished_at,policy_version"

func scanJob(row pgx.Row) (*v1.Job, error) {
	j := &v1.Job{Catalog: &v1.CatalogRef{}}
	var status int16
	var at time.Time
	var finished *time.Time
	err := row.Scan(&j.JobId, &j.Action, &j.Catalog.CatalogId, &j.Catalog.Version, &j.ActionSha256, &j.SubjectId, &j.Reason, &status, &at, &finished, &j.PolicyVersion)
	j.Status = v1.JobStatus(status)
	j.CreatedAt = timestamppb.New(at)
	if finished != nil {
		j.FinishedAt = timestamppb.New(*finished)
	}
	return j, err
}

func (s *Service) get(ctx context.Context, id string) (*v1.Job, error) {
	j, err := scanJob(s.Store.Pool.QueryRow(ctx, "SELECT "+jobColumns+" FROM jobs WHERE job_id=$1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, failure(connect.CodeNotFound, "JOB_UNKNOWN")
	}
	if err != nil {
		return nil, failure(connect.CodeUnavailable, "JOB_DATABASE_UNAVAILABLE")
	}
	rows, err := s.Store.Pool.Query(ctx, "SELECT status,count(*) FROM tasks WHERE job_id=$1 GROUP BY status ORDER BY status", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c v1.TaskCount
		var status int16
		if err := rows.Scan(&status, &c.Count); err != nil {
			return nil, err
		}
		c.Status = v1.TaskStatus(status)
		j.Counts = append(j.Counts, &c)
		j.TotalTasks += c.Count
	}
	return j, rows.Err()
}

const taskColumns = "job_id,task_id,host_id,hostname,result,started_at,finished_at,output_stored,step_count"

func scanTask(row pgx.Row) (*v1.Task, error) {
	t := &v1.Task{Result: &v1.ExecutionResult{}}
	var raw []byte
	var start, end *time.Time
	err := row.Scan(&t.JobId, &t.TaskId, &t.HostId, &t.Hostname, &raw, &start, &end, &t.OutputStored, &t.StepCount)
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(raw, t.Result); err != nil {
		return nil, err
	}
	if start != nil {
		t.StartedAt = timestamppb.New(*start)
	}
	if end != nil {
		t.FinishedAt = timestamppb.New(*end)
	}
	return t, nil
}
func (s *Service) tasks(ctx context.Context, id string) ([]*v1.Task, error) {
	rows, err := s.Store.Pool.Query(ctx, "SELECT "+taskColumns+" FROM tasks WHERE job_id=$1 ORDER BY position", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []*v1.Task{}
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, t)
	}
	return items, rows.Err()
}

func partition(ctx context.Context, tx pgx.Tx, at time.Time) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(418006)"); err != nil {
		return err
	}
	month := time.Date(at.UTC().Year(), at.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	_, err := tx.Exec(ctx, fmt.Sprintf("CREATE TABLE IF NOT EXISTS tasks_%s PARTITION OF tasks FOR VALUES FROM ('%s') TO ('%s')", month.Format("200601"), month.Format(time.RFC3339), month.AddDate(0, 1, 0).Format(time.RFC3339)))
	return err
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
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,418006))", subject); err != nil {
		return nil, err
	}
	identity, _ := api.FromContext(ctx)
	if !denied && identity != nil && identity.Subject.Kind == "service_account" {
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM jobs WHERE subject_id=$1 AND status IN (1,2)", subject).Scan(&n); err != nil {
			return nil, err
		}
		if n >= 5 {
			return nil, failure(connect.CodeResourceExhausted, "CONCURRENT_JOB_LIMIT")
		}
	}
	var sequence int64
	if err := tx.QueryRow(ctx, "INSERT INTO job_sequences(day,value) VALUES ($1,1) ON CONFLICT(day) DO UPDATE SET value=job_sequences.value+1 RETURNING value", at.Format("2006-01-02")).Scan(&sequence); err != nil {
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
	if _, err := tx.Exec(ctx, "INSERT INTO jobs(job_id,created_at,subject_id,action,action_definition,catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures,finished_at,origin_instance) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)", id, at, subject, a.Name, definition, p.CatalogID, p.Version, digest, version, reason, int16(status), batch, failures, finished, s.instanceID); err != nil {
		return nil, err
	}
	if !denied {
		raw, _ := proto.Marshal(&v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_PENDING})
		for i, h := range targets {
			if _, err := tx.Exec(ctx, "INSERT INTO tasks(job_id,task_id,created_at,host_id,hostname,position,status,result) VALUES ($1,$2,$3,$4,$5,$6,1,$7)", id, fmt.Sprintf("%s-%d", id, i), at, h.ID, h.Name, i, raw); err != nil {
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
	var found bool
	err := s.Store.Pool.QueryRow(readCtx, "SELECT EXISTS(SELECT 1 FROM jobs WHERE job_id=$1 AND created_at=$2 AND subject_id=$3)", id, created, subject).Scan(&found)
	return err == nil && found
}

func (s *Service) setTerminal(ctx context.Context, jobID, taskID string, result *v1.ExecutionResult) error {
	raw, err := proto.Marshal(result)
	if err != nil {
		return err
	}
	tag, err := s.Store.Pool.Exec(ctx, "UPDATE tasks SET status=$3,result=$4,finished_at=now(),output_state='unavailable' WHERE job_id=$1 AND task_id=$2 AND status IN (1,2)", jobID, taskID, int16(result.Status), raw)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var terminal bool
		err := s.Store.Pool.QueryRow(ctx, "SELECT status>2 FROM tasks WHERE job_id=$1 AND task_id=$2", jobID, taskID).Scan(&terminal)
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
	rows, err := s.Store.Pool.Query(ctx, "SELECT job_id,status FROM jobs WHERE status IN (1,2) OR (status IN (4,5) AND finished_at>=now()-interval '24 hours') ORDER BY job_id")
	if err != nil {
		return 0, 0, err
	}
	type item struct {
		id     string
		status int16
	}
	items := []item{}
	for rows.Next() {
		var v item
		if err := rows.Scan(&v.id, &v.status); err != nil {
			rows.Close()
			return 0, 0, err
		}
		items = append(items, v)
	}
	err = rows.Err()
	rows.Close()
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
