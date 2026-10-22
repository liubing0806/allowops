package job

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/store"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func paginate[T proto.Message](scope string, r *v1.PageRequest, items []T) ([]T, *v1.PageResponse, error) {
	n := 50
	offset := 0
	sum := sha256.Sum256([]byte(scope))
	binding := hex.EncodeToString(sum[:])
	if r != nil {
		if r.PageSize > 200 {
			return nil, nil, failure(connect.CodeInvalidArgument, "PAGE_SIZE_EXCEEDED")
		}
		if r.PageSize > 0 {
			n = int(r.PageSize)
		}
		if r.PageToken != "" {
			raw, err := base64.RawURLEncoding.DecodeString(r.PageToken)
			if err != nil {
				return nil, nil, failure(connect.CodeInvalidArgument, "INVALID_PAGE_TOKEN")
			}
			parts := strings.Split(string(raw), ":")
			if len(parts) != 2 || parts[0] != binding {
				return nil, nil, failure(connect.CodeInvalidArgument, "INVALID_PAGE_TOKEN")
			}
			offset, err = strconv.Atoi(parts[1])
			if err != nil || offset < 0 || offset > len(items) {
				return nil, nil, failure(connect.CodeInvalidArgument, "INVALID_PAGE_TOKEN")
			}
		}
	}
	end := min(offset+n, len(items))
	bytes := 512
	for i := offset; i < end; i++ {
		raw, err := protojson.Marshal(items[i])
		if err != nil {
			return nil, nil, err
		}
		size := max(len(raw), proto.Size(items[i])) + 2
		if bytes+size > ResponseBytes {
			if i == offset {
				return nil, nil, failure(connect.CodeResourceExhausted, "JOB_RESPONSE_LIMIT")
			}
			end = i
			break
		}
		bytes += size
	}
	page := &v1.PageResponse{}
	if end < len(items) {
		page.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(binding + ":" + strconv.Itoa(end)))
	}
	return items[offset:end], page, nil
}

func (s *Service) GetJob(ctx context.Context, r *v1.GetJobRequest) (*v1.GetJobResponse, error) {
	m, err := s.operation(ctx, "get_job", false, func(ctx context.Context) (proto.Message, error) {
		if r == nil {
			return nil, failure(connect.CodeInvalidArgument, "REQUEST_REQUIRED")
		}
		f, err := format(r.ResponseFormat)
		if err != nil {
			return nil, err
		}
		seconds, err := s.waitValue(r.WaitSeconds, s.Config.WaitSeconds)
		if err != nil {
			return nil, err
		}
		j, err := s.get(ctx, r.JobId)
		if err != nil {
			return nil, err
		}
		if _, _, err := s.authorize(ctx, j, authz.ViewJobs, false, ""); err != nil {
			return nil, err
		}
		j, err = s.wait(ctx, r.JobId, seconds)
		if err != nil {
			return nil, err
		}
		summary, err := s.summary(ctx, j, f)
		if err != nil {
			return nil, err
		}
		return &v1.GetJobResponse{Job: j, Summary: summary}, nil
	})
	if err != nil {
		return nil, err
	}
	return m.(*v1.GetJobResponse), nil
}

func (s *Service) ListJobs(ctx context.Context, r *v1.ListJobsRequest) (*v1.ListJobsResponse, error) {
	m, err := s.operation(ctx, "list_jobs", false, func(ctx context.Context) (proto.Message, error) {
		if r == nil {
			return nil, failure(connect.CodeInvalidArgument, "REQUEST_REQUIRED")
		}
		id, _ := api.FromContext(ctx)
		actor, _ := api.RequestInfo(ctx)
		subject := r.SubjectId
		if id.Subject.Kind == "service_account" {
			if subject != "" && subject != actor {
				return nil, failure(connect.CodePermissionDenied, "JOB_OWNER_REQUIRED")
			}
			subject = actor
		}
		var from, to *time.Time
		if r.Created != nil {
			if r.Created.From != nil {
				if err := r.Created.From.CheckValid(); err != nil {
					return nil, failure(connect.CodeInvalidArgument, "INVALID_TIME_RANGE")
				}
				v := r.Created.From.AsTime()
				from = &v
			}
			if r.Created.To != nil {
				if err := r.Created.To.CheckValid(); err != nil {
					return nil, failure(connect.CodeInvalidArgument, "INVALID_TIME_RANGE")
				}
				v := r.Created.To.AsTime()
				to = &v
			}
			if from != nil && to != nil && !from.Before(*to) {
				return nil, failure(connect.CodeInvalidArgument, "INVALID_TIME_RANGE")
			}
		}
		statuses := []int16{}
		for _, status := range r.Statuses {
			if status < 1 || status > 7 {
				return nil, failure(connect.CodeInvalidArgument, "INVALID_JOB_STATUS")
			}
			statuses = append(statuses, int16(status))
		}
		rows, err := s.Store.Pool.Query(ctx, "SELECT job_id FROM jobs WHERE ($1='' OR subject_id=$1) AND ($2='' OR action=$2) AND ($3::timestamptz IS NULL OR created_at>=$3) AND ($4::timestamptz IS NULL OR created_at<$4) AND (cardinality($5::smallint[])=0 OR status=ANY($5)) ORDER BY created_at DESC,job_id DESC", subject, r.Action, from, to, statuses)
		if err != nil {
			return nil, err
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		items := []*v1.Job{}
		for _, id := range ids {
			j, err := s.get(ctx, id)
			if err != nil {
				return nil, err
			}
			if _, _, err := s.authorize(ctx, j, authz.ViewJobs, false, ""); err != nil {
				if connect.CodeOf(err) == connect.CodePermissionDenied {
					continue
				}
				return nil, err
			}
			items = append(items, j)
		}
		scope := fmt.Sprintf("jobs:%s:%s:%s:%v:%v:%v", actor, subject, r.Action, from, to, statuses)
		items, page, err := paginate(scope, r.Page, items)
		return &v1.ListJobsResponse{Jobs: items, Page: page}, err
	})
	if err != nil {
		return nil, err
	}
	return m.(*v1.ListJobsResponse), nil
}

func (s *Service) ListTasks(ctx context.Context, r *v1.ListTasksRequest) (*v1.ListTasksResponse, error) {
	m, err := s.operation(ctx, "list_tasks", false, func(ctx context.Context) (proto.Message, error) {
		if r == nil {
			return nil, failure(connect.CodeInvalidArgument, "REQUEST_REQUIRED")
		}
		j, err := s.get(ctx, r.JobId)
		if err != nil {
			return nil, err
		}
		if _, _, err := s.authorize(ctx, j, authz.ViewJobs, false, ""); err != nil {
			return nil, err
		}
		all, err := s.tasks(ctx, r.JobId)
		if err != nil {
			return nil, err
		}
		items := []*v1.Task{}
		for _, status := range r.Statuses {
			if status < 1 || status > 9 {
				return nil, failure(connect.CodeInvalidArgument, "INVALID_TASK_STATUS")
			}
		}
		for _, t := range all {
			if r.Hostname != "" && r.Hostname != t.Hostname {
				continue
			}
			matches := len(r.Statuses) == 0
			for _, status := range r.Statuses {
				matches = matches || status == t.Result.Status
			}
			if matches {
				items = append(items, t)
			}
		}
		actor, _ := api.RequestInfo(ctx)
		items, page, err := paginate(fmt.Sprintf("tasks:%s:%s:%s:%v", actor, r.JobId, r.Hostname, r.Statuses), r.Page, items)
		return &v1.ListTasksResponse{Tasks: items, Page: page}, err
	})
	if err != nil {
		return nil, err
	}
	return m.(*v1.ListTasksResponse), nil
}

func (s *Service) ListTaskSteps(ctx context.Context, r *v1.ListTaskStepsRequest) (*v1.ListTaskStepsResponse, error) {
	m, err := s.operation(ctx, "list_task_steps", false, func(ctx context.Context) (proto.Message, error) {
		if r == nil {
			return nil, failure(connect.CodeInvalidArgument, "REQUEST_REQUIRED")
		}
		j, err := s.get(ctx, r.JobId)
		if err != nil {
			return nil, err
		}
		if _, _, err := s.authorize(ctx, j, authz.ViewJobs, false, ""); err != nil {
			return nil, err
		}
		var exists bool
		if err := s.Store.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM tasks WHERE job_id=$1 AND task_id=$2)", r.JobId, r.TaskId).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			return nil, failure(connect.CodeNotFound, "TASK_UNKNOWN")
		}
		rows, err := s.Store.Pool.Query(ctx, "SELECT step_index,name,result FROM task_steps WHERE job_id=$1 AND task_id=$2 ORDER BY step_index", r.JobId, r.TaskId)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		items := []*v1.TaskStep{}
		for rows.Next() {
			v := &v1.TaskStep{Result: &v1.ExecutionResult{}}
			var raw []byte
			if err := rows.Scan(&v.Index, &v.Name, &raw); err != nil {
				return nil, err
			}
			if err := proto.Unmarshal(raw, v.Result); err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		actor, _ := api.RequestInfo(ctx)
		items, page, err := paginate("steps:"+actor+":"+r.JobId+":"+r.TaskId, r.Page, items)
		return &v1.ListTaskStepsResponse{Steps: items, Page: page}, err
	})
	if err != nil {
		return nil, err
	}
	return m.(*v1.ListTaskStepsResponse), nil
}

func (s *Service) CancelJob(ctx context.Context, r *v1.CancelJobRequest) (*v1.CancelJobResponse, error) {
	m, err := s.operation(ctx, "cancel_job", true, func(ctx context.Context) (proto.Message, error) {
		if r == nil {
			return nil, failure(connect.CodeInvalidArgument, "REQUEST_REQUIRED")
		}
		j, err := s.get(ctx, r.JobId)
		if err != nil {
			return nil, err
		}
		version, rules, err := s.authorize(ctx, j, authz.ViewJobs, true, "")
		if err != nil {
			return nil, err
		}
		if err := s.audit(ctx, "cancel_job", "authorized", "allow", j.JobId, version, rules); err != nil {
			return nil, err
		}
		tx, err := s.Store.Pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback(ctx)
		var status int16
		var requested bool
		if err := tx.QueryRow(ctx, "SELECT status,cancel_requested FROM jobs WHERE job_id=$1 FOR UPDATE", j.JobId).Scan(&status, &requested); err != nil {
			return nil, err
		}
		var cancelledTasks []string
		if status <= 2 && !requested {
			if _, err := tx.Exec(ctx, "UPDATE jobs SET cancel_requested=true WHERE job_id=$1", j.JobId); err != nil {
				return nil, err
			}
			rows, err := tx.Query(ctx, "UPDATE tasks SET status=8,result=$2,finished_at=now(),output_state='unavailable' WHERE job_id=$1 AND status=1 RETURNING task_id", j.JobId, pendingResult(v1.TaskStatus_TASK_STATUS_CANCELLED, "CANCELLED"))
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var taskID string
				if err := rows.Scan(&taskID); err != nil {
					rows.Close()
					return nil, err
				}
				cancelledTasks = append(cancelledTasks, taskID)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return nil, err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		s.clearTasks(j.JobId, cancelledTasks...)
		operationInfo(ctx).Committed = status <= 2
		if status <= 2 {
			s.startCancelWorker(j.JobId, !requested)
		} else {
			s.mu.Lock()
			delete(s.cancelWorkers, j.JobId)
			s.mu.Unlock()
		}
		j, err = s.get(ctx, j.JobId)
		return &v1.CancelJobResponse{Job: j}, err
	})
	if err != nil {
		return nil, err
	}
	return m.(*v1.CancelJobResponse), nil
}

// startCancelWorker runs the job's cancellation worker on this instance. The first
// request always starts it. A repeated request restarts it only when the worker this
// instance started stopped on an unrecoverable error; a running worker, here or on
// another instance, is never duplicated.
func (s *Service) startCancelWorker(id string, first bool) {
	s.mu.Lock()
	if s.cancelWorkers == nil {
		s.cancelWorkers = map[string]bool{}
	}
	running, stopped := s.cancelWorkers[id]
	if running || (!first && !stopped) {
		s.mu.Unlock()
		return
	}
	s.cancelWorkers[id] = true
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		finished := s.cancelTasks(s.ctx, id)
		s.mu.Lock()
		if finished {
			delete(s.cancelWorkers, id)
		} else {
			s.cancelWorkers[id] = false
		}
		s.mu.Unlock()
	}()
}

// cancelTasks reports whether the worker finished the job, as opposed to stopping
// on a SQL error or service shutdown.
func (s *Service) cancelTasks(ctx context.Context, id string) bool {
	for {
		type target struct {
			id, host, connection string
			status               int16
		}
		var targets []target
		err := retrySQL(ctx, id, func(ctx context.Context) error {
			targets = nil
			rows, err := s.Store.Pool.Query(ctx, "SELECT task_id,host_id,COALESCE(connection_id,''),status FROM tasks WHERE job_id=$1 AND status IN (1,2) AND dispatched", id)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var t target
				if err := rows.Scan(&t.id, &t.host, &t.connection, &t.status); err != nil {
					return err
				}
				targets = append(targets, t)
			}
			return rows.Err()
		})
		if err != nil {
			logSQLFailure(ctx, slog.LevelError, "job cancellation worker stopped", id, err)
			return false
		}
		if len(targets) == 0 {
			if err := retrySQL(ctx, id, func(ctx context.Context) error { return s.finishJob(ctx, id) }); err != nil {
				logSQLFailure(ctx, slog.LevelError, "job cancellation worker stopped", id, err)
				return false
			}
			return true
		}
		for _, t := range targets {
			if ctx.Err() != nil {
				return false
			}
			if t.status != 2 {
				continue
			}
			cancelCtx, done := context.WithTimeout(ctx, 10*time.Second)
			m := &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{JobId: id, TaskId: t.id, Reason: "CANCELLED"}}}
			if bound, ok := s.Router.(interface {
				SendToConnection(context.Context, string, string, *v1.ConnectResponse) (*v1.TaskCompleted, error)
			}); ok {
				_, err = bound.SendToConnection(cancelCtx, t.host, t.connection, m)
			} else {
				_, err = s.Router.Send(cancelCtx, t.host, m)
			}
			done()
			if errors.Is(err, store.ErrOffline) {
				s.dispatchTerminal(ctx, id, t.id, &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_OFFLINE, Reason: "OFFLINE"})
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(pollInterval):
		}
	}
}
