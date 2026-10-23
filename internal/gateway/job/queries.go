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
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func pageBinding(scope string) string {
	sum := sha256.Sum256([]byte(scope))
	return hex.EncodeToString(sum[:])
}

func pageSize(r *v1.PageRequest) (int, error) {
	if r == nil || r.PageSize == 0 {
		return 50, nil
	}
	if r.PageSize > 200 {
		return 0, failure(connect.CodeInvalidArgument, "PAGE_SIZE_EXCEEDED")
	}
	return int(r.PageSize), nil
}

// fitResponse returns how many leading items fit in ResponseBytes.
func fitResponse[T proto.Message](items []T) (int, error) {
	bytes := 512
	for i, item := range items {
		raw, err := protojson.Marshal(item)
		if err != nil {
			return 0, err
		}
		size := max(len(raw), proto.Size(item)) + 2
		if bytes+size > ResponseBytes {
			if i == 0 {
				return 0, failure(connect.CodeResourceExhausted, "JOB_RESPONSE_LIMIT")
			}
			return i, nil
		}
		bytes += size
	}
	return len(items), nil
}

func paginate[T proto.Message](scope string, r *v1.PageRequest, items []T) ([]T, *v1.PageResponse, error) {
	offset := 0
	binding := pageBinding(scope)
	n, err := pageSize(r)
	if err != nil {
		return nil, nil, err
	}
	if r != nil && r.PageToken != "" {
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
	end := min(offset+n, len(items))
	fit, err := fitResponse(items[offset:end])
	if err != nil {
		return nil, nil, err
	}
	end = offset + fit
	page := &v1.PageResponse{}
	if end < len(items) {
		page.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(binding + ":" + strconv.Itoa(end)))
	}
	return items[offset:end], page, nil
}

// jobCursor is the position of a job in the ListJobs order (created_at DESC,
// job_id DESC). The token of a page holds the cursor of its last job.
type jobCursor struct {
	created time.Time
	id      string
}

func (c jobCursor) token(binding string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(binding + ":" + strconv.FormatInt(c.created.UnixMicro(), 10) + ":" + c.id))
}

func parseJobCursor(token, binding string) (*jobCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, failure(connect.CodeInvalidArgument, "INVALID_PAGE_TOKEN")
	}
	parts := strings.SplitN(string(raw), ":", 3)
	if len(parts) != 3 || parts[0] != binding || parts[2] == "" {
		return nil, failure(connect.CodeInvalidArgument, "INVALID_PAGE_TOKEN")
	}
	micros, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, failure(connect.CodeInvalidArgument, "INVALID_PAGE_TOKEN")
	}
	return &jobCursor{created: time.UnixMicro(micros), id: parts[2]}, nil
}

type jobFilter struct {
	subject, action string
	from, to        *time.Time
	statuses        []int16
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
		id, _ := reqctx.FromContext(ctx)
		actor, _ := reqctx.RequestInfo(ctx)
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
		size, err := pageSize(r.Page)
		if err != nil {
			return nil, err
		}
		scope := fmt.Sprintf("jobs:%s:%s:%s:%v:%v:%v", actor, subject, r.Action, from, to, statuses)
		binding := pageBinding(scope)
		var after *jobCursor
		if r.Page != nil && r.Page.PageToken != "" {
			if after, err = parseJobCursor(r.Page.PageToken, binding); err != nil {
				return nil, err
			}
		}
		// Candidates are read in bounded batches after the cursor and
		// authorized one by one. One job beyond the page tells whether another
		// page exists, so hidden jobs never produce empty or dangling pages.
		filter := jobFilter{subject: subject, action: r.Action, from: from, to: to, statuses: statuses}
		batch := min(max(size+1, 50), 250)
		items := []*v1.Job{}
		for len(items) <= size {
			candidates, err := filter.candidates(ctx, s.Store, after, batch)
			if err != nil {
				return nil, err
			}
			for _, c := range candidates {
				j, err := s.get(ctx, c.id)
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
				if len(items) > size {
					break
				}
			}
			if len(candidates) < batch {
				break
			}
			after = &candidates[len(candidates)-1]
		}
		more := len(items) > size
		items = items[:min(len(items), size)]
		fit, err := fitResponse(items)
		if err != nil {
			return nil, err
		}
		more = more || fit < len(items)
		items = items[:fit]
		page := &v1.PageResponse{}
		if more {
			last := items[len(items)-1]
			page.NextPageToken = jobCursor{created: last.CreatedAt.AsTime(), id: last.JobId}.token(binding)
		}
		return &v1.ListJobsResponse{Jobs: items, Page: page}, nil
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
		actor, _ := reqctx.RequestInfo(ctx)
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
		exists, err := taskExists(ctx, s.Store.Pool, r.JobId, r.TaskId)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, failure(connect.CodeNotFound, "TASK_UNKNOWN")
		}
		items, err := listTaskSteps(ctx, s.Store.Pool, r.JobId, r.TaskId)
		if err != nil {
			return nil, err
		}
		actor, _ := reqctx.RequestInfo(ctx)
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
		status, requested, err := lockJobForCancel(ctx, tx, j.JobId)
		if err != nil {
			return nil, err
		}
		var cancelledTasks []string
		if status <= 2 && !requested {
			if err := requestJobCancel(ctx, tx, j.JobId); err != nil {
				return nil, err
			}
			cancelledTasks, err = cancelPendingTasks(ctx, tx, j.JobId, pendingResult(v1.TaskStatus_TASK_STATUS_CANCELLED, "CANCELLED"))
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
		var targets []cancelTarget
		err := retrySQL(ctx, id, func(ctx context.Context) error {
			var err error
			targets, err = listCancelTargets(ctx, s.Store.Pool, id)
			return err
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
