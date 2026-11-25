package job

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store/db"
	"google.golang.org/protobuf/proto"
)

func (s *Service) finishApproval(ctx context.Context, q *db.Queries, a db.ApprovalRequest, status v1.ApprovalStatus, actor, reason, recheckCode string, version uint64) (db.ApprovalRequest, error) {
	jobStatus := v1.JobStatus_JOB_STATUS_DENIED
	taskReason := ""
	switch status {
	case approvalRejected:
		taskReason = "APPROVAL_REJECTED"
	case approvalExpired:
		taskReason = "APPROVAL_EXPIRED"
	case approvalCancelled:
		jobStatus = v1.JobStatus_JOB_STATUS_CANCELLED
		taskReason = "APPROVAL_CANCELLED"
	case approvalExecutionDenied:
		taskReason = "RECHECK_DENIED"
	}
	row, err := q.FinishApproval(ctx, db.FinishApprovalParams{
		ApprovalID: a.ApprovalID, Status: int16(status), ApprovedCount: a.ApprovedCount,
		DecidedBy: actor, DecisionReason: reason, RecheckError: recheckCode,
		RecheckPolicyVersion: pgtype.Int8{Valid: recheckCode != "", Int64: int64(version)},
	})
	if err != nil {
		return row, err
	}
	affected, err := q.FinishApprovalJob(ctx, db.FinishApprovalJobParams{JobID: a.JobID, Status: int16(jobStatus)})
	if err := approvalJobUpdateError(affected, err); err != nil {
		return row, err
	}
	_, err = q.CancelPendingTasks(ctx, db.CancelPendingTasksParams{JobID: a.JobID, Result: pendingResult(v1.TaskStatus_TASK_STATUS_CANCELLED, taskReason)})
	return row, err
}

func (s *Service) expireApproval(ctx context.Context, tx pgx.Tx, a db.ApprovalRequest) error {
	expired, err := s.finishApproval(ctx, db.New(tx), a, approvalExpired, "", "", "", 0)
	if err != nil {
		return err
	}
	if err := s.auditApproval(ctx, a, "expire_approval", "deny", "APPROVAL_EXPIRED", uint64(a.PolicyVersion), a.MatchedRules); err != nil {
		return err
	}
	if err := commitApproval(ctx, tx); err != nil {
		return err
	}
	if state := operationInfo(ctx); state != nil {
		state.Committed = true
	}
	s.notifyApproval(expired, "expired")
	return nil
}

func (s *Service) expireApprovalVote(ctx context.Context, tx pgx.Tx, a db.ApprovalRequest) error {
	if err := s.expireApproval(ctx, tx, a); err != nil {
		return err
	}
	return failure(connect.CodeFailedPrecondition, "APPROVAL_EXPIRED")
}

func (s *Service) sweepApprovals(ctx context.Context) error {
	for range 50 {
		expired, err := s.sweepApproval(ctx)
		if err != nil || !expired {
			return err
		}
	}
	return nil
}

func (s *Service) sweepApproval(ctx context.Context) (bool, error) {
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	q := db.New(tx)
	a, err := q.LockExpiredApproval(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := q.LockApprovalJob(ctx, a.JobID); err != nil {
		return false, err
	}
	return true, s.expireApproval(ctx, tx, a)
}

func (s *Service) startApprovalSweeper() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		tick := time.NewTicker(s.approvalConfig().SweepInterval)
		defer tick.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-tick.C:
				if err := s.sweepApprovals(s.ctx); err != nil && s.ctx.Err() == nil {
					slog.Error("approval expiration sweep failed", "instance_id", s.instanceID)
				}
			}
		}
	}()
}

func (s *Service) CancelApproval(ctx context.Context, r *connect.Request[v1.CancelApprovalRequest]) (*connect.Response[v1.CancelApprovalResponse], error) {
	m, err := s.operation(ctx, "cancel_approval", true, func(ctx context.Context) (proto.Message, error) {
		id := r.Msg.GetApprovalId()
		if !clientRequestIDPattern.MatchString(id) {
			return nil, failure(connect.CodeInvalidArgument, "INVALID_APPROVAL_ID")
		}
		tx, err := s.Store.Pool.Begin(ctx)
		if err != nil {
			return nil, approvalError(err)
		}
		defer tx.Rollback(ctx)
		q := db.New(tx)
		a, j, err := lockApprovalForCancel(ctx, q, id)
		if err != nil {
			return nil, approvalError(err)
		}
		if a.Status != int16(approvalPending) || j.Status != int16(jobPendingApproval) {
			return nil, failure(connect.CodeFailedPrecondition, "APPROVAL_NOT_PENDING")
		}
		a, err = s.cancelPendingApproval(ctx, tx, a, "cancel_approval")
		if err != nil {
			return nil, approvalError(err)
		}
		votes, err := q.ListApprovalDecisions(ctx, id)
		if err != nil {
			return nil, approvalError(err)
		}
		if err := s.commitCancelledApproval(ctx, tx, a); err != nil {
			return nil, approvalError(err)
		}
		details, err := s.approvalDetails(a, votes, "APPROVAL_NOT_PENDING")
		return &v1.CancelApprovalResponse{Approval: details}, err
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m.(*v1.CancelApprovalResponse)), nil
}

func lockApprovalForCancel(ctx context.Context, q *db.Queries, id string) (db.ApprovalRequest, db.Job, error) {
	if err := q.LockPolicyReadsShared(ctx); err != nil {
		return db.ApprovalRequest{}, db.Job{}, err
	}
	a, err := q.LockApproval(ctx, id)
	if err != nil {
		return a, db.Job{}, err
	}
	job, err := q.LockApprovalJob(ctx, a.JobID)
	return a, job, err
}

func (s *Service) authorizeApprovalCancel(ctx context.Context, tx pgx.Tx, a db.ApprovalRequest, pending bool) error {
	actor, ip := reqctx.RequestInfo(ctx)
	id, _ := reqctx.FromContext(ctx)
	approvalOperation(ctx, a.ApprovalID, a.JobID, a.Action, uint64(a.PolicyVersion), nil)
	if actor == a.RequesterSubjectID && (pending || id.Subject.Kind == "service_account") {
		return nil
	}
	if id.Subject.Kind == "service_account" && !pending {
		return failure(connect.CodePermissionDenied, "JOB_OWNER_REQUIRED")
	}
	_, ids, err := approvalTargets(a)
	if err != nil {
		return err
	}
	hosts, _, err := readApprovalHosts(ctx, db.New(tx), ids, true)
	if err != nil {
		return err
	}
	p, err := s.loadApprovalPolicy(ctx, tx, a, hosts)
	if err != nil {
		return err
	}
	subject, _, _, exists, err := p.access.LoadSubjectTx(ctx, tx, actor, id.Subject.Kind)
	if err != nil {
		return err
	}
	allowed, rules := allowedApprovalHosts(p.evaluate(ctx, subject, ip, authz.ExecuteAction), len(hosts))
	approvalOperation(ctx, a.ApprovalID, a.JobID, a.Action, p.version, rules)
	if !exists || !allowed {
		return failure(connect.CodePermissionDenied, "JOB_OPERATION_DENIED")
	}
	return nil
}

func (s *Service) cancelPendingApproval(ctx context.Context, tx pgx.Tx, a db.ApprovalRequest, op string) (db.ApprovalRequest, error) {
	if err := s.authorizeApprovalCancel(ctx, tx, a, true); err != nil {
		return a, err
	}
	if !time.Now().UTC().Before(a.ExpiresAt.Time) {
		return a, s.expireApprovalVote(ctx, tx, a)
	}
	state := operationInfo(ctx)
	if err := s.auditApproval(ctx, a, op, "allow", "authorized", state.Version, state.Rules); err != nil {
		return a, err
	}
	if !time.Now().UTC().Before(a.ExpiresAt.Time) {
		return a, s.expireApprovalVote(ctx, tx, a)
	}
	return s.finishApproval(ctx, db.New(tx), a, approvalCancelled, reqctx.ActorID(ctx), "", "", 0)
}

func (s *Service) commitCancelledApproval(ctx context.Context, tx pgx.Tx, a db.ApprovalRequest) error {
	if err := commitApproval(ctx, tx); err != nil {
		return err
	}
	operationInfo(ctx).Committed = true
	s.notifyApproval(a, "cancelled")
	return nil
}
