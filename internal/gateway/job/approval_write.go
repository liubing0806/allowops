package job

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store/db"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	approvalPending         = v1.ApprovalStatus_APPROVAL_STATUS_PENDING
	approvalApproved        = v1.ApprovalStatus_APPROVAL_STATUS_APPROVED
	approvalRejected        = v1.ApprovalStatus_APPROVAL_STATUS_REJECTED
	approvalExpired         = v1.ApprovalStatus_APPROVAL_STATUS_EXPIRED
	approvalCancelled       = v1.ApprovalStatus_APPROVAL_STATUS_CANCELLED
	approvalExecutionDenied = v1.ApprovalStatus_APPROVAL_STATUS_EXECUTION_DENIED
	jobPendingApproval      = v1.JobStatus_JOB_STATUS_PENDING_APPROVAL
)

func approvalError(err error) error {
	if err == nil {
		return nil
	}
	var coded *connect.Error
	if errors.As(err, &coded) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return failure(connect.CodeNotFound, "APPROVAL_UNKNOWN")
	}
	return failure(connect.CodeUnavailable, "APPROVAL_DATABASE_UNAVAILABLE")
}

func approvalOperation(ctx context.Context, id, jobID, action string, version uint64, rules []string) {
	state := operationInfo(ctx)
	state.JobID, state.Resource, state.Action = jobID, "approval:"+id, action
	state.Version, state.Rules = version, rules
}

func (s *Service) auditApproval(ctx context.Context, a db.ApprovalRequest, op, outcome, reason string, version uint64, rules []string) error {
	_, err := s.appendApprovalAudit(ctx, a, op, outcome, reason, version, rules)
	return err
}

func (s *Service) appendApprovalAudit(ctx context.Context, a db.ApprovalRequest, op, outcome, reason string, version uint64, rules []string) (audit.Event, error) {
	actor, ip := reqctx.RequestInfo(ctx)
	if actor == "" {
		actor = "gateway:" + s.instanceID
	}
	event, err := s.Audit.Append(ctx, audit.Payload{
		SubjectID: actor, SourceIP: ip, Operation: op, Resource: "approval:" + a.ApprovalID,
		Reason: reason, Decision: outcome, Action: a.Action, JobID: a.JobID, PolicyVersion: version, MatchedRules: rules,
	})
	if err != nil {
		if state := operationInfo(ctx); state != nil && reason == "authorized" {
			state.AuthorizationAuditFailed = true
		}
		return audit.Event{}, failure(connect.CodeUnavailable, "AUDIT_UNAVAILABLE")
	}
	return event, nil
}

func commitApproval(ctx context.Context, tx pgx.Tx) error {
	commitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return tx.Commit(commitCtx)
}

func (s *Service) ApproveRequest(ctx context.Context, r *connect.Request[v1.ApproveRequestRequest]) (*connect.Response[v1.ApproveRequestResponse], error) {
	m, err := s.operation(ctx, "approve_job", true, func(ctx context.Context) (proto.Message, error) {
		if _, human := humanApprover(ctx); !human {
			return nil, failure(connect.CodePermissionDenied, "HUMAN_APPROVER_REQUIRED")
		}
		if len(r.Msg.GetExpectedRequestDigest()) != sha256.Size {
			return nil, failure(connect.CodeInvalidArgument, "EXPECTED_REQUEST_DIGEST_REQUIRED")
		}
		a, j, err := s.voteApproval(ctx, r.Msg.ApprovalId, r.Msg.Reason, r.Msg.ExpectedRequestDigest)
		if err != nil {
			return nil, approvalError(err)
		}
		return &v1.ApproveRequestResponse{Approval: a, Job: j}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m.(*v1.ApproveRequestResponse)), nil
}

func (s *Service) RejectRequest(ctx context.Context, r *connect.Request[v1.RejectRequestRequest]) (*connect.Response[v1.RejectRequestResponse], error) {
	m, err := s.operation(ctx, "reject_approval", true, func(ctx context.Context) (proto.Message, error) {
		if _, human := humanApprover(ctx); !human {
			return nil, failure(connect.CodePermissionDenied, "HUMAN_APPROVER_REQUIRED")
		}
		a, _, err := s.voteApproval(ctx, r.Msg.GetApprovalId(), r.Msg.GetReason(), nil)
		if err != nil {
			return nil, approvalError(err)
		}
		return &v1.RejectRequestResponse{Approval: a}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m.(*v1.RejectRequestResponse)), nil
}

func (s *Service) voteApproval(ctx context.Context, id, reason string, expected []byte) (*v1.ApprovalRequest, *v1.Job, error) {
	approve := expected != nil
	if !clientRequestIDPattern.MatchString(id) {
		return nil, nil, failure(connect.CodeInvalidArgument, "INVALID_APPROVAL_ID")
	}
	if !validApprovalText(reason) || (!approve && strings.TrimSpace(reason) == "") {
		return nil, nil, failure(connect.CodeInvalidArgument, "INVALID_APPROVAL_REASON")
	}
	route, err := db.New(s.Store.Pool).GetApprovalRoute(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if approve {
		s.submitMu.RLock()
		defer s.submitMu.RUnlock()
		if s.draining.Load() {
			return nil, nil, failure(connect.CodeUnavailable, "GATEWAY_DRAINING")
		}
	}
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)
	q := db.New(tx)
	if err := q.LockPolicyReadsShared(ctx); err != nil {
		return nil, nil, err
	}
	if approve {
		if err := q.LockCatalogReadsShared(ctx); err != nil {
			return nil, nil, err
		}
		if err := q.LockJobSubject(ctx, route.RequesterSubjectID); err != nil {
			return nil, nil, err
		}
	}
	a, err := q.LockApproval(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	j, err := q.LockApprovalJob(ctx, route.JobID)
	if err != nil {
		return nil, nil, err
	}
	approvalOperation(ctx, id, a.JobID, a.Action, uint64(a.PolicyVersion), a.MatchedRules)
	if a.Status != int16(approvalPending) || a.ConsumedAt.Valid || j.Status != int16(jobPendingApproval) {
		return nil, nil, failure(connect.CodeFailedPrecondition, "APPROVAL_NOT_PENDING")
	}
	_, ids, err := approvalTargets(a)
	if err != nil {
		return nil, nil, err
	}
	hosts, hostState, err := readApprovalHosts(ctx, q, ids, true)
	if err != nil {
		return nil, nil, err
	}
	if !time.Now().UTC().Before(a.ExpiresAt.Time) {
		return nil, nil, s.expireApprovalVote(ctx, tx, a)
	}
	var plan canonicalApprovalRequest
	if approve {
		if subtle.ConstantTimeCompare(expected, a.RequestDigest) != 1 {
			return nil, nil, failure(connect.CodeFailedPrecondition, "APPROVAL_DIGEST_MISMATCH")
		}
		plan, err = verifyApprovalPlan(ctx, q, a, j, ids)
		if err != nil {
			return nil, nil, err
		}
	}
	policy, err := s.loadApprovalPolicy(ctx, tx, a, hosts)
	if err != nil {
		return nil, nil, err
	}
	actor, ip := reqctx.RequestInfo(ctx)
	identity, _ := humanApprover(ctx)
	voter, email, _, exists, err := policy.access.LoadSubjectTx(ctx, tx, actor, identity.Subject.Kind)
	if err != nil {
		return nil, nil, err
	}
	if !exists {
		return nil, nil, failure(connect.CodePermissionDenied, "HUMAN_APPROVER_REQUIRED")
	}
	requester, requesterEmail, owner, requesterExists, err := policy.access.LoadSubjectTx(ctx, tx, a.RequesterSubjectID, a.RequesterKind)
	if err != nil {
		return nil, nil, err
	}
	separation, err := approvalPeople(ctx, tx, policy.access, a, requesterEmail, owner)
	if err != nil {
		return nil, nil, err
	}
	requirements, err := approvalConstraints(a)
	if err != nil {
		return nil, nil, err
	}
	votes, err := q.ListApprovalDecisions(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	prior, err := priorVoters(ctx, tx, policy.access, votes)
	if err != nil {
		return nil, nil, err
	}
	code, rules := policy.canVote(ctx, voter, person(actor, email), ip, separation, requirements, prior)
	approvalOperation(ctx, id, a.JobID, a.Action, policy.version, rules)
	if code != "" {
		if code == "ALREADY_APPROVED_BY_ACTOR" {
			return nil, nil, failure(connect.CodeAlreadyExists, code)
		}
		return nil, nil, failure(connect.CodePermissionDenied, code)
	}

	operation, decision := "approve_job", v1.ApprovalVote_APPROVAL_VOTE_APPROVE
	if !approve {
		operation, decision = "reject_approval", v1.ApprovalVote_APPROVAL_VOTE_REJECT
	}
	event, err := s.appendApprovalAudit(ctx, a, operation, "allow", "authorized", policy.version, rules)
	if err != nil {
		return nil, nil, err
	}
	if !time.Now().UTC().Before(a.ExpiresAt.Time) {
		return nil, nil, s.expireApprovalVote(ctx, tx, a)
	}
	// The audit timestamp also binds a vote to its authenticated source IP.
	votedAt := event.At
	if votedAt.IsZero() {
		votedAt = time.Now().UTC()
	}
	vote := db.ApprovalDecision{
		ApprovalID: id, ActorID: actor, ActorEmail: email, Decision: int16(decision), Reason: reason,
		DecidedAt: timestamptz(votedAt), PolicyVersion: int64(policy.version), MatchedRules: approvalStrings(rules),
	}
	if err := q.InsertApprovalDecision(ctx, db.InsertApprovalDecisionParams(vote)); err != nil {
		return nil, nil, err
	}
	votes = append(votes, vote)
	if !approve {
		a, err = s.finishApproval(ctx, q, a, approvalRejected, actor, reason, "", 0)
		if err != nil {
			return nil, nil, err
		}
		if err := commitApproval(ctx, tx); err != nil {
			return nil, nil, err
		}
		operationInfo(ctx).Committed = true
		s.notifyApproval(a, "rejected")
		response, err := s.approvalDetails(a, votes, "APPROVAL_NOT_PENDING")
		return response, nil, err
	}

	a.ApprovedCount = int32(len(votes))
	if a.ApprovedCount < a.MinApprovals {
		a, err = q.UpdateApprovalCount(ctx, db.UpdateApprovalCountParams{ApprovalID: id, ApprovedCount: a.ApprovedCount})
		if err != nil {
			return nil, nil, err
		}
		job, err := getJob(ctx, tx, a.JobID)
		if err != nil {
			return nil, nil, err
		}
		if err := commitApproval(ctx, tx); err != nil {
			return nil, nil, err
		}
		operationInfo(ctx).Committed = true
		return s.approvedResponse(a, job, votes, "ALREADY_APPROVED_BY_ACTOR")
	}

	action, recheckCode, err := s.recheckApproval(ctx, tx, a, policy, requester, requesterExists, separation, requirements, hostState, votes, ip)
	if err != nil {
		return nil, nil, err
	}
	if recheckCode != "" {
		_, err := s.finishApproval(ctx, q, a, approvalExecutionDenied, actor, reason, recheckCode, policy.version)
		if err != nil {
			return nil, nil, err
		}
		if err := s.auditApproval(ctx, a, "approval_recheck", "deny", recheckCode, policy.version, rules); err != nil {
			return nil, nil, err
		}
		if err := commitApproval(ctx, tx); err != nil {
			return nil, nil, err
		}
		operationInfo(ctx).Committed = true
		return nil, nil, failure(connect.CodeFailedPrecondition, recheckCode)
	}

	if a.RequesterKind == "service_account" {
		active, err := q.CountActiveJobsBySubject(ctx, a.RequesterSubjectID)
		if err != nil {
			return nil, nil, err
		}
		if active >= 5 {
			return nil, nil, failure(connect.CodeResourceExhausted, "CONCURRENT_JOB_LIMIT")
		}
	}
	request, err := plan.request()
	if err != nil {
		return nil, nil, failure(connect.CodeFailedPrecondition, "APPROVAL_DIGEST_MISMATCH")
	}
	if !time.Now().UTC().Before(a.ExpiresAt.Time) {
		return nil, nil, s.expireApprovalVote(ctx, tx, a)
	}
	nonce := rand.Text()
	consumed, err := q.ConsumeApproval(ctx, db.ConsumeApprovalParams{
		ApprovalID: id, ApprovedCount: a.ApprovedCount, DecidedBy: actor, DecisionReason: reason,
		ConsumedByInstance: s.instanceID, ConsumeNonce: nonce, RecheckPolicyVersion: pgtype.Int8{Valid: true, Int64: int64(policy.version)},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// The locked pending row can miss this update only at the SQL expiry guard.
		return nil, nil, s.expireApprovalVote(ctx, tx, a)
	}
	if err != nil {
		return nil, nil, err
	}
	affected, err := q.QueueApprovedJob(ctx, db.QueueApprovedJobParams{JobID: a.JobID, OriginInstance: s.instanceID, PolicyVersion: int64(policy.version)})
	if err != nil || affected != 1 {
		return nil, nil, approvalJobUpdateError(affected, err)
	}
	if err := s.auditApproval(ctx, a, "approval_recheck", "allow", "digest="+hex.EncodeToString(a.RequestDigest), policy.version, rules); err != nil {
		return nil, nil, err
	}
	job := &v1.Job{
		JobId: j.JobID, Action: j.Action, Catalog: &v1.CatalogRef{CatalogId: j.CatalogID, Version: uint64(j.CatalogVersion)},
		ActionSha256: j.ActionSha256, SubjectId: j.SubjectID, Reason: j.Reason, Status: v1.JobStatus_JOB_STATUS_QUEUED,
		CreatedAt: timestamppb.New(j.CreatedAt.Time), PolicyVersion: policy.version, TotalTasks: uint64(len(ids)),
		Counts: []*v1.TaskCount{{Status: v1.TaskStatus_TASK_STATUS_PENDING, Count: uint64(len(ids))}},
	}
	if err := commitApproval(ctx, tx); err != nil && !s.approvalConsumptionCommitted(ctx, j.JobID, id, nonce) {
		return nil, nil, err
	}
	s.startSchedule(job, action, request, plan.BatchSize, plan.MaxFailures)
	operationInfo(ctx).Committed = true
	s.notifyApproval(consumed, "approved")
	return s.approvedResponse(consumed, job, votes, "APPROVAL_NOT_PENDING")
}

func (s *Service) approvedResponse(a db.ApprovalRequest, j *v1.Job, votes []db.ApprovalDecision, cannot string) (*v1.ApprovalRequest, *v1.Job, error) {
	summary, err := s.approvalSummary(a)
	if err != nil {
		return nil, nil, err
	}
	j.Approval = summary
	details, err := s.approvalDetails(a, votes, cannot)
	return details, j, err
}

func (s *Service) approvalConsumptionCommitted(ctx context.Context, jobID, id, nonce string) bool {
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var found pgtype.Bool
	// A share lock waits for PostgreSQL to settle the original transaction
	// before interpreting a pending row as evidence that it rolled back.
	q := db.New(s.Store.Pool)
	err := retrySQL(readCtx, jobID, func(ctx context.Context) error {
		var err error
		found, err = q.ApprovalConsumptionCommitted(ctx, db.ApprovalConsumptionCommittedParams{ApprovalID: id, ConsumeNonce: nonce})
		return err
	})
	return err == nil && found.Valid && found.Bool
}

func approvalJobUpdateError(affected int64, err error) error {
	if err != nil {
		return err
	}
	if affected != 1 {
		return failure(connect.CodeFailedPrecondition, "APPROVAL_NOT_PENDING")
	}
	return nil
}
