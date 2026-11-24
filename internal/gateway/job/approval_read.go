package job

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store/db"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Service) ApprovalHandler() http.Handler {
	_, handler := rpc.NewApprovalServiceHandler(s, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(1<<20))
	return s.Access.Middleware(handler)
}

func (s *Service) approvalURL(id string) string {
	if base := s.approvalConfig().ConsoleBaseURL; base != "" {
		return base + "/approvals/" + id
	}
	return ""
}

func approvalTime(t pgtype.Timestamptz) *timestamppb.Timestamp {
	if t.Valid {
		return timestamppb.New(t.Time)
	}
	return nil
}

func approvalRoleSets(sets [][]string) []*v1.PolicyApprovalRoleSet {
	out := make([]*v1.PolicyApprovalRoleSet, 0, len(sets))
	for _, set := range sets {
		out = append(out, &v1.PolicyApprovalRoleSet{Roles: set})
	}
	return out
}

func (s *Service) approvalSummary(row db.ApprovalRequest) (*v1.JobApprovalSummary, error) {
	c, err := approvalConstraints(row)
	if err != nil {
		return nil, err
	}
	return &v1.JobApprovalSummary{
		ApprovalId: row.ApprovalID, Status: v1.ApprovalStatus(row.Status), ExpiresAt: approvalTime(row.ExpiresAt),
		MinApprovals: uint32(row.MinApprovals), ApprovedCount: uint32(row.ApprovedCount),
		RequiredApproverRoleSets: approvalRoleSets(c.RequiredApproverRoleSets), DecidedAt: approvalTime(row.DecidedAt),
		DecisionReason: row.DecisionReason, ConsoleUrl: s.approvalURL(row.ApprovalID), RecheckError: row.RecheckError,
	}, nil
}

func (s *Service) attachApproval(ctx context.Context, j *v1.Job) error {
	return s.attachApprovals(ctx, []*v1.Job{j})
}

func (s *Service) attachApprovals(ctx context.Context, jobs []*v1.Job) error {
	if len(jobs) == 0 {
		return nil
	}
	ids := make([]string, len(jobs))
	byID := make(map[string]*v1.Job, len(jobs))
	for i, job := range jobs {
		ids[i] = job.JobId
		byID[job.JobId] = job
	}
	rows, err := db.New(s.Store.Pool).ListApprovalsByJobIDs(ctx, ids)
	if err != nil {
		return failure(connect.CodeUnavailable, "APPROVAL_DATABASE_UNAVAILABLE")
	}
	for _, row := range rows {
		summary, err := s.approvalSummary(db.ApprovalRequest{
			ApprovalID: row.ApprovalID, Status: row.Status, ExpiresAt: row.ExpiresAt,
			MinApprovals: row.MinApprovals, ApprovedCount: row.ApprovedCount, RequiredApproverRoles: row.RequiredApproverRoles,
			DecidedAt: row.DecidedAt, DecisionReason: row.DecisionReason, RecheckError: row.RecheckError,
		})
		if err != nil {
			return err
		}
		byID[row.JobID].Approval = summary
	}
	return nil
}

func (s *Service) approvalDetails(row db.ApprovalRequest, decisions []db.ApprovalDecision, cannotVote string) (*v1.ApprovalRequest, error) {
	summary, err := s.approvalSummary(row)
	if err != nil {
		return nil, err
	}
	targets, _, err := approvalTargets(row)
	if err != nil {
		return nil, err
	}
	p := &v1.ApprovalRequest{
		ApprovalId: row.ApprovalID, JobId: row.JobID, Status: summary.Status,
		CreatedAt: approvalTime(row.CreatedAt), ExpiresAt: summary.ExpiresAt,
		Action: row.Action, ActionRisk: row.ActionRisk,
		Catalog:      &v1.CatalogRef{CatalogId: row.CatalogID, Version: uint64(row.CatalogVersion)},
		ActionSha256: row.ActionSha256, ParamsJson: row.ParamsJson, FiltersJson: row.FiltersJson, TargetSelector: row.TargetSelector,
		BatchSize: uint32(row.BatchSize), MaxFailures: uint32(row.MaxFailures), RequestDigest: row.RequestDigest,
		RequesterSubjectId: row.RequesterSubjectID, RequesterKind: row.RequesterKind, RequesterOwnerId: row.RequesterOwnerID,
		Reason: row.Reason, PolicyVersion: uint64(row.PolicyVersion), MatchedRules: row.MatchedRules,
		RequiredApproverRoleSets: summary.RequiredApproverRoleSets, MinApprovals: summary.MinApprovals,
		AllowOwnerApprove: row.AllowOwnerApprove, ApprovedCount: summary.ApprovedCount, DecidedAt: summary.DecidedAt,
		DecidedBy: row.DecidedBy, DecisionReason: row.DecisionReason, RecheckError: row.RecheckError, ConsoleUrl: summary.ConsoleUrl,
		ContextTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED, NotifyStatus: row.NotifyStatus, NotifyError: row.NotifyError,
		CanApprove: cannotVote == "", CannotApproveReason: cannotVote,
	}
	if row.RecheckPolicyVersion.Valid {
		p.RecheckPolicyVersion = proto.Uint64(uint64(row.RecheckPolicyVersion.Int64))
	}
	if len(row.EvidenceJobIds) > 0 {
		p.Evidence = &v1.JobEvidence{JobIds: row.EvidenceJobIds, Summary: row.EvidenceSummary}
	}
	for _, target := range targets {
		p.Targets = append(p.Targets, &v1.ApprovalTarget{HostId: target.HostID, Hostname: target.Hostname})
	}
	for _, decision := range decisions {
		p.Decisions = append(p.Decisions, &v1.ApprovalDecisionRecord{
			ActorId: decision.ActorID, ActorEmail: decision.ActorEmail, Vote: v1.ApprovalVote(decision.Decision),
			Reason: decision.Reason, DecidedAt: approvalTime(decision.DecidedAt),
			PolicyVersion: uint64(decision.PolicyVersion), MatchedRules: decision.MatchedRules,
		})
	}
	return p, nil
}

func (s *Service) visibleApproval(ctx context.Context, id string) (*v1.ApprovalRequest, error) {
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return nil, approvalError(err)
	}
	defer tx.Rollback(ctx)
	q := db.New(tx)
	row, err := q.GetApproval(ctx, id)
	if err != nil {
		return nil, approvalError(err)
	}
	actor, ip := reqctx.RequestInfo(ctx)
	own := actor == row.RequesterSubjectID
	identity, human := humanApprover(ctx)
	cannot := "HUMAN_APPROVER_REQUIRED"
	if !human && !own {
		return nil, failure(connect.CodePermissionDenied, "APPROVAL_ACCESS_DENIED")
	}
	if human && own {
		cannot = "SELF_APPROVAL_FORBIDDEN"
	}
	if human && !own {
		_, ids, err := approvalTargets(row)
		if err != nil {
			return nil, approvalError(err)
		}
		hosts, _, err := readApprovalHosts(ctx, q, ids, false)
		if err != nil {
			return nil, approvalError(err)
		}
		p, err := s.loadApprovalPolicy(ctx, tx, row, hosts)
		if err != nil {
			return nil, err
		}
		subject, email, _, exists, err := p.access.LoadSubjectTx(ctx, tx, actor, identity.Subject.Kind)
		if err != nil {
			return nil, approvalError(err)
		}
		if !exists {
			return nil, failure(connect.CodePermissionDenied, "APPROVAL_ACCESS_DENIED")
		}
		view, _ := allowedApprovalHosts(p.evaluate(ctx, subject, ip, authz.ViewApprovals), len(hosts))
		approve, rules := allowedApprovalHosts(p.evaluate(ctx, subject, ip, authz.ApproveJobs), len(hosts))
		if !view && !approve {
			return nil, failure(connect.CodePermissionDenied, "APPROVAL_ACCESS_DENIED")
		}
		if row.Status == int16(approvalPending) && time.Now().Before(row.ExpiresAt.Time) {
			_, freshEmail, owner, _, err := p.access.LoadSubjectTx(ctx, tx, row.RequesterSubjectID, row.RequesterKind)
			if err != nil {
				return nil, approvalError(err)
			}
			separation, err := approvalPeople(ctx, tx, p.access, row, freshEmail, owner)
			if err != nil {
				return nil, approvalError(err)
			}
			roles, err := approvalConstraints(row)
			if err != nil {
				return nil, approvalError(err)
			}
			votes, err := q.ListApprovalDecisions(ctx, id)
			if err != nil {
				return nil, approvalError(err)
			}
			prior, err := priorVoters(ctx, tx, p.access, votes)
			if err != nil {
				return nil, approvalError(err)
			}
			cannot, _ = votePermission(subject, person(actor, email), separation, roles, prior, approve, rules)
			return s.approvalDetails(row, votes, cannot)
		}
		if row.Status == int16(approvalPending) {
			cannot = "APPROVAL_EXPIRED"
		} else {
			cannot = "APPROVAL_NOT_PENDING"
		}
	}
	votes, err := q.ListApprovalDecisions(ctx, id)
	if err != nil {
		return nil, approvalError(err)
	}
	return s.approvalDetails(row, votes, cannot)
}

func (s *Service) GetApproval(ctx context.Context, r *connect.Request[v1.GetApprovalRequest]) (*connect.Response[v1.GetApprovalResponse], error) {
	m, err := s.operation(ctx, "get_approval", false, func(ctx context.Context) (proto.Message, error) {
		if !clientRequestIDPattern.MatchString(r.Msg.GetApprovalId()) {
			return nil, failure(connect.CodeInvalidArgument, "INVALID_APPROVAL_ID")
		}
		a, err := s.visibleApproval(ctx, r.Msg.ApprovalId)
		if err != nil {
			return nil, err
		}
		approvalOperation(ctx, a.ApprovalId, a.JobId, a.Action, a.PolicyVersion, a.MatchedRules)
		return &v1.GetApprovalResponse{Approval: a}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m.(*v1.GetApprovalResponse)), nil
}

func (s *Service) ListApprovals(ctx context.Context, r *connect.Request[v1.ListApprovalsRequest]) (*connect.Response[v1.ListApprovalsResponse], error) {
	m, err := s.operation(ctx, "list_approvals", false, func(ctx context.Context) (proto.Message, error) {
		return s.listApprovals(ctx, r.Msg)
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m.(*v1.ListApprovalsResponse)), nil
}

func (s *Service) listApprovals(ctx context.Context, r *v1.ListApprovalsRequest) (*v1.ListApprovalsResponse, error) {
	if r == nil {
		return nil, failure(connect.CodeInvalidArgument, "REQUEST_REQUIRED")
	}
	actor := reqctx.ActorID(ctx)
	id, _ := reqctx.FromContext(ctx)
	requester := r.RequesterSubjectId
	if id.Subject.Kind == "service_account" {
		if requester != "" && requester != actor {
			return &v1.ListApprovalsResponse{Page: &v1.PageResponse{}}, nil
		}
		requester = actor
	}
	n, err := pageSize(r.Page)
	if err != nil {
		return nil, err
	}
	statuses := make([]int16, len(r.Statuses))
	for i, status := range r.Statuses {
		if status < approvalPending || status > approvalExecutionDenied {
			return nil, failure(connect.CodeInvalidArgument, "INVALID_APPROVAL_STATUS")
		}
		statuses[i] = int16(status)
	}
	from, to, err := jobTimeRange(r.Created)
	if err != nil {
		return nil, err
	}
	if !validApprovalText(r.Action) || !validApprovalText(requester) {
		return nil, failure(connect.CodeInvalidArgument, "INVALID_APPROVAL_FILTER")
	}
	scope := fmt.Sprintf("approvals:%q:%q:%q:%v:%v:%v:%t", actor, requester, r.Action, from, to, statuses, r.OnlyActionable)
	binding := pageBinding(scope)
	filter := db.ListApprovalCandidatesParams{
		Requester: requester, Action: r.Action, CreatedFrom: optionalTimestamptz(from), CreatedTo: optionalTimestamptz(to),
		Statuses: statuses, OnlyActionable: r.OnlyActionable, PageLimit: int32(max(50, n+1)),
	}
	if token := r.Page.GetPageToken(); token != "" {
		cursor, err := parseJobCursor(token, binding)
		if err != nil || !clientRequestIDPattern.MatchString(cursor.id) {
			return nil, failure(connect.CodeInvalidArgument, "INVALID_PAGE_TOKEN")
		}
		filter.AfterCreated, filter.AfterID = timestamptz(cursor.created), cursor.id
	}
	q := db.New(s.Store.Pool)
	var items []*v1.ApprovalRequest
	for len(items) <= n {
		rows, err := q.ListApprovalCandidates(ctx, filter)
		if err != nil {
			return nil, approvalError(err)
		}
		for _, row := range rows {
			a, err := s.visibleApproval(ctx, row.ApprovalID)
			if connect.CodeOf(err) == connect.CodePermissionDenied {
				continue
			}
			if err != nil {
				return nil, err
			}
			if !r.OnlyActionable || a.CanApprove {
				items = append(items, a)
			}
			if len(items) > n {
				break
			}
		}
		if len(rows) < int(filter.PageLimit) {
			break
		}
		last := rows[len(rows)-1]
		filter.AfterCreated, filter.AfterID = last.CreatedAt, last.ApprovalID
	}
	fit, err := fitResponseBytes(items[:min(n, len(items))], 1<<20)
	if err != nil {
		return nil, err
	}
	page := &v1.PageResponse{}
	if fit < len(items) {
		last := items[fit-1]
		page.NextPageToken = jobCursor{created: last.CreatedAt.AsTime(), id: last.ApprovalId}.token(binding)
	}
	return &v1.ListApprovalsResponse{Approvals: items[:fit], Page: page}, nil
}
