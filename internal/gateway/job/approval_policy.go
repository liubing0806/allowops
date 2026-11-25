package job

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store/db"
)

// ApprovalAccess is the transaction-aware authorization boundary. Existing
// job-only AccessChecker implementations can continue to submit ordinary jobs.
type ApprovalAccess interface {
	PolicyEngineTx(context.Context, pgx.Tx) (*authz.Engine, uint64, error)
	EvaluateWithEngine(context.Context, *authz.Engine, uint64, authz.Subject, string, authz.Operation, authz.Action, []authz.Host) []authz.HostResult
	LoadSubjectTx(context.Context, pgx.Tx, string, string) (authz.Subject, string, string, bool, error)
	LoadUserEmailTx(context.Context, pgx.Tx, string) (string, error)
	CheckCredentialValidTx(context.Context, pgx.Tx, string, string) (bool, error)
}

type approvalPolicy struct {
	access  ApprovalAccess
	engine  *authz.Engine
	version uint64
	action  authz.Action
	hosts   []authz.Host
}

func (p approvalPolicy) evaluate(ctx context.Context, subject authz.Subject, sourceIP string, op authz.Operation) []authz.HostResult {
	return p.access.EvaluateWithEngine(ctx, p.engine, p.version, subject, sourceIP, op, p.action, p.hosts)
}

func allowedApprovalHosts(results []authz.HostResult, expected int) (bool, []string) {
	allowed := expected > 0 && len(results) == expected
	var rules []string
	for _, result := range results {
		allowed = allowed && result.Err == nil && result.Result.Decision == "allow"
		rules = append(rules, result.Result.RuleIDs...)
	}
	return allowed, dedupeStrings(rules)
}

func (s *Service) loadApprovalPolicy(ctx context.Context, tx pgx.Tx, row db.ApprovalRequest, hosts []authz.Host) (approvalPolicy, error) {
	access, ok := s.Access.(ApprovalAccess)
	if !ok {
		return approvalPolicy{}, failure(connect.CodeUnavailable, "APPROVAL_ACCESS_UNAVAILABLE")
	}
	engine, version, err := access.PolicyEngineTx(ctx, tx)
	if err != nil {
		return approvalPolicy{}, failure(connect.CodeUnavailable, "APPROVAL_POLICY_UNAVAILABLE")
	}
	return approvalPolicy{access: access, engine: engine, version: version, action: authz.Action{Name: row.Action, Risk: row.ActionRisk}, hosts: hosts}, nil
}

func approvalConstraints(row db.ApprovalRequest) (*authz.EffectiveApproval, error) {
	r := &authz.EffectiveApproval{MinApprovals: int(row.MinApprovals), AllowOwnerApprove: row.AllowOwnerApprove}
	if err := json.Unmarshal(row.RequiredApproverRoles, &r.RequiredApproverRoleSets); err != nil {
		return nil, err
	}
	return r, nil
}

func approvalTargets(row db.ApprovalRequest) ([]frozenTarget, []string, error) {
	var targets []frozenTarget
	if err := json.Unmarshal(row.TargetHosts, &targets); err != nil {
		return nil, nil, err
	}
	ids := make([]string, len(targets))
	for i, target := range targets {
		ids[i] = target.HostID
	}
	return targets, ids, nil
}

// readApprovalHosts keeps the frozen order for evaluation, even though the row
// locks are acquired in ascending host ID order.
func readApprovalHosts(ctx context.Context, q *db.Queries, ids []string, lock bool) ([]authz.Host, string, error) {
	var rows []db.ReadApprovalHostsRow
	if lock {
		locked, err := q.LockApprovalHosts(ctx, ids)
		if err != nil {
			return nil, "", err
		}
		for _, row := range locked {
			rows = append(rows, db.ReadApprovalHostsRow(row))
		}
	} else {
		var err error
		rows, err = q.ReadApprovalHosts(ctx, ids)
		if err != nil {
			return nil, "", err
		}
	}

	byID := make(map[string]db.ReadApprovalHostsRow, len(rows))
	for _, row := range rows {
		byID[row.HostID] = row
	}
	hosts := make([]authz.Host, len(ids))
	var recheckCode string
	for i, id := range ids {
		row := byID[id]
		hosts[i].ID = id
		if row.CertificateStatus != "active" {
			recheckCode = "RECHECK_HOST_DELETED"
		}
		if row.AuthorizationLabels != nil {
			if err := json.Unmarshal(row.AuthorizationLabels, &hosts[i].Labels); err != nil {
				return nil, "", err
			}
		}
		if recheckCode == "" && len(hosts[i].Labels) == 0 {
			recheckCode = "RECHECK_HOST_UNLABELED"
		}
	}
	return hosts, recheckCode, nil
}

type approvalPerson struct{ id, email string }

func normalizedEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

// samePerson tests the intersection of the uid and verified email keys.
func (p approvalPerson) samePerson(other approvalPerson) bool {
	return (p.id != "" && p.id == other.id) || (p.email != "" && p.email == other.email)
}

func person(id, email string) approvalPerson { return approvalPerson{id, normalizedEmail(email)} }

type approvalSeparation struct {
	requesters []approvalPerson
	owners     []approvalPerson
	issuer     approvalPerson
	// A third-party issuer at submission stays disqualified after an owner change.
	issuerWasOwner bool
}

func (s approvalSeparation) check(p approvalPerson, allowOwner bool) string {
	for _, requester := range s.requesters {
		if p.samePerson(requester) {
			return "SELF_APPROVAL_FORBIDDEN"
		}
	}
	if p.samePerson(s.issuer) && (!s.issuerWasOwner || !allowOwner) {
		return "SELF_APPROVAL_FORBIDDEN"
	}
	if !allowOwner {
		for _, owner := range s.owners {
			if p.samePerson(owner) {
				return "SELF_APPROVAL_FORBIDDEN"
			}
		}
	}
	return ""
}

func approvalPeople(ctx context.Context, tx pgx.Tx, a ApprovalAccess, row db.ApprovalRequest, freshEmail, currentOwner string) (approvalSeparation, error) {
	s := approvalSeparation{requesters: []approvalPerson{person(row.RequesterSubjectID, row.RequesterEmail), person(row.RequesterSubjectID, freshEmail)}}
	if row.RequesterKind != "service_account" {
		return s, nil
	}
	for _, owner := range []string{row.RequesterOwnerID, currentOwner} {
		if owner == "" {
			continue
		}
		email, err := a.LoadUserEmailTx(ctx, tx, owner)
		if err != nil {
			return s, err
		}
		s.owners = append(s.owners, person(owner, email))
	}
	if row.RequesterTokenIssuerID != "" {
		email, err := a.LoadUserEmailTx(ctx, tx, row.RequesterTokenIssuerID)
		if err != nil {
			return s, err
		}
		s.issuer = person(row.RequesterTokenIssuerID, email)
		s.issuerWasOwner = row.RequesterTokenIssuerID == row.RequesterOwnerID
	}
	return s, nil
}

func satisfiesApproverRoles(roles []string, required [][]string) bool {
	for _, set := range required {
		if !slices.ContainsFunc(set, func(role string) bool { return slices.Contains(roles, role) }) {
			return false
		}
	}
	return true
}

func (p approvalPolicy) canVote(ctx context.Context, subject authz.Subject, voter approvalPerson, ip string, separation approvalSeparation, requirements *authz.EffectiveApproval, prior []approvalPerson) (string, []string) {
	allowed, rules := allowedApprovalHosts(p.evaluate(ctx, subject, ip, authz.ApproveJobs), len(p.hosts))
	return votePermission(subject, voter, separation, requirements, prior, allowed, rules)
}

func votePermission(subject authz.Subject, voter approvalPerson, separation approvalSeparation, requirements *authz.EffectiveApproval, prior []approvalPerson, allowed bool, rules []string) (string, []string) {
	if code := separation.check(voter, requirements.AllowOwnerApprove); code != "" {
		return code, nil
	}
	for _, earlier := range prior {
		if voter.samePerson(earlier) {
			return "ALREADY_APPROVED_BY_ACTOR", nil
		}
	}
	if !satisfiesApproverRoles(subject.Roles, requirements.RequiredApproverRoleSets) {
		return "APPROVER_ROLES_REQUIRED", nil
	}
	if !allowed {
		return "APPROVE_JOBS_DENIED", rules
	}
	return "", rules
}

func humanApprover(ctx context.Context) (*reqctx.Identity, bool) {
	id, ok := reqctx.FromContext(ctx)
	return id, ok && id.Subject.Kind != "service_account" && id.User != nil
}

func priorVoters(ctx context.Context, tx pgx.Tx, a ApprovalAccess, votes []db.ApprovalDecision) ([]approvalPerson, error) {
	var people []approvalPerson
	for _, vote := range votes {
		people = append(people, person(vote.ActorID, vote.ActorEmail))
		email, err := a.LoadUserEmailTx(ctx, tx, vote.ActorID)
		if err != nil {
			return nil, err
		}
		people = append(people, person(vote.ActorID, email))
	}
	return people, nil
}
