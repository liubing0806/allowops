package job

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store/db"
)

type approvalSubmission struct {
	plan                      canonicalApprovalRequest
	requirements              *authz.EffectiveApproval
	clientRequestID, selector string
	evidence                  *v1.JobEvidence
}

type frozenTarget struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
}

func (s *Service) existingApproval(ctx context.Context, q *db.Queries, requester string, submission *approvalSubmission) (db.ApprovalRequest, error) {
	if submission == nil || submission.clientRequestID == "" {
		return db.ApprovalRequest{}, nil
	}
	a, err := q.GetApprovalByClientRequest(ctx, db.GetApprovalByClientRequestParams{RequesterSubjectID: requester, ClientRequestID: submission.clientRequestID})
	if errors.Is(err, pgx.ErrNoRows) {
		return db.ApprovalRequest{}, nil
	}
	if err != nil {
		return db.ApprovalRequest{}, err
	}
	digest, err := submission.plan.digest()
	if err != nil {
		return db.ApprovalRequest{}, err
	}
	if subtle.ConstantTimeCompare(a.RequestDigest, digest[:]) != 1 {
		return db.ApprovalRequest{}, failure(connect.CodeAlreadyExists, "CLIENT_REQUEST_ID_CONFLICT")
	}
	return a, nil
}

func (s *Service) insertApproval(ctx context.Context, tx pgx.Tx, j newJob, targets []host, submission *approvalSubmission) (db.ApprovalRequest, error) {
	var empty db.ApprovalRequest
	id, ok := reqctx.FromContext(ctx)
	if !ok {
		return empty, failure(connect.CodeUnauthenticated, "AUTHENTICATION_REQUIRED")
	}
	access, ok := s.Access.(ApprovalAccess)
	if !ok {
		return empty, failure(connect.CodeUnavailable, "APPROVAL_ACCESS_UNAVAILABLE")
	}
	_, ip := reqctx.RequestInfo(ctx)
	kind, credential, issuer := id.Subject.Kind, id.TokenID, id.TokenIssuerID
	if kind != "service_account" {
		if id.User == nil || (kind != "oidc" && kind != "ldap") {
			return empty, failure(connect.CodeUnauthenticated, "AUTHENTICATION_REQUIRED")
		}
		credential = id.Session.GetSessionId()
	}
	if credential == "" {
		return empty, failure(connect.CodeUnauthenticated, "APPROVAL_CREDENTIAL_REQUIRED")
	}
	// Freeze the requester at submission. Authentication may have read the
	// service account or verified email before a concurrent identity change.
	_, email, owner, exists, err := access.LoadSubjectTx(ctx, tx, j.subject, kind)
	if err != nil {
		return empty, approvalError(err)
	}
	if !exists {
		return empty, failure(connect.CodeUnauthenticated, "APPROVAL_REQUESTER_REQUIRED")
	}
	q := db.New(tx)
	sequence, err := q.NextApprovalSequence(ctx, pgtype.Date{Time: j.at, Valid: true})
	if err != nil {
		return empty, err
	}
	approvalID := fmt.Sprintf("apr-%s-%04d", j.at.Format("20060102"), sequence)
	requirements := submission.requirements
	ttl := s.approvalConfig().DefaultTTL
	if requirements.TTLSeconds > 0 {
		ttl = min(time.Duration(requirements.TTLSeconds)*time.Second, s.approvalConfig().MaxTTL)
	}
	roleSets := requirements.RequiredApproverRoleSets
	if roleSets == nil {
		roleSets = [][]string{}
	}
	roles, err := catalog.CanonicalJSON(roleSets)
	if err != nil {
		return empty, err
	}
	frozenTargets := make([]frozenTarget, len(targets))
	for i, target := range targets {
		frozenTargets[i] = frozenTarget{HostID: target.ID, Hostname: target.Name}
	}
	targetJSON, err := catalog.CanonicalJSON(frozenTargets)
	if err != nil {
		return empty, err
	}
	digest, err := submission.plan.digest()
	if err != nil {
		return empty, err
	}
	state := operationInfo(ctx)
	pending, err := q.InsertApproval(ctx, db.InsertApprovalParams{
		ApprovalID: approvalID, JobID: j.id, CreatedAt: timestamptz(j.at), ExpiresAt: timestamptz(j.at.Add(ttl)),
		Action: j.action, ActionRisk: submission.plan.ActionRisk, CatalogID: j.catalogID, CatalogVersion: j.catalogVersion,
		ActionSha256: j.digest, ParamsJson: submission.plan.Params, FiltersJson: submission.plan.Filters,
		TargetSelector: submission.selector, TargetHosts: targetJSON, BatchSize: int32(j.batch), MaxFailures: int32(j.failures),
		RequestDigest: digest[:], RequesterSubjectID: j.subject, RequesterKind: kind, RequesterEmail: email,
		RequesterOwnerID: owner, RequesterCredentialID: credential, RequesterTokenIssuerID: issuer, RequesterSourceIp: ip,
		ClientRequestID: submission.clientRequestID, Reason: j.reason, EvidenceJobIds: approvalStrings(submission.evidence.GetJobIds()),
		EvidenceSummary: submission.evidence.GetSummary(), PolicyVersion: int64(j.policyVersion), MatchedRules: approvalStrings(state.Rules),
		RequiredApproverRoles: roles, MinApprovals: int32(max(1, requirements.MinApprovals)), AllowOwnerApprove: requirements.AllowOwnerApprove,
	})
	if err != nil {
		return empty, err
	}
	if err := s.auditApproval(ctx, pending, "request_approval", "require_approval", "digest="+hex.EncodeToString(digest[:]), j.policyVersion, state.Rules); err != nil {
		return empty, err
	}
	return pending, nil
}

func approvalStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
