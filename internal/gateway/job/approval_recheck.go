package job

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"slices"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/store/db"
)

func verifyApprovalPlan(ctx context.Context, q *db.Queries, a db.ApprovalRequest, j db.Job, ids []string) (canonicalApprovalRequest, error) {
	var empty canonicalApprovalRequest
	badDigest := failure(connect.CodeFailedPrecondition, "APPROVAL_DIGEST_MISMATCH")
	if a.JobID != j.JobID || a.RequesterSubjectID != j.SubjectID || a.Action != j.Action ||
		a.CatalogID != j.CatalogID || a.CatalogVersion != j.CatalogVersion ||
		a.BatchSize != j.BatchSize || a.MaxFailures != j.MaxFailures ||
		subtle.ConstantTimeCompare(a.ActionSha256, j.ActionSha256) != 1 {
		return empty, badDigest
	}
	var definition catalog.Action
	if err := execd.DecodeJSON(j.ActionDefinition, &definition); err != nil {
		return empty, badDigest
	}
	actionHash, err := catalog.ActionDigest(definition)
	if err != nil || actionHash != hex.EncodeToString(j.ActionSha256) || a.ActionRisk != definition.Risk {
		return empty, badDigest
	}
	tasks, err := q.ListApprovalTargets(ctx, a.JobID)
	if err != nil {
		return empty, err
	}
	if len(tasks) == 0 || len(tasks) != len(ids) {
		return empty, badDigest
	}
	for i, task := range tasks {
		if ids[i] != task {
			return empty, badDigest
		}
	}
	if _, err := execd.DecodeParameters(a.ParamsJson); err != nil {
		return empty, badDigest
	}
	plan := canonicalApprovalRequest{
		Version: 1, Action: j.Action, ActionRisk: a.ActionRisk, CatalogID: j.CatalogID, CatalogVersion: j.CatalogVersion,
		ActionSHA256: actionHash, Params: a.ParamsJson, Filters: a.FiltersJson, TargetHostIDs: ids,
		BatchSize: uint32(j.BatchSize), MaxFailures: uint32(j.MaxFailures),
	}
	digest, err := plan.digest()
	if err != nil || subtle.ConstantTimeCompare(digest[:], a.RequestDigest) != 1 {
		return empty, badDigest
	}
	return plan, nil
}

func (s *Service) recheckApproval(ctx context.Context, tx pgx.Tx, a db.ApprovalRequest, policy approvalPolicy, requester authz.Subject, requesterExists bool, separation approvalSeparation, frozen *authz.EffectiveApproval, hostState string, votes []db.ApprovalDecision, voterIP string) (catalog.Action, string, error) {
	q := db.New(tx)
	var empty catalog.Action
	action, valid, err := s.recheckCatalog(ctx, q, a)
	if err != nil {
		return empty, "", err
	}
	if !valid {
		return empty, "RECHECK_CATALOG_CHANGED", nil
	}
	credential, err := policy.access.CheckCredentialValidTx(ctx, tx, a.RequesterKind, a.RequesterCredentialID)
	if err != nil {
		return empty, "", err
	}
	if !credential {
		return empty, "RECHECK_CREDENTIAL_REVOKED", nil
	}
	if !requesterExists {
		return empty, "RECHECK_REQUESTER_INVALID", nil
	}
	if hostState != "" {
		return empty, hostState, nil
	}
	result := policy.evaluate(ctx, requester, a.RequesterSourceIp, authz.ExecuteAction)
	if len(result) != len(policy.hosts) {
		return empty, "RECHECK_POLICY_DENIED", nil
	}
	requirements := []*authz.EffectiveApproval{frozen}
	for _, host := range result {
		switch {
		case host.Err == nil && host.Result.Decision == "allow":
		case host.Err == nil && host.Result.Decision == "require_approval" && host.Result.Approval != nil:
			requirements = append(requirements, host.Result.Approval)
		default:
			return empty, "RECHECK_POLICY_DENIED", nil
		}
	}
	effective := authz.MergeEffectiveApprovals(requirements)
	if len(votes) < effective.MinApprovals {
		return empty, "RECHECK_POLICY_TIGHTENED", nil
	}
	var prior []approvalPerson
	for i, vote := range votes {
		subject, email, _, exists, err := policy.access.LoadSubjectTx(ctx, tx, vote.ActorID, "")
		if err != nil {
			return empty, "", err
		}
		if !exists {
			return empty, "RECHECK_POLICY_TIGHTENED", nil
		}
		fromIP := voterIP
		if i < len(votes)-1 {
			// Reuse the IP from the authorization audit for this historical vote.
			// The final approver's connection cannot stand in for an earlier one.
			fromIP, err = q.GetApprovalVoteSourceIP(ctx, db.GetApprovalVoteSourceIPParams{
				At: vote.DecidedAt, JobID: a.JobID, Resource: "approval:" + a.ApprovalID,
				SubjectID: vote.ActorID, PolicyVersion: vote.PolicyVersion,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return empty, "RECHECK_POLICY_TIGHTENED", nil
			}
			if err != nil {
				return empty, "", err
			}
		}
		current := person(vote.ActorID, email)
		recorded := person(vote.ActorID, vote.ActorEmail)
		if separation.check(recorded, effective.AllowOwnerApprove) != "" ||
			slices.ContainsFunc(prior, recorded.samePerson) {
			return empty, "RECHECK_POLICY_TIGHTENED", nil
		}
		code, _ := policy.canVote(ctx, subject, current, fromIP, separation, effective, prior)
		if code != "" {
			return empty, "RECHECK_POLICY_TIGHTENED", nil
		}
		prior = append(prior, current, recorded)
	}
	// Revalidate the expiry component after policy and vote evaluation. The
	// credential row is locked, but its timestamp advances independently.
	credential, err = policy.access.CheckCredentialValidTx(ctx, tx, a.RequesterKind, a.RequesterCredentialID)
	if err != nil {
		return empty, "", err
	}
	if !credential {
		return empty, "RECHECK_CREDENTIAL_REVOKED", nil
	}
	return action, "", nil
}

func (s *Service) recheckCatalog(ctx context.Context, q *db.Queries, a db.ApprovalRequest) (catalog.Action, bool, error) {
	original, err := s.approvalCatalog(ctx, q, a.CatalogID, a.CatalogVersion)
	if err != nil {
		return catalog.Action{}, false, err
	}
	digest := hex.EncodeToString(a.ActionSha256)
	if original == nil || original.Digests[a.Action] != digest {
		return catalog.Action{}, false, nil
	}
	action, ok := original.Actions[a.Action]
	if !ok || action.Risk != a.ActionRisk {
		return catalog.Action{}, false, nil
	}
	refs, err := q.CurrentCatalogs(ctx)
	if err != nil {
		return catalog.Action{}, false, err
	}
	for _, ref := range refs {
		if !slices.Contains(ref.ActionNames, a.Action) {
			continue
		}
		if ref.CatalogID == original.CatalogID && ref.Version == original.Version {
			return action, true, nil
		}
		current, err := s.approvalCatalog(ctx, q, ref.CatalogID, ref.Version)
		return action, current != nil && current.Digests[a.Action] == digest, err
	}
	return catalog.Action{}, false, nil
}

// An absent or invalid signed envelope invalidates the execution plan. A query
// error leaves the approval pending so the caller can retry after recovery.
func (s *Service) approvalCatalog(ctx context.Context, q *db.Queries, id string, version int64) (*catalog.Package, error) {
	row, err := q.GetCatalog(ctx, structCatalogRef(id, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	env, err := catalog.ParseEnvelope(row.Dsse)
	if err != nil {
		return nil, nil
	}
	p, err := catalog.Verify(env, s.Trusted, catalog.VerifyOptions{})
	if err != nil || p.CatalogID != id || p.Version != version {
		return nil, nil
	}
	return p, nil
}
