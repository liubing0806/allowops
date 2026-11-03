package api

import (
	"context"
	"time"

	"github.com/liubing0806/allowops/internal/store/db"
)

// Policy data access: policy versions, policy tests and the inputs of the
// policy snapshot. See sql.go for the statements kept hand-written.

// lockPolicyWrites serializes policy writers for the rest of the transaction.
func lockPolicyWrites(ctx context.Context, q querier) error {
	return db.New(q).LockPolicyWrites(ctx)
}

// getPolicyVersion reads one policy version; version 0 selects the newest.
func getPolicyVersion(ctx context.Context, q querier, version uint64) (db.PolicyVersion, error) {
	return db.New(q).GetPolicyVersion(ctx, version)
}

// currentPolicyVersion returns the newest stored version number, or 0 when no
// version is stored.
func currentPolicyVersion(ctx context.Context, q querier) (int64, error) {
	return db.New(q).GetCurrentPolicyVersionNumber(ctx)
}

// listPolicyVersions returns every stored version number, newest first.
func listPolicyVersions(ctx context.Context, q querier) ([]uint64, error) {
	rows, err := db.New(q).ListPolicyVersionNumbers(ctx)
	if err != nil {
		return nil, err
	}
	versions := []uint64{}
	for _, n := range rows {
		versions = append(versions, uint64(n))
	}
	return versions, nil
}

// activeHostLabels returns the labels of active hosts ordered by hostname.
func activeHostLabels(ctx context.Context, q querier) ([]db.ListActiveHostLabelsRow, error) {
	return db.New(q).ListActiveHostLabels(ctx)
}

// currentCatalogEnvelopes returns the unexpired newest envelope of each catalog.
func currentCatalogEnvelopes(ctx context.Context, q querier) ([][]byte, error) {
	return db.New(q).ListCurrentCatalogEnvelopes(ctx)
}

// policyTest is a stored policy test; the byte fields hold JSON or hashes.
type policyTest struct {
	id, actor                              string
	baseVersion                            uint64
	candidate, candidateHash, snapshotHash []byte
	environment, test, changes             []byte
	expires                                time.Time
}

func insertPolicyTest(ctx context.Context, q querier, t policyTest) error {
	// Policy versions are bigint rows, so the base version fits int64.
	return db.New(q).InsertPolicyTest(ctx, db.InsertPolicyTestParams{TestID: t.id, ActorID: t.actor, BaseVersion: int64(t.baseVersion), Candidate: t.candidate, CandidateHash: t.candidateHash, SnapshotHash: t.snapshotHash, Environment: t.environment, Test: t.test, Changes: t.changes, ExpiresAt: timestamptz(t.expires)})
}

// policyTestChanges returns the stored changes of a live test owned by actor.
func policyTestChanges(ctx context.Context, q querier, id, actor string) ([]byte, error) {
	return db.New(q).GetPolicyTestChanges(ctx, db.GetPolicyTestChangesParams{TestID: id, ActorID: actor})
}

// lockPolicyTest locks an unconsumed, unexpired test of actor at the base
// version and returns its candidate hash, snapshot hash and environment.
func lockPolicyTest(ctx context.Context, q querier, id, actor string, base uint64) (candidateHash, snapshotHash, environment []byte, err error) {
	r, err := db.New(q).LockPolicyTest(ctx, db.LockPolicyTestParams{TestID: id, ActorID: actor, BaseVersion: int64(base)})
	return r.CandidateHash, r.SnapshotHash, r.Environment, err
}

func consumePolicyTest(ctx context.Context, q querier, id string) error {
	return db.New(q).ConsumePolicyTest(ctx, id)
}

// notifyPolicy announces a new policy version on the policy channel.
func notifyPolicy(ctx context.Context, q querier, version string) error {
	return db.New(q).NotifyPolicy(ctx, db.NotifyPolicyParams{PgNotify: PolicyChannel, PgNotify_2: version})
}
