-- Policy versions and policy tests used by the gateway API. The two
-- "INSERT INTO policy_versions(" statements stay hand-written in
-- internal/gateway/api/sql.go because API tests identify them by SQL text.

-- name: LockPolicyWrites :exec
SELECT pg_advisory_xact_lock(418005);

-- name: GetPolicyVersion :one
SELECT version,rules,created_at,created_by,reason,rolled_back_from FROM policy_versions WHERE version=COALESCE(NULLIF($1,0),(SELECT max(version) FROM policy_versions));

-- name: ListPolicyVersionNumbers :many
SELECT version FROM policy_versions ORDER BY version DESC;

-- name: ListActiveHostLabels :many
SELECT host_id,hostname,authorization_labels,reported_labels FROM hosts WHERE certificate_status='active' ORDER BY hostname;

-- name: ListCurrentCatalogEnvelopes :many
SELECT dsse FROM (SELECT DISTINCT ON(catalog_id) catalog_id,dsse,expires_at FROM catalog_versions ORDER BY catalog_id,version DESC) current WHERE expires_at>now() ORDER BY catalog_id;

-- name: InsertPolicyTest :exec
INSERT INTO policy_tests(test_id,actor_id,base_version,candidate,candidate_hash,snapshot_hash,environment,test,changes,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);

-- name: GetPolicyTestChanges :one
SELECT changes FROM policy_tests WHERE test_id=$1 AND actor_id=$2 AND expires_at>now();

-- name: LockPolicyTest :one
SELECT candidate_hash,snapshot_hash,environment FROM policy_tests WHERE test_id=$1 AND actor_id=$2 AND base_version=$3 AND expires_at>clock_timestamp() AND NOT consumed FOR UPDATE;

-- name: ConsumePolicyTest :exec
UPDATE policy_tests SET consumed=true WHERE test_id=$1;

-- name: NotifyPolicy :exec
SELECT pg_notify($1,$2);

-- name: GetCurrentPolicyVersionNumber :one
SELECT COALESCE(max(version),0)::bigint FROM policy_versions;
