-- name: LockPolicyReadsShared :exec
SELECT pg_advisory_xact_lock_shared(418005);

-- name: LockCatalogReadsShared :exec
SELECT pg_advisory_xact_lock_shared(418001);

-- name: NextApprovalSequence :one
INSERT INTO approval_sequences(day,value) VALUES ($1,1)
ON CONFLICT(day) DO UPDATE SET value=approval_sequences.value+1
RETURNING value;

-- name: InsertApproval :one
INSERT INTO approval_requests (
    approval_id, job_id, created_at, expires_at, status, action, action_risk,
    catalog_id, catalog_version, action_sha256, params_json, filters_json, target_selector,
    target_hosts, batch_size, max_failures, request_digest, requester_subject_id, requester_kind,
    requester_email, requester_owner_id, requester_credential_id, requester_token_issuer_id,
    requester_source_ip, client_request_id, reason, evidence_job_ids, evidence_summary,
    policy_version, matched_rules, required_approver_roles, min_approvals, allow_owner_approve, notify_seq
) VALUES (
    $1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
    $19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,1
) RETURNING *;

-- name: CountPendingApprovals :one
SELECT count(*) AS global_count, count(*) FILTER (WHERE requester_subject_id=$1) AS subject_count
FROM approval_requests WHERE status=1 AND expires_at>clock_timestamp();

-- name: GetApprovalByClientRequest :one
SELECT * FROM approval_requests WHERE requester_subject_id=$1 AND client_request_id=$2 AND client_request_id<>'';

-- name: GetApproval :one
SELECT * FROM approval_requests WHERE approval_id=$1;

-- name: ListApprovalsByJobIDs :many
SELECT approval_id, job_id, status, expires_at, min_approvals, approved_count,
    required_approver_roles, decided_at, decision_reason, recheck_error
FROM approval_requests WHERE job_id=ANY($1::text[]);

-- name: GetApprovalRoute :one
SELECT job_id, requester_subject_id FROM approval_requests WHERE approval_id=$1;

-- name: GetApprovalIDByJob :one
SELECT approval_id FROM approval_requests WHERE job_id=$1;

-- name: LockApproval :one
SELECT * FROM approval_requests WHERE approval_id=$1 FOR UPDATE;

-- name: LockApprovalJob :one
SELECT * FROM jobs WHERE job_id=$1 FOR UPDATE;

-- name: ReadApprovalHosts :many
SELECT host_id, authorization_labels, certificate_status
FROM hosts WHERE host_id=ANY($1::text[]) ORDER BY host_id;

-- name: LockApprovalHosts :many
SELECT host_id, authorization_labels, certificate_status
FROM hosts WHERE host_id=ANY($1::text[]) ORDER BY host_id FOR SHARE;

-- name: ListApprovalTargets :many
SELECT host_id FROM tasks WHERE job_id=$1 ORDER BY position;

-- name: ListApprovalDecisions :many
SELECT * FROM approval_decisions WHERE approval_id=$1 ORDER BY decided_at, actor_id;

-- name: InsertApprovalDecision :exec
INSERT INTO approval_decisions (
    approval_id, actor_id, actor_email, decision, reason, decided_at, policy_version, matched_rules
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8);

-- name: UpdateApprovalCount :one
UPDATE approval_requests SET approved_count=$2 WHERE approval_id=$1 AND status=1 RETURNING *;

-- name: FinishApproval :one
UPDATE approval_requests SET status=$2, decided_at=clock_timestamp(), decided_by=$3,
    decision_reason=$4, recheck_policy_version=$5, recheck_error=$6, approved_count=$7, notify_seq=notify_seq+1, notify_status='skipped', notify_error=''
WHERE approval_id=$1 AND status=1 RETURNING *;

-- name: FinishApprovalJob :execrows
UPDATE jobs SET status=$2, finished_at=clock_timestamp() WHERE job_id=$1 AND status=8;

-- name: ConsumeApproval :one
UPDATE approval_requests SET status=2, approved_count=$2, decided_at=clock_timestamp(),
    decided_by=$3, decision_reason=$4, consumed_at=clock_timestamp(), consumed_by_instance=$5,
    consume_nonce=$6, recheck_policy_version=$7, notify_seq=notify_seq+1, notify_status='skipped', notify_error=''
WHERE approval_id=$1 AND status=1 AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING *;

-- name: QueueApprovedJob :execrows
UPDATE jobs SET status=1, origin_instance=$2, policy_version=$3 WHERE job_id=$1 AND status=8;

-- name: ApprovalConsumptionCommitted :one
SELECT status=2 AND consume_nonce=$2 AS committed FROM approval_requests WHERE approval_id=$1 FOR SHARE;

-- name: LockExpiredApproval :one
SELECT * FROM approval_requests WHERE status=1 AND expires_at<=clock_timestamp()
ORDER BY expires_at, approval_id LIMIT 1 FOR UPDATE SKIP LOCKED;

-- name: ListApprovalCandidates :many
SELECT approval_id, created_at FROM approval_requests
WHERE (sqlc.arg(requester)::text='' OR requester_subject_id=sqlc.arg(requester))
  AND (sqlc.arg(action)::text='' OR action=sqlc.arg(action))
  AND (sqlc.narg(created_from)::timestamptz IS NULL OR created_at>=sqlc.narg(created_from))
  AND (sqlc.narg(created_to)::timestamptz IS NULL OR created_at<sqlc.narg(created_to))
  AND (cardinality(sqlc.arg(statuses)::smallint[])=0 OR status=ANY(sqlc.arg(statuses)))
  AND (NOT sqlc.arg(only_actionable)::boolean OR (status=1 AND expires_at>clock_timestamp()))
  AND (sqlc.narg(after_created)::timestamptz IS NULL OR
      (created_at,approval_id)<(sqlc.narg(after_created),sqlc.arg(after_id)::text))
ORDER BY created_at DESC, approval_id DESC LIMIT sqlc.arg(page_limit);

-- name: GetApprovalVoteSourceIP :one
SELECT source_ip FROM audit_events
WHERE at=$1 AND job_id=$2 AND resource=$3 AND subject_id=$4 AND policy_version=$5
  AND operation='approve_job' AND decision='allow' AND reason='authorized'
ORDER BY seq DESC LIMIT 1;

-- name: UpdateApprovalNotification :execrows
UPDATE approval_requests SET notify_status=$3, notify_error=$4
WHERE approval_id=$1 AND notify_seq=$2;
