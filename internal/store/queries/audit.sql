-- Audit chain statements. Event-row reads (the full column list scanned into
-- audit.Event) stay hand-written in internal/gateway/audit/sql.go because they
-- stream rows and map scan failures per row.

-- name: LockAuditAdvisory :exec
SELECT pg_advisory_xact_lock($1);

-- name: TryLockAuditAdvisory :one
SELECT pg_try_advisory_lock($1);

-- name: UnlockAuditAdvisory :exec
SELECT pg_advisory_unlock($1);

-- name: PingAuditSession :exec
SELECT 1;

-- name: GetAuditTip :one
SELECT seq,hash,at FROM audit_events ORDER BY seq DESC,at DESC LIMIT 1;

-- name: GetAuditBoundary :one
SELECT seq,hash FROM audit_boundary WHERE singleton;

-- name: GetLastAuditCheckpointAt :one
SELECT at FROM audit_events WHERE checkpoint_seq IS NOT NULL ORDER BY seq DESC LIMIT 1;

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (seq,at,subject_id,operation,resource,decision,reason,matched_rules,source_ip,hostname,action,job_id,task_id,policy_version,outputs,checkpoint_seq,checkpoint_hash,hash_input,prev_hash,hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20);

-- name: GetAuditMaxSeq :one
SELECT max(seq) FROM audit_events;

-- name: GetAuditSeqBounds :one
SELECT min(seq),max(seq) FROM audit_events WHERE (sqlc.narg(from_at)::timestamptz IS NULL OR at >= sqlc.narg(from_at)) AND (sqlc.narg(to_at)::timestamptz IS NULL OR at < sqlc.narg(to_at));

-- name: AuditEventExists :one
SELECT EXISTS(SELECT FROM audit_events WHERE seq=$1);

-- name: GetAuditEventHash :one
SELECT hash FROM audit_events WHERE seq=$1 ORDER BY at LIMIT 1;

-- name: GetAuditBoundaryHash :one
SELECT hash FROM audit_boundary WHERE seq=$1;

-- name: GetAuditExportCursor :one
SELECT next_seq,preceding_hash FROM audit_export_cursors WHERE name=$1;

-- name: InsertAuditExportCursor :exec
INSERT INTO audit_export_cursors(name,next_seq,preceding_hash) VALUES ($1,$2,$3);

-- name: UpdateAuditExportCursor :exec
UPDATE audit_export_cursors SET next_seq=$2,preceding_hash=$3 WHERE name=$1;

-- name: CreateAuditPartitions :exec
SELECT audit_create_partitions($1,$2);

-- name: GetAuditLastEventBefore :one
SELECT seq,hash FROM audit_events WHERE at<$1 ORDER BY seq DESC LIMIT 1;

-- name: GetAuditRetainedPrevHash :one
SELECT prev_hash FROM audit_events WHERE seq=$1 AND at>=$2;

-- name: AuditExportPending :one
SELECT EXISTS(SELECT FROM audit_export_cursors WHERE next_seq<=$1);

-- name: UpdateAuditBoundary :exec
UPDATE audit_boundary SET seq=$1,hash=$2 WHERE singleton;

-- name: ListExpiredAuditPartitions :many
SELECT name FROM audit_partitions WHERE ends_at<=$1 ORDER BY starts_at;

-- name: DeleteAuditPartition :exec
DELETE FROM audit_partitions WHERE name=$1;
