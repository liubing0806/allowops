-- Host label updates, host import previews and join tokens used by the
-- gateway API. The host list/lookup statements (interval text parameter and an
-- optional FOR UPDATE suffix) and "INSERT INTO join_tokens(" (matched by SQL
-- text in API tests) are hand-written in internal/gateway/api/sql.go and
-- hosts_sql.go.

-- name: UpdateHostLabels :exec
UPDATE hosts SET authorization_labels=$2,revision=revision+1 WHERE host_id=$1;

-- name: DeleteExpiredHostImportPreviews :exec
DELETE FROM host_import_previews WHERE expires_at<=now();

-- name: InsertHostImportPreview :exec
INSERT INTO host_import_previews(preview_id,actor_id,csv_sha256,rows,targets,invalid_count,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7);

-- name: GetHostImportPreview :one
SELECT actor_id,csv_sha256,rows,targets,invalid_count,expires_at,updated_count FROM host_import_previews WHERE preview_id=$1;

-- name: LockHostImportPreview :one
SELECT actor_id,csv_sha256,rows,targets,invalid_count,expires_at,updated_count FROM host_import_previews WHERE preview_id=$1 FOR UPDATE;

-- name: SetHostImportPreviewUpdated :exec
UPDATE host_import_previews SET updated_count=$2 WHERE preview_id=$1;

-- name: GetJoinTokenByHash :one
SELECT token_id,max_uses,used_count,expires_at,created_at,revoked_at FROM join_tokens WHERE token_hash=$1;

-- name: ListJoinTokens :many
SELECT token_id,max_uses,used_count,expires_at,created_at,revoked_at FROM join_tokens ORDER BY token_id;

-- name: RevokeJoinToken :execrows
UPDATE join_tokens SET revoked=true,revoked_at=CASE WHEN revoked THEN revoked_at ELSE now() END WHERE token_id=$1;
