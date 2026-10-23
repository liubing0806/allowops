-- Catalog uploads, publication timestamps and system status counters used by
-- the gateway API. The catalog list statement has an optional current-version
-- filter and stays hand-written in internal/gateway/api/catalogs_sql.go.

-- name: DeleteExpiredCatalogUploads :exec
DELETE FROM catalog_uploads WHERE expires_at<=now();

-- name: InsertCatalogUpload :exec
INSERT INTO catalog_uploads(upload_id,actor_id,envelope_size,envelope_sha256,expires_at) VALUES ($1,$2,$3,$4,$5);

-- name: LockCatalogUpload :one
SELECT actor_id,envelope_size,envelope_sha256,data,expires_at,published_catalog,chunk_ends FROM catalog_uploads WHERE upload_id=$1 FOR UPDATE;

-- name: AppendCatalogUploadChunk :exec
UPDATE catalog_uploads SET data=data||sqlc.arg(chunk)::bytea,chunk_ends=sqlc.arg(chunk_ends) WHERE upload_id=sqlc.arg(upload_id);

-- name: SetCatalogUploadPublished :exec
UPDATE catalog_uploads SET published_catalog=$2 WHERE upload_id=$1;

-- name: GetCatalogPublishedAt :one
SELECT published_at FROM catalog_versions WHERE catalog_id=$1 AND version=$2;

-- name: CountExpiringCatalogs :one
SELECT count(*) FROM catalog_versions c WHERE c.version=(SELECT max(version) FROM catalog_versions WHERE catalog_id=c.catalog_id) AND expires_at>now() AND expires_at<=now()+interval '14 days';

-- name: CountExpiringServiceAccountTokens :one
SELECT count(*) FROM service_account_tokens WHERE revoked_at IS NULL AND expires_at>now() AND expires_at<=now()+interval '7 days';

-- name: ListGatewayInstanceHosts :many
SELECT i.instance_id,i.version,i.draining,i.started_at,i.last_seen,(SELECT count(*) FROM hosts h WHERE h.instance_id=i.instance_id AND host_id=ANY(sqlc.arg(host_ids)::text[]) AND certificate_status='active')::bigint AS connected_hosts FROM gateway_instances i ORDER BY instance_id;
