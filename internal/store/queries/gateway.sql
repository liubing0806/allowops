-- name: GetHost :one
SELECT * FROM hosts WHERE host_id = $1;

-- name: GetCatalog :one
SELECT * FROM catalog_versions WHERE catalog_id = $1 AND version = $2;

-- name: CurrentCatalogs :many
SELECT DISTINCT ON (catalog_id) catalog_id,version,digest,expires_at,action_names,octet_length(dsse)::bigint AS envelope_size_bytes FROM catalog_versions ORDER BY catalog_id, version DESC;

-- name: ConsumeToken :one
UPDATE join_tokens SET used_count = used_count + 1
WHERE token_hash = $1 AND NOT revoked AND expires_at > now() AND used_count < max_uses
RETURNING token_id;

-- name: InsertHost :exec
INSERT INTO hosts(host_id, hostname, certificate_serial, certificate_expires_at) VALUES ($1,$2,$3,$4);

-- name: InsertCatalog :exec
INSERT INTO catalog_versions(catalog_id,version,dsse,digest,expires_at,action_names) VALUES ($1,$2,$3,$4,$5,$6);

-- name: RegisterInstance :exec
INSERT INTO gateway_instances(instance_id) VALUES ($1);

-- name: TouchConnection :exec
UPDATE hosts SET last_seen = $3 WHERE host_id = $1 AND connection_id = $2;

-- name: DisconnectHost :exec
UPDATE hosts SET instance_id = NULL, connection_id = NULL, last_seen = $3 WHERE host_id = $1 AND connection_id = $2;

-- name: DeleteExpiredMessages :exec
DELETE FROM gateway_messages WHERE expires_at <= now();
