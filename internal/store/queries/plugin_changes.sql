-- name: ListCatalogChangeHistory :many
SELECT catalog_id, version, published_at, cardinality(action_names)::int AS action_count
FROM catalog_versions
WHERE published_at IS NOT NULL AND published_at >= $1 AND published_at <= $2
ORDER BY published_at DESC, catalog_id ASC, version DESC
LIMIT $3;

-- name: ListPolicyChangeHistory :many
SELECT version, created_at, created_by, reason, COALESCE(rolled_back_from, 0)::bigint AS rolled_back_from
FROM policy_versions
WHERE created_at >= $1 AND created_at <= $2
ORDER BY created_at DESC, version DESC
LIMIT $3;
