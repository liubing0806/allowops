-- Console users, role mappings, service accounts and login sessions used by
-- the gateway API. The "UPDATE console_users SET manual_roles=" and
-- "INSERT INTO join_tokens(" statements stay hand-written in
-- internal/gateway/api/sql.go because API tests identify them by SQL text.

-- name: ListMappedRoles :many
SELECT roles FROM role_mappings WHERE provider_id=sqlc.arg(provider_id) AND group_name=ANY(sqlc.arg(groups)::text[]) ORDER BY group_name;

-- name: GetConsoleUser :one
SELECT user_id,provider_id,provider_subject,kind,username,email,display_name,groups,manual_roles,teams,revision FROM console_users WHERE user_id=$1;

-- name: SearchConsoleUsers :many
SELECT user_id,provider_id,provider_subject,kind,username,email,display_name,groups,manual_roles,teams,revision FROM console_users WHERE sqlc.arg(query)::text='' OR position(lower(sqlc.arg(query)::text) in lower(username||' '||email||' '||display_name))>0 ORDER BY user_id;

-- name: UpsertConsoleUser :exec
INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username,email,groups) VALUES (sqlc.arg(user_id),sqlc.arg(provider_id),sqlc.arg(provider_subject),sqlc.arg(kind),sqlc.arg(provider_subject),sqlc.arg(email),sqlc.arg(groups))
      ON CONFLICT(provider_id,provider_subject) DO UPDATE SET email=EXCLUDED.email,groups=EXCLUDED.groups,revision=console_users.revision+1;

-- name: GetConsoleUserID :one
SELECT user_id FROM console_users WHERE provider_id=$1 AND provider_subject=$2;

-- name: GetRoleMappingRevision :one
SELECT revision FROM role_mapping_state;

-- name: ListRoleMappings :many
SELECT provider_id,group_name,roles FROM role_mappings ORDER BY provider_id,group_name;

-- name: BumpRoleMappingRevision :execrows
UPDATE role_mapping_state SET revision=revision+1 WHERE revision=$1;

-- name: DeleteRoleMappings :exec
DELETE FROM role_mappings;

-- name: InsertRoleMapping :exec
INSERT INTO role_mappings(provider_id,group_name,roles) VALUES ($1,$2,$3);

-- name: LockRoleMappingState :one
SELECT initialized FROM role_mapping_state FOR UPDATE;

-- name: MarkRoleMappingsInitialized :exec
UPDATE role_mapping_state SET initialized=true;

-- name: ListRoleNames :many
SELECT DISTINCT name FROM (
      SELECT name FROM roles UNION SELECT unnest(manual_roles) FROM console_users UNION SELECT unnest(roles) FROM service_accounts UNION SELECT unnest(roles) FROM role_mappings
      UNION SELECT jsonb_array_elements_text(rule->'roles') FROM policy_versions p CROSS JOIN LATERAL jsonb_array_elements(p.rules->'rules') rule WHERE p.version=(SELECT max(version) FROM policy_versions)
    ) names WHERE name <> '*' ORDER BY name;

-- name: InsertServiceAccount :one
INSERT INTO service_accounts(account_id,name,owner_user_id,description,roles,teams) VALUES ($1,$2,$3,$4,$5,$6) RETURNING account_id,name,owner_user_id,description,roles,teams,revision,created_at;

-- name: GetServiceAccount :one
SELECT account_id,name,owner_user_id,description,roles,teams,revision,created_at FROM service_accounts WHERE account_id=$1;

-- name: ListServiceAccounts :many
SELECT account_id,name,owner_user_id,description,roles,teams,revision,created_at FROM service_accounts ORDER BY account_id;

-- name: UpdateServiceAccount :one
UPDATE service_accounts SET owner_user_id=$3,description=$4,roles=$5,teams=$6,revision=revision+1 WHERE account_id=$1 AND revision=$2 RETURNING account_id,name,owner_user_id,description,roles,teams,revision,created_at;

-- name: InsertServiceAccountToken :one
INSERT INTO service_account_tokens(token_id,account_id,token_hash,description,expires_at) VALUES ($1,$2,$3,$4,$5) RETURNING token_id,account_id,description,created_at,expires_at,last_used_at,revoked_at;

-- name: ListServiceAccountTokens :many
SELECT token_id,account_id,description,created_at,expires_at,last_used_at,revoked_at FROM service_account_tokens WHERE account_id=$1 ORDER BY token_id;

-- name: RevokeServiceAccountToken :execrows
UPDATE service_account_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE account_id=$1 AND token_id=$2;

-- name: TouchServiceAccountToken :one
UPDATE service_account_tokens SET last_used_at=now() WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>now() RETURNING account_id;

-- name: TouchIdentitySession :one
UPDATE identity_sessions SET last_used_at=now() WHERE token_hash=$1 AND client=$2 AND revoked_at IS NULL AND expires_at>now() RETURNING session_id,csrf_token;

-- name: GetIdentitySession :one
SELECT session_id,user_id,created_at,expires_at,last_used_at,revoked_at FROM identity_sessions WHERE session_id=$1;

-- name: InsertIdentitySession :one
INSERT INTO identity_sessions(session_id,user_id,token_hash,client,csrf_token,expires_at) VALUES ($1,$2,$3,$4,$5,$6) RETURNING session_id,user_id,created_at,expires_at,last_used_at,revoked_at;

-- name: ListCliSessions :many
SELECT session_id,user_id,created_at,expires_at,last_used_at,revoked_at FROM identity_sessions WHERE user_id=$1 AND client='cli' ORDER BY session_id;

-- name: RevokeIdentitySession :exec
UPDATE identity_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE session_id=$1;

-- name: RevokeCliSession :execrows
UPDATE identity_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE session_id=$1 AND user_id=$2 AND client='cli';

-- name: LockOidcAdmission :exec
SELECT pg_advisory_xact_lock(418010);

-- name: DeleteExpiredOidcTransactions :exec
DELETE FROM oidc_transactions WHERE expires_at<=clock_timestamp();

-- name: CountLiveOidcTransactions :one
SELECT count(*) FROM oidc_transactions WHERE expires_at>clock_timestamp();

-- name: InsertOidcTransaction :exec
INSERT INTO oidc_transactions(state_hash,provider_id,client,nonce,provider_verifier,loopback_uri,cli_state,cli_challenge,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9);

-- name: BindOidcTransaction :one
UPDATE oidc_transactions SET binding_hash=$2 WHERE state_hash=$1 AND expires_at>now() AND binding_hash IS NULL RETURNING provider_id,nonce,provider_verifier;

-- name: TakeOidcTransaction :one
DELETE FROM oidc_transactions WHERE state_hash=$1 AND binding_hash=$2 AND expires_at>now() RETURNING provider_id,client,nonce,provider_verifier,loopback_uri,cli_state,cli_challenge;

-- name: InsertCliLoginCode :exec
INSERT INTO cli_login_codes(code_hash,user_id,challenge,expires_at) VALUES ($1,$2,$3,$4);

-- name: LockCliLoginCode :one
SELECT user_id,challenge FROM cli_login_codes WHERE code_hash=$1 AND expires_at>clock_timestamp() FOR UPDATE;

-- name: DeleteCliLoginCode :exec
DELETE FROM cli_login_codes WHERE code_hash=$1;
