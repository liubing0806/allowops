-- Limit the number of deletions per pass. Skip rows locked by active requests
-- or by a cleanup worker on another gateway replica.

-- name: DeleteExpiredPolicyTestBatch :exec
DELETE FROM policy_tests WHERE test_id IN (
    SELECT test_id FROM policy_tests WHERE expires_at <= now()
    ORDER BY expires_at, test_id LIMIT $1 FOR UPDATE SKIP LOCKED
);

-- name: DeleteExpiredCliLoginCodeBatch :exec
DELETE FROM cli_login_codes WHERE code_hash IN (
    SELECT code_hash FROM cli_login_codes WHERE expires_at <= now()
    ORDER BY expires_at, code_hash LIMIT $1 FOR UPDATE SKIP LOCKED
);

-- name: DeleteExpiredOidcTransactionBatch :exec
DELETE FROM oidc_transactions WHERE state_hash IN (
    SELECT state_hash FROM oidc_transactions WHERE expires_at <= now()
    ORDER BY expires_at, state_hash LIMIT $1 FOR UPDATE SKIP LOCKED
);

-- name: DeleteOldIdentitySessionBatch :exec
DELETE FROM identity_sessions WHERE session_id IN (
    SELECT session_id FROM identity_sessions WHERE expires_at < now() - interval '30 days'
    ORDER BY expires_at, session_id LIMIT $1 FOR UPDATE SKIP LOCKED
);
