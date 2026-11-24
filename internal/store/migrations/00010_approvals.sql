-- +goose Up
ALTER TABLE jobs DROP CONSTRAINT jobs_status_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_status_check CHECK (status BETWEEN 1 AND 8);
CREATE INDEX jobs_pending_approval ON jobs(created_at DESC, job_id) WHERE status = 8;

ALTER TABLE service_account_tokens
    ADD COLUMN created_by_user_id text NOT NULL DEFAULT '';

CREATE TABLE approval_sequences (
    day date PRIMARY KEY,
    value bigint NOT NULL CHECK (value > 0)
);

CREATE TABLE approval_requests (
    approval_id text PRIMARY KEY,
    job_id text NOT NULL UNIQUE REFERENCES jobs(job_id),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    status smallint NOT NULL CHECK (status BETWEEN 1 AND 6),
    action text NOT NULL,
    action_risk text NOT NULL CHECK (action_risk IN ('read', 'write', 'dangerous')),
    catalog_id text NOT NULL,
    catalog_version bigint NOT NULL,
    action_sha256 bytea NOT NULL CHECK (octet_length(action_sha256) = 32),
    params_json bytea NOT NULL,
    filters_json bytea NOT NULL,
    target_selector text NOT NULL DEFAULT '',
    target_hosts jsonb NOT NULL,
    batch_size integer NOT NULL CHECK (batch_size > 0),
    max_failures integer NOT NULL CHECK (max_failures >= 0),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    requester_subject_id text NOT NULL,
    requester_kind text NOT NULL CHECK (requester_kind IN ('service_account', 'ldap', 'oidc')),
    requester_email text NOT NULL DEFAULT '',
    requester_owner_id text NOT NULL DEFAULT '',
    requester_credential_id text NOT NULL DEFAULT '',
    requester_token_issuer_id text NOT NULL DEFAULT '',
    requester_source_ip text NOT NULL DEFAULT '',
    client_request_id text NOT NULL DEFAULT '',
    reason text NOT NULL,
    evidence_job_ids text[] NOT NULL DEFAULT '{}',
    evidence_summary text NOT NULL DEFAULT '',
    policy_version bigint NOT NULL,
    matched_rules text[] NOT NULL DEFAULT '{}',
    required_approver_roles jsonb NOT NULL DEFAULT '[]'::jsonb,
    min_approvals integer NOT NULL CHECK (min_approvals BETWEEN 1 AND 5),
    allow_owner_approve boolean NOT NULL DEFAULT false,
    approved_count integer NOT NULL DEFAULT 0 CHECK (approved_count >= 0),
    decided_at timestamptz,
    decided_by text NOT NULL DEFAULT '',
    decision_reason text NOT NULL DEFAULT '',
    consumed_at timestamptz,
    consumed_by_instance text NOT NULL DEFAULT '',
    consume_nonce text NOT NULL DEFAULT '',
    recheck_policy_version bigint,
    recheck_error text NOT NULL DEFAULT '',
    notify_seq bigint NOT NULL DEFAULT 0,
    notify_status text NOT NULL DEFAULT 'skipped' CHECK (notify_status IN ('skipped', 'sent', 'partial_failed', 'failed')),
    notify_error text NOT NULL DEFAULT '',
    CHECK (expires_at > created_at),
    CHECK (approved_count <= min_approvals)
);
CREATE INDEX approval_requests_pending_expires ON approval_requests(expires_at) WHERE status = 1;
CREATE INDEX approval_requests_requester_created ON approval_requests(requester_subject_id, created_at DESC, approval_id);
CREATE INDEX approval_requests_created ON approval_requests(created_at DESC, approval_id);
CREATE UNIQUE INDEX approval_requests_client_request ON approval_requests(requester_subject_id, client_request_id) WHERE client_request_id <> '';

CREATE TABLE approval_decisions (
    approval_id text NOT NULL REFERENCES approval_requests(approval_id),
    actor_id text NOT NULL,
    actor_email text NOT NULL DEFAULT '',
    decision smallint NOT NULL CHECK (decision IN (1, 2)),
    reason text NOT NULL DEFAULT '',
    decided_at timestamptz NOT NULL,
    policy_version bigint NOT NULL,
    matched_rules text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (approval_id, actor_id)
);

-- +goose Down
DROP TABLE approval_decisions;
DROP TABLE approval_requests;
DROP TABLE approval_sequences;
ALTER TABLE service_account_tokens DROP COLUMN created_by_user_id;
DROP INDEX jobs_pending_approval;
-- 08 08 encodes ExecutionResult.status = TASK_STATUS_CANCELLED.
UPDATE tasks SET status = 8, finished_at = clock_timestamp(), output_state = 'unavailable',
    result = decode('0808', 'hex')
    WHERE status = 1 AND job_id IN (SELECT job_id FROM jobs WHERE status = 8);
UPDATE jobs SET status = 7, finished_at = clock_timestamp() WHERE status = 8;
ALTER TABLE jobs DROP CONSTRAINT jobs_status_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_status_check CHECK (status BETWEEN 1 AND 7);
