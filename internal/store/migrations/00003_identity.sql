-- +goose Up
CREATE TABLE console_users (
    user_id text PRIMARY KEY,
    provider_id text NOT NULL,
    provider_subject text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('oidc','ldap')),
    username text NOT NULL,
    email text NOT NULL DEFAULT '',
    display_name text NOT NULL DEFAULT '',
    groups text[] NOT NULL DEFAULT '{}',
    manual_roles text[] NOT NULL DEFAULT '{}',
    teams text[] NOT NULL DEFAULT '{}',
    revision bigint NOT NULL DEFAULT 1,
    UNIQUE(provider_id, provider_subject)
);
CREATE TABLE roles (name text PRIMARY KEY, description text NOT NULL DEFAULT '');
INSERT INTO roles(name) VALUES ('admin'),('operator'),('auditor'),('viewer'),('publisher');
CREATE TABLE role_mapping_state (singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), revision bigint NOT NULL DEFAULT 1, initialized boolean NOT NULL DEFAULT false);
INSERT INTO role_mapping_state VALUES (true,1,false);
CREATE TABLE role_mappings (provider_id text NOT NULL, group_name text NOT NULL, roles text[] NOT NULL, PRIMARY KEY(provider_id,group_name));
CREATE TABLE service_accounts (
    account_id text PRIMARY KEY,
    name text UNIQUE NOT NULL CHECK(name <> ''),
    owner_user_id text NOT NULL REFERENCES console_users(user_id),
    description text NOT NULL DEFAULT '',
    roles text[] NOT NULL DEFAULT '{}',
    teams text[] NOT NULL DEFAULT '{}',
    revision bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE service_account_tokens (
    token_id text PRIMARY KEY,
    account_id text NOT NULL REFERENCES service_accounts(account_id),
    token_hash bytea UNIQUE NOT NULL CHECK(octet_length(token_hash)=32),
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    CHECK(expires_at > created_at)
);
CREATE TABLE identity_sessions (
    session_id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES console_users(user_id),
    token_hash bytea UNIQUE NOT NULL CHECK(octet_length(token_hash)=32),
    client text NOT NULL CHECK(client IN ('cli','console')),
    csrf_token text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    CHECK(expires_at > created_at)
);
CREATE INDEX identity_sessions_user ON identity_sessions(user_id,session_id);
CREATE TABLE policy_versions (
    version bigint PRIMARY KEY CHECK(version > 0),
    rules jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by text NOT NULL,
    reason text NOT NULL DEFAULT '',
    rolled_back_from bigint REFERENCES policy_versions(version)
);
CREATE TABLE policy_tests (
    test_id text PRIMARY KEY,
    actor_id text NOT NULL,
    base_version bigint NOT NULL REFERENCES policy_versions(version),
    candidate jsonb NOT NULL,
    candidate_hash bytea NOT NULL CHECK(octet_length(candidate_hash)=32),
    snapshot_hash bytea NOT NULL CHECK(octet_length(snapshot_hash)=32),
    environment jsonb NOT NULL,
    test jsonb NOT NULL,
    changes jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed boolean NOT NULL DEFAULT false
);
CREATE TABLE oidc_transactions (
    state_hash bytea PRIMARY KEY CHECK(octet_length(state_hash)=32),
    provider_id text NOT NULL,
    client text NOT NULL CHECK(client IN ('cli','console')),
    nonce text NOT NULL,
    provider_verifier text NOT NULL,
    binding_hash bytea CHECK(octet_length(binding_hash)=32),
    loopback_uri text NOT NULL DEFAULT '',
    cli_state text NOT NULL DEFAULT '',
    cli_challenge text NOT NULL DEFAULT '',
    expires_at timestamptz NOT NULL
);
CREATE TABLE cli_login_codes (
    code_hash bytea PRIMARY KEY CHECK(octet_length(code_hash)=32),
    user_id text NOT NULL REFERENCES console_users(user_id),
    challenge text NOT NULL,
    expires_at timestamptz NOT NULL
);
-- +goose Down
DROP TABLE cli_login_codes;
DROP TABLE oidc_transactions;
DROP TABLE policy_tests;
DROP TABLE policy_versions;
DROP TABLE identity_sessions;
DROP TABLE service_account_tokens;
DROP TABLE service_accounts;
DROP TABLE role_mappings;
DROP TABLE role_mapping_state;
DROP TABLE roles;
DROP TABLE console_users;
