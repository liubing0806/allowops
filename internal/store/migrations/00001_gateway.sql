-- +goose Up
CREATE TABLE gateway_instances (
    instance_id text PRIMARY KEY,
    started_at timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE join_tokens (
    token_id text PRIMARY KEY,
    token_hash bytea UNIQUE NOT NULL CHECK (octet_length(token_hash) = 32),
    max_uses bigint NOT NULL CHECK (max_uses > 0),
    used_count bigint NOT NULL DEFAULT 0 CHECK (used_count >= 0 AND used_count <= max_uses),
    expires_at timestamptz NOT NULL,
    revoked boolean NOT NULL DEFAULT false
);
CREATE TABLE hosts (
    host_id text PRIMARY KEY,
    hostname text NOT NULL,
    authorization_labels jsonb NOT NULL DEFAULT '{}',
    reported_labels jsonb NOT NULL DEFAULT '{}',
    certificate_serial text NOT NULL,
    certificate_status text NOT NULL DEFAULT 'active' CHECK (certificate_status IN ('active','deleted')),
    certificate_expires_at timestamptz NOT NULL,
    last_seen timestamptz,
    instance_id text REFERENCES gateway_instances(instance_id),
    connection_id text,
    agent_version text NOT NULL DEFAULT '',
    CHECK ((instance_id IS NULL) = (connection_id IS NULL))
);
-- Tombstones retain immutable identities; deleted hostnames can register again.
CREATE UNIQUE INDEX hosts_active_hostname ON hosts(hostname) WHERE certificate_status = 'active';
CREATE TABLE catalog_versions (
    catalog_id text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    dsse bytea NOT NULL,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    expires_at timestamptz NOT NULL,
    action_names text[] NOT NULL,
    PRIMARY KEY (catalog_id, version)
);
-- G15: transient transport only. No outputs, task history or replay.
CREATE TABLE gateway_messages (
    message_id text PRIMARY KEY,
    origin_instance text NOT NULL REFERENCES gateway_instances(instance_id),
    host_id text NOT NULL REFERENCES hosts(host_id),
    connection_id text NOT NULL,
    request bytea NOT NULL,
    response bytea,
    failure text NOT NULL DEFAULT '',
    expires_at timestamptz NOT NULL,
    CHECK (octet_length(request) <= 1048576),
    CHECK (octet_length(response) <= 1048576)
);
CREATE INDEX gateway_messages_expiry ON gateway_messages(expires_at);
-- +goose Down
DROP TABLE gateway_messages;
DROP TABLE catalog_versions;
DROP TABLE hosts;
DROP TABLE join_tokens;
DROP TABLE gateway_instances;
