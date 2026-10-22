-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'allowops_audit_writer') THEN
        CREATE ROLE allowops_audit_writer NOLOGIN;
    END IF;
END $$;
-- +goose StatementEnd
CREATE TABLE audit_events (
    seq bigint NOT NULL CHECK (seq > 0),
    at timestamptz NOT NULL,
    subject_id text NOT NULL,
    operation text NOT NULL,
    resource text NOT NULL,
    decision text NOT NULL,
    reason text NOT NULL,
    matched_rules text[] NOT NULL,
    source_ip text NOT NULL,
    hostname text NOT NULL,
    action text NOT NULL,
    job_id text NOT NULL,
    task_id text NOT NULL,
    policy_version bigint NOT NULL CHECK (policy_version >= 0),
    outputs jsonb NOT NULL,
    checkpoint_seq bigint,
    checkpoint_hash bytea,
    hash_input bytea NOT NULL,
    prev_hash bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
    hash bytea NOT NULL CHECK (octet_length(hash) = 32),
    PRIMARY KEY (seq, at),
    CHECK ((checkpoint_seq IS NULL) = (checkpoint_hash IS NULL)),
    CHECK (checkpoint_hash IS NULL OR octet_length(checkpoint_hash) = 32)
) PARTITION BY RANGE (at);
CREATE INDEX audit_events_at ON audit_events(at, seq);
REVOKE ALL ON audit_events FROM PUBLIC, allowops_audit_writer;
GRANT SELECT, INSERT ON audit_events TO allowops_audit_writer;

CREATE TABLE audit_partitions (
    name text PRIMARY KEY,
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL
);
-- A retained boundary is an internal anchor, not evidence of external delivery.
CREATE TABLE audit_boundary (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    seq bigint NOT NULL,
    hash bytea NOT NULL CHECK (octet_length(hash) = 32)
);
INSERT INTO audit_boundary(seq, hash) VALUES (0, decode(repeat('00',32),'hex'));
GRANT SELECT ON audit_boundary TO allowops_audit_writer;

CREATE TABLE audit_export_cursors (
    name text PRIMARY KEY,
    next_seq bigint NOT NULL CHECK (next_seq > 0),
    preceding_hash bytea NOT NULL CHECK (octet_length(preceding_hash) = 32)
);
GRANT SELECT, INSERT, UPDATE ON audit_export_cursors TO allowops_audit_writer;

-- Maintenance credentials own partitions; gateway credentials cannot create/drop.
-- +goose StatementBegin
CREATE FUNCTION audit_create_partitions(first_month timestamptz, months integer DEFAULT 3)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    start_at timestamptz;
    end_at timestamptz;
    partition_name text;
BEGIN
    IF months < 1 OR months > 120 THEN
        RAISE EXCEPTION 'months must be between 1 and 120';
    END IF;
    FOR i IN 0..months-1 LOOP
        start_at := (date_trunc('month',first_month AT TIME ZONE 'UTC') + make_interval(months=>i)) AT TIME ZONE 'UTC';
        end_at := (start_at AT TIME ZONE 'UTC' + interval '1 month') AT TIME ZONE 'UTC';
        partition_name := 'audit_events_' || to_char(start_at AT TIME ZONE 'UTC','YYYYMM');
        EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_events FOR VALUES FROM (%L) TO (%L)',partition_name,start_at,end_at);
        EXECUTE format('REVOKE ALL ON %I FROM PUBLIC, allowops_audit_writer',partition_name);
        EXECUTE format('GRANT SELECT, INSERT ON %I TO allowops_audit_writer',partition_name);
        INSERT INTO audit_partitions VALUES (partition_name,start_at,end_at) ON CONFLICT DO NOTHING;
    END LOOP;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION audit_create_partitions(timestamptz,integer) FROM PUBLIC;
SELECT audit_create_partitions(now(),3);

-- +goose Down
DROP FUNCTION audit_create_partitions(timestamptz,integer);
DROP TABLE audit_export_cursors;
DROP TABLE audit_boundary;
DROP TABLE audit_partitions;
DROP TABLE audit_events;
-- The NOLOGIN role may be used by other databases; do not drop it here.
