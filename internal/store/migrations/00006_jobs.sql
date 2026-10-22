-- +goose Up
CREATE TABLE job_sequences (
    day date PRIMARY KEY,
    value bigint NOT NULL CHECK (value > 0)
);
CREATE TABLE jobs (
    job_id text PRIMARY KEY,
    created_at timestamptz NOT NULL,
    subject_id text NOT NULL,
    origin_instance text NOT NULL REFERENCES gateway_instances(instance_id),
    action text NOT NULL,
    action_definition bytea NOT NULL,
    catalog_id text NOT NULL,
    catalog_version bigint NOT NULL,
    action_sha256 bytea NOT NULL CHECK (octet_length(action_sha256)=32),
    policy_version bigint NOT NULL,
    reason text NOT NULL,
    status smallint NOT NULL CHECK (status BETWEEN 1 AND 7),
    batch_size integer NOT NULL CHECK (batch_size>0),
    max_failures integer NOT NULL CHECK (max_failures>=0),
    cancel_requested boolean NOT NULL DEFAULT false,
    finished_at timestamptz,
    UNIQUE (job_id,created_at)
);
CREATE INDEX jobs_subject_created ON jobs(subject_id,created_at DESC,job_id);
CREATE INDEX jobs_origin_active ON jobs(origin_instance) WHERE status IN (1,2);
CREATE TABLE tasks (
    job_id text NOT NULL,
    task_id text NOT NULL,
    created_at timestamptz NOT NULL,
    host_id text NOT NULL REFERENCES hosts(host_id),
    hostname text NOT NULL,
    position integer NOT NULL,
    connection_id text,
    dispatched boolean NOT NULL DEFAULT false,
    status smallint NOT NULL CHECK (status BETWEEN 1 AND 9),
    result bytea NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    output_stored boolean NOT NULL DEFAULT false,
    output_state text NOT NULL DEFAULT 'pending' CHECK (output_state IN ('pending','stored','failed','unavailable')),
    -- A23: redacted, filtered output only; optional and bounded per stream.
    stdout_preview bytea CHECK (octet_length(stdout_preview)<=4096),
    stderr_preview bytea CHECK (octet_length(stderr_preview)<=4096),
    stdout_sha256 bytea CHECK (octet_length(stdout_sha256)=32),
    stderr_sha256 bytea CHECK (octet_length(stderr_sha256)=32),
    stdout_size bigint NOT NULL DEFAULT 0 CHECK (stdout_size>=0),
    stderr_size bigint NOT NULL DEFAULT 0 CHECK (stderr_size>=0),
    step_count integer NOT NULL DEFAULT 0,
    PRIMARY KEY (job_id,task_id,created_at),
    FOREIGN KEY (job_id,created_at) REFERENCES jobs(job_id,created_at)
) PARTITION BY RANGE (created_at);
CREATE INDEX tasks_host_connection ON tasks(host_id,connection_id) WHERE status IN (1,2);
CREATE TABLE task_steps (
    job_id text NOT NULL,
    task_id text NOT NULL,
    created_at timestamptz NOT NULL,
    step_index integer NOT NULL CHECK (step_index>=0),
    name text NOT NULL,
    result bytea NOT NULL,
    PRIMARY KEY (job_id,task_id,created_at,step_index),
    FOREIGN KEY (job_id,task_id,created_at) REFERENCES tasks(job_id,task_id,created_at)
);
-- +goose Down
DROP TABLE task_steps;
DROP TABLE tasks;
DROP TABLE jobs;
DROP TABLE job_sequences;
