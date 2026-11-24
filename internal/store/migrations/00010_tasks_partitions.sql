-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'allowops_job_writer') THEN
        CREATE ROLE allowops_job_writer NOLOGIN;
    END IF;
END $$;
-- +goose StatementEnd
GRANT SELECT, INSERT, UPDATE ON job_sequences, jobs, tasks TO allowops_job_writer;
GRANT SELECT, INSERT ON task_steps TO allowops_job_writer;

-- +goose StatementBegin
CREATE FUNCTION tasks_create_partitions(first_month timestamptz, months integer DEFAULT 3)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    start_at timestamptz;
    end_at timestamptz;
    partition_name text;
BEGIN
    IF months < 1 OR months > 120 THEN
        RAISE EXCEPTION 'months must be between 1 and 120';
    END IF;
    PERFORM pg_advisory_xact_lock(418006);
    FOR i IN 0..months-1 LOOP
        start_at := (date_trunc('month', first_month AT TIME ZONE 'UTC') + make_interval(months => i)) AT TIME ZONE 'UTC';
        end_at := (start_at AT TIME ZONE 'UTC' + interval '1 month') AT TIME ZONE 'UTC';
        partition_name := 'tasks_' || to_char(start_at AT TIME ZONE 'UTC', 'YYYYMM');
        EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF tasks FOR VALUES FROM (%L) TO (%L)', partition_name, start_at, end_at);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON %I TO allowops_job_writer', partition_name);
    END LOOP;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION tasks_create_partitions(timestamptz,integer) FROM PUBLIC;
SELECT tasks_create_partitions(now(), 3);

-- +goose Down
DROP FUNCTION tasks_create_partitions(timestamptz,integer);
-- Keep the partitions and their grants to preserve access to persisted jobs.
-- The NOLOGIN role may be used by other databases.
