-- +goose Up
-- Keyset pagination of ListJobs without a subject filter.
CREATE INDEX jobs_created ON jobs(created_at DESC,job_id DESC);
-- +goose Down
DROP INDEX jobs_created;
