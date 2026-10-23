-- +goose Up
-- The gateway process that accepted a task's terminal result and owns its
-- output persistence. It can differ from jobs.origin_instance. Rows written
-- before this column exist keep NULL: their owner is unknown.
-- On the partitioned parent the column and index apply to every existing and
-- future monthly partition.
ALTER TABLE tasks ADD COLUMN output_instance text;
CREATE INDEX tasks_output_pending ON tasks(output_instance) WHERE output_state='pending' AND status>2;
-- +goose Down
DROP INDEX tasks_output_pending;
ALTER TABLE tasks DROP COLUMN output_instance;
