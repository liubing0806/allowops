package store

import (
	"context"
	"errors"
)

// EnsurePartitions creates partitions in one transaction and reports whether
// the optional tasks partition function ran.
func (s *Store) EnsurePartitions(ctx context.Context, months int) (bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, errors.New("begin partition maintenance failed")
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "SELECT audit_create_partitions(now(), $1)", months); err != nil {
		return false, errors.New("ensure audit_events partitions failed")
	}
	var tasks bool
	err = tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT FROM pg_catalog.pg_proc
		WHERE oid = pg_catalog.to_regprocedure('tasks_create_partitions(timestamptz, integer)')
		  AND prokind = 'f'
	)`).Scan(&tasks)
	if err != nil {
		return false, errors.New("check tasks partition function failed")
	}
	if tasks {
		if _, err := tx.Exec(ctx, "SELECT tasks_create_partitions(now(), $1::integer)", months); err != nil {
			return false, errors.New("ensure tasks partitions failed")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, errors.New("commit partition maintenance failed")
	}
	return tasks, nil
}
