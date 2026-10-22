package audit

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type Anchor struct {
	Seq  uint64
	Hash []byte
}

type RetentionOptions struct {
	Months                    int     // zero means the design default of 12 calendar months.
	RequireExternalCheckpoint bool    // A19 defaults to false; true requires an external checkpoint.
	ExternalCheckpoint        *Anchor // supplied by a separately trusted external system.
}

// CreatePartitions uses maintenance credentials. Run monthly before the existing
// three-month partition horizon expires; append never performs privileged DDL.
func (s *Store) CreatePartitions(ctx context.Context, first time.Time, months int) error {
	_, err := s.Pool.Exec(ctx, "SELECT audit_create_partitions($1,$2)", first, months)
	return err
}

// Prune deletes whole expired UTC calendar partitions, keeping the partial
// boundary month. It atomically saves the last removed seq/hash as an internal
// boundary checkpoint. This anchor alone does not establish external trust.
func (s *Store) Prune(ctx context.Context, o RetentionOptions) (Anchor, error) {
	if o.Months == 0 {
		o.Months = 12
	}
	if o.Months < 1 || o.Months > 120 {
		return Anchor{}, ErrInvalid
	}
	now := s.Config.Now().UTC()
	cutoff := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -o.Months, 0)
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Anchor{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", exportLock); err != nil {
		return Anchor{}, err
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", appendLock); err != nil {
		return Anchor{}, err
	}
	var boundary Anchor
	if err := tx.QueryRow(ctx, "SELECT seq,hash FROM audit_boundary WHERE singleton").Scan(&boundary.Seq, &boundary.Hash); err != nil {
		return boundary, err
	}
	var seq *uint64
	var hash []byte
	err = tx.QueryRow(ctx, "SELECT seq,hash FROM audit_events WHERE at<$1 ORDER BY seq DESC LIMIT 1", cutoff).Scan(&seq, &hash)
	if err != nil && err != pgx.ErrNoRows {
		return boundary, err
	}
	if seq != nil {
		boundary = Anchor{Seq: *seq, Hash: hash}
		if o.RequireExternalCheckpoint && (o.ExternalCheckpoint == nil || o.ExternalCheckpoint.Seq != boundary.Seq || !bytes.Equal(o.ExternalCheckpoint.Hash, boundary.Hash)) {
			return boundary, fmt.Errorf("external retention checkpoint required or mismatched")
		}
		var retainedHash []byte
		if err := tx.QueryRow(ctx, "SELECT prev_hash FROM audit_events WHERE seq=$1 AND at>=$2", boundary.Seq+1, cutoff).Scan(&retainedHash); err != nil {
			return boundary, ErrUnavailable
		}
		if !bytes.Equal(retainedHash, boundary.Hash) {
			return boundary, ErrUnavailable
		}
		var pending bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT FROM audit_export_cursors WHERE next_seq<=$1)", boundary.Seq).Scan(&pending); err != nil {
			return boundary, err
		}
		if pending {
			return boundary, fmt.Errorf("retention would delete unexported audit events")
		}
		if _, err := tx.Exec(ctx, "UPDATE audit_boundary SET seq=$1,hash=$2 WHERE singleton", boundary.Seq, boundary.Hash); err != nil {
			return boundary, err
		}
	}
	rows, err := tx.Query(ctx, "SELECT name FROM audit_partitions WHERE ends_at<=$1 ORDER BY starts_at", cutoff)
	if err != nil {
		return boundary, err
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return boundary, err
		}
		names = append(names, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return boundary, err
	}
	for _, name := range names {
		if _, err := tx.Exec(ctx, "DROP TABLE "+pgx.Identifier{name}.Sanitize()); err != nil {
			return boundary, err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM audit_partitions WHERE name=$1", name); err != nil {
			return boundary, err
		}
	}
	return boundary, tx.Commit(ctx)
}
