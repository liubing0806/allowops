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
	return createPartitions(ctx, s.Pool, first, months)
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
	if err := lockXact(ctx, tx, exportLock); err != nil {
		return Anchor{}, err
	}
	if err := lockXact(ctx, tx, appendLock); err != nil {
		return Anchor{}, err
	}
	var boundary Anchor
	if boundary.Seq, boundary.Hash, err = currentBoundary(ctx, tx); err != nil {
		return boundary, err
	}
	last, err := lastEventBefore(ctx, tx, cutoff)
	if err != nil {
		return boundary, err
	}
	if last != nil {
		boundary = *last
		if o.RequireExternalCheckpoint && (o.ExternalCheckpoint == nil || o.ExternalCheckpoint.Seq != boundary.Seq || !bytes.Equal(o.ExternalCheckpoint.Hash, boundary.Hash)) {
			return boundary, fmt.Errorf("external retention checkpoint required or mismatched")
		}
		retainedHash, err := retainedPrevHash(ctx, tx, boundary.Seq+1, cutoff)
		if err != nil {
			return boundary, ErrUnavailable
		}
		if !bytes.Equal(retainedHash, boundary.Hash) {
			return boundary, ErrUnavailable
		}
		pending, err := exportPending(ctx, tx, boundary.Seq)
		if err != nil {
			return boundary, err
		}
		if pending {
			return boundary, fmt.Errorf("retention would delete unexported audit events")
		}
		if err := updateBoundary(ctx, tx, boundary); err != nil {
			return boundary, err
		}
	}
	names, err := expiredPartitions(ctx, tx, cutoff)
	if err != nil {
		return boundary, err
	}
	for _, name := range names {
		if err := dropPartition(ctx, tx, name); err != nil {
			return boundary, err
		}
	}
	return boundary, tx.Commit(ctx)
}
