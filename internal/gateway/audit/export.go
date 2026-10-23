package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
)

type ExportPage struct {
	JSONLines                          []byte
	FirstSeq, LastSeq, SnapshotLastSeq uint64
	PrecedingHash                      []byte
}

// Bounds maps times to an unfiltered contiguous interval, including the row
// just before the requested time range when it remains available.
func (s *Store) Bounds(ctx context.Context, from, to *time.Time) (uint64, uint64, error) {
	first, last, err := seqBounds(ctx, s.Pool, from, to)
	if err != nil || first == nil {
		return 0, 0, err
	}
	if *first > 1 {
		exists, err := eventExists(ctx, s.Pool, *first-1)
		if err != nil {
			return 0, 0, err
		}
		if exists {
			*first = *first - 1
		}
	}
	return *first, *last, nil
}

func (s *Store) ExportPage(ctx context.Context, next, last uint64, limit int) (ExportPage, error) {
	p := ExportPage{SnapshotLastSeq: last}
	if limit == 0 {
		limit = s.Config.ExportBytes
	}
	if limit < 1 || limit > s.Config.MaxExportBytes {
		return p, ErrLimit
	}
	if next == 0 || next > last {
		return p, ErrInvalid
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return p, err
	}
	defer tx.Rollback(ctx)
	anchor, err := preceding(ctx, tx, next)
	if err != nil {
		return p, err
	}
	if len(anchor) != 32 {
		return p, ErrUnavailable
	}
	p.PrecedingHash = anchor
	rows, err := eventsBetween(ctx, tx, next, last)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	expected := next
	previous := anchor
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return p, err
		}
		if e.Seq != expected || !bytes.Equal(e.PrevHash, previous) {
			return p, ErrUnavailable
		}
		if err := checkEvent(e); err != nil {
			return p, ErrUnavailable
		}
		b, err := Line(e)
		if err != nil {
			return p, err
		}
		if len(b) > limit {
			return p, ErrLimit
		}
		if len(p.JSONLines)+len(b) > limit {
			break
		}
		if p.FirstSeq == 0 {
			p.FirstSeq = e.Seq
		}
		p.LastSeq = e.Seq
		p.JSONLines = append(p.JSONLines, b...)
		expected++
		previous = e.Hash
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return p, err
	}
	if p.LastSeq == 0 {
		return p, ErrUnavailable
	}
	// A missing trailing row cannot masquerade as a completed export.
	if expected <= last && p.LastSeq > 0 {
		exists, err := eventExists(ctx, tx, expected)
		if err != nil {
			return p, err
		}
		if !exists {
			return p, ErrUnavailable
		}
	}
	return p, nil
}

// ExportStorage is the A18 seam. Commit must make complete records durable
// before Exporter advances the DB cursor. Each call may be replayed after crash.
type ExportStorage interface {
	Commit(context.Context, []Event) error
}

type FileStorage struct {
	Directory string
	MaxBytes  int64
}

// Commit writes immutable, complete files. A retry publishes additional copies
// (at least once), never appends after a possibly torn last line.
func (f FileStorage) Commit(ctx context.Context, events []Event) error {
	if f.Directory == "" || f.MaxBytes < 1 {
		return ErrInvalid
	}
	if err := os.MkdirAll(f.Directory, 0700); err != nil {
		return err
	}
	var file *os.File
	var size int64
	var target string
	finish := func() error {
		if file == nil {
			return nil
		}
		name := file.Name()
		defer os.Remove(name)
		if err := file.Sync(); err != nil {
			file.Close()
			file = nil
			return err
		}
		if err := file.Close(); err != nil {
			file = nil
			return err
		}
		file = nil
		if err := os.Rename(name, target); err != nil {
			return err
		}
		dir, err := os.Open(f.Directory)
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	}
	defer func() {
		if file != nil {
			name := file.Name()
			file.Close()
			os.Remove(name)
		}
	}()
	for _, e := range events {
		if err := ctx.Err(); err != nil {
			return err
		}
		b, err := Line(e)
		if err != nil {
			return err
		}
		if int64(len(b)) > f.MaxBytes {
			return ErrLimit
		}
		if file != nil && size+int64(len(b)) > f.MaxBytes {
			if err := finish(); err != nil {
				return err
			}
			size = 0
		}
		if file == nil {
			file, err = os.CreateTemp(f.Directory, ".audit-*")
			if err != nil {
				return err
			}
			target = filepath.Join(f.Directory, fmt.Sprintf("audit-%020d-%s.jsonl", e.Seq, filepath.Base(file.Name())[1:]))
		}
		if _, err := file.Write(b); err != nil {
			return err
		}
		size += int64(len(b))
	}
	return finish()
}

// Exporter owns the designated instance's persistent destination and cursor.
type Exporter struct {
	Store     *Store
	Storage   ExportStorage
	Cursor    string
	BatchSize int
}

func (x *Exporter) Once(ctx context.Context) (count uint64, err error) {
	if x.Cursor == "" || x.Storage == nil {
		return 0, ErrInvalid
	}
	// Use a dedicated physical connection. Acknowledged unlock permits immediate
	// replay; physical close also prevents locks leaking into the pool on failure.
	conn, err := x.Store.Pool.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	var acquired bool
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if acquired {
			if unlockErr := unlock(cleanup, conn, exportLock); err == nil {
				err = unlockErr
			}
		}
		_ = conn.Conn().Close(cleanup)
		conn.Release()
	}()
	acquired, err = tryLock(ctx, conn, exportLock)
	if err != nil {
		return 0, err
	}
	if !acquired {
		return 0, ErrBusy
	}
	next, anchor, err := exportCursor(ctx, conn, x.Cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		seq, hash, err := currentBoundary(ctx, conn)
		if err != nil {
			return 0, err
		}
		anchor = hash
		next = seq + 1
		if err := insertExportCursor(ctx, conn, x.Cursor, next, anchor); err != nil {
			return 0, err
		}
	} else if err != nil {
		return 0, err
	}
	n := x.BatchSize
	if n == 0 {
		n = 200
	}
	if n < 1 || n > x.Store.Config.VerifyRows {
		return 0, ErrLimit
	}
	rows, err := eventsFrom(ctx, conn, next, n)
	if err != nil {
		return 0, err
	}
	var events []Event
	previous := anchor
	expected := next
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			rows.Close()
			return 0, err
		}
		if e.Seq != expected || !bytes.Equal(e.PrevHash, previous) {
			rows.Close()
			return 0, ErrUnavailable
		}
		if err := checkEvent(e); err != nil {
			rows.Close()
			return 0, ErrUnavailable
		}
		events = append(events, e)
		previous = e.Hash
		expected++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, nil
	}
	if err := x.Storage.Commit(ctx, events); err != nil {
		return 0, err
	}
	err = updateExportCursor(ctx, conn, x.Cursor, expected, previous)
	return uint64(len(events)), err
}

func (x *Exporter) Run(ctx context.Context, interval time.Duration) (err error) {
	if interval <= 0 || x.Cursor == "" || x.Storage == nil {
		return ErrInvalid
	}
	// Hold leadership through idle polling. The separate batch lock in Once
	// still permits retention maintenance between batches.
	owner, err := x.Store.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	claimed, warned := false, false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if claimed {
			if unlockErr := unlock(cleanup, owner, exportLeaderLock); err == nil {
				err = unlockErr
			}
		}
		_ = owner.Conn().Close(cleanup)
		owner.Release()
	}()
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		if !claimed {
			var err error
			if claimed, err = tryLock(ctx, owner, exportLeaderLock); err != nil {
				return err
			}
			if !claimed && !warned {
				slog.Warn("another audit exporter holds the instance lock", "cursor", x.Cursor)
				warned = true
			}
		}
		if claimed {
			// Once uses another connection; verify that the session holding
			// leadership is still alive before starting the next batch.
			if err := ping(ctx, owner); err != nil {
				return err
			}
			if _, err := x.Once(ctx); err != nil && !errors.Is(err, ErrBusy) {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}
