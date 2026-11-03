package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Appender is the gateway integration seam for all audited operations.
type Appender interface {
	Append(context.Context, Payload) (Event, error)
}

type Store struct {
	Pool   *pgxpool.Pool
	Config Config
}

func New(pool *pgxpool.Pool, c Config) *Store {
	d := DefaultConfig()
	if c.PayloadBytes == 0 {
		c.PayloadBytes = d.PayloadBytes
	}
	if c.VerifyRows == 0 {
		c.VerifyRows = d.VerifyRows
	}
	if c.ExportBytes == 0 {
		c.ExportBytes = d.ExportBytes
	}
	if c.MaxExportBytes == 0 {
		c.MaxExportBytes = d.MaxExportBytes
	}
	if c.PageSize == 0 {
		c.PageSize = d.PageSize
	}
	if c.MaxPageSize == 0 {
		c.MaxPageSize = d.MaxPageSize
	}
	if c.ResponseBytes == 0 {
		c.ResponseBytes = d.ResponseBytes
	}
	if c.Now == nil {
		c.Now = d.Now
	}
	if len(c.CursorKey) == 0 {
		c.CursorKey = make([]byte, 32)
		if _, err := rand.Read(c.CursorKey); err != nil {
			panic(err)
		}
	}
	c.CursorKey = bytes.Clone(c.CursorKey)
	return &Store{Pool: pool, Config: c}
}

func (s *Store) Append(ctx context.Context, p Payload) (Event, error) { return s.append(ctx, p, false) }

// Checkpoint serializes both the due check and append with ordinary writers.
// Multiple timer owners cannot append duplicate checkpoints for the same period.
func (s *Store) Checkpoint(ctx context.Context) (Event, error) {
	return s.append(ctx, Payload{SubjectID: "allowops", Operation: "audit_checkpoint", Decision: "success"}, true)
}

func (s *Store) append(ctx context.Context, p Payload, checkpoint bool) (Event, error) {
	// READ COMMITTED refreshes the tip query's snapshot after the lock wait.
	// REPEATABLE READ can otherwise reuse a snapshot taken before that wait.
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Event{}, err
	}
	defer tx.Rollback(ctx)
	if err = lockXact(ctx, tx, appendLock); err != nil {
		return Event{}, err
	}
	seq, previous, at, err := tip(ctx, tx)
	if err != nil {
		return Event{}, err
	}
	now := s.Config.Now().UTC().Truncate(time.Microsecond)
	if now.Before(at) {
		now = at
	}
	if checkpoint {
		var last time.Time
		last, err = lastCheckpointAt(ctx, tx)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return Event{}, err
		}
		if err == nil && now.Sub(last) < 5*time.Minute {
			return Event{}, nil
		}
		p.CheckpointSeq = &seq
		p.CheckpointHash = previous
	} else if p.CheckpointSeq != nil || len(p.CheckpointHash) != 0 || p.Operation == "audit_checkpoint" {
		return Event{}, ErrInvalid
	}
	if seq >= math.MaxInt64 {
		return Event{}, ErrLimit
	}
	p.Seq = seq + 1
	p.At = now
	p, err = normalize(p)
	if err != nil {
		return Event{}, err
	}
	input, err := canonical(p)
	if err != nil {
		return Event{}, err
	}
	if len(input) > s.Config.PayloadBytes {
		return Event{}, ErrLimit
	}
	e := Event{Payload: p, PrevHash: previous, Hash: digest(previous, input), HashInput: input}
	outputs, err := json.Marshal(p.Outputs)
	if err != nil {
		return Event{}, err
	}
	err = insertEvent(ctx, tx, p, outputs, input, previous, e.Hash)
	if err != nil {
		return Event{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Event{}, err
	}
	return e, nil
}

func (s *Store) RunCheckpoints(ctx context.Context) error {
	if _, err := s.Checkpoint(ctx); err != nil {
		return err
	}
	timer := time.NewTicker(5 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if _, err := s.Checkpoint(ctx); err != nil {
				return err
			}
		}
	}
}

func (s *Store) Events(ctx context.Context, from, to uint64) ([]Event, error) {
	if from == 0 || to < from || to > math.MaxInt64 {
		return nil, ErrInvalid
	}
	if to-from >= uint64(s.Config.VerifyRows) {
		return nil, ErrLimit
	}
	rows, err := eventsBetween(ctx, s.Pool, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
		if len(events) > s.Config.VerifyRows {
			return nil, ErrLimit
		}
	}
	return events, rows.Err()
}
