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

const columns = `seq,at,subject_id,operation,resource,decision,reason,matched_rules,source_ip,hostname,action,job_id,task_id,policy_version,outputs,checkpoint_seq,checkpoint_hash,hash_input,prev_hash,hash`

func scan(row pgx.Row) (Event, error) {
	var e Event
	var outputs []byte
	e.Version = 1
	err := row.Scan(&e.Seq, &e.At, &e.SubjectID, &e.Operation, &e.Resource, &e.Decision, &e.Reason, &e.MatchedRules, &e.SourceIP, &e.Hostname, &e.Action, &e.JobID, &e.TaskID, &e.PolicyVersion, &outputs, &e.CheckpointSeq, &e.CheckpointHash, &e.HashInput, &e.PrevHash, &e.Hash)
	if err != nil {
		var fieldError pgx.ScanArgError
		if errors.As(err, &fieldError) && e.Seq != 0 {
			return e, errMalformedEvent
		}
		return e, err
	}
	e.At = e.At.UTC()
	decoder := json.NewDecoder(bytes.NewReader(outputs))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&e.Outputs); err != nil {
		return e, errMalformedEvent
	}
	return e, nil
}

func tip(ctx context.Context, tx pgx.Tx) (uint64, []byte, time.Time, error) {
	var seq uint64
	var hash []byte
	var at time.Time
	err := tx.QueryRow(ctx, "SELECT seq,hash,at FROM audit_events ORDER BY seq DESC,at DESC LIMIT 1").Scan(&seq, &hash, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, "SELECT seq,hash FROM audit_boundary WHERE singleton").Scan(&seq, &hash)
	}
	return seq, hash, at, err
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
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", appendLock); err != nil {
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
		err = tx.QueryRow(ctx, "SELECT at FROM audit_events WHERE checkpoint_seq IS NOT NULL ORDER BY seq DESC LIMIT 1").Scan(&last)
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
	_, err = tx.Exec(ctx, `INSERT INTO audit_events (`+columns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, p.Seq, p.At, p.SubjectID, p.Operation, p.Resource, p.Decision, p.Reason, p.MatchedRules, p.SourceIP, p.Hostname, p.Action, p.JobID, p.TaskID, p.PolicyVersion, outputs, p.CheckpointSeq, p.CheckpointHash, input, previous, e.Hash)
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
	rows, err := s.Pool.Query(ctx, "SELECT "+columns+" FROM audit_events WHERE seq>=$1 AND seq<=$2 ORDER BY seq,at", from, to)
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
