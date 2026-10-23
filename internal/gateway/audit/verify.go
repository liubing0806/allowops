package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/jackc/pgx/v5"
)

type VerifyOptions struct {
	From, To                                 uint64
	ExpectedPrecedingHash, ExpectedFinalHash []byte
}

type Verification struct {
	Valid               bool    `json:"valid"`
	CheckedCount        uint64  `json:"checked_count"`
	FirstInvalidSeq     *uint64 `json:"first_invalid_seq,omitempty"`
	Reason              string  `json:"reason,omitempty"`
	ActualPrecedingHash []byte  `json:"actual_preceding_hash"`
	ActualFinalHash     []byte  `json:"actual_final_hash"`
	ExternallyAnchored  bool    `json:"externally_anchored"`
}

func validateOptions(o VerifyOptions, max int) error {
	if o.From == 0 || o.To < o.From || o.To > math.MaxInt64 {
		return ErrInvalid
	}
	if o.To-o.From >= uint64(max) {
		return ErrLimit
	}
	if (len(o.ExpectedPrecedingHash) != 0 && len(o.ExpectedPrecedingHash) != 32) || (len(o.ExpectedFinalHash) != 0 && len(o.ExpectedFinalHash) != 32) {
		return ErrInvalid
	}
	return nil
}

func broken(v Verification, seq uint64, reason string) Verification {
	v.Valid = false
	v.FirstInvalidSeq = &seq
	v.Reason = reason
	v.ExternallyAnchored = false
	return v
}

type chainVerifier struct {
	options  VerifyOptions
	result   Verification
	next     uint64
	previous []byte
}

func newVerifier(o VerifyOptions, preceding []byte) *chainVerifier {
	c := &chainVerifier{options: o, result: Verification{ActualPrecedingHash: preceding, ActualFinalHash: preceding}, next: o.From, previous: preceding}
	if len(preceding) != 32 {
		c.result = broken(c.result, o.From, "preceding anchor unavailable")
	} else if len(o.ExpectedPrecedingHash) > 0 && !bytes.Equal(preceding, o.ExpectedPrecedingHash) {
		c.result = broken(c.result, o.From, "external preceding anchor mismatch")
	}
	return c
}

func (c *chainVerifier) add(e Event) bool {
	if c.result.FirstInvalidSeq != nil {
		return false
	}
	fail := func(seq uint64, reason string) bool { c.result = broken(c.result, seq, reason); return false }
	if e.Seq != c.next {
		if e.Seq < c.next {
			return fail(e.Seq, "duplicate or reordered sequence")
		}
		return fail(c.next, "missing, duplicate or reordered sequence")
	}
	if !bytes.Equal(e.PrevHash, c.previous) {
		return fail(e.Seq, "previous hash mismatch")
	}
	if err := checkEvent(e); err != nil {
		return fail(e.Seq, err.Error())
	}
	c.result.CheckedCount++
	c.previous = e.Hash
	c.result.ActualFinalHash = e.Hash
	c.next++
	return true
}

func (c *chainVerifier) finish() Verification {
	if c.result.FirstInvalidSeq != nil {
		return c.result
	}
	if c.next != c.options.To+1 {
		return broken(c.result, c.next, "missing sequence or retained history unavailable")
	}
	if len(c.options.ExpectedFinalHash) > 0 && !bytes.Equal(c.previous, c.options.ExpectedFinalHash) {
		return broken(c.result, c.options.To, "external final anchor mismatch")
	}
	c.result.Valid = true
	c.result.ExternallyAnchored = len(c.options.ExpectedPrecedingHash) > 0 || len(c.options.ExpectedFinalHash) > 0
	return c.result
}

func preceding(ctx context.Context, tx pgx.Tx, from uint64) ([]byte, error) {
	if from == 1 {
		return make([]byte, 32), nil
	}
	return precedingHash(ctx, tx, from-1)
}

func (s *Store) Verify(ctx context.Context, o VerifyOptions) (Verification, error) {
	if err := validateOptions(o, s.Config.VerifyRows); err != nil {
		return Verification{}, err
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Verification{}, err
	}
	defer tx.Rollback(ctx)
	hash, err := preceding(ctx, tx, o.From)
	if err != nil {
		return Verification{}, err
	}
	rows, err := eventsBetween(ctx, tx, o.From, o.To)
	if err != nil {
		return Verification{}, err
	}
	chain := newVerifier(o, hash)
	if chain.result.FirstInvalidSeq != nil {
		rows.Close()
		return chain.finish(), nil
	}
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			rows.Close()
			if errors.Is(err, errMalformedEvent) {
				seq := e.Seq
				if seq > chain.next {
					return broken(chain.result, chain.next, "missing sequence"), nil
				}
				return broken(chain.result, seq, errMalformedEvent.Error()), nil
			}
			return Verification{}, err
		}
		if !chain.add(e) {
			rows.Close()
			return chain.finish(), nil
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Verification{}, err
	}
	return chain.finish(), nil
}

// VerifyReader preserves file order. It never sorts records to hide reordering.
// An exported first row's prev_hash gives internal consistency only; callers
// supply hashes from a separately trusted system to establish external trust.
func VerifyReader(r io.Reader, o VerifyOptions, c Config) (Verification, error) {
	if c.VerifyRows == 0 {
		c.VerifyRows = DefaultConfig().VerifyRows
	}
	if c.PayloadBytes == 0 {
		c.PayloadBytes = DefaultConfig().PayloadBytes
	}
	if err := validateOptions(o, c.VerifyRows); err != nil {
		return Verification{}, err
	}
	scanner := bufio.NewScanner(r)
	// The displayed payload may expand 6x through HTML escaping, while the
	// authoritative bytes add 4/3 through Base64. Include fixed envelope fields.
	scanner.Buffer(make([]byte, 4096), c.PayloadBytes*8+4096)
	var chain *chainVerifier
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			return Verification{}, fmt.Errorf("empty JSON Lines record")
		}
		var e Event
		dec := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			if e.Seq >= o.From && e.Seq <= o.To {
				v := Verification{}
				if chain != nil {
					v = chain.result
				}
				return broken(v, e.Seq, "malformed JSON Lines record"), nil
			}
			return Verification{}, fmt.Errorf("invalid JSON Lines record")
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			return Verification{}, fmt.Errorf("trailing JSON Lines data")
		}
		if e.Seq < o.From || e.Seq > o.To {
			continue
		}
		if chain == nil {
			anchor := e.PrevHash
			if o.From == 1 {
				anchor = make([]byte, 32)
			}
			chain = newVerifier(o, anchor)
		}
		if !chain.add(e) {
			return chain.finish(), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return Verification{}, err
	}
	if chain == nil {
		chain = newVerifier(o, nil)
	}
	return chain.finish(), nil
}
