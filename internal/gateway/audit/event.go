// Package audit implements the PostgreSQL audit chain and its byte protocol.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"time"
	"unicode/utf8"
)

var ErrLimit = errors.New("audit size or count limit exceeded")
var ErrUnavailable = errors.New("audit interval unavailable")
var ErrBusy = errors.New("another audit exporter holds the lock")
var ErrInvalid = errors.New("invalid audit request")
var errMalformedEvent = errors.New("malformed audit payload")

const appendLock int64 = 418007
const exportLock int64 = 418008
const exportLeaderLock int64 = 418009

// Payload is the v1 canonical schema. Field declaration order is wire order.
// No parameters, credentials or output contents belong in this schema.
type Payload struct {
	Version        int       `json:"version"`
	Seq            uint64    `json:"seq,string"`
	At             time.Time `json:"at"`
	SubjectID      string    `json:"subject_id"`
	Operation      string    `json:"operation"`
	Resource       string    `json:"resource"`
	Decision       string    `json:"decision"`
	Reason         string    `json:"reason"`
	MatchedRules   []string  `json:"matched_rules"`
	SourceIP       string    `json:"source_ip"`
	Hostname       string    `json:"hostname"`
	Action         string    `json:"action"`
	JobID          string    `json:"job_id"`
	TaskID         string    `json:"task_id"`
	PolicyVersion  uint64    `json:"policy_version,string"`
	Outputs        []Output  `json:"outputs"`
	CheckpointSeq  *uint64   `json:"checkpoint_seq,string"`
	CheckpointHash []byte    `json:"checkpoint_hash"`
}

type Output struct {
	ObjectPath string  `json:"object_path"`
	SHA256     []byte  `json:"sha256"`
	Stream     int32   `json:"stream"`
	StepIndex  *uint32 `json:"step_index"`
}

// Event also serves as the JSON Lines envelope. HashInput is never reconstructed
// when exporting; it is the exact bytea read from PostgreSQL.
type Event struct {
	Payload   `json:"event"`
	PrevHash  []byte `json:"prev_hash"`
	Hash      []byte `json:"hash"`
	HashInput []byte `json:"hash_input"`
}

type Config struct {
	PayloadBytes, VerifyRows, ExportBytes, MaxExportBytes int
	PageSize, MaxPageSize, ResponseBytes                  int
	CursorKey                                             []byte // P5 supplies the same secret to each API instance.
	Now                                                   func() time.Time
}

func DefaultConfig() Config {
	return Config{PayloadBytes: 64 << 10, VerifyRows: 10000, ExportBytes: 256 << 10, MaxExportBytes: 512 << 10, PageSize: 50, MaxPageSize: 200, ResponseBytes: 1 << 20, Now: time.Now}
}

// canonical encodes an already normalized payload, without trailing newline.
func canonical(p Payload) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}

func normalize(p Payload) (Payload, error) {
	if p.Seq == 0 || p.Seq > math.MaxInt64 || p.PolicyVersion > math.MaxInt64 || p.At.IsZero() || p.At.Year() < 1 || p.At.Year() > 9999 {
		return p, ErrInvalid
	}
	p.Version = 1
	p.At = p.At.UTC().Truncate(time.Microsecond)
	strings := []string{p.SubjectID, p.Operation, p.Resource, p.Decision, p.Reason, p.SourceIP, p.Hostname, p.Action, p.JobID, p.TaskID}
	strings = append(strings, p.MatchedRules...)
	for _, o := range p.Outputs {
		strings = append(strings, o.ObjectPath)
		if len(o.SHA256) != sha256.Size || (o.Stream != 1 && o.Stream != 2) {
			return p, ErrInvalid
		}
	}
	for _, s := range strings {
		if !utf8.ValidString(s) {
			return p, ErrInvalid
		}
	}
	if p.SourceIP != "" {
		ip, err := netip.ParseAddr(p.SourceIP)
		if err != nil || ip.Zone() != "" {
			return p, ErrInvalid
		}
		p.SourceIP = ip.Unmap().String()
	}
	p.MatchedRules = slices.Clone(p.MatchedRules)
	if p.MatchedRules == nil {
		p.MatchedRules = []string{}
	}
	slices.Sort(p.MatchedRules)
	p.MatchedRules = slices.Compact(p.MatchedRules)
	p.Outputs = slices.Clone(p.Outputs)
	if p.Outputs == nil {
		p.Outputs = []Output{}
	}
	if p.CheckpointSeq == nil {
		p.CheckpointHash = nil
	} else if len(p.CheckpointHash) != sha256.Size {
		return p, ErrInvalid
	}
	return p, nil
}

func digest(previous, input []byte) []byte {
	h := sha256.New()
	h.Write(previous)
	h.Write(input)
	return h.Sum(nil)
}

func Line(e Event) ([]byte, error) { b, err := json.Marshal(e); return append(b, '\n'), err }

func checkEvent(e Event) error {
	if len(e.PrevHash) != sha256.Size || len(e.Hash) != sha256.Size {
		return fmt.Errorf("invalid hash length")
	}
	if !bytes.Equal(digest(e.PrevHash, e.HashInput), e.Hash) {
		return fmt.Errorf("hash mismatch")
	}
	p, err := normalize(e.Payload)
	if err != nil {
		return fmt.Errorf("invalid payload")
	}
	e.Payload.At = e.Payload.At.UTC()
	original, err := canonical(e.Payload)
	if err != nil {
		return err
	}
	b, err := canonical(p)
	if err != nil {
		return err
	}
	if !bytes.Equal(original, b) {
		return fmt.Errorf("noncanonical display fields")
	}
	if e.Version != 1 || !bytes.Equal(b, e.HashInput) {
		return fmt.Errorf("display fields or canonical bytes mismatch")
	}
	if e.CheckpointSeq != nil && (*e.CheckpointSeq != e.Seq-1 || !bytes.Equal(e.CheckpointHash, e.PrevHash)) {
		return fmt.Errorf("checkpoint mismatch")
	}
	return nil
}
