package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestCanonicalBytes(t *testing.T) {
	at := time.Date(2026, 10, 13, 20, 0, 0, 123456789, time.FixedZone("test", 8*3600))
	p, err := normalize(Payload{Seq: 1, At: at, SubjectID: "审计<&", Operation: "view_audit", SourceIP: "::ffff:192.0.2.1", MatchedRules: []string{"b", "a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"version":1,"seq":"1","at":"2026-10-13T12:00:00.123456Z","subject_id":"审计<&","operation":"view_audit","resource":"","decision":"","reason":"","matched_rules":["a","b"],"source_ip":"192.0.2.1","hostname":"","action":"","job_id":"","task_id":"","policy_version":"0","outputs":[],"checkpoint_seq":null,"checkpoint_hash":null}`
	if string(got) != want {
		t.Fatalf("canonical bytes:\ngot  %s\nwant %s", got, want)
	}
	expected := sha256.Sum256(append(make([]byte, 32), []byte(want)...))
	if !bytes.Equal(digest(make([]byte, 32), got), expected[:]) {
		t.Fatal("hash concatenation differs from golden payload")
	}
	t.Logf("golden hash=%s", hex.EncodeToString(expected[:]))
}

func TestVerifyFilesDetectsTampering(t *testing.T) {
	var events []Event
	prev := make([]byte, 32)
	for seq := uint64(1); seq <= 3; seq++ {
		p, _ := normalize(Payload{Seq: seq, At: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC), Operation: "test"})
		b, _ := canonical(p)
		e := Event{Payload: p, HashInput: b, PrevHash: prev, Hash: digest(prev, b)}
		events = append(events, e)
		prev = e.Hash
	}
	data := func(es []Event) []byte {
		var out []byte
		for _, e := range es {
			b, _ := Line(e)
			out = append(out, b...)
		}
		return out
	}
	opts := VerifyOptions{From: 1, To: 3, ExpectedFinalHash: prev}
	v, err := VerifyReader(bytes.NewReader(data(events)), opts, Config{})
	if err != nil || !v.Valid || !v.ExternallyAnchored {
		t.Fatalf("valid file=%+v err=%v", v, err)
	}
	for _, tc := range []struct {
		name   string
		change func([]Event) []Event
		seq    uint64
	}{
		{"field", func(es []Event) []Event { es[1].Reason = "changed"; return es }, 2},
		{"delete", func(es []Event) []Event { return []Event{es[0], es[2]} }, 2},
		{"duplicate", func(es []Event) []Event { return []Event{es[0], es[1], es[1], es[2]} }, 2},
		{"reorder", func(es []Event) []Event { return []Event{es[0], es[2], es[1]} }, 2},
		{"bytes", func(es []Event) []Event { es[1].HashInput = append(bytes.Clone(es[1].HashInput), ' '); return es }, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := VerifyReader(bytes.NewReader(data(tc.change(append([]Event(nil), events...)))), opts, Config{})
			if err != nil || v.Valid || v.FirstInvalidSeq == nil || *v.FirstInvalidSeq != tc.seq {
				t.Fatalf("verification=%+v err=%v; want invalid seq %d", v, err, tc.seq)
			}
		})
	}
	// Rewriting every hash stays internally consistent. An external tip catches it.
	rewritten := append([]Event(nil), events...)
	prev = make([]byte, 32)
	for i := range rewritten {
		rewritten[i].Reason = "rewrite"
		rewritten[i].HashInput, _ = canonical(rewritten[i].Payload)
		rewritten[i].PrevHash = prev
		rewritten[i].Hash = digest(prev, rewritten[i].HashInput)
		prev = rewritten[i].Hash
	}
	v, err = VerifyReader(bytes.NewReader(data(rewritten)), VerifyOptions{From: 1, To: 3}, Config{})
	if err != nil || !v.Valid || v.ExternallyAnchored {
		t.Fatalf("internal rewrite=%+v %v", v, err)
	}
	v, err = VerifyReader(bytes.NewReader(data(rewritten)), opts, Config{})
	if err != nil || v.Valid || v.Reason != "external final anchor mismatch" {
		t.Fatalf("external rewrite=%+v %v", v, err)
	}
	if _, err := VerifyReader(strings.NewReader("{} {}\n"), opts, Config{}); err == nil {
		t.Fatal("accepted multiple JSON objects in one line")
	}
}

func TestVerifyExportedHTMLCharacters(t *testing.T) {
	p, err := normalize(Payload{Seq: 1, At: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC), Reason: strings.Repeat("<", 55<<10)})
	if err != nil {
		t.Fatal(err)
	}
	input, err := canonical(p)
	if err != nil || len(input) > DefaultConfig().PayloadBytes {
		t.Fatalf("canonical payload bytes=%d err=%v", len(input), err)
	}
	previous := make([]byte, 32)
	line, err := Line(Event{Payload: p, HashInput: input, PrevHash: previous, Hash: digest(previous, input)})
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyReader(bytes.NewReader(line), VerifyOptions{From: 1, To: 1}, Config{})
	if err != nil || !v.Valid {
		t.Fatalf("exported line bytes=%d verification valid=%t err=%v", len(line), v.Valid, err)
	}
}
