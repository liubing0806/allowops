package logquery

import (
	"context"
	"fmt"
	"strings"
)

// runExport writes the matching records oldest first, one per line:
// "<time> <text>", with backslash, newline and carriage return in the text
// escaped as \\, \n and \r. The last line is a trailer starting with "# ":
// matched, scanned_bytes, scan_limit_reached and, when records are left,
// next_cursor. A positive maxOutput ends the page at the first record that
// does not fit; a first record that does not fit alone is shortened.
func runExport(ctx context.Context, cfg Config, roots []string, p Params, redact func(string) string, maxOutput int64) ([]byte, bool, error) {
	p.Order = "asc"
	q, err := prepare(ctx, cfg, roots, p, MaxExportRecords, MaxExportRecords)
	if err != nil {
		return nil, false, err
	}
	defer q.close()
	s, location := q.s, q.s.parser.location
	// Room for the trailer: its counters and a cursor, whose length differs
	// between records only in a few digits.
	trailerRoom := 0
	var body strings.Builder
	var next *hit
	records := 0
	err = s.forward(ctx, q.segments, q.position, q.cursor, func(h hit) {
		s.matchRecord(h.record, func() {
			if next != nil {
				return
			}
			if records == q.p.Limit {
				next = &h
				return
			}
			if trailerRoom == 0 {
				trailerRoom = len(q.next(h)) + 160
			}
			text := formatTime(h.record.time, location) + " " + escapeRecord(redact(h.record.text)) + "\n"
			if maxOutput > 0 && int64(body.Len()+len(text)+trailerRoom) > maxOutput {
				if records > 0 {
					next = &h
					return
				}
				text = cut(text, max(int(maxOutput)-trailerRoom-1, 0)) + "\n"
			}
			body.WriteString(text)
			records++
		})
	})
	if err != nil {
		return nil, false, err
	}
	fmt.Fprintf(&body, "# matched=%d scanned_bytes=%d scan_limit_reached=%t", s.matched, s.scanned, s.limited)
	if next != nil {
		fmt.Fprintf(&body, " next_cursor=%s", q.next(*next))
	}
	body.WriteString("\n")
	return []byte(body.String()), s.limited, nil
}

var recordEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, "\r", `\r`)

func escapeRecord(text string) string { return recordEscaper.Replace(text) }
