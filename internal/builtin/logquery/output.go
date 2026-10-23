package logquery

import (
	"context"
	"encoding/json"
	"time"
	"unicode/utf8"
)

type SearchOutput struct {
	Source           string      `json:"source"`
	Since            string      `json:"since"`
	Until            string      `json:"until"`
	Order            string      `json:"order"`
	Records          []Record    `json:"records"`
	Matched          int         `json:"matched"`
	HasMore          bool        `json:"has_more"`
	NextCursor       string      `json:"next_cursor,omitempty"`
	Files            *FileCounts `json:"files,omitempty"`
	ScannedBytes     int64       `json:"scanned_bytes"`
	ScanLimitReached bool        `json:"scan_limit_reached"`
	// ScannedSince (desc) or ScannedUntil (asc) bounds the part of the range
	// actually scanned; it equals since or until unless a limit was reached.
	ScannedSince string `json:"scanned_since,omitempty"`
	ScannedUntil string `json:"scanned_until,omitempty"`
}

// Record is one log record. Line is omitted when reading started at a bisected
// offset, where the line number is unknown; Offset is the record's byte offset
// in the (decompressed) file. Records of a container output stream have no
// file; Stream is stdout or stderr for container and Pod output.
type Record struct {
	Time            string `json:"time"`
	File            string `json:"file,omitempty"`
	Line            int    `json:"line,omitempty"`
	Offset          *int64 `json:"offset,omitempty"`
	Stream          string `json:"stream,omitempty"`
	Text            string `json:"text"`
	RecordTruncated bool   `json:"record_truncated"`
}

type FileCounts struct {
	Searched          int `json:"searched"`
	SkippedOutOfRange int `json:"skipped_out_of_range"`
	SkippedNotRegular int `json:"skipped_not_regular"`
	SkippedUnparsed   int `json:"skipped_unparsed"`
}

type SourcesOutput struct {
	Sources []SourceSummary `json:"sources"`
}

type SourceSummary struct {
	Name              string `json:"name"`
	Type              string `json:"type"`
	Files             int    `json:"files"`
	Bytes             int64  `json:"bytes"`
	Earliest          string `json:"earliest,omitempty"`
	Latest            string `json:"latest,omitempty"`
	TimestampParsed   bool   `json:"timestamp_parsed"`
	Status            string `json:"status"`
	SkippedNotRegular int    `json:"skipped_not_regular,omitempty"`
}

// encodeSearch returns at most limit records. With a positive maxOutput it
// returns the longest prefix of the page whose JSON fits; the next cursor then
// points at the first record left out. A single record that does not fit
// alone is shortened instead, so every page makes progress.
func encodeSearch(out SearchOutput, hits []hit, limit int, location *time.Location, redact func(string) string, maxOutput int64, next func(hit) string) ([]byte, error) {
	records := make([]Record, min(limit, len(hits)))
	for i := range records {
		h := hits[i]
		records[i] = Record{Time: formatTime(h.record.time, location), Line: h.record.line, Stream: h.record.stream, Text: redact(h.record.text), RecordTruncated: h.record.truncated}
		if h.file != nil {
			offset := h.record.offset
			records[i].File, records[i].Offset = h.file.name, &offset
		}
	}
	encode := func(n int) ([]byte, error) {
		page := out
		page.Records = records[:n]
		page.HasMore = n < len(hits)
		if page.HasMore {
			page.NextCursor = next(hits[n])
		}
		data, err := json.Marshal(page)
		return append(data, '\n'), err
	}
	data, err := encode(len(records))
	if err != nil || maxOutput <= 0 || int64(len(data)) <= maxOutput {
		return data, err
	}
	// Largest n whose encoding fits; encode(0) is assumed to fit.
	lo, hi := 0, len(records)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if data, err = encode(mid); err != nil {
			return nil, err
		}
		if int64(len(data)) <= maxOutput {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	if lo > 0 || len(records) == 0 {
		return encode(lo)
	}
	// Shorten the first record until the page fits.
	text := records[0].Text
	records[0].Text = ""
	records[0].RecordTruncated = true
	empty, err := encode(1)
	if err != nil {
		return nil, err
	}
	// JSON escaping expands one byte to at most six.
	keep := int(maxOutput-int64(len(empty))) / 6
	for keep > 0 {
		records[0].Text = cut(text, keep)
		if data, err = encode(1); err != nil || int64(len(data)) <= maxOutput {
			return data, err
		}
		keep /= 2
	}
	records[0].Text = ""
	return encode(1)
}

// cut shortens text to at most n bytes without splitting a UTF-8 sequence.
func cut(text string, n int) string {
	if len(text) <= n {
		return text
	}
	for n > 0 && !utf8.RuneStart(text[n]) {
		n--
	}
	return text[:n]
}

func runSources(ctx context.Context, cfg Config, roots []string) ([]byte, error) {
	out := SourcesOutput{Sources: []SourceSummary{}}
	for _, name := range cfg.SourceNames() {
		source := cfg.Sources[name]
		parser, err := newTimeParser(source.Timestamp)
		if err != nil {
			return nil, err
		}
		resolved, err := resolveFiles(ctx, source, roots)
		if err != nil {
			return nil, err
		}
		summary := SourceSummary{Name: name, Type: source.Type, Files: len(resolved.files), SkippedNotRegular: resolved.skippedNotRegular, Status: "no_files"}
		var earliest, latest time.Time
		for _, f := range resolved.files {
			if err := f.readHeader(parser); err != nil {
				return nil, err
			}
			summary.Bytes += f.size
			if f.parsed && (earliest.IsZero() || f.start.Before(earliest)) {
				earliest = f.start
			}
			if f.mtime.After(latest) {
				latest = f.mtime
			}
		}
		if len(resolved.files) > 0 {
			summary.Status, summary.Latest = "timestamp_unparsed", formatTime(latest, parser.location)
		}
		if !earliest.IsZero() {
			summary.Status, summary.TimestampParsed, summary.Earliest = "ok", true, formatTime(earliest, parser.location)
		}
		out.Sources = append(out.Sources, summary)
	}
	data, err := json.Marshal(out)
	return append(data, '\n'), err
}
