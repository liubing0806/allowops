package logquery

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
)

// now is the execution time used for relative ranges; tests replace it.
var now = time.Now

type Params struct {
	Source     string `json:"source"`
	Since      string `json:"since,omitempty"`
	Until      string `json:"until,omitempty"`
	Pattern    string `json:"pattern,omitempty"`
	Fixed      bool   `json:"fixed,omitempty"`
	Exclude    string `json:"exclude,omitempty"`
	IgnoreCase bool   `json:"ignore_case,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Order      string `json:"order,omitempty"`
	Cursor     string `json:"cursor,omitempty"`
}

// Run executes one log_query request. redact transforms each record's text
// after matching and before encoding; nil keeps the original text. A positive
// maxOutput is the action's max_output: the builtin drops records from the
// page, or shortens a single record, so the JSON never needs truncation.
func Run(ctx context.Context, cfg Config, p Params, redact func(string) string, maxOutput int64) (builtin.Result, error) {
	r := builtin.Result{ExitCode: builtin.ExitFailure}
	if err := cfg.Validate(); err != nil {
		return r, err
	}
	cfg = cfg.withDefaults()
	roots, err := cfg.resolvedRoots()
	if err != nil {
		return r, err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if redact == nil {
		redact = func(s string) string { return s }
	}
	var output []byte
	switch cfg.Mode {
	case ModeSources:
		output, err = runSources(ctx, cfg, roots)
	case ModeSearch:
		output, r.Truncated, err = runSearch(ctx, cfg, roots, p, redact, maxOutput)
	}
	if err != nil {
		return r, err
	}
	r.Stdout = string(output)
	r.ExitCode = builtin.ExitSuccess
	return r, nil
}

// timeline resolves a source's files, reads their first timestamps and keeps
// the files that overlap [since, until], ordered by start time then name.
type timeline struct {
	files  []*logFile
	counts FileCounts
}

func buildTimeline(ctx context.Context, source Source, roots []string, parser *timeParser, since, until time.Time) (timeline, error) {
	var t timeline
	resolved, err := resolveFiles(ctx, source, roots)
	if err != nil {
		return t, err
	}
	t.counts.SkippedNotRegular = resolved.skippedNotRegular
	if len(resolved.files) == 0 {
		return t, codeError(CodeSourceNoFiles, "no regular file matches %s; call log_sources to list sources", strings.Join(source.Paths, ", "))
	}
	for _, f := range resolved.files {
		if err := f.readHeader(parser); err != nil {
			return t, err
		}
		switch {
		case f.mtime.Before(since) || (f.parsed && f.start.After(until)):
			t.counts.SkippedOutOfRange++
		case !f.parsed:
			t.counts.SkippedUnparsed++
		default:
			t.files = append(t.files, f)
		}
	}
	if len(t.files) == 0 && t.counts.SkippedUnparsed > 0 {
		return t, codeError(CodeTimestampUnparsed, "no file in range has a timestamp matching layouts %q; omit the time range or check timestamp.layouts", source.Timestamp.Layouts)
	}
	slices.SortStableFunc(t.files, func(a, b *logFile) int {
		if c := a.start.Compare(b.start); c != 0 {
			return c
		}
		return strings.Compare(a.name, b.name)
	})
	return t, nil
}

type hit struct {
	file   *logFile
	record record
}

type searcher struct {
	cfg          Config
	source       Source
	parser       *timeParser
	since, until time.Time
	match        func(string) bool
	scanned      int64
	matched      int
	searched     int
	limited      bool
	first, last  time.Time // earliest and latest in-range records scanned
}

func compilePatterns(p Params) (func(string) bool, error) {
	compile := func(name, text string) (func(string) bool, error) {
		if text == "" {
			return nil, nil
		}
		if len(text) > MaxPatternLength {
			return nil, codeError(CodePatternInvalid, "%s exceeds %d characters", name, MaxPatternLength)
		}
		expr := text
		if p.Fixed {
			expr = regexp.QuoteMeta(text)
		}
		if p.IgnoreCase {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, codeError(CodePatternInvalid, "%s: %v", name, err)
		}
		return re.MatchString, nil
	}
	include, err := compile("pattern", p.Pattern)
	if err != nil {
		return nil, err
	}
	exclude, err := compile("exclude", p.Exclude)
	if err != nil {
		return nil, err
	}
	return func(text string) bool {
		return (include == nil || include(text)) && (exclude == nil || !exclude(text))
	}, nil
}

func runSearch(ctx context.Context, cfg Config, roots []string, p Params, redact func(string) string, maxOutput int64) ([]byte, bool, error) {
	source, ok := cfg.Sources[p.Source]
	if !ok {
		return nil, false, codeError(CodeSourceUnknown, "source %q is not configured; available: %s", p.Source, strings.Join(cfg.SourceNames(), ", "))
	}
	if p.Limit == 0 {
		p.Limit = min(DefaultLimit, cfg.MaxPageRecords)
	}
	if p.Order == "" {
		p.Order = "desc"
	}
	if p.Limit < 1 || p.Limit > cfg.MaxPageRecords || (p.Order != "desc" && p.Order != "asc") {
		return nil, false, fmt.Errorf("limit allowed 1..%d, order allowed desc, asc", cfg.MaxPageRecords)
	}
	match, err := compilePatterns(p)
	if err != nil {
		return nil, false, err
	}
	parser, err := newTimeParser(source.Timestamp)
	if err != nil {
		return nil, false, err
	}
	var c *cursor
	var since, until, cursorTime time.Time
	if p.Cursor != "" {
		decoded, err := decodeCursor(p.Cursor)
		if err != nil {
			return nil, false, codeError(CodeCursorInvalid, "%v", err)
		}
		if decoded.Source != p.Source || decoded.Hash != paramsHash(p) {
			return nil, false, codeError(CodeCursorInvalid, "cursor belongs to a request with other parameters; repeat the previous parameters with the cursor")
		}
		if cursorTime, since, until, err = decoded.times(); err != nil {
			return nil, false, codeError(CodeCursorInvalid, "cursor times: %v", err)
		}
		if err := checkWindow(since, until, cfg.MaxWindow); err != nil || cursorTime.Before(since) || cursorTime.After(until) {
			return nil, false, codeError(CodeCursorInvalid, "cursor range is invalid")
		}
		c = &decoded
	} else if since, until, err = parseTimeRange(p.Since, p.Until, now(), cfg.MaxWindow); err != nil {
		return nil, false, err
	}
	tl, err := buildTimeline(ctx, source, roots, parser, since, until)
	if err != nil {
		return nil, false, err
	}
	s := &searcher{cfg: cfg, source: source, parser: parser, since: since, until: until, match: match}
	position := -1
	if c != nil {
		if position, err = s.checkCursor(tl, *c, cursorTime); err != nil {
			return nil, false, err
		}
	}
	var hits []hit
	if p.Order == "asc" {
		hits, err = s.ascending(ctx, tl.files, p.Limit+1, position, c)
	} else {
		hits, err = s.descending(ctx, tl.files, p.Limit+1, position, c)
	}
	if err != nil {
		return nil, false, err
	}
	tl.counts.Searched = s.searched
	out := SearchOutput{Source: p.Source, Since: formatTime(since, parser.location), Until: formatTime(until, parser.location), Order: p.Order,
		Matched: s.matched, Files: tl.counts, ScannedBytes: s.scanned, ScanLimitReached: s.limited}
	if p.Order == "asc" {
		out.ScannedUntil = out.Until
		if s.limited {
			out.ScannedUntil = formatTime(maxTime(s.last, since), parser.location)
		}
	} else {
		out.ScannedSince = out.Since
		if s.limited {
			out.ScannedSince = out.Until
			if !s.first.IsZero() {
				out.ScannedSince = formatTime(s.first, parser.location)
			}
		}
	}
	next := func(h hit) string {
		return cursor{V: 1, Source: p.Source, Dev: h.file.dev, Inode: h.file.ino, Offset: h.record.offset, Time: h.record.time.UTC().Format(time.RFC3339Nano),
			Since: since.UTC().Format(time.RFC3339Nano), Until: until.UTC().Format(time.RFC3339Nano), Hash: paramsHash(p)}.encode()
	}
	output, err := encodeSearch(out, hits, p.Limit, parser.location, redact, maxOutput, next)
	return output, s.limited, err
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// checkCursor finds the cursor's file by device and inode, so a renamed file
// is still found after rotation, and checks the record at the offset.
func (s *searcher) checkCursor(tl timeline, c cursor, at time.Time) (int, error) {
	expired := func(why string) error {
		return codeError(CodeCursorExpired, "%s; query again with since or until set to %s", why, formatTime(at, s.parser.location))
	}
	position := slices.IndexFunc(tl.files, func(f *logFile) bool { return f.dev == c.Dev && f.ino == c.Inode })
	if position < 0 {
		return 0, expired("the cursor's file is no longer part of the source")
	}
	f := tl.files[position]
	if c.Offset < 0 || (!f.gz && c.Offset >= f.size) {
		return 0, codeError(CodeCursorInvalid, "cursor offset is outside the file")
	}
	file, err := f.open()
	if err != nil {
		return 0, err
	}
	defer file.Close()
	reader, err := s.reader(file, f, c.Offset-min(c.Offset, 1))
	if err != nil {
		return 0, err
	}
	defer reader.Close()
	lines := newLineReader(reader, c.Offset-min(c.Offset, 1), 0, s.cfg.MaxRecordBytes, &s.scanned)
	if c.Offset > 0 {
		previous, err := lines.reader.ReadByte()
		if err != nil {
			return 0, codeError(CodeCursorInvalid, "cursor offset is outside the file")
		}
		*lines.scanned++
		lines.offset++
		if previous != '\n' {
			// The content at the offset changed (for example copytruncate).
			return 0, expired("the cursor offset is no longer at a line start")
		}
	}
	line, err := lines.next()
	if err != nil {
		return 0, codeError(CodeCursorInvalid, "cursor offset is outside the file")
	}
	if t, ok := s.parser.parse(line.text); !ok || !t.Equal(at) {
		return 0, expired("the record at the cursor changed")
	}
	return position, nil
}

// reader returns the file content from offset: a section of a plain file, or
// the decompressed stream with offset bytes skipped and counted as scanned.
func (s *searcher) reader(file *os.File, f *logFile, offset int64) (io.ReadCloser, error) {
	if !f.gz {
		return io.NopCloser(io.NewSectionReader(file, offset, f.size-offset)), nil
	}
	z, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	skipped, err := io.CopyN(io.Discard, z, offset)
	s.scanned += skipped
	if err != nil && err != io.EOF {
		z.Close()
		return nil, err
	}
	return z, nil
}

// scanFile reads records from start. Records outside [since, until], after
// end (when end >= 0), or without a timestamp are not passed to emit. It
// returns exceeded when the scan budget ran out inside the file.
func (s *searcher) scanFile(ctx context.Context, file *os.File, f *logFile, start, end int64, align bool, emit func(record)) (bool, error) {
	reader, err := s.reader(file, f, start)
	if err != nil {
		return false, err
	}
	defer reader.Close()
	number := 0
	if start == 0 {
		number = 1
	}
	lines := newLineReader(contextReader{ctx, reader}, start, number, s.cfg.MaxRecordBytes, &s.scanned)
	if align && start > 0 {
		if err := lines.skipLine(); err != nil && err != io.EOF {
			return false, err
		}
	}
	records := newRecordReader(lines, s.parser, s.source.Multiline, s.cfg.MaxRecordBytes)
	for {
		r, err := records.next()
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		// Bytes read ahead for the next record do not count against this one.
		exceeded := s.scanned-(lines.offset-r.end) > s.cfg.MaxScan
		if !r.timed || r.time.Before(s.since) {
			if exceeded {
				return true, nil
			}
			continue
		}
		if r.time.After(s.until) || (end >= 0 && r.offset > end) {
			return false, nil
		}
		if exceeded {
			return true, nil
		}
		if s.first.IsZero() || r.time.Before(s.first) {
			s.first = r.time
		}
		if r.time.After(s.last) {
			s.last = r.time
		}
		emit(r)
	}
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// ascending scans oldest first and keeps the first want hits.
func (s *searcher) ascending(ctx context.Context, files []*logFile, want, position int, c *cursor) ([]hit, error) {
	var hits []hit
	if position < 0 {
		position = 0
	}
	for i := position; i < len(files); i++ {
		if s.searched == s.cfg.MaxFiles || s.scanned >= s.cfg.MaxScan {
			s.limited = true
			break
		}
		f := files[i]
		file, err := f.open()
		if err != nil {
			return nil, err
		}
		s.searched++
		start := int64(0)
		if c != nil && i == position {
			start = c.Offset
		} else if !f.gz {
			if start, _, err = seekSince(file, f.size, s.parser, s.since); err != nil {
				file.Close()
				return nil, err
			}
		}
		exceeded, err := s.scanFile(ctx, file, f, start, -1, false, func(r record) {
			s.matchRecord(r, func() {
				if len(hits) < want {
					hits = append(hits, hit{f, r})
				}
			})
		})
		file.Close()
		if err != nil {
			return nil, err
		}
		if exceeded {
			s.limited = true
			break
		}
	}
	return hits, nil
}

func (s *searcher) matchRecord(r record, keep func()) {
	if s.match(r.text) {
		s.matched++
		keep()
	}
}

// descending scans files newest first. Each file is read forward from its
// start position, keeping the newest hits of that file in a ring buffer. The
// scanned part is always a suffix of the range: when the budget runs out
// inside a file, that file's hits are discarded.
func (s *searcher) descending(ctx context.Context, files []*logFile, want, position int, c *cursor) ([]hit, error) {
	var hits []hit
	if position < 0 {
		position = len(files) - 1
	}
	for i := position; i >= 0; i-- {
		remaining := s.cfg.MaxScan - s.scanned
		if s.searched == s.cfg.MaxFiles || remaining <= 0 {
			s.limited = true
			break
		}
		f := files[i]
		file, err := f.open()
		if err != nil {
			return nil, err
		}
		end := int64(-1)
		if c != nil && i == position {
			end = c.Offset
		}
		start, partial := int64(0), false
		if f.gz {
			if gzipSize(file, f.size) > remaining {
				file.Close()
				s.limited = true
				break
			}
		} else {
			if start, _, err = seekSince(file, f.size, s.parser, s.since); err != nil {
				file.Close()
				return nil, err
			}
			stop := f.size
			if end >= 0 {
				stop = min(f.size, end+int64(s.cfg.MaxRecordBytes)+1)
			} else if f.size-start > remaining {
				stop, _ = seekAfter(file, f.size, s.parser, s.until)
			}
			if stop-start > remaining {
				start, partial = stop-remaining, true
			}
		}
		s.searched++
		ring := newRing(max(want-len(hits), 0))
		matchedBefore, firstBefore := s.matched, s.first
		exceeded, err := s.scanFile(ctx, file, f, start, end, partial, func(r record) {
			s.matchRecord(r, func() { ring.push(hit{f, r}) })
		})
		file.Close()
		if err != nil {
			return nil, err
		}
		if exceeded {
			s.matched, s.first = matchedBefore, firstBefore
			s.limited = true
			break
		}
		hits = append(hits, ring.newestFirst()...)
		if partial {
			s.limited = true
			break
		}
	}
	return hits, nil
}

// ring keeps the last n hits pushed.
type ring struct {
	items []hit
	next  int
	full  bool
}

func newRing(n int) *ring { return &ring{items: make([]hit, n)} }

func (r *ring) push(h hit) {
	if len(r.items) == 0 {
		return
	}
	r.items[r.next] = h
	r.next = (r.next + 1) % len(r.items)
	r.full = r.full || r.next == 0
}

func (r *ring) newestFirst() []hit {
	count := r.next
	if r.full {
		count = len(r.items)
	}
	result := make([]hit, 0, count)
	for i := 1; i <= count; i++ {
		result = append(result, r.items[(r.next-i+len(r.items))%len(r.items)])
	}
	return result
}
