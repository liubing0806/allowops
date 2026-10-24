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
	// Level applies to search, stats and patterns; Bucket to stats; Top to
	// patterns.
	Level  []string `json:"level,omitempty"`
	Bucket string   `json:"bucket,omitempty"`
	Top    int      `json:"top,omitempty"`
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
	case ModeStats:
		output, r.Truncated, err = runStats(ctx, cfg, roots, p)
	case ModePatterns:
		output, r.Truncated, err = runPatterns(ctx, cfg, roots, p, redact, maxOutput)
	case ModeExport:
		output, r.Truncated, err = runExport(ctx, cfg, roots, p, redact, maxOutput)
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
	file   *logFile // nil for records of a container output stream
	record record
}

type searcher struct {
	cfg    Config
	source Source
	parser *timeParser
	// content finds record starts in the text of stamped lines; nil for
	// file sources, whose parser does that.
	content      *timeParser
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

// query is a validated request: the resolved range, the source's segments
// and the cursor position within them.
type query struct {
	p            Params
	s            *searcher
	segments     []segment
	counts       *FileCounts
	position     int
	cursor       *cursor
	since, until time.Time
	docker       *dockerClient
	level        *levelRule // nil when the source declares no level rule
}

func (q *query) close() {
	if q.docker != nil {
		q.docker.close()
	}
}

// prepare validates the request parameters and resolves the source's
// segments. maxLimit bounds p.Limit; defaultLimit replaces an omitted one.
func prepare(ctx context.Context, cfg Config, roots []string, p Params, defaultLimit, maxLimit int) (*query, error) {
	source, ok := cfg.Sources[p.Source]
	if !ok {
		return nil, codeError(CodeSourceUnknown, "source %q is not configured; available: %s", p.Source, strings.Join(cfg.SourceNames(), ", "))
	}
	if p.Limit == 0 {
		p.Limit = defaultLimit
	}
	if p.Order == "" {
		p.Order = "desc"
	}
	if p.Limit < 1 || p.Limit > maxLimit || (p.Order != "desc" && p.Order != "asc") {
		return nil, fmt.Errorf("limit allowed 1..%d, order allowed desc, asc", maxLimit)
	}
	match, err := compilePatterns(p)
	if err != nil {
		return nil, err
	}
	match, rule, err := withLevels(source, p.Level, match)
	if err != nil {
		return nil, err
	}
	parser, content, err := sourceParsers(source)
	if err != nil {
		return nil, err
	}
	q := &query{p: p, position: -1, level: rule}
	var cursorTime time.Time
	if p.Cursor != "" {
		decoded, err := decodeCursor(p.Cursor)
		if err != nil {
			return nil, codeError(CodeCursorInvalid, "%v", err)
		}
		if decoded.Source != p.Source || decoded.Hash != paramsHash(p) {
			return nil, codeError(CodeCursorInvalid, "cursor belongs to a request with other parameters; repeat the previous parameters with the cursor")
		}
		if cursorTime, q.since, q.until, err = decoded.times(); err != nil {
			return nil, codeError(CodeCursorInvalid, "cursor times: %v", err)
		}
		if err := checkWindow(q.since, q.until, cfg.MaxWindow); err != nil || cursorTime.Before(q.since) || cursorTime.After(q.until) {
			return nil, codeError(CodeCursorInvalid, "cursor range is invalid")
		}
		q.cursor = &decoded
	} else if q.since, q.until, err = parseTimeRange(p.Since, p.Until, now(), cfg.MaxWindow); err != nil {
		return nil, err
	}
	q.s = &searcher{cfg: cfg, source: source, parser: parser, content: content, since: q.since, until: q.until, match: match}
	if source.Type == TypeContainerStdout {
		q.docker = newDockerClient()
		if q.segments, err = stdoutSegments(ctx, q.docker, source, q.since, q.until, p.Order, q.cursor); err != nil {
			q.close()
			return nil, err
		}
		return q, nil
	}
	tl, err := buildTimeline(ctx, source, roots, parser, q.since, q.until)
	if err != nil {
		return nil, err
	}
	q.counts = &tl.counts
	for _, f := range tl.files {
		q.segments = append(q.segments, f)
	}
	if q.cursor != nil {
		if q.position, err = q.s.checkCursor(tl, *q.cursor, cursorTime); err != nil {
			return nil, err
		}
	}
	return q, nil
}

// next returns the cursor that resumes at h.
func (q *query) next(h hit) string {
	c := cursor{V: 1, Source: q.p.Source, Time: h.record.time.UTC().Format(time.RFC3339Nano),
		Since: q.since.UTC().Format(time.RFC3339Nano), Until: q.until.UTC().Format(time.RFC3339Nano), Hash: paramsHash(q.p)}
	if h.file != nil {
		c.Dev, c.Inode, c.Offset = h.file.dev, h.file.ino, h.record.offset
	} else {
		c.Seq = h.record.seq
	}
	return c.encode()
}

func runSearch(ctx context.Context, cfg Config, roots []string, p Params, redact func(string) string, maxOutput int64) ([]byte, bool, error) {
	q, err := prepare(ctx, cfg, roots, p, min(DefaultLimit, cfg.MaxPageRecords), cfg.MaxPageRecords)
	if err != nil {
		return nil, false, err
	}
	defer q.close()
	p, s := q.p, q.s
	var hits []hit
	if p.Order == "asc" {
		hits, err = s.ascending(ctx, q.segments, p.Limit+1, q.position, q.cursor)
	} else {
		hits, err = s.descending(ctx, q.segments, p.Limit+1, q.position, q.cursor)
	}
	if err != nil {
		return nil, false, err
	}
	if q.counts != nil {
		q.counts.Searched = s.searched
	}
	location := s.parser.location
	out := SearchOutput{Source: p.Source, Since: formatTime(q.since, location), Until: formatTime(q.until, location), Order: p.Order,
		Matched: s.matched, Files: q.counts, ScannedBytes: s.scanned, ScanLimitReached: s.limited}
	if p.Order == "asc" {
		out.ScannedUntil = out.Until
		if s.limited {
			out.ScannedUntil = formatTime(maxTime(s.last, q.since), location)
		}
	} else {
		out.ScannedSince = out.Since
		if s.limited {
			out.ScannedSince = out.Until
			if !s.first.IsZero() {
				out.ScannedSince = formatTime(s.first, location)
			}
		}
	}
	output, err := encodeSearch(out, hits, p.Limit, location, redact, maxOutput, q.next)
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
	records := s.records(s.fileLines(lines), start > 0)
	return s.scanRecords(records, func(r *record) verdict {
		switch {
		case !r.timed || r.time.Before(s.since):
			return skipRecord
		case r.time.After(s.until) || (end >= 0 && r.offset > end):
			return stopScan
		}
		return keepRecord
	}, emit)
}

// fileLines returns the line source for a file of the searched source:
// Pod log files are in the CRI format.
func (s *searcher) fileLines(lines *lineReader) lineSource {
	if s.source.Type == TypeK8sPod {
		return &criLines{lines: lines, max: s.cfg.MaxRecordBytes}
	}
	return lines
}

// records groups lines into records by the source's multiline rule.
// midstream tells that reading began after the start of the data.
func (s *searcher) records(lines lineSource, midstream bool) *recordReader {
	records := newRecordReader(lines, s.parser, s.source.multiline(), s.cfg.MaxRecordBytes)
	records.content, records.dropOrphans = s.content, midstream
	return records
}

type verdict int

const (
	keepRecord verdict = iota
	skipRecord
	stopScan
)

// scanRecords passes records to emit until check returns stopScan or the
// stream ends; skipRecord drops a record. It returns exceeded when the scan
// budget ran out. Bytes read ahead for the next record do not count against
// the current one.
func (s *searcher) scanRecords(records *recordReader, check func(*record) verdict, emit func(record)) (bool, error) {
	for {
		r, err := records.next()
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		exceeded := s.scanned-(records.lines.position()-r.end) > s.cfg.MaxScan
		switch check(&r) {
		case skipRecord:
			if exceeded {
				return true, nil
			}
			continue
		case stopScan:
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

// scanStop tells how a segment scan ended.
type scanStop int

const (
	scanDone     scanStop = iota
	scanExceeded          // the budget ran out inside the segment
	scanPartial           // desc read only the end of the segment
	scanSkipped           // desc did not read the segment: it cannot fit the budget
)

// segment is one part of a source's timeline, ordered oldest first: a log
// file, or a time window of a container output stream. Hits of a segment
// carry the position a cursor needs.
type segment interface {
	// ascend passes the in-range records oldest first, from the cursor c
	// when it is not nil. It returns scanDone or scanExceeded.
	ascend(ctx context.Context, s *searcher, c *cursor, emit func(hit)) (scanStop, error)
	// descend passes the in-range records oldest first, up to the cursor c
	// when it is not nil, reading at most remaining bytes.
	descend(ctx context.Context, s *searcher, c *cursor, remaining int64, emit func(hit)) (scanStop, error)
}

// forward passes every in-range record oldest first, from segment position
// (the cursor's segment when c is not nil) to the end of the range or the
// first limit reached. Matching is up to emit. Modes that read the whole
// range in time order, such as export, use it directly.
func (s *searcher) forward(ctx context.Context, segments []segment, position int, c *cursor, emit func(hit)) error {
	if position < 0 {
		position = 0
	}
	for i := position; i < len(segments); i++ {
		if s.searched == s.cfg.MaxFiles || s.scanned >= s.cfg.MaxScan {
			s.limited = true
			break
		}
		var from *cursor
		if i == position {
			from = c
		}
		stop, err := segments[i].ascend(ctx, s, from, emit)
		if err != nil {
			return err
		}
		if stop == scanExceeded {
			s.limited = true
			break
		}
	}
	return nil
}

// ascending scans oldest first and keeps the first want hits.
func (s *searcher) ascending(ctx context.Context, segments []segment, want, position int, c *cursor) ([]hit, error) {
	var hits []hit
	err := s.forward(ctx, segments, position, c, func(h hit) {
		s.matchRecord(h.record, func() {
			if len(hits) < want {
				hits = append(hits, h)
			}
		})
	})
	return hits, err
}

func (s *searcher) matchRecord(r record, keep func()) {
	if s.match(r.text) {
		s.matched++
		keep()
	}
}

// maxSplits bounds how often desc splits segments that exceeded the budget;
// the bytes read for discarded attempts are bounded by 4 * max_scan.
const maxSplits = 32

// splitter is a segment that desc can split in two by time when reading it
// exceeds the budget: then the newer half is read first and the older half
// after it.
type splitter interface {
	split() (older, newer segment, ok bool)
}

// descending scans segments newest first. Each segment is read forward,
// keeping its newest hits in a ring buffer. The scanned part is always a
// suffix of the range: when the budget runs out inside a segment, that
// segment's hits are discarded; a segment that can be split is retried as
// two halves.
func (s *searcher) descending(ctx context.Context, segments []segment, want, position int, c *cursor) ([]hit, error) {
	var hits []hit
	if position < 0 {
		position = len(segments) - 1
	}
	// Segments newest first; the cursor applies to the first one.
	pending := slices.Clone(segments[:position+1])
	slices.Reverse(pending)
	from, splits, discarded := c, 0, int64(0)
	for len(pending) > 0 {
		remaining := s.cfg.MaxScan - s.scanned
		if s.searched == s.cfg.MaxFiles || remaining <= 0 {
			s.limited = true
			break
		}
		current := pending[0]
		ring := newRing(max(want-len(hits), 0))
		matchedBefore, firstBefore, scannedBefore := s.matched, s.first, s.scanned
		stop, err := current.descend(ctx, s, from, remaining, func(h hit) {
			s.matchRecord(h.record, func() { ring.push(h) })
		})
		if err != nil {
			return nil, err
		}
		if stop == scanExceeded {
			s.matched, s.first = matchedBefore, firstBefore
			if sp, ok := current.(splitter); ok && splits < maxSplits && discarded+s.scanned-scannedBefore <= 4*s.cfg.MaxScan {
				if older, newer, ok := sp.split(); ok {
					// scanned_bytes counts the segments whose hits are kept.
					splits++
					discarded += s.scanned - scannedBefore
					s.scanned = scannedBefore
					pending = append([]segment{newer, older}, pending[1:]...)
					continue
				}
			}
			s.limited = true
			break
		}
		if stop == scanSkipped {
			s.limited = true
			break
		}
		pending, from = pending[1:], nil
		hits = append(hits, ring.newestFirst()...)
		if stop == scanPartial {
			s.limited = true
			break
		}
	}
	return hits, nil
}

func (f *logFile) ascend(ctx context.Context, s *searcher, c *cursor, emit func(hit)) (scanStop, error) {
	file, err := f.open()
	if err != nil {
		return scanDone, err
	}
	defer file.Close()
	s.searched++
	start := int64(0)
	if c != nil {
		start = c.Offset
	} else if !f.gz {
		if start, _, err = seekSince(file, f.size, s.parser, s.since); err != nil {
			return scanDone, err
		}
	}
	exceeded, err := s.scanFile(ctx, file, f, start, -1, false, func(r record) { emit(hit{f, r}) })
	if err != nil || !exceeded {
		return scanDone, err
	}
	return scanExceeded, nil
}

func (f *logFile) descend(ctx context.Context, s *searcher, c *cursor, remaining int64, emit func(hit)) (scanStop, error) {
	file, err := f.open()
	if err != nil {
		return scanDone, err
	}
	defer file.Close()
	end := int64(-1)
	if c != nil {
		end = c.Offset
	}
	start, partial := int64(0), false
	if f.gz {
		if gzipSize(file, f.size) > remaining {
			return scanSkipped, nil
		}
	} else {
		if start, _, err = seekSince(file, f.size, s.parser, s.since); err != nil {
			return scanDone, err
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
	exceeded, err := s.scanFile(ctx, file, f, start, end, partial, func(r record) { emit(hit{f, r}) })
	switch {
	case err != nil:
		return scanDone, err
	case exceeded:
		return scanExceeded, nil
	case partial:
		return scanPartial, nil
	}
	return scanDone, nil
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
