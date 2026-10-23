package logquery

import (
	"bufio"
	"io"
	"time"
)

const (
	// bisectBlock ends the binary search; the rest is read sequentially.
	bisectBlock = 64 << 10
	// probeLines is the number of lines a probe reads looking for a timestamp.
	probeLines = 64
	// probePrefix is the part of each probed line kept for timestamp parsing.
	probePrefix = 1024
)

// lineReader yields lines with their byte offsets. Bytes beyond max in one
// line are read and counted but not retained.
type lineReader struct {
	reader  *bufio.Reader
	offset  int64 // offset of the next line
	number  int   // line number of the next line; 0 when unknown
	max     int
	scanned *int64
}

func newLineReader(r io.Reader, offset int64, number, max int, scanned *int64) *lineReader {
	return &lineReader{reader: bufio.NewReaderSize(r, 64<<10), offset: offset, number: number, max: max, scanned: scanned}
}

type rawLine struct {
	text      string
	offset    int64
	number    int
	truncated bool
}

func (l *lineReader) next() (rawLine, error) {
	line := rawLine{offset: l.offset, number: l.number}
	var text []byte
	var length int64
	ended := false
	for {
		part, err := l.reader.ReadSlice('\n')
		length += int64(len(part))
		if keep := l.max - len(text); keep > 0 {
			text = append(text, part[:min(len(part), keep)]...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil && (err != io.EOF || length == 0) {
			return line, err
		}
		ended = len(part) > 0 && part[len(part)-1] == '\n'
		break
	}
	if l.scanned != nil {
		*l.scanned += length
	}
	l.offset += length
	if l.number > 0 {
		l.number++
	}
	content := length
	if ended {
		content--
	}
	line.truncated = content > int64(l.max)
	text = trimEOL(text)
	line.text = string(text)
	return line, nil
}

func trimEOL(text []byte) []byte {
	if n := len(text); n > 0 && text[n-1] == '\n' {
		text = text[:n-1]
	}
	if n := len(text); n > 0 && text[n-1] == '\r' {
		text = text[:n-1]
	}
	return text
}

// skipLine discards the rest of the current line, used when a read starts at
// an arbitrary offset.
func (l *lineReader) skipLine() error {
	_, err := l.next()
	l.number = 0
	return err
}

// record is one log record: a timestamped line plus, for timestamp_start,
// the following lines without a timestamp.
type record struct {
	end       int64 // offset after the record's last line
	time      time.Time
	timed     bool
	offset    int64
	line      int
	text      string
	truncated bool
}

type recordReader struct {
	lines     *lineReader
	parser    *timeParser
	multiline bool
	max       int
	pending   *record
	last      time.Time
	done      bool
}

func newRecordReader(lines *lineReader, parser *timeParser, multiline string, max int) *recordReader {
	return &recordReader{lines: lines, parser: parser, multiline: multiline != MultilineNone, max: max}
}

// next returns io.EOF after the last record.
func (r *recordReader) next() (record, error) {
	for !r.done {
		line, err := r.lines.next()
		if err == io.EOF {
			r.done = true
			break
		}
		if err != nil {
			return record{}, err
		}
		t, timed := r.parser.parse(line.text)
		if !r.multiline {
			if timed {
				r.last = t
			}
			return record{end: r.lines.offset, time: r.last, timed: !r.last.IsZero(), offset: line.offset, line: line.number, text: line.text, truncated: line.truncated}, nil
		}
		if timed || r.pending == nil {
			current := &record{time: t, timed: timed, offset: line.offset, line: line.number, text: line.text, truncated: line.truncated}
			previous := r.pending
			r.pending = current
			if previous != nil {
				previous.end = line.offset
				return *previous, nil
			}
			continue
		}
		r.pending.append(line, r.max)
	}
	if r.pending != nil {
		previous := r.pending
		r.pending = nil
		previous.end = r.lines.offset
		return *previous, nil
	}
	return record{}, io.EOF
}

func (r *record) append(line rawLine, max int) {
	if r.truncated && len(r.text) >= max {
		return
	}
	room := max - len(r.text) - 1
	if room < len(line.text) {
		r.truncated = true
		if room <= 0 {
			return
		}
		r.text += "\n" + line.text[:room]
		return
	}
	r.text += "\n" + line.text
	r.truncated = r.truncated || line.truncated
}

type probe struct {
	start int64 // offset of the timestamped line
	time  time.Time
	found bool
	eof   bool // reached the end without a timestamp
}

// probeReader looks for a timestamp in the next probeLines lines of reader,
// whose first byte is at offset.
func probeReader(reader *bufio.Reader, offset int64, parser *timeParser) probe {
	lines := &lineReader{reader: reader, offset: offset, max: probePrefix}
	for i := 0; i < probeLines; i++ {
		line, err := lines.next()
		if err != nil {
			return probe{eof: true}
		}
		if t, ok := parser.parse(line.text); ok {
			return probe{start: line.offset, time: t, found: true}
		}
	}
	return probe{}
}

// probeAt probes from the first line start after off.
func probeAt(r io.ReaderAt, size, off int64, parser *timeParser) probe {
	reader := bufio.NewReaderSize(io.NewSectionReader(r, off, size-off), 4096)
	if off > 0 {
		skipped, err := reader.ReadString('\n')
		if err != nil {
			return probe{eof: true}
		}
		off += int64(len(skipped))
	}
	return probeReader(reader, off, parser)
}

// lineStart returns the first line start at or after off.
func lineStart(r io.ReaderAt, size, off int64) (int64, error) {
	if off <= 0 {
		return 0, nil
	}
	var previous [1]byte
	if _, err := r.ReadAt(previous[:], off-1); err != nil {
		return 0, err
	}
	if previous[0] == '\n' {
		return off, nil
	}
	reader := bufio.NewReaderSize(io.NewSectionReader(r, off, size-off), 4096)
	skipped, err := reader.ReadString('\n')
	if err == io.EOF {
		return size, nil
	}
	return off + int64(len(skipped)), err
}

// bisect finds a line start lo such that every record whose time satisfies
// !before(time) starts at or after lo, and an upper bound hi before which all
// records satisfying before(time) start. ok is false when probeLines
// consecutive lines have no timestamp; the caller then scans from the start.
func bisect(r io.ReaderAt, size int64, parser *timeParser, before func(time.Time) bool) (lo, hi int64, ok bool, err error) {
	hi = size
	for top := size; top-lo > bisectBlock; {
		mid := lo + (top-lo)/2
		p := probeAt(r, size, mid, parser)
		switch {
		case !p.found && !p.eof:
			return 0, size, false, nil
		case p.eof || !before(p.time):
			top = mid
			if p.found {
				hi = min(hi, p.start)
			}
		default:
			lo = mid
		}
	}
	lo, err = lineStart(r, size, lo)
	return lo, hi, true, err
}

// seekSince returns the offset to start reading for records at or after since.
func seekSince(r io.ReaderAt, size int64, parser *timeParser, since time.Time) (int64, bool, error) {
	offset, _, ok, err := bisect(r, size, parser, func(t time.Time) bool { return t.Before(since) })
	return offset, ok, err
}

// seekAfter returns an offset at or after the end of records not after until.
func seekAfter(r io.ReaderAt, size int64, parser *timeParser, until time.Time) (int64, bool) {
	_, hi, ok, err := bisect(r, size, parser, func(t time.Time) bool { return !t.After(until) })
	if err != nil || !ok {
		return size, false
	}
	return hi, true
}
