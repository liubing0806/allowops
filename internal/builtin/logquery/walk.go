package logquery

import (
	"context"
	"time"
)

// prepareScan is the common setup of the stats and patterns modes: source,
// pattern and level matching, time range and the segments of the range. They
// take no limit, order or cursor; the whole range is read oldest first.
func prepareScan(ctx context.Context, cfg Config, roots []string, p Params) (*query, error) {
	p.Limit, p.Order, p.Cursor = 0, "asc", ""
	return prepare(ctx, cfg, roots, p, 1, 1)
}

// walk passes every record in [since, until] to visit, oldest first, with the
// name of the file it came from ("" for container output). Matching is left
// to visit. A scan limit stops the walk and sets s.limited, so the visited
// records are always the beginning of the range.
func (q *query) walk(ctx context.Context, visit func(file string, r record)) error {
	return q.s.forward(ctx, q.segments, q.position, nil, func(h hit) {
		file := ""
		if h.file != nil {
			file = h.file.name
		}
		visit(file, h.record)
	})
}

// fileCounts returns the file counters of the scan; container output has none.
func (q *query) fileCounts() FileCounts {
	if q.counts == nil {
		return FileCounts{}
	}
	counts := *q.counts
	counts.Searched = q.s.searched
	return counts
}

// scannedUntil is the end of the scanned part of the range.
func (s *searcher) scannedUntil() time.Time {
	if s.limited {
		return maxTime(s.last, s.since)
	}
	return s.until
}
