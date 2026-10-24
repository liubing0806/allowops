package logquery

import (
	"context"
	"strings"
	"time"
)

// prepareScan is the common setup of the stats and patterns modes: source,
// pattern and level matching, time range and the files of the range.
func prepareScan(ctx context.Context, cfg Config, roots []string, p Params) (*searcher, timeline, *levelRule, error) {
	source, ok := cfg.Sources[p.Source]
	if !ok {
		return nil, timeline{}, nil, codeError(CodeSourceUnknown, "source %q is not configured; available: %s", p.Source, strings.Join(cfg.SourceNames(), ", "))
	}
	match, err := compilePatterns(p)
	if err != nil {
		return nil, timeline{}, nil, err
	}
	match, rule, err := withLevels(source, p.Level, match)
	if err != nil {
		return nil, timeline{}, nil, err
	}
	parser, err := newTimeParser(source.Timestamp)
	if err != nil {
		return nil, timeline{}, nil, err
	}
	since, until, err := parseTimeRange(p.Since, p.Until, now(), cfg.MaxWindow)
	if err != nil {
		return nil, timeline{}, nil, err
	}
	tl, err := buildTimeline(ctx, source, roots, parser, since, until)
	if err != nil {
		return nil, timeline{}, nil, err
	}
	return &searcher{cfg: cfg, source: source, parser: parser, since: since, until: until, match: match}, tl, rule, nil
}

// walk passes every record in [since, until] to visit, oldest first, with the
// name of the file it came from. Matching is left to visit. It is the record
// stream of the stats and patterns modes; other source types can supply
// records here. A scan limit stops the walk and sets s.limited, so the
// visited records are always the beginning of the range.
func (s *searcher) walk(ctx context.Context, files []*logFile, visit func(file string, r record)) error {
	for _, f := range files {
		if s.searched == s.cfg.MaxFiles || s.scanned >= s.cfg.MaxScan {
			s.limited = true
			break
		}
		file, err := f.open()
		if err != nil {
			return err
		}
		s.searched++
		start := int64(0)
		if !f.gz {
			if start, _, err = seekSince(file, f.size, s.parser, s.since); err != nil {
				file.Close()
				return err
			}
		}
		exceeded, err := s.scanFile(ctx, file, f, start, -1, false, func(r record) { visit(f.name, r) })
		file.Close()
		if err != nil {
			return err
		}
		if exceeded {
			s.limited = true
			break
		}
	}
	return nil
}

// scannedUntil is the end of the scanned part of the range.
func (s *searcher) scannedUntil() time.Time {
	if s.limited {
		return maxTime(s.last, s.since)
	}
	return s.until
}
