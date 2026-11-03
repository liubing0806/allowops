package logquery

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/liubing0806/allowops/internal/params"
)

const (
	// AutoBuckets bounds the bucket count when bucket is omitted.
	AutoBuckets = 60
	// MaxBuckets bounds an explicit bucket; a narrower one falls back to the
	// automatic width.
	MaxBuckets = 720
)

// bucketWidths are the automatic bucket widths, narrowest first.
var bucketWidths = []time.Duration{
	time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 15 * time.Second, 30 * time.Second,
	time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 30 * time.Minute,
	time.Hour, 2 * time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour,
}

// StatsOutput is the stats mode result (design 7.1). It holds numbers, times
// and file names only, never log text.
type StatsOutput struct {
	Source     string            `json:"source"`
	Since      string            `json:"since"`
	Until      string            `json:"until"`
	Bucket     string            `json:"bucket"`
	Matched    int               `json:"matched"`
	FirstMatch string            `json:"first_match,omitempty"`
	LastMatch  string            `json:"last_match,omitempty"`
	Histogram  []HistogramBucket `json:"histogram"`
	// ByLevel is present, possibly empty, when the source declares a level
	// rule.
	ByLevel          *map[string]int `json:"by_level,omitempty"`
	ByFile           []FileCount     `json:"by_file"`
	Files            FileCounts      `json:"files"`
	ScannedBytes     int64           `json:"scanned_bytes"`
	ScanLimitReached bool            `json:"scan_limit_reached"`
	ScannedUntil     string          `json:"scanned_until"`
}

// HistogramBucket counts matches in [Start, Start+bucket). Empty buckets are
// omitted.
type HistogramBucket struct {
	Start string `json:"start"`
	Count int    `json:"count"`
}

type FileCount struct {
	File  string `json:"file"`
	Count int    `json:"count"`
}

func statsParameters(cfg Config) map[string]params.Definition {
	cfg.Mode = ModeSearch
	defs := Parameters(cfg)
	delete(defs, "limit")
	delete(defs, "order")
	delete(defs, "cursor")
	defs["bucket"] = params.Definition{Type: params.String, Description: "Histogram bucket width (1m, 5m, 1h); default keeps at most 60 buckets", Regex: `^[1-9][0-9]{0,4}(s|m|h)$`, MaxLen: 8, Optional: true}
	return defs
}

// bucketStart aligns t to a multiple of width since midnight of t's day in
// location, so buckets start at 14:45 rather than at the request time.
func bucketStart(t time.Time, width time.Duration, location *time.Location) time.Time {
	local := t.In(location)
	midnight := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, location)
	return midnight.Add(local.Sub(midnight) / width * width)
}

// chooseBucket returns the requested width, or the narrowest automatic width
// giving at most AutoBuckets when the request is empty or gives more than
// MaxBuckets.
func chooseBucket(text string, since, until time.Time, location *time.Location) (time.Duration, error) {
	count := func(width time.Duration) time.Duration {
		start := bucketStart(since, width, location)
		return (until.Sub(start) + width - 1) / width
	}
	if text != "" {
		width, err := time.ParseDuration(text)
		if err != nil || width < time.Second {
			return 0, fmt.Errorf("bucket %q must be a duration of at least 1s", text)
		}
		if count(width) <= MaxBuckets {
			return width, nil
		}
	}
	for _, width := range bucketWidths {
		if count(width) <= AutoBuckets {
			return width, nil
		}
	}
	return bucketWidths[len(bucketWidths)-1], nil
}

func runStats(ctx context.Context, cfg Config, roots []string, p Params) ([]byte, bool, error) {
	q, err := prepareScan(ctx, cfg, roots, p)
	if err != nil {
		return nil, false, err
	}
	defer q.close()
	s, rule := q.s, q.level
	location := s.parser.location
	width, err := chooseBucket(p.Bucket, s.since, s.until, location)
	if err != nil {
		return nil, false, err
	}
	origin := bucketStart(s.since, width, location)
	counts := map[int64]int{}
	var indexes []int64
	var byFile []FileCount
	var byLevel map[string]int
	var byLevelOut *map[string]int
	if rule != nil {
		byLevel = map[string]int{}
		byLevelOut = &byLevel
	}
	var first, last time.Time
	err = q.walk(ctx, func(file string, r record) {
		if !s.match(r.text) {
			return
		}
		s.matched++
		if first.IsZero() || r.time.Before(first) {
			first = r.time
		}
		last = maxTime(last, r.time)
		index := int64(r.time.Sub(origin) / width)
		if counts[index] == 0 {
			indexes = append(indexes, index)
		}
		counts[index]++
		if file != "" {
			if n := len(byFile); n == 0 || byFile[n-1].File != file {
				byFile = append(byFile, FileCount{File: file})
			}
			byFile[len(byFile)-1].Count++
		}
		if rule != nil {
			byLevel[rule.of(r.text)]++
		}
	})
	if err != nil {
		return nil, false, err
	}
	out := StatsOutput{Source: p.Source, Since: formatTime(s.since, location), Until: formatTime(s.until, location), Bucket: width.String(),
		Matched: s.matched, Histogram: []HistogramBucket{}, ByLevel: byLevelOut, ByFile: []FileCount{}, Files: q.fileCounts(),
		ScannedBytes: s.scanned, ScanLimitReached: s.limited, ScannedUntil: formatTime(s.scannedUntil(), location)}
	if !first.IsZero() {
		out.FirstMatch, out.LastMatch = formatTime(first, location), formatTime(last, location)
	}
	// Files are read in start-time order but may overlap, so sort the buckets.
	slices.Sort(indexes)
	for _, index := range indexes {
		out.Histogram = append(out.Histogram, HistogramBucket{Start: formatTime(origin.Add(time.Duration(index)*width), location), Count: counts[index]})
	}
	out.ByFile = append(out.ByFile, byFile...)
	data, err := json.Marshal(out)
	return append(data, '\n'), s.limited, err
}
