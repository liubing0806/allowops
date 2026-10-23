// Package logquery implements the log_query builtin: named log sources from the
// signed catalog, time ranges, multiline records, paginated JSON results and
// fixed error codes (docs/log-search-design.md section 6).
package logquery

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	// Source time zones must resolve on hosts without a zoneinfo database.
	_ "time/tzdata"

	"github.com/liubing0806/allowops/internal/builtin"
)

// Modes. Phase 2 adds stats and patterns; each catalog action uses one mode.
const (
	ModeSources = "sources"
	ModeSearch  = "search"
)

// Source types. Phase 3 adds container_stdout, container_file and k8s_pod.
const TypeFile = "file"

const (
	MultilineTimestampStart = "timestamp_start"
	MultilineNone           = "none"
)

// Defaults are also the upper bounds: builtin_config may only tighten them.
const (
	DefaultMaxFiles             = builtin.DefaultLogMaxFiles
	DefaultMaxScan        int64 = builtin.DefaultLogMaxScan
	DefaultMaxWindow            = 24 * time.Hour
	DefaultMaxPageRecords       = 200
	DefaultMaxRecordBytes       = 64 << 10
	DefaultLimit                = 50
	DefaultRange                = time.Hour
	MaxPatternLength            = 200
)

type Config struct {
	Mode           string            `json:"mode"`
	Sources        map[string]Source `json:"sources"`
	AllowedRoots   []string          `json:"allowed_roots"`
	MaxFiles       int               `json:"max_files"`
	MaxScan        int64             `json:"max_scan"`
	MaxWindow      time.Duration     `json:"max_window"`
	MaxPageRecords int               `json:"max_page_records"`
	MaxRecordBytes int               `json:"max_record_bytes"`
	Timeout        time.Duration     `json:"timeout"`
}

// Source is one named log source. Type selects the reader; only file exists in
// phase 1. Later types add their own fields and validation in validate().
type Source struct {
	Type      string    `json:"type"`
	Paths     []string  `json:"paths"`
	Timestamp Timestamp `json:"timestamp"`
	Multiline string    `json:"multiline,omitempty"`
}

type Timestamp struct {
	Layouts   []string `json:"layouts"`
	Timezone  string   `json:"timezone,omitempty"`
	Bracketed bool     `json:"bracketed,omitempty"`
}

var sourceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// globBase is the literal directory prefix of a glob.
func globBase(glob string) string {
	if i := strings.IndexAny(glob, `*?[\`); i >= 0 {
		return filepath.Dir(glob[:i])
	}
	return glob
}

// Validate checks the signed configuration lexically. It does not touch the
// file system, so it can run where the catalog is signed. Run additionally
// resolves allowed_roots and every matched path on the host.
func (c Config) Validate() error {
	if c.Mode != ModeSources && c.Mode != ModeSearch {
		return fmt.Errorf("log_query mode allowed: %s, %s", ModeSources, ModeSearch)
	}
	if len(c.AllowedRoots) == 0 {
		return errors.New("log_query allowed_roots required")
	}
	for _, root := range c.AllowedRoots {
		if !filepath.IsAbs(root) || strings.ContainsAny(root, "\x00\r\n") {
			return errors.New("log_query allowed_roots must be absolute paths without NUL/newlines")
		}
	}
	if len(c.Sources) == 0 {
		return errors.New("log_query sources required")
	}
	for name, source := range c.Sources {
		if !sourceName.MatchString(name) {
			return fmt.Errorf("log_query source name %q must match %s", name, sourceName)
		}
		if err := source.validate(c.AllowedRoots); err != nil {
			return fmt.Errorf("log_query source %s: %w", name, err)
		}
	}
	if c.MaxFiles < 0 || c.MaxFiles > DefaultMaxFiles || c.MaxScan < 0 || c.MaxScan > DefaultMaxScan || c.MaxWindow < 0 || c.MaxWindow > DefaultMaxWindow ||
		c.MaxPageRecords < 0 || c.MaxPageRecords > DefaultMaxPageRecords || c.MaxRecordBytes < 0 || c.MaxRecordBytes > DefaultMaxRecordBytes || c.Timeout < 0 || c.Timeout > builtin.DefaultTimeout {
		return fmt.Errorf("log_query limits may only tighten defaults: max_files %d, max_scan %d, max_window %s, max_page_records %d, max_record_bytes %d, timeout %s",
			DefaultMaxFiles, DefaultMaxScan, DefaultMaxWindow, DefaultMaxPageRecords, DefaultMaxRecordBytes, builtin.DefaultTimeout)
	}
	return nil
}

func (s Source) validate(roots []string) error {
	switch s.Type {
	case TypeFile:
	default:
		return fmt.Errorf("type allowed: %s", TypeFile)
	}
	if len(s.Paths) == 0 {
		return errors.New("paths required")
	}
	for _, glob := range s.Paths {
		if !filepath.IsAbs(glob) || strings.ContainsAny(glob, "\x00\r\n") {
			return errors.New("paths must be absolute globs without NUL/newlines")
		}
		if slices.Contains(strings.Split(glob, string(filepath.Separator)), "..") {
			return errors.New("paths must not contain parent directory segments")
		}
		if _, err := filepath.Match(glob, ""); err != nil {
			return fmt.Errorf("invalid glob %q: %w", glob, err)
		}
		base := globBase(glob)
		if !slices.ContainsFunc(roots, func(root string) bool { return within(filepath.Clean(root), base) }) {
			return fmt.Errorf("path %q is outside allowed_roots", glob)
		}
	}
	switch s.Multiline {
	case "", MultilineTimestampStart, MultilineNone:
	default:
		return fmt.Errorf("multiline allowed: %s, %s", MultilineTimestampStart, MultilineNone)
	}
	_, err := newTimeParser(s.Timestamp)
	return err
}

// multiline returns the source's multiline rule with the default applied.
func (s Source) multiline() string {
	if s.Multiline == "" {
		return MultilineTimestampStart
	}
	return s.Multiline
}

// sourceParsers returns the parser of line timestamps, used for record times,
// bisection and file headers, and the parser of record starts in the text of
// stamped lines (nil when lines are not stamped).
func sourceParsers(s Source) (parser, content *timeParser, err error) {
	parser, err = newTimeParser(s.Timestamp)
	return parser, nil, err
}

func (c Config) withDefaults() Config {
	if c.MaxFiles == 0 {
		c.MaxFiles = DefaultMaxFiles
	}
	if c.MaxScan == 0 {
		c.MaxScan = DefaultMaxScan
	}
	if c.MaxWindow == 0 {
		c.MaxWindow = DefaultMaxWindow
	}
	if c.MaxPageRecords == 0 {
		c.MaxPageRecords = DefaultMaxPageRecords
	}
	if c.MaxRecordBytes == 0 {
		c.MaxRecordBytes = DefaultMaxRecordBytes
	}
	if c.Timeout == 0 {
		c.Timeout = builtin.DefaultTimeout
	}
	return c
}

// resolvedRoots checks allowed_roots on the executing host.
func (c Config) resolvedRoots() ([]string, error) {
	roots := make([]string, len(c.AllowedRoots))
	for i, root := range c.AllowedRoots {
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, fmt.Errorf("resolve allowed_root: %w", err)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, errors.New("allowed_root must be a directory")
		}
		roots[i] = resolved
	}
	return roots, nil
}

// SourceNames returns the configured source names in sorted order.
func (c Config) SourceNames() []string {
	names := make([]string, 0, len(c.Sources))
	for name := range c.Sources {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
