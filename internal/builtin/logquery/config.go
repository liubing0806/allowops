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
	ModeExport  = "export"
)

// Source types: host log files, a container's output through the Docker
// Engine API, log files inside a container, and Kubernetes Pod logs on the
// node (docs/log-search-design.md section 8).
const (
	TypeFile            = "file"
	TypeContainerStdout = "container_stdout"
	TypeContainerFile   = "container_file"
	TypeK8sPod          = "k8s_pod"
)

const (
	MultilineTimestampStart = "timestamp_start"
	MultilineNone           = "none"
)

// Defaults are also the upper bounds: builtin_config may only tighten them.
const (
	DefaultMaxFiles             = builtin.DefaultLogMaxFiles
	DefaultMaxScan        int64 = builtin.DefaultLogMaxScan
	DefaultMaxWindow            = 24 * time.Hour
	DefaultMaxPageRecords       = 500
	DefaultMaxRecordBytes       = 64 << 10
	DefaultLimit                = 50
	DefaultRange                = time.Hour
	MaxPatternLength            = 200
	// MaxExportRecords bounds one export page; max_output usually ends it
	// earlier.
	MaxExportRecords = 100000
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

// Source is one named log source. Type selects the reader:
//   - file: Paths on the host, inside Config.AllowedRoots.
//   - container_stdout: the output of Container read through the Docker API.
//   - container_file: Paths inside Container, inside the source's own
//     AllowedRoots (container paths).
//   - k8s_pod: CRI logs of Container in the Pods of Namespace whose names start
//     with Pod, on this node.
//
// Container output and Pod logs carry the runtime's time on each line;
// Timestamp.Layouts then only find record starts for timestamp_start.
type Source struct {
	Type         string    `json:"type"`
	Paths        []string  `json:"paths,omitempty"`
	Timestamp    Timestamp `json:"timestamp"`
	Multiline    string    `json:"multiline,omitempty"`
	Container    string    `json:"container,omitempty"`
	AllowedRoots []string  `json:"allowed_roots,omitempty"`
	Namespace    string    `json:"namespace,omitempty"`
	Pod          string    `json:"pod,omitempty"`
}

type Timestamp struct {
	Layouts   []string `json:"layouts"`
	Timezone  string   `json:"timezone,omitempty"`
	Bracketed bool     `json:"bracketed,omitempty"`
}

var (
	sourceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	// containerName follows Docker's rule for container names.
	containerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	// dnsLabel is a Kubernetes namespace or container name; podPrefix is the
	// start of a Pod name. Neither contains '_', which separates the parts of
	// a /var/log/pods directory name.
	dnsLabel  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	podPrefix = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)
)

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
	if c.Mode != ModeSources && c.Mode != ModeSearch && c.Mode != ModeExport {
		return fmt.Errorf("log_query mode allowed: %s, %s, %s", ModeSources, ModeSearch, ModeExport)
	}
	files := false
	for _, source := range c.Sources {
		files = files || source.Type == TypeFile
	}
	if files && len(c.AllowedRoots) == 0 {
		return errors.New("log_query allowed_roots required for file sources")
	}
	if err := checkRoots(c.AllowedRoots); err != nil {
		return fmt.Errorf("log_query %w", err)
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

func checkRoots(roots []string) error {
	for _, root := range roots {
		if !filepath.IsAbs(root) || strings.ContainsAny(root, "\x00\r\n") {
			return errors.New("allowed_roots must be absolute paths without NUL/newlines")
		}
	}
	return nil
}

func (s Source) validate(roots []string) error {
	// Fields of other types are rejected so a misplaced field is not ignored.
	unexpected := func(fields map[string]bool) error {
		for name, set := range fields {
			if set {
				return fmt.Errorf("%s does not apply to type %s", name, s.Type)
			}
		}
		return nil
	}
	switch s.Type {
	case TypeFile:
		if err := unexpected(map[string]bool{"container": s.Container != "", "allowed_roots": s.AllowedRoots != nil, "namespace": s.Namespace != "", "pod": s.Pod != ""}); err != nil {
			return err
		}
		if err := checkPaths(s.Paths, roots); err != nil {
			return err
		}
	case TypeContainerFile:
		if err := unexpected(map[string]bool{"namespace": s.Namespace != "", "pod": s.Pod != ""}); err != nil {
			return err
		}
		if !containerName.MatchString(s.Container) {
			return fmt.Errorf("container must match %s", containerName)
		}
		if len(s.AllowedRoots) == 0 {
			return errors.New("allowed_roots (paths inside the container) required")
		}
		if err := checkRoots(s.AllowedRoots); err != nil {
			return err
		}
		if err := checkPaths(s.Paths, s.AllowedRoots); err != nil {
			return err
		}
	case TypeContainerStdout:
		if err := unexpected(map[string]bool{"paths": s.Paths != nil, "allowed_roots": s.AllowedRoots != nil, "namespace": s.Namespace != "", "pod": s.Pod != ""}); err != nil {
			return err
		}
		if !containerName.MatchString(s.Container) {
			return fmt.Errorf("container must match %s", containerName)
		}
		return s.validateStamped()
	case TypeK8sPod:
		if err := unexpected(map[string]bool{"paths": s.Paths != nil, "allowed_roots": s.AllowedRoots != nil}); err != nil {
			return err
		}
		if !dnsLabel.MatchString(s.Namespace) || !dnsLabel.MatchString(s.Container) {
			return fmt.Errorf("namespace and container must match %s", dnsLabel)
		}
		if !podPrefix.MatchString(s.Pod) {
			return fmt.Errorf("pod (a Pod name prefix) must match %s", podPrefix)
		}
		return s.validateStamped()
	default:
		return fmt.Errorf("type allowed: %s, %s, %s, %s", TypeFile, TypeContainerStdout, TypeContainerFile, TypeK8sPod)
	}
	switch s.Multiline {
	case "", MultilineTimestampStart, MultilineNone:
	default:
		return fmt.Errorf("multiline allowed: %s, %s", MultilineTimestampStart, MultilineNone)
	}
	_, err := newTimeParser(s.Timestamp)
	return err
}

// validateStamped checks a source whose lines carry the runtime's time.
// Layouts are needed only to find record starts for timestamp_start.
func (s Source) validateStamped() error {
	switch s.Multiline {
	case "", MultilineNone:
	case MultilineTimestampStart:
		if len(s.Timestamp.Layouts) == 0 {
			return errors.New("multiline timestamp_start requires timestamp.layouts to find record starts")
		}
	default:
		return fmt.Errorf("multiline allowed: %s, %s", MultilineTimestampStart, MultilineNone)
	}
	if s.Timestamp.Bracketed && len(s.Timestamp.Layouts) == 0 {
		return errors.New("timestamp.bracketed requires timestamp.layouts")
	}
	if len(s.Timestamp.Layouts) > 0 {
		_, err := newTimeParser(s.Timestamp)
		return err
	}
	_, err := loadLocation(s.Timestamp.Timezone)
	return err
}

// checkPaths checks globs lexically against roots.
func checkPaths(paths, roots []string) error {
	if len(paths) == 0 {
		return errors.New("paths required")
	}
	for _, glob := range paths {
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
	return nil
}

// stamped reports whether the source's lines carry the runtime's time.
func (s Source) stamped() bool {
	return s.Type == TypeContainerStdout || s.Type == TypeK8sPod
}

// multiline returns the source's multiline rule with the default applied:
// timestamp_start for files, none for stamped lines.
func (s Source) multiline() string {
	if s.Multiline == "" && s.stamped() {
		return MultilineNone
	}
	if s.Multiline == "" {
		return MultilineTimestampStart
	}
	return s.Multiline
}

// sourceParsers returns the parser of line timestamps, used for record times,
// bisection and file headers, and the parser of record starts in the text of
// stamped lines (nil when lines are not stamped or have no layouts).
func sourceParsers(s Source) (parser, content *timeParser, err error) {
	if !s.stamped() {
		parser, err = newTimeParser(s.Timestamp)
		return parser, nil, err
	}
	location, err := loadLocation(s.Timestamp.Timezone)
	if err != nil {
		return nil, nil, err
	}
	if len(s.Timestamp.Layouts) > 0 {
		if content, err = newTimeParser(s.Timestamp); err != nil {
			return nil, nil, err
		}
	}
	return runtimeParser(location), content, nil
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
