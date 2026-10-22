// Package logsearch searches regular and gzip log files within allowed roots.
package logsearch

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
)

// Config limits all files in one search. Byte limits are numeric YAML values.
// Defaults: 50 files, 256MiB decompressed scan, 1000 matches,
// 20 context lines, 10s timeout. MaxContext and MaxMatches only tighten schemas.
// The executor applies final max_output only after redaction and filtering.
type Config struct {
	AllowedRoots []string      `yaml:"allowed_roots"`
	MaxFiles     int           `yaml:"max_files"`
	MaxScan      int64         `yaml:"max_scan"`
	MaxMatches   int           `yaml:"max_matches"`
	MaxContext   int           `yaml:"max_context"`
	Timeout      time.Duration `yaml:"timeout"`
}

type Params struct {
	PathGlob   string `json:"path_glob"`
	Pattern    string `json:"pattern"`
	Fixed      bool   `json:"fixed,omitempty"`
	Exclude    string `json:"exclude,omitempty"`
	Context    int    `json:"context,omitempty"`
	MaxMatches int    `json:"max_matches,omitempty"`
}

type Result = builtin.Result

func (c Config) Validate() error {
	if len(c.AllowedRoots) == 0 {
		return errors.New("allowed_roots is required")
	}
	for _, root := range c.AllowedRoots {
		if !filepath.IsAbs(root) {
			return errors.New("allowed_roots must be absolute")
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			return fmt.Errorf("resolve allowed_root: %w", err)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return errors.New("allowed_root must be a directory")
		}
	}
	if c.MaxFiles < 0 || c.MaxFiles > 1000 || c.MaxScan < 0 || c.MaxScan > 1<<30 || c.MaxMatches < 0 || c.MaxMatches > 10000 || c.MaxContext < 0 || c.MaxContext > 100 || c.Timeout < 0 {
		return errors.New("invalid log_search limits: files <= 1000, scan <= 1GiB, matches <= 10000, context <= 100; limits must be nonnegative")
	}
	return nil
}

func ParamsSchema() map[string]any {
	text := func(max int) map[string]any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": max, "pattern": "^[^-]"}
	}
	return map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false, "required": []string{"path_glob", "pattern"}, "properties": map[string]any{
		"path_glob": text(4096), "pattern": text(200), "fixed": map[string]any{"type": "boolean", "default": false}, "exclude": map[string]any{"type": "string", "maxLength": 200, "pattern": "^([^-].*)?$"},
		"context": map[string]any{"type": "integer", "minimum": 0, "maximum": 100, "default": 0}, "max_matches": map[string]any{"type": "integer", "minimum": 1, "maximum": 10000, "default": builtin.DefaultLogMaxMatches},
	}}
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// ErrGlobLimit means path_glob examined more directory entries than allowed.
var ErrGlobLimit = errors.New("path_glob examined too many directory entries")

const maxGlobEntries = 20000

type logFile struct{ name, root, relative string }

// Resolve and validate every match before reading, including matches beyond the
// file limit. os.Root confines the later open even if symlinks change meanwhile.
func files(ctx context.Context, cfg Config, glob string) ([]logFile, error) {
	if !filepath.IsAbs(glob) {
		return nil, errors.New("path_glob must be absolute")
	}
	for _, part := range strings.Split(glob, string(filepath.Separator)) {
		if part == ".." {
			return nil, errors.New("path_glob must not contain parent directory segments")
		}
	}
	base := glob
	if i := strings.IndexAny(glob, "*?["); i >= 0 {
		base = filepath.Dir(glob[:i])
	}
	lexicallyAllowed := false
	for _, root := range cfg.AllowedRoots {
		if within(filepath.Clean(root), base) {
			lexicallyAllowed = true
		}
	}
	if !lexicallyAllowed {
		return nil, errors.New("path_glob is outside allowed_roots")
	}
	matches, err := filepath.Glob(glob)
	if err != nil {
		return nil, err
	}
	roots := make([]string, len(cfg.AllowedRoots))
	for i, root := range cfg.AllowedRoots {
		roots[i], err = filepath.EvalSymlinks(root)
		if err != nil {
			return nil, err
		}
	}
	result := make([]logFile, 0, min(len(matches), cfg.MaxFiles))
	for _, name := range matches {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolved, err := filepath.EvalSymlinks(name)
		if err != nil {
			return nil, err
		}
		root := ""
		for _, candidate := range roots {
			if within(candidate, resolved) {
				root = candidate
				break
			}
		}
		if root == "" {
			return nil, errors.New("matched file is outside allowed_roots")
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("matched path must be a regular file")
		}
		rel, err := filepath.Rel(root, resolved)
		if err != nil {
			return nil, err
		}
		if len(result) <= cfg.MaxFiles {
			result = append(result, logFile{name, root, rel})
		}
	}
	return result, nil
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

func Run(ctx context.Context, cfg Config, p Params) (Result, error) {
	r := Result{ExitCode: builtin.ExitFailure}
	if err := cfg.Validate(); err != nil {
		return r, err
	}
	if cfg.MaxFiles == 0 {
		cfg.MaxFiles = builtin.DefaultLogMaxFiles
	}
	if cfg.MaxScan == 0 {
		cfg.MaxScan = builtin.DefaultLogMaxScan
	}
	if cfg.MaxMatches == 0 {
		cfg.MaxMatches = builtin.DefaultLogMaxMatches
	}
	if cfg.MaxContext == 0 {
		cfg.MaxContext = builtin.DefaultLogMaxContext
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = builtin.DefaultTimeout
	}
	for _, s := range []string{p.PathGlob, p.Pattern, p.Exclude} {
		if strings.HasPrefix(s, "-") || strings.ContainsAny(s, "\x00\r\n") {
			return r, errors.New("string parameters must not start with - or contain NUL/newlines")
		}
	}
	if p.Pattern == "" || len(p.Pattern) > 200 || len(p.Exclude) > 200 || len(p.PathGlob) > 4096 || p.Context < 0 || p.Context > cfg.MaxContext || p.MaxMatches < 0 || p.MaxMatches > cfg.MaxMatches {
		return r, errors.New("invalid log_search parameters or configured limits exceeded")
	}
	if p.MaxMatches == 0 {
		p.MaxMatches = cfg.MaxMatches
	}
	match := func(s string) bool { return strings.Contains(s, p.Pattern) }
	if !p.Fixed {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return r, fmt.Errorf("invalid pattern: %w", err)
		}
		match = re.MatchString
	}
	exclude := func(string) bool { return false }
	if p.Exclude != "" {
		if p.Fixed {
			exclude = func(s string) bool { return strings.Contains(s, p.Exclude) }
		} else {
			re, err := regexp.Compile(p.Exclude)
			if err != nil {
				return r, fmt.Errorf("invalid exclude: %w", err)
			}
			exclude = re.MatchString
		}
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return r, err
	}
	matched, err := files(ctx, cfg, p.PathGlob)
	if err != nil {
		return r, err
	}
	if len(matched) > cfg.MaxFiles {
		matched = matched[:cfg.MaxFiles]
		r.Truncated = true
	}
	state := searchState{cfg: cfg, p: p, result: &r, match: match, exclude: exclude}
	for _, file := range matched {
		stop, err := state.search(ctx, file)
		if err != nil {
			r.Stdout = state.output.String()
			return r, err
		}
		if stop {
			break
		}
	}
	r.Stdout = state.output.String()
	r.ExitCode = builtin.ExitSuccess
	return r, nil
}

type numberedLine struct {
	number int
	text   string
}
type searchState struct {
	cfg            Config
	p              Params
	result         *Result
	match, exclude func(string) bool
	output         strings.Builder
	scanned        int64
	matches        int
}

func (s *searchState) emit(name string, line numberedLine) {
	fmt.Fprintf(&s.output, "%s:%d:%s\n", name, line.number, line.text)
}

func (s *searchState) search(ctx context.Context, file logFile) (bool, error) {
	root, err := os.OpenRoot(file.root)
	if err != nil {
		return false, err
	}
	defer root.Close()
	f, err := root.OpenFile(file.relative, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("matched path must be a regular file")
	}
	var source io.Reader = contextReader{ctx, f}
	if strings.HasSuffix(file.name, ".gz") {
		z, err := gzip.NewReader(source)
		if err != nil {
			return false, err
		}
		defer z.Close()
		source = z
	}
	remaining := s.cfg.MaxScan - s.scanned
	limited := &io.LimitedReader{R: contextReader{ctx, source}, N: remaining + 1}
	reader := bufio.NewReaderSize(limited, 4096)
	before := make([]numberedLine, 0, s.p.Context)
	after, lastEmitted := 0, 0
	for number := 1; ; number++ {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		var line []byte
		var readErr error
		for {
			part, err := reader.ReadSlice('\n')
			s.scanned += int64(len(part))
			// Scan bytes, including buffered lines, are bounded by MaxScan.
			// Final output truncation belongs to the executor, after redaction.
			if s.scanned > s.cfg.MaxScan {
				s.result.Truncated = true
				return true, nil
			}
			line = append(line, part...)
			if err != bufio.ErrBufferFull {
				readErr = err
				break
			}
		}
		if readErr != nil && readErr != io.EOF {
			return false, readErr
		}
		if len(line) == 0 && readErr == io.EOF {
			return false, nil
		}
		text := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		current := numberedLine{number, text}
		ignored := s.exclude(text)
		hit := !ignored && s.matches < s.p.MaxMatches && s.match(text)
		if hit {
			s.matches++
			for _, previous := range before {
				if previous.number > lastEmitted && !s.exclude(previous.text) {
					s.emit(file.name, previous)
					lastEmitted = previous.number
				}
			}
			after = s.p.Context
			s.emit(file.name, current)
			lastEmitted = number
		} else if after > 0 {
			if !ignored {
				s.emit(file.name, current)
				lastEmitted = number
			}
			after--
		}
		if s.p.Context > 0 {
			if len(before) == s.p.Context {
				copy(before, before[1:])
				before = before[:len(before)-1]
			}
			before = append(before, current)
		}
		if s.matches == s.p.MaxMatches && after == 0 {
			s.result.Truncated = true
			return true, nil
		}
		if readErr == io.EOF {
			return false, nil
		}
	}
}
