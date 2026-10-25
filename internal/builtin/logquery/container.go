package logquery

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// stdoutWindows is the number of time windows a desc search of container
// output reads, newest first. The Docker API can only read forward, so desc
// keeps the scanned part a suffix of the range by reading short windows from
// the end, as it reads the newest file first for file sources.
const stdoutWindows = 8

// stdoutWindow is the container output in [from, to): one segment of a
// container_stdout source. The last window of a range ends after until.
type stdoutWindow struct {
	client   *dockerClient
	name     string
	tty      bool
	from, to time.Time
}

// stdoutSegments inspects the container and splits [since, until] into the
// windows that the order reads. A desc cursor ends the range at its time.
func stdoutSegments(ctx context.Context, client *dockerClient, source Source, since, until time.Time, order string, c *cursor) ([]segment, error) {
	info, err := client.inspect(ctx, source.Container)
	if err != nil {
		return nil, err
	}
	end := until
	if c != nil && order == "desc" {
		if at, _, _, err := c.times(); err == nil {
			end = at
		}
	}
	end = end.Add(time.Nanosecond)
	window := func(from, to time.Time) segment {
		return &stdoutWindow{client: client, name: source.Container, tty: info.Config.Tty, from: from, to: to}
	}
	if order == "asc" {
		return []segment{window(since, end)}, nil
	}
	width := end.Sub(since) / stdoutWindows
	if width < time.Millisecond {
		return []segment{window(since, end)}, nil
	}
	segments := make([]segment, stdoutWindows)
	for i := range segments {
		from, to := since.Add(time.Duration(i)*width), since.Add(time.Duration(i+1)*width)
		if i == stdoutWindows-1 {
			to = end
		}
		segments[i] = window(from, to)
	}
	return segments, nil
}

// split halves the window. Windows narrower than a millisecond stay whole.
func (w *stdoutWindow) split() (segment, segment, bool) {
	width := w.to.Sub(w.from)
	if width < 2*time.Millisecond {
		return nil, nil, false
	}
	middle := w.from.Add(width / 2)
	older, newer := *w, *w
	older.to, newer.from = middle, middle
	return &older, &newer, true
}

func (w *stdoutWindow) ascend(ctx context.Context, s *searcher, c *cursor, emit func(hit)) (scanStop, error) {
	from, at, seq := w.from, time.Time{}, 0
	if c != nil {
		at, _, _, _ = c.times()
		from, seq = maxTime(from, at), c.Seq
	}
	exceeded, err := w.scan(ctx, s, from, func(r *record) verdict {
		if c != nil && r.time.Equal(at) && r.seq < seq {
			return skipRecord
		}
		return keepRecord
	}, emit)
	if err != nil || !exceeded {
		return scanDone, err
	}
	return scanExceeded, nil
}

func (w *stdoutWindow) descend(ctx context.Context, s *searcher, c *cursor, _ int64, emit func(hit)) (scanStop, error) {
	at, seq := time.Time{}, 0
	if c != nil {
		at, _, _, _ = c.times()
		seq = c.Seq
	}
	exceeded, err := w.scan(ctx, s, w.from, func(r *record) verdict {
		if c != nil && r.time.Equal(at) && r.seq > seq {
			return stopScan
		}
		return keepRecord
	}, emit)
	if err != nil || !exceeded {
		return scanDone, err
	}
	return scanExceeded, nil
}

// scan reads the output from from on and passes the records of the window
// that check keeps. Each record gets its index among the records with the
// same time, counted from the first record at that time.
func (w *stdoutWindow) scan(ctx context.Context, s *searcher, from time.Time, check func(*record) verdict, emit func(hit)) (bool, error) {
	body, err := w.client.logs(ctx, w.name, from, "")
	if err != nil {
		return false, err
	}
	defer body.Close()
	lines := newDockerLines(contextReader{ctx, body}, w.tty, s.cfg.MaxRecordBytes, &s.scanned)
	records := s.records(lines, true)
	var previous time.Time
	seq := 0
	return s.scanRecords(records, func(r *record) verdict {
		if !r.timed || r.time.Before(from) || r.time.Before(s.since) {
			return skipRecord
		}
		if !r.time.Before(w.to) || r.time.After(s.until) {
			return stopScan
		}
		if r.time.Equal(previous) {
			seq++
		} else {
			previous, seq = r.time, 0
		}
		r.seq = seq
		return check(r)
	}, func(r record) { emit(hit{nil, r}) })
}

// stdoutSummary reads the time of the first and the last output line.
func stdoutSummary(ctx context.Context, name string, source Source, location *time.Location) SourceSummary {
	summary := SourceSummary{Name: name, Type: source.Type, Status: "no_records"}
	client := newDockerClient()
	defer client.close()
	unavailable := func(err error) SourceSummary {
		summary.Status, summary.Reason = "unavailable", CodeSourceUnavailable
		var coded *Error
		if errors.As(err, &coded) && coded.Code == CodeSourceUnsupported {
			summary.Status, summary.Reason = "unsupported", CodeSourceUnsupported
		}
		return summary
	}
	info, err := client.inspect(ctx, source.Container)
	if err != nil {
		return unavailable(err)
	}
	edge := func(tail string) (time.Time, bool, error) {
		body, err := client.logs(ctx, source.Container, time.Time{}, tail)
		if err != nil {
			return time.Time{}, false, err
		}
		defer body.Close()
		var scanned int64
		lines := newDockerLines(contextReader{ctx, body}, info.Config.Tty, probePrefix, &scanned)
		var last time.Time
		found := false
		for {
			line, err := lines.next()
			if err == io.EOF {
				return last, found, nil
			}
			if err != nil {
				return last, found, err
			}
			last, found = line.time, true
			if tail == "" {
				return last, found, nil
			}
		}
	}
	earliest, found, err := edge("")
	if err != nil {
		return unavailable(err)
	}
	if !found {
		return summary
	}
	latest, _, err := edge("1")
	if err != nil {
		return unavailable(err)
	}
	summary.Status, summary.TimestampParsed = "ok", true
	summary.Earliest, summary.Latest = formatTime(earliest, location), formatTime(latest, location)
	return summary
}

// containerRoot is where one allowed root of a container_file source is on
// the host: inner, relative to base, is opened as an os.Root inside the
// os.Root of base, so symlinks in the container resolve inside the root.
type containerRoot struct {
	path        string // the allowed root inside the container
	base, inner string
}

// containerRoots maps the source's allowed roots to host paths. A root in a
// bind mount or volume uses the mount's source; other roots use the overlay2
// MergedDir. Mounts nested below an allowed root are not visible through
// MergedDir, so paths in them are not read unless a root covers the mount.
func containerRoots(info containerInfo, source Source) ([]containerRoot, error) {
	var roots []containerRoot
	for _, root := range source.AllowedRoots {
		root = filepath.Clean(root)
		var mount *dockerMount
		for i, m := range info.Mounts {
			if within(filepath.Clean(m.Destination), root) && (mount == nil || len(m.Destination) > len(mount.Destination)) {
				mount = &info.Mounts[i]
			}
		}
		switch {
		case mount != nil && mount.Source != "" && (mount.Type == "bind" || mount.Type == "volume"):
			inner, _ := filepath.Rel(filepath.Clean(mount.Destination), root)
			roots = append(roots, containerRoot{path: root, base: mount.Source, inner: inner})
		case mount != nil:
			return nil, codeError(CodeSourceUnsupported, "%s is in a %s mount without a host path", root, mount.Type)
		case info.GraphDriver != nil && info.GraphDriver.Name == "overlay2" && info.GraphDriver.Data["MergedDir"] != "":
			inner, _ := filepath.Rel("/", root)
			roots = append(roots, containerRoot{path: root, base: info.GraphDriver.Data["MergedDir"], inner: inner})
		default:
			driver := "none"
			if info.GraphDriver != nil {
				driver = info.GraphDriver.Name
			}
			return nil, codeError(CodeSourceUnsupported, "%s is outside every mount and the storage driver is %s, not overlay2", root, driver)
		}
	}
	return roots, nil
}

// resolveContainerFiles expands the globs of a container_file source inside
// the container's roots on the host.
func resolveContainerFiles(ctx context.Context, source Source) (resolvedFiles, error) {
	client := newDockerClient()
	defer client.close()
	info, err := client.inspect(ctx, source.Container)
	if err != nil {
		return resolvedFiles{}, err
	}
	roots, err := containerRoots(info, source)
	if err != nil {
		return resolvedFiles{}, err
	}
	var result resolvedFiles
	seen := map[[2]uint64]bool{}
	for _, glob := range source.Paths {
		var root *containerRoot
		for i := range roots {
			if within(roots[i].path, globBase(glob)) && (root == nil || len(roots[i].path) > len(root.path)) {
				root = &roots[i]
			}
		}
		if root == nil {
			return result, codeError(CodePathOutsideRoots, "%s is outside allowed_roots", glob)
		}
		pattern, _ := filepath.Rel(root.path, glob)
		err := globRoot(ctx, root.base, root.inner, pattern, func(rel string) string { return filepath.Join(root.path, rel) }, &result, seen)
		if err != nil {
			return result, err
		}
	}
	sortFiles(result.files)
	return result, nil
}

// openRoot opens base and then inner inside it. Symlinks in inner resolve
// inside base; one that leaves it is PATH_OUTSIDE_ROOTS. A missing inner
// returns nil and no error.
func openRoot(base, inner string) (*os.Root, error) {
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	if inner == "" || inner == "." {
		return root, nil
	}
	defer root.Close()
	nested, err := root.OpenRoot(inner)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, outsideRoot(inner, err)
	}
	return nested, nil
}

// outsideRoot reports an os.Root error for a path that leaves the root as
// PATH_OUTSIDE_ROOTS.
func outsideRoot(name string, err error) error {
	if strings.Contains(err.Error(), "escapes") {
		return codeError(CodePathOutsideRoots, "%s resolves outside its root", name)
	}
	return err
}

// globRoot matches pattern inside base/inner and adds the regular files.
// display returns the name shown for a match.
func globRoot(ctx context.Context, base, inner, pattern string, display func(string) string, result *resolvedFiles, seen map[[2]uint64]bool) error {
	root, err := openRoot(base, inner)
	if err != nil || root == nil {
		return err
	}
	defer root.Close()
	matches, err := fs.Glob(root.FS(), pattern)
	if err != nil {
		return err
	}
	for _, rel := range matches {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := root.Stat(rel)
		if errors.Is(err, fs.ErrNotExist) {
			result.skippedNotRegular++
			continue
		}
		if err != nil {
			return outsideRoot(display(rel), err)
		}
		if !info.Mode().IsRegular() {
			result.skippedNotRegular++
			continue
		}
		stat := info.Sys().(*syscall.Stat_t)
		key := [2]uint64{uint64(stat.Dev), stat.Ino}
		if seen[key] {
			continue
		}
		seen[key] = true
		name := display(rel)
		result.files = append(result.files, &logFile{name: name, root: base, inner: inner, rel: rel, dev: key[0], ino: key[1], size: info.Size(), mtime: info.ModTime(), gz: strings.HasSuffix(name, ".gz")})
	}
	return nil
}

// sourceStatus returns the summary status for a source error, or "" when
// the error should fail the request.
func sourceStatus(err error) (string, string) {
	var coded *Error
	if errors.As(err, &coded) {
		switch coded.Code {
		case CodeSourceUnavailable:
			return "unavailable", coded.Code
		case CodeSourceUnsupported:
			return "unsupported", coded.Code
		}
	}
	return "", ""
}
