package logquery

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// headerBytes bounds the decompressed prefix read for a file's first timestamp.
const headerBytes = 256 << 10

// logFile is one regular file of a file source. Name is the matched path; the
// file is opened through os.Root at root/rel so later symlink changes cannot
// leave the allowed root.
type logFile struct {
	name, root, rel string
	dev, ino        uint64
	size            int64
	mtime           time.Time
	gz              bool
	start           time.Time
	parsed          bool
}

type resolvedFiles struct {
	files             []*logFile
	skippedNotRegular int
}

// resolveFiles expands a file source's globs. Matches that are not regular
// files are skipped and counted; a match that resolves outside every allowed
// root fails the request.
func resolveFiles(ctx context.Context, source Source, roots []string) (resolvedFiles, error) {
	var result resolvedFiles
	seen := map[[2]uint64]bool{}
	for _, glob := range source.Paths {
		matches, err := filepath.Glob(glob)
		if err != nil {
			return result, err
		}
		for _, name := range matches {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			resolved, err := filepath.EvalSymlinks(name)
			if errors.Is(err, fs.ErrNotExist) {
				result.skippedNotRegular++ // dangling symlink or removed meanwhile
				continue
			}
			if err != nil {
				return result, err
			}
			root := ""
			for _, candidate := range roots {
				if within(candidate, resolved) {
					root = candidate
					break
				}
			}
			if root == "" {
				return result, codeError(CodePathOutsideRoots, "%s resolves outside allowed_roots", name)
			}
			info, err := os.Stat(resolved)
			if errors.Is(err, fs.ErrNotExist) {
				result.skippedNotRegular++
				continue
			}
			if err != nil {
				return result, err
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
			rel, err := filepath.Rel(root, resolved)
			if err != nil {
				return result, err
			}
			result.files = append(result.files, &logFile{name: name, root: root, rel: rel, dev: key[0], ino: key[1], size: info.Size(), mtime: info.ModTime(), gz: strings.HasSuffix(name, ".gz")})
		}
	}
	slices.SortFunc(result.files, func(a, b *logFile) int { return strings.Compare(a.name, b.name) })
	return result, nil
}

// open opens the file inside its allowed root and checks that it is still the
// regular file that was resolved.
func (f *logFile) open() (*os.File, error) {
	root, err := os.OpenRoot(f.root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.OpenFile(f.rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || uint64(stat.Dev) != f.dev || stat.Ino != f.ino {
		file.Close()
		return nil, fmt.Errorf("%s changed during the request", f.name)
	}
	f.size, f.mtime = info.Size(), info.ModTime()
	return file, nil
}

// readHeader records the first parsable timestamp within the first
// probeLines lines. Unreadable gzip data counts as unparsed.
func (f *logFile) readHeader(parser *timeParser) error {
	file, err := f.open()
	if err != nil {
		return err
	}
	defer file.Close()
	var reader io.Reader = file
	if f.gz {
		z, err := gzip.NewReader(file)
		if err != nil {
			return nil
		}
		defer z.Close()
		reader = z
	}
	p := probeReader(bufio.NewReaderSize(io.LimitReader(reader, headerBytes), 4096), 0, parser)
	f.start, f.parsed = p.time, p.found
	return nil
}

// gzipSize reads the ISIZE trailer: the uncompressed size modulo 2^32 of the
// last member. It is an estimate used only to stop desc scans early.
func gzipSize(file *os.File, size int64) int64 {
	var trailer [4]byte
	if size < 18 {
		return 0
	}
	if _, err := file.ReadAt(trailer[:], size-4); err != nil {
		return 0
	}
	return int64(binary.LittleEndian.Uint32(trailer[:]))
}
