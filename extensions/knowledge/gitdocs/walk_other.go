//go:build !linux

package gitdocs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func walkDirectory(ctx context.Context, rootDir string, subdirParts []string, state *loadState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cur := filepath.Clean(rootDir)
	info, err := os.Stat(cur)
	if err != nil || !info.IsDir() {
		return errors.New("gitdocs: failed to open root directory")
	}
	for _, part := range subdirParts {
		if err := ctx.Err(); err != nil {
			return err
		}
		cur = filepath.Join(cur, part)
		linfo, err := os.Lstat(cur)
		if err != nil {
			return errors.New("gitdocs: failed to open subdir")
		}
		if linfo.Mode()&fs.ModeSymlink != 0 {
			return errSymlink
		}
		if !linfo.IsDir() {
			return errors.New("gitdocs: subdir is not a directory")
		}
	}
	return walkDirPath(ctx, cur, "", 0, state)
}

func walkDirPath(ctx context.Context, dirPath, relPrefix string, depth int, state *loadState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.Open(dirPath)
	if err != nil {
		return errors.New("gitdocs: failed to open directory")
	}
	var visible []string
	for {
		if err := ctx.Err(); err != nil {
			f.Close()
			return err
		}
		names, err := f.Readdirnames(256)
		for _, name := range names {
			state.entries++
			if state.entries > state.maxEntries {
				f.Close()
				return errEntryLimit
			}
			if strings.HasPrefix(name, ".") {
				continue
			}
			visible = append(visible, name)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			f.Close()
			return errors.New("gitdocs: failed to read directory")
		}
	}
	f.Close()
	slices.Sort(visible)

	for _, name := range visible {
		if err := ctx.Err(); err != nil {
			return err
		}
		fullPath := filepath.Join(dirPath, name)
		linfo, err := os.Lstat(fullPath)
		if err != nil {
			return errors.New("gitdocs: failed to inspect directory entry")
		}
		if linfo.Mode()&fs.ModeSymlink != 0 {
			return errSymlink
		}
		if linfo.IsDir() {
			if depth >= maxWalkDepth {
				return errDepthLimit
			}
			subPrefix := name
			if relPrefix != "" {
				subPrefix = relPrefix + "/" + name
			}
			if err := walkDirPath(ctx, fullPath, subPrefix, depth+1, state); err != nil {
				return err
			}
			continue
		}
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		if !linfo.Mode().IsRegular() {
			return errNonRegularFile
		}
		data, err := readRegularPath(fullPath, linfo, state.maxFileBytes)
		if err != nil {
			return err
		}
		id := name
		if relPrefix != "" {
			id = relPrefix + "/" + name
		}
		if err := state.addFile(id, data); err != nil {
			return err
		}
	}
	return nil
}

func readRegularPath(path string, expected fs.FileInfo, maxBytes int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("gitdocs: failed to open markdown file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, errors.New("gitdocs: failed to stat markdown file")
	}
	if !info.Mode().IsRegular() || !os.SameFile(expected, info) {
		return nil, errNonRegularFile
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, errors.New("gitdocs: failed to read markdown file")
	}
	if len(data) > maxBytes {
		return nil, errFileSizeLimit
	}
	return data, nil
}
