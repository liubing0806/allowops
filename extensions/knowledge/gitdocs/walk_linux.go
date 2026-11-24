//go:build linux

package gitdocs

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

func walkDirectory(ctx context.Context, rootDir string, subdirParts []string, state *loadState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	curFD, err := unix.Open(rootDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("gitdocs: failed to open root directory")
	}
	for _, part := range subdirParts {
		if err := ctx.Err(); err != nil {
			unix.Close(curFD)
			return err
		}
		var st unix.Stat_t
		if err := unix.Fstatat(curFD, part, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			unix.Close(curFD)
			return errors.New("gitdocs: failed to open subdir")
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			unix.Close(curFD)
			return errSymlink
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			unix.Close(curFD)
			return errors.New("gitdocs: subdir is not a directory")
		}
		nextFD, err := unix.Openat(curFD, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(curFD)
		if err != nil {
			if errors.Is(err, unix.ELOOP) {
				return errSymlink
			}
			return errors.New("gitdocs: failed to open subdir")
		}
		curFD = nextFD
	}
	return walkDirFD(ctx, curFD, "", 0, state)
}

func walkDirFD(ctx context.Context, dirFD int, relPrefix string, depth int, state *loadState) error {
	dirFile := os.NewFile(uintptr(dirFD), "dir")
	defer dirFile.Close()

	var visible []string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		names, err := dirFile.Readdirnames(256)
		for _, name := range names {
			state.entries++
			if state.entries > state.maxEntries {
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
			return errors.New("gitdocs: failed to read directory")
		}
	}
	slices.Sort(visible)

	for _, name := range visible {
		if err := ctx.Err(); err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return errors.New("gitdocs: failed to inspect directory entry")
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			return errSymlink
		case unix.S_IFDIR:
			if depth >= maxWalkDepth {
				return errDepthLimit
			}
			subFD, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				if errors.Is(err, unix.ELOOP) {
					return errSymlink
				}
				return errors.New("gitdocs: failed to open subdirectory")
			}
			subPrefix := name
			if relPrefix != "" {
				subPrefix = relPrefix + "/" + name
			}
			if err := walkDirFD(ctx, subFD, subPrefix, depth+1, state); err != nil {
				return err
			}
		default:
			if !strings.HasSuffix(name, ".md") {
				continue
			}
			data, err := readRegularAt(dirFD, name, state.maxFileBytes)
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
	}
	runtime.KeepAlive(dirFile)
	return nil
}

func readRegularAt(dirFD int, name string, maxBytes int) ([]byte, error) {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, errSymlink
		}
		return nil, errors.New("gitdocs: failed to open markdown file")
	}
	file := os.NewFile(uintptr(fd), "markdown")
	defer file.Close()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, errors.New("gitdocs: failed to stat markdown file")
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errNonRegularFile
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, errors.New("gitdocs: failed to read markdown file")
	}
	if len(data) > maxBytes {
		return nil, errFileSizeLimit
	}
	runtime.KeepAlive(file)
	return data, nil
}
