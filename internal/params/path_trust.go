package params

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ErrPathNotTrusted is the fixed rejection code for a path that someone other
// than root or the running uid could replace. The error never carries the path.
var ErrPathNotTrusted = errors.New("PATH_NOT_TRUSTED")

type entryOwner struct {
	mode fs.FileMode
	uid  uint32
}

func lstatOwner(path string) (entryOwner, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return entryOwner{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return entryOwner{}, errors.New("no ownership information")
	}
	return entryOwner{mode: info.Mode(), uid: stat.Uid}, nil
}

// CheckPathTrusted closes the gap between ResolvePath and the moment the target
// program reopens the path: the program may run as root and follows whatever is
// on disk then. It walks every component from "/" to the final entry without
// following links and requires each to be owned by root or uid and not
// writable by group or other, so no other user can rename or replace a
// component after the check. A directory with the sticky bit may be group or
// other writable (like /tmp): others cannot replace entries they do not own,
// but the directory and its child entries are still checked. ACLs and mount
// options are not examined. The check must run in the process that executes
// the command, with the uid the command runs as.
func CheckPathTrusted(path string, uid int) error {
	return checkPathTrusted(path, uint32(uid), lstatOwner)
}

func checkPathTrusted(path string, uid uint32, stat func(string) (entryOwner, error)) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrPathNotTrusted
	}
	current := "/"
	rest := strings.TrimPrefix(path, "/")
	for {
		entry, err := stat(current)
		if err != nil || !entryTrusted(entry, uid) {
			return ErrPathNotTrusted
		}
		if rest == "" {
			return nil
		}
		name, remainder, _ := strings.Cut(rest, "/")
		current, rest = filepath.Join(current, name), remainder
	}
}

func entryTrusted(entry entryOwner, uid uint32) bool {
	if entry.mode&fs.ModeSymlink != 0 || (entry.uid != 0 && entry.uid != uid) {
		return false
	}
	if entry.mode.Perm()&0o022 == 0 {
		return true
	}
	return entry.mode.IsDir() && entry.mode&fs.ModeSticky != 0
}

// CheckPathsTrusted applies CheckPathTrusted to every path-typed value that
// Parse returned. The error names the parameter, not the path.
func CheckPathsTrusted(defs map[string]Definition, values map[string]any, uid int) error {
	for _, name := range names(defs) {
		if defs[name].Type != Path {
			continue
		}
		if path, ok := values[name].(string); ok {
			if err := CheckPathTrusted(path, uid); err != nil {
				return fmt.Errorf("parameter %s: %w", name, err)
			}
		}
	}
	return nil
}
