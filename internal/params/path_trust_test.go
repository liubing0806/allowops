package params

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeTree(entries map[string]entryOwner) func(string) (entryOwner, error) {
	return func(path string) (entryOwner, error) {
		if e, ok := entries[path]; ok {
			return e, nil
		}
		return entryOwner{}, fs.ErrNotExist
	}
}

func TestCheckPathTrustedWalksEveryComponent(t *testing.T) {
	const me, other = 1000, 2000
	dir := func(perm fs.FileMode, uid uint32) entryOwner { return entryOwner{mode: fs.ModeDir | perm, uid: uid} }
	tree := func(change map[string]entryOwner) func(string) (entryOwner, error) {
		entries := map[string]entryOwner{
			"/": dir(0o755, 0), "/var": dir(0o755, 0), "/var/app": dir(0o755, me),
			"/var/app/log": {mode: 0o640, uid: me}, "/var/app/link": {mode: fs.ModeSymlink | 0o777, uid: me},
		}
		for k, v := range change {
			entries[k] = v
		}
		return fakeTree(entries)
	}
	cases := []struct {
		name   string
		path   string
		change map[string]entryOwner
		ok     bool
	}{
		{"owned by root and by the running uid", "/var/app/log", nil, true},
		{"root itself", "/", nil, true},
		{"component owned by another uid", "/var/app/log", map[string]entryOwner{"/var/app": dir(0o755, other)}, false},
		{"final entry owned by another uid", "/var/app/log", map[string]entryOwner{"/var/app/log": {mode: 0o640, uid: other}}, false},
		{"group writable component", "/var/app/log", map[string]entryOwner{"/var": dir(0o775, 0)}, false},
		{"other writable component", "/var/app/log", map[string]entryOwner{"/var/app": dir(0o757, me)}, false},
		{"group writable final entry", "/var/app/log", map[string]entryOwner{"/var/app/log": {mode: 0o660, uid: me}}, false},
		{"sticky world writable component", "/var/app/log", map[string]entryOwner{"/var": dir(0o777|fs.ModeSticky, 0)}, true},
		{"sticky component owned by another uid", "/var/app/log", map[string]entryOwner{"/var": dir(0o777|fs.ModeSticky, other)}, false},
		{"sticky does not excuse a writable child", "/var/app/log", map[string]entryOwner{"/var": dir(0o777|fs.ModeSticky, 0), "/var/app": dir(0o777, me)}, false},
		{"sticky does not excuse a writable file", "/var/app/log", map[string]entryOwner{"/var/app/log": {mode: 0o666 | fs.ModeSticky, uid: me}}, false},
		{"symbolic link", "/var/app/link", nil, false},
		{"missing component", "/var/app/missing", nil, false},
		{"relative path", "var/app/log", nil, false},
		{"unclean path", "/var/app/../app/log", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkPathTrusted(c.path, me, tree(c.change))
			if c.ok && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !c.ok && !errors.Is(err, ErrPathNotTrusted) {
				t.Fatalf("err = %v, want PATH_NOT_TRUSTED", err)
			}
			if err != nil && strings.Contains(err.Error(), c.path) {
				t.Errorf("error echoes the path: %v", err)
			}
		})
	}
}

func TestCheckPathTrustedOnFilesystem(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the fixtures; ownership by another uid cannot be built")
	}
	me := os.Geteuid()
	base := t.TempDir()
	if CheckPathTrusted(base, me) != nil {
		t.Skip("an ancestor of the temp directory is writable by others on this machine")
	}
	dir := filepath.Join(base, "dir")
	file := filepath.Join(dir, "file")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckPathTrusted(file, me); err != nil {
		t.Fatalf("owned, private path rejected: %v", err)
	}
	// Every ancestor belongs to the test user, so another uid must not trust them.
	if err := CheckPathTrusted(file, me+1); !errors.Is(err, ErrPathNotTrusted) {
		t.Errorf("components owned by another uid: err = %v, want PATH_NOT_TRUSTED", err)
	}
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := CheckPathTrusted(file, me); !errors.Is(err, ErrPathNotTrusted) {
		t.Errorf("group writable directory: err = %v, want PATH_NOT_TRUSTED", err)
	}
	// A directory swapped for a symbolic link after resolution is not followed.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, dir); err != nil {
		t.Fatal(err)
	}
	if err := CheckPathTrusted(file, me); !errors.Is(err, ErrPathNotTrusted) {
		t.Errorf("symbolic link component: err = %v, want PATH_NOT_TRUSTED", err)
	}
}

func TestCheckPathsTrustedNamesParameterNotPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the fixtures")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	defs := map[string]Definition{
		"file": {Type: Path, Description: "file", AllowedRoots: []string{base}},
		"name": {Type: String, Description: "name"},
	}
	err := CheckPathsTrusted(defs, map[string]any{"file": base, "name": base}, os.Geteuid())
	if !errors.Is(err, ErrPathNotTrusted) || !strings.Contains(err.Error(), "parameter file") || strings.Contains(err.Error(), base) {
		t.Fatalf("err = %v, want PATH_NOT_TRUSTED naming the parameter only", err)
	}
	// Only path-typed values are checked.
	if err := CheckPathsTrusted(defs, map[string]any{"name": base}, os.Geteuid()); err != nil {
		t.Fatalf("string parameter was checked: %v", err)
	}
}
