package pluginhost

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectedCredentialRotationAndContainment(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "volume")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "token")
	files, err := newCredentialFiles(Config{Credentials: map[string]string{"token": path}, AllowProjectedCredentials: true})
	if errors.Is(err, errProjected) {
		t.Skip("openat2 unavailable; startup failed closed")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer files.close()
	link := func(target, name string) {
		t.Helper()
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	link("..data/token", path)
	for _, name := range []string{"first", "second", "oversize"} {
		revision := filepath.Join(dir, name)
		if err := os.Mkdir(revision, 0o700); err != nil {
			t.Fatal(err)
		}
		body := name
		if name == "oversize" {
			body = strings.Repeat("a", maxCredentialBytes+1)
		}
		writeCredential(t, filepath.Join(revision, "token"), body, 0o600)
		staging := filepath.Join(dir, "..data_staging")
		link(name, staging)
		if err := os.Rename(staging, filepath.Join(dir, "..data")); err != nil {
			t.Fatal(err)
		}
		got, err := files.read("token")
		if name == "oversize" {
			if !errors.Is(err, errCredentialSize) || got != nil {
				t.Fatalf("oversize projected credential: %v", err)
			}
		} else if err != nil || string(got) != body {
			t.Fatalf("projected revision %s: data=%q, err=%v", name, got, err)
		}
	}
	outside := filepath.Join(parent, "outside")
	writeCredential(t, outside, "outside-data", 0o600)
	for _, target := range []string{"../outside", outside} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		link(target, path)
		if got, err := files.read("token"); got != nil || !errors.Is(err, errCredentialRead) {
			t.Fatalf("projected credential escaped root: %v", err)
		}
	}
}
