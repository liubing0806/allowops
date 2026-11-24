package pluginhost

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func writeCredential(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialReadsFromPinnedDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "opaque-directory")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "opaque-token-path")
	writeCredential(t, path, "original", 0o400)
	c, err := newCredentialFiles(Config{Credentials: map[string]string{"api": path}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	if err := os.Rename(dir, dir+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCredential(t, path, "replacement", 0o600)
	if got, err := c.read("api"); err != nil || string(got) != "original" {
		t.Fatalf("did not use original directory: %q, %v", got, err)
	}
	for _, ref := range []string{"", "opaque ref!", "../api"} {
		if _, err := c.read(ref); !errors.Is(err, errCredentialRef) {
			t.Errorf("expected fixed invalid-reference error: %v", err)
		}
	}
	if _, err := c.read("unset"); !errors.Is(err, errCredentialMissing) {
		t.Errorf("expected fixed unknown-reference error: %v", err)
	}
}

func TestCredentialRejectsInvalidFileModesAndTypes(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "secret")
	c, err := newCredentialFiles(Config{Credentials: map[string]string{"token": base}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	for _, mode := range []os.FileMode{0o000, 0o440, 0o640, 0o620, 0o601, 0o644, 0o700} {
		writeCredential(t, base, "opaque-data", mode)
		if _, err := c.read("token"); err == nil || strings.Contains(err.Error(), "opaque-data") || strings.Contains(err.Error(), base) {
			t.Errorf("mode %o: %v", mode, err)
		}
		if err := os.Remove(base); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mkfifo(base, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.read("token"); !errors.Is(err, errCredentialFile) {
		t.Fatalf("FIFO check: %v", err)
	}
	if err := os.Remove(base); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	writeCredential(t, other, "opaque-data", 0o600)
	if err := os.Symlink("other", base); err != nil {
		t.Fatal(err)
	}
	if _, err := c.read("token"); !errors.Is(err, errCredentialRead) {
		t.Fatalf("last-component symlink check: %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := newCredentialFiles(Config{Credentials: map[string]string{"api": other}}); !errors.Is(err, errCredentialDirectory) {
		t.Fatalf("world writable directory check: %v", err)
	}
}

func TestCredentialReadByteLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	c, err := newCredentialFiles(Config{Credentials: map[string]string{"key": path}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	writeCredential(t, path, strings.Repeat("x", maxCredentialBytes), 0o600)
	if got, err := c.read("key"); err != nil || len(got) != maxCredentialBytes {
		t.Fatalf("size=%d error=%v", len(got), err)
	}
	writeCredential(t, path, strings.Repeat("x", maxCredentialBytes+1), 0o600)
	if got, err := c.read("key"); !errors.Is(err, errCredentialSize) || got != nil {
		t.Fatalf("size=%d error=%v", len(got), err)
	}
}
