package jvmarthas

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/jvmtarget"
)

// arthasTree writes the five files below root/dir and returns their checksums.
func arthasTree(t *testing.T, root, dir string) map[string]string {
	t.Helper()
	sums := map[string]string{}
	if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range FileNames {
		content := []byte("content of " + name)
		if err := os.WriteFile(filepath.Join(root, dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		sums[name] = hex.EncodeToString(sum[:])
	}
	return sums
}

func openTestRoot(t *testing.T, dir string) Files {
	t.Helper()
	r, err := jvmtarget.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

const filesDir = "/usr/share/allowops/arthas/4.3.5"

func TestVerifyFilesAcceptsTheExpectedFiles(t *testing.T) {
	base := t.TempDir()
	sums := arthasTree(t, base, filesDir)
	if err := verifyFiles(openTestRoot(t, base), filesDir, sums); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFilesRejects(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, base string, sums map[string]string)
		want   string
	}{
		{"changed content", func(t *testing.T, base string, _ map[string]string) {
			if err := os.WriteFile(filepath.Join(base, filesDir, "arthas-core.jar"), []byte("tampered"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "arthas-core.jar"},
		{"missing file", func(t *testing.T, base string, _ map[string]string) {
			if err := os.Remove(filepath.Join(base, filesDir, "logback.xml")); err != nil {
				t.Fatal(err)
			}
		}, "logback.xml"},
		{"missing directory", func(t *testing.T, base string, _ map[string]string) {
			if err := os.RemoveAll(filepath.Join(base, "usr")); err != nil {
				t.Fatal(err)
			}
		}, "arthas-agent.jar"},
		{"symbolic link instead of the file", func(t *testing.T, base string, _ map[string]string) {
			path := filepath.Join(base, filesDir, "arthas.properties")
			os.Remove(path)
			other := filepath.Join(base, "other")
			if err := os.WriteFile(other, []byte("content of arthas.properties"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, path); err != nil {
				t.Fatal(err)
			}
		}, "arthas.properties"},
		{"directory instead of the file", func(t *testing.T, base string, _ map[string]string) {
			path := filepath.Join(base, filesDir, "arthas-spy.jar")
			os.Remove(path)
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}, "arthas-spy.jar"},
		{"wrong checksum in the configuration", func(t *testing.T, _ string, sums map[string]string) {
			sums["arthas-agent.jar"] = strings.Repeat("0", 64)
		}, "arthas-agent.jar"},
		{"file larger than the limit", func(t *testing.T, base string, sums map[string]string) {
			big := make([]byte, maxFileBytes+1)
			if err := os.WriteFile(filepath.Join(base, filesDir, "arthas-core.jar"), big, 0o644); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(big)
			sums["arthas-core.jar"] = hex.EncodeToString(sum[:])
		}, "arthas-core.jar"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			sums := arthasTree(t, base, filesDir)
			tc.change(t, base, sums)
			err := verifyFiles(openTestRoot(t, base), filesDir, sums)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %s", err, tc.want)
			}
		})
	}
}

func TestVerifyFilesFollowsLinksOnlyInsideTheRoot(t *testing.T) {
	base := t.TempDir()
	sums := arthasTree(t, base, "/real/arthas")
	outside := t.TempDir()
	arthasTree(t, outside, "/real/arthas") // identical files outside the root must not be read
	if err := os.MkdirAll(filepath.Join(base, "usr/share/allowops"), 0o755); err != nil {
		t.Fatal(err)
	}
	// An absolute link in the middle of the path resolves inside the root, to /real/arthas.
	if err := os.Symlink("/real/arthas", filepath.Join(base, "usr/share/allowops/arthas")); err != nil {
		t.Fatal(err)
	}
	if err := verifyFiles(openTestRoot(t, base), "/usr/share/allowops/arthas", sums); err != nil {
		t.Fatalf("link inside the root: %v", err)
	}
	// A link that points out of the root through the real file system must not be followed.
	if err := os.Remove(filepath.Join(base, "usr/share/allowops/arthas")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "real/arthas"), filepath.Join(base, "usr/share/allowops/arthas")); err != nil {
		t.Fatal(err)
	}
	if err := verifyFiles(openTestRoot(t, base), "/usr/share/allowops/arthas", sums); err == nil {
		t.Error("a link to a directory outside the root was followed")
	}
}

func TestCheckInstalled(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "arthas")
	arthasTree(t, base, "arthas")
	if err := CheckInstalled(dir); err != nil {
		t.Fatalf("complete directory: %v", err)
	}
	for _, name := range FileNames {
		path := filepath.Join(dir, name)
		saved, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := CheckInstalled(dir); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("without %s: err = %v", name, err)
		}
		// A directory or a symbolic link is not the file.
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := CheckInstalled(dir); err == nil {
			t.Errorf("a directory named %s was accepted", name)
		}
		os.Remove(path)
		if err := os.Symlink(filepath.Join(base, "elsewhere"), path); err != nil {
			t.Fatal(err)
		}
		if err := CheckInstalled(dir); err == nil {
			t.Errorf("a symbolic link named %s was accepted", name)
		}
		os.Remove(path)
		if err := os.WriteFile(path, saved, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckInstalled(filepath.Join(base, "missing")); err == nil {
		t.Error("a missing directory was accepted")
	}
	if err := CheckInstalled(dir); err != nil {
		t.Errorf("after restoring: %v", err)
	}
}
