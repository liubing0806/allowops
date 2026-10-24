package logsearch

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Design 6.8 item 2: directories, FIFOs and devices matched by path_glob are
// skipped instead of failing the whole search.
func TestSkipsNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeLog(t, path, "hit\n")
	if err := os.Mkdir(filepath.Join(dir, "archive.log"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.log"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{AllowedRoots: []string{dir}}
	r, err := Run(context.Background(), cfg, Params{PathGlob: filepath.Join(dir, "*.log"), Pattern: "hit", Fixed: true})
	if err != nil || r.ExitCode != 0 || r.Stdout != path+":1:hit\n" {
		t.Fatalf("got %#v, %v", r, err)
	}
	r, err = Run(context.Background(), cfg, Params{PathGlob: dir, Pattern: "hit", Fixed: true})
	if err != nil || r.ExitCode != 0 || r.Stdout != "" {
		t.Fatalf("directory only: %#v, %v", r, err)
	}
}
