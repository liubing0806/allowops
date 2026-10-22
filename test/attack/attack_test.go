package attack

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/executor"
	"github.com/liubing0806/allowops/internal/params"
)

// Security 1, 2 and T10: metacharacters reach an actual echo process unchanged.
func TestSecurity1LiteralShellAttacks(t *testing.T) {
	a := catalog.Action{Name: "echo", Description: "echo", Risk: "read", Params: map[string]params.Definition{"value": {Type: params.String, MaxLen: 128, Description: "value"}}, Exec: []any{"/bin/echo", "{value}"}, Timeout: "1s", MaxOutput: 1024}
	for _, input := range []string{"; rm -rf /", "$(id)", "`id`", "a{value}b"} {
		r, err := executor.Run(context.Background(), a, map[string]any{"value": input}, nil)
		if err != nil || r.ExitCode != 0 || r.Stdout != input+"\n" {
			t.Fatalf("%q => %#v %v", input, r, err)
		}
	}
	for _, input := range []string{"--output=/etc/passwd", strings.Repeat("x", 10000), "a\nb", "a\rb", "a\x00b"} {
		if _, err := executor.Run(context.Background(), a, map[string]any{"value": input}, nil); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}

// Security 1: shell command strings must never occur in production Go source.
func TestSecurity1NoShellCommandStrings(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, forbidden := range []string{"sh -c", "bash -c"} {
			if strings.Contains(string(data), forbidden) {
				t.Errorf("%s contains %q", path, forbidden)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Security 4 and T7: traversal, sibling prefixes and symlink escapes never reach echo.
func TestPathEscapeAttacks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	sibling := root + "-sibling"
	if err := os.Mkdir(sibling, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(sibling)
	a := catalog.Action{Name: "echo_path", Description: "echo path", Risk: "read", Params: map[string]params.Definition{"path": {Type: params.Path, Description: "path", AllowedRoots: []string{root}}}, Exec: []any{"/bin/echo", "{path}"}, Timeout: "1s", MaxOutput: 1024}
	for _, path := range []string{"../../etc/shadow", filepath.Join(root, "..", filepath.Base(outside)), link, sibling, "-escape"} {
		r, err := executor.Run(context.Background(), a, map[string]any{"path": path}, nil)
		if err == nil || r.Stdout != "" {
			t.Fatalf("accepted path %q => %#v %v", path, r, err)
		}
	}
}
