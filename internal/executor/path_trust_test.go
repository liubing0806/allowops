package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
)

const secretText = "path-trust-fixture\n"

func catPathAction(root string) catalog.Action {
	return catalog.Action{
		Name: "cat_path", Description: "cat_path", Risk: "read", Exec: []any{"/bin/cat", "{file}"}, Timeout: "5s", MaxOutput: 1024,
		Params: map[string]params.Definition{"file": {Type: params.Path, Description: "file", AllowedRoots: []string{root}}},
	}
}

// pathFixture creates root/<dir>/file and applies the modes. Chmod avoids the umask.
func pathFixture(t *testing.T, dirMode, fileMode os.FileMode) (root, file string) {
	t.Helper()
	root = t.TempDir()
	dir := filepath.Join(root, "dir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file = filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte(secretText), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		t.Fatal(err)
	}
	return root, file
}

// requireTrustedTemp skips a test that needs accepted paths when an ancestor
// of the temp directory is itself writable by other users on this machine.
func requireTrustedTemp(t *testing.T) {
	t.Helper()
	root, file := pathFixture(t, 0o755, 0o644)
	if _, err := Run(context.Background(), catPathAction(root), map[string]any{"file": file}, nil); err != nil {
		t.Skipf("temp directory ancestors are not trusted on this machine: %v", err)
	}
}

func TestPathParameterRejectsComponentsOthersCanWrite(t *testing.T) {
	requireTrustedTemp(t)
	for name, modes := range map[string][2]os.FileMode{
		"group writable directory": {0o775, 0o644},
		"other writable directory": {0o757, 0o644},
		"group writable file":      {0o755, 0o664},
		"other writable file":      {0o755, 0o666},
	} {
		t.Run(name, func(t *testing.T) {
			root, file := pathFixture(t, modes[0], modes[1])
			r, err := Run(context.Background(), catPathAction(root), map[string]any{"file": file}, nil)
			if err == nil || !strings.Contains(err.Error(), "PATH_NOT_TRUSTED") {
				t.Fatalf("err = %v, want PATH_NOT_TRUSTED", err)
			}
			if strings.Contains(err.Error(), file) {
				t.Errorf("error echoes the path: %v", err)
			}
			if r.Stdout != "" {
				t.Errorf("command ran and printed %q", r.Stdout)
			}
		})
	}
}

func TestPathParameterAcceptsOwnedChildOfStickyDirectory(t *testing.T) {
	requireTrustedTemp(t)
	// Like /tmp: others can create entries but cannot replace ours.
	root, file := pathFixture(t, 0o755|os.ModeSticky|0o022, 0o600)
	r, err := Run(context.Background(), catPathAction(root), map[string]any{"file": file}, nil)
	if err != nil || r.Stdout != secretText {
		t.Fatalf("stdout = %q, err = %v; want the file content", r.Stdout, err)
	}
}

func TestPathParameterChecksEveryStepBeforeAnyStarts(t *testing.T) {
	requireTrustedTemp(t)
	root, file := pathFixture(t, 0o775, 0o644)
	a := catPathAction(root)
	a.Exec = nil
	a.Steps = []catalog.Step{{Name: "first", Exec: []any{"/bin/cat", "{file}"}}, {Name: "second", Exec: []any{"/bin/cat", "{file}"}}}
	started := false
	r, err := RunWithCallbacks(context.Background(), a, map[string]any{"file": file}, nil, nil, Callbacks{Started: func() error { started = true; return nil }})
	if err == nil || !strings.Contains(err.Error(), "PATH_NOT_TRUSTED") {
		t.Fatalf("err = %v, want PATH_NOT_TRUSTED", err)
	}
	if started {
		t.Error("an untrusted path must be rejected before the action starts")
	}
	for _, step := range r.Steps {
		if step.Stdout != "" {
			t.Errorf("step %s printed %q", step.Name, step.Stdout)
		}
	}
}
