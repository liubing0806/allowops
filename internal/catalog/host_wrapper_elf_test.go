package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// RR-c-04: env, timeout, ... start the target with execvp. glibc runs an
// executable file that is neither ELF nor "#!" through /bin/sh, so a wrapped
// target must be ELF unless allow_interpreter is set. Top-level exec[0] is
// started by the executor directly (ENOEXEC is an error) and is not affected.
func TestHostWrappedTargetRequiresELF(t *testing.T) {
	dir := t.TempDir()
	text := filepath.Join(dir, "text")
	if err := os.WriteFile(text, []byte("echo no shebang\n"), 0700); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0700); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("\x7fEL"), 0700); err != nil {
		t.Fatal(err)
	}
	badMagic := filepath.Join(dir, "badmagic")
	if err := os.WriteFile(badMagic, []byte("\x7fELGxxxx\necho not elf\n"), 0700); err != nil {
		t.Fatal(err)
	}
	elf, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(dir, "copied")
	if err := os.WriteFile(copied, elf, 0700); err != nil {
		t.Fatal(err)
	}
	wrappers := [][]any{
		{"/usr/bin/env"},
		{"/usr/bin/timeout", "5"},
		{"/usr/bin/nice", "-n", "1"},
		{"/usr/bin/ionice", "-c", "2"},
		{"/usr/bin/stdbuf", "-oL"},
		{"/usr/bin/xargs", "-r"},
		{"/usr/bin/nsenter", "-t", "1", "-n"},
		{"/usr/sbin/chroot", "/"},
		{"/usr/bin/env", "/usr/bin/timeout", "5"},
	}
	for i, wrapper := range wrappers {
		for _, mode := range []string{"exec", "steps"} {
			for _, allow := range []bool{false, true} {
				for _, tc := range []struct {
					name   string
					target string
					elf    bool
				}{{"text", text, false}, {"empty", empty, false}, {"short magic", short, false}, {"wrong last magic byte", badMagic, false}, {"elf", copied, true}} {
					t.Run(fmt.Sprintf("wrapper%d/%s/allow%t/%s", i, mode, allow, tc.name), func(t *testing.T) {
						argv := append(append([]any{}, wrapper...), tc.target)
						a := Action{Name: "wrapped_elf", Description: "wrapped elf", Risk: "read", Timeout: "1s", MaxOutput: 1024, AllowInterpreter: allow}
						if mode == "exec" {
							a.Exec = argv
						} else {
							a.Steps = []Step{{Name: "one", Exec: argv}}
						}
						want := allow || tc.elf
						if got := CheckHost(a); got.Supported != want {
							t.Errorf("%v: supported=%t; want %t (%s)", argv, got.Supported, want, got.Reason)
						}
					})
				}
			}
		}
	}
	// The top-level program keeps the shebang-only check.
	a := Action{Name: "top_level", Description: "top level", Risk: "read", Timeout: "1s", MaxOutput: 1024, Exec: []any{text}}
	if got := CheckHost(a); !got.Supported {
		t.Errorf("top-level non-ELF exec[0] must keep the shebang-only check: %s", got.Reason)
	}
	// A wrapper in another root or mount namespace keeps the name-only checks.
	a.Exec = []any{"/usr/bin/nsenter", "-m", "-t", "1", "/not/on/host"}
	if got := CheckHost(a); !got.Supported {
		t.Errorf("other mount namespace changed: %s", got.Reason)
	}
}
