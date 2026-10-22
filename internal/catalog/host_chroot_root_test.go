package catalog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/liubing0806/allowops/internal/params"
)

// RR-c-01: chroot into any spelling of the local root keeps the local
// filesystem, so its target gets the same shebang/interpreter checks as "/".
func TestHostChrootLocalRootSpellings(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(dir, "rootlink")
	if err := os.Symlink("/", rootLink); err != nil {
		t.Fatal(err)
	}
	loopA, loopB := filepath.Join(dir, "loopa"), filepath.Join(dir, "loopb")
	if err := os.Symlink(loopB, loopA); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(loopA, loopB); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/proc/self/root"); err != nil {
		t.Skipf("/proc/self/root unavailable: %v", err)
	}
	for _, root := range []string{"/", "//", "/.", "/usr/..", rootLink, "/proc/self/root"} {
		for _, allow := range []bool{false, true} {
			a := Action{Name: "chroot_root", Description: "chroot root", Risk: "read", Timeout: "1s", MaxOutput: 1024, AllowInterpreter: allow}
			a.Exec = []any{"/usr/sbin/chroot", root, script}
			wantAccepted := allow
			if _, err := ResolveExecutable(a.Exec, nil, allow); (err == nil) != wantAccepted {
				t.Errorf("root=%q allow=%t: ResolveExecutable accepted=%t; want %t (err=%v)", root, allow, err == nil, wantAccepted, err)
			}
			if got := CheckHost(a); got.Supported != wantAccepted {
				t.Errorf("root=%q allow=%t: CheckHost supported=%t; want %t (%s)", root, allow, got.Supported, wantAccepted, got.Reason)
			}
		}
	}
	// A root that cannot be resolved is rejected (fail closed), with or without
	// allow_interpreter.
	for _, allow := range []bool{false, true} {
		a := Action{Name: "chroot_loop", Description: "chroot loop", Risk: "read", Timeout: "1s", MaxOutput: 1024, AllowInterpreter: allow}
		a.Exec = []any{"/usr/sbin/chroot", loopA, script}
		if got := CheckHost(a); got.Supported {
			t.Errorf("allow=%t: unresolvable chroot root accepted", allow)
		}
	}
	// A different root keeps the existing name-only checks, also with --skip-chdir.
	other := t.TempDir()
	for _, argv := range [][]any{
		{"/usr/sbin/chroot", other, script},
		{"/usr/sbin/chroot", "--skip-chdir", other, script},
		{"/usr/sbin/chroot", filepath.Join(dir, "missing"), script},
	} {
		a := Action{Name: "chroot_other", Description: "chroot other", Risk: "read", Timeout: "1s", MaxOutput: 1024, Exec: argv}
		if got := CheckHost(a); !got.Supported {
			t.Errorf("%v: other root must keep name-only checks: %s", argv, got.Reason)
		}
	}
}

// A root supplied by a parameter may render as the local root.
func TestHostChrootDynamicRootRejected(t *testing.T) {
	a := Action{
		Name: "chroot_param", Description: "chroot param", Risk: "read", Timeout: "1s", MaxOutput: 1024,
		Params: map[string]params.Definition{"root": {Type: params.String, Description: "root"}},
		Exec:   []any{"/usr/sbin/chroot", "{root}", "/usr/bin/true"},
	}
	if got := CheckHost(a); got.Supported {
		t.Errorf("dynamic chroot root accepted: %+v", got)
	}
}
