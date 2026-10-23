package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// RR-c-01b: nsenter -r<dir> and --root=<dir> set the root directory. A root
// that is this host's own root keeps the local filesystem, so the target is
// inspected like the target of chroot. util-linux nsenter takes the directory
// only attached (-r<dir>, --root=<dir>); "-r <dir>" is -r without operand and
// <dir> is the program. Plain -r, -a, -m, --mount[=file] keep name-only checks.
func TestHostNsenterExplicitLocalRoot(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fixture")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/usr/bin/nsenter"); err != nil {
		t.Fatalf("required local fixture unavailable: %v", err)
	}
	for _, root := range [][]any{
		{"-r/"}, {"--root=/"}, {"--root=/proc/self/root"}, {"-r/proc/self/root"}, {"--root=//"}, {"--root=/usr/.."},
	} {
		for _, mode := range []string{"exec", "steps"} {
			for _, allow := range []bool{false, true} {
				t.Run(fmt.Sprintf("%v/%s/allow%t", root, mode, allow), func(t *testing.T) {
					for _, tc := range []struct {
						target string
						want   bool
					}{{script, allow}, {"/usr/bin/true", true}} {
						argv := append(append([]any{"/usr/bin/nsenter", "-t", "1", "-n"}, root...), tc.target)
						a := Action{Name: "nsenter_root", Description: "nsenter root", Risk: "read", Timeout: "1s", MaxOutput: 1024, AllowInterpreter: allow}
						if mode == "exec" {
							a.Exec = argv
						} else {
							a.Steps = []Step{{Name: "one", Exec: argv}}
						}
						if got := CheckHost(a); got.Supported != tc.want {
							t.Errorf("%v: supported=%t; want %t (%s)", argv, got.Supported, tc.want, got.Reason)
						}
					}
				})
			}
		}
	}
	// Another root, and the options without a directory, keep name-only checks.
	for _, argv := range [][]any{
		{"/usr/bin/nsenter", "-t", "1", "-n", "-r", "/not/on/host"},
		{"/usr/bin/nsenter", "-t", "1", "-n", "-r/other", "/not/on/host"},
		{"/usr/bin/nsenter", "-t", "1", "-n", "--root=/other", script + ".missing"},
		{"/usr/bin/nsenter", "-t", "1", "-n", "-r", "-W", "/", script},
		{"/usr/bin/nsenter", "-t", "1", "-n", "--root", script},
		{"/usr/bin/nsenter", "-t", "1", "-a", script},
		{"/usr/bin/nsenter", "-t", "1", "-m", script},
		{"/usr/bin/nsenter", "-t", "1", "--mount", script},
		{"/usr/bin/nsenter", "-t", "1", "--mount=/proc/1/ns/mnt", script},
		{"/usr/bin/nsenter", "-t", "1", "-r/", "-m", script},
		{"/usr/bin/nsenter", "-t", "1", "-r/", "-r", script},
	} {
		a := Action{Name: "nsenter_root_other", Description: "nsenter root other", Risk: "read", Timeout: "1s", MaxOutput: 1024, Exec: argv}
		if got := CheckHost(a); !got.Supported {
			t.Errorf("%v: must keep name-only checks: %s", argv, got.Reason)
		}
	}
}
