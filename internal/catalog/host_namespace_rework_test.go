package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestHostSameFilesystemNamespaceTargets(t *testing.T) {
	dir := t.TempDir()
	script, alias := filepath.Join(dir, "script"), filepath.Join(dir, "alias")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/sh", alias); err != nil {
		t.Fatal(err)
	}
	for _, program := range []string{"/usr/bin/nsenter", "/usr/sbin/chroot", "/usr/bin/true"} {
		if _, err := os.Stat(program); err != nil {
			t.Fatalf("required local fixture unavailable: %s", program)
		}
	}
	for i, wrapper := range [][]any{
		{"/usr/bin/nsenter", "-t", "1", "-n"},
		{"/usr/bin/nsenter", "--target=1", "--net"},
		{"/usr/bin/nsenter", "-t1", "-n", []any{"-F"}},
		{"/usr/sbin/chroot", "/"},
		{"/usr/sbin/chroot", "--userspec=0:0", "/"},
		{"/usr/bin/env", "/usr/bin/nsenter", "-t", "1", "-n", "/usr/sbin/chroot", "/"},
	} {
		for _, mode := range []string{"exec", "steps"} {
			for j, target := range []string{script, alias, "/usr/bin/true"} {
				for _, allow := range []bool{false, true} {
					t.Run(fmt.Sprintf("wrapper%d/%s/target%d/allow%t", i, mode, j, allow), func(t *testing.T) {
						argv := append(append([]any{}, wrapper...), target)
						a := Action{Name: "local_namespace", Description: "local target", Risk: "read", Timeout: "1s", MaxOutput: 1024, AllowInterpreter: allow}
						if mode == "exec" {
							a.Exec = argv
							if _, err := ResolveExecutable(argv, nil, allow); (err == nil) != (allow || j == 2) {
								t.Errorf("ResolveExecutable accepted=%t; want %t", err == nil, allow || j == 2)
							}
						} else {
							a.Steps = []Step{{Name: "one", Exec: argv}}
						}
						if got := CheckHost(a); got.Supported != (allow || j == 2) {
							t.Errorf("CheckHost supported=%t; want %t", got.Supported, allow || j == 2)
						}
					})
				}
			}
		}
	}
}

func TestHostNamespaceFilesystemBoundaries(t *testing.T) {
	for _, argv := range [][]any{
		{"/usr/bin/nsenter", "-t", "1", "-m", "/not/on/host"},
		{"/usr/bin/nsenter", "--mount=/proc/1/ns/mnt", "/not/on/host"},
		{"/usr/bin/nsenter", "-a", "/not/on/host"},
		{"/usr/bin/nsenter", "-n", "--root=/other", "/not/on/host"},
		{"/usr/sbin/chroot", "/other", "/not/on/host"},
	} {
		a := Action{Name: "boundary", Description: "boundary", Risk: "read", Timeout: "1s", MaxOutput: 1024, Exec: argv}
		if s := CheckHost(a); !s.Supported {
			t.Errorf("changed existing namespace boundary for %v: %s", argv, s.Reason)
		}
	}
}
