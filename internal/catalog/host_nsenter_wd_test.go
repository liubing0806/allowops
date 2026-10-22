package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// RR-c-02: nsenter -w/-W/-e change the working directory or environment, not
// the mount namespace or root. An absolute target is the same file the host
// inspects; a relative or PATH-searched target cannot be resolved in advance.
func TestHostNsenterWorkingDirectoryAndEnv(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/usr/bin/nsenter"); err != nil {
		t.Fatalf("required local fixture unavailable: %v", err)
	}
	contexts := [][]any{
		{"-w"}, {"--wd"}, {"-w/"}, {"--wd=/"},
		{"-W", "/"}, {"--wdns", "/"}, {"--wdns=/"},
		{"-e"}, {"--env"},
	}
	for _, ctx := range contexts {
		wrapper := append([]any{"/usr/bin/nsenter", "-t", "1", "-n"}, ctx...)
		for _, allow := range []bool{false, true} {
			for _, mode := range []string{"exec", "steps"} {
				t.Run(fmt.Sprintf("%v/allow%t/%s", ctx, allow, mode), func(t *testing.T) {
					check := func(target string, want bool) {
						t.Helper()
						argv := append(append([]any{}, wrapper...), target)
						a := Action{Name: "nsenter_ctx", Description: "nsenter ctx", Risk: "read", Timeout: "1s", MaxOutput: 1024, AllowInterpreter: allow}
						if mode == "exec" {
							a.Exec = argv
						} else {
							a.Steps = []Step{{Name: "one", Exec: argv}}
						}
						if got := CheckHost(a); got.Supported != want {
							t.Errorf("%v: supported=%t; want %t (%s)", argv, got.Supported, want, got.Reason)
						}
					}
					check(script, allow)              // absolute script: inspected on the host
					check("/usr/bin/true", true)      // absolute ELF
					check("./relative/target", false) // relative to a changed cwd
					check("bare_name", false)         // PATH of a changed environment
				})
			}
		}
	}
	// Nested wrappers also lose the cwd/PATH they would resolve against.
	for _, argv := range [][]any{
		{"/usr/bin/nsenter", "-n", "-W", "/", "/usr/bin/env", "./relative"},
		{"/usr/bin/nsenter", "-n", "-e", "/usr/bin/env", "bare_name"},
		{"/usr/bin/nsenter", "-n", "-w", "/usr/bin/timeout", "1", "./relative"},
		{"/usr/bin/nsenter", "-n", "-W", "/", "/usr/bin/env", script},
	} {
		a := Action{Name: "nsenter_nested", Description: "nsenter nested", Risk: "read", Timeout: "1s", MaxOutput: 1024, Exec: argv}
		if got := CheckHost(a); got.Supported {
			t.Errorf("%v: nested target after nsenter -w/-W/-e accepted", argv)
		}
	}
	// A different mount namespace or root keeps the existing name-only checks.
	for _, argv := range [][]any{
		{"/usr/bin/nsenter", "-m", "-w", "./not/on/host"},
		{"/usr/bin/nsenter", "-a", "-e", "bare_name"},
		{"/usr/bin/nsenter", "-n", "-r", "-W", "/", "./not/on/host"},
	} {
		a := Action{Name: "nsenter_other", Description: "nsenter other", Risk: "read", Timeout: "1s", MaxOutput: 1024, Exec: argv}
		if got := CheckHost(a); !got.Supported {
			t.Errorf("%v: other mount namespace/root must keep name-only checks: %s", argv, got.Reason)
		}
	}
}

// RR-c-02: after nsenter -w/-W/-e a relative target or bare command name is
// rejected because the cwd or PATH it resolves against is unknown, even when a
// same-named "#!" script exists in the executor's cwd or PATH. The rejection
// must not depend on whether such a file exists.
func TestHostNsenterUnknownContextRejectsExistingScript(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"relscript", "pathscript"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	if _, err := os.Stat("/usr/bin/nsenter"); err != nil {
		t.Fatalf("required local fixture unavailable: %v", err)
	}
	for _, ctx := range [][]any{{"-w"}, {"--wd=/"}, {"-W", "/"}, {"--wdns=/"}, {"-e"}, {"--env"}} {
		for _, target := range [][]any{
			{"./relscript"}, {"relscript"}, {"pathscript"}, {"/usr/bin/env", "./relscript"}, {"/usr/bin/env", "pathscript"},
		} {
			for _, allow := range []bool{false, true} {
				for _, mode := range []string{"exec", "steps"} {
					t.Run(fmt.Sprintf("%v/%v/allow%t/%s", ctx, target, allow, mode), func(t *testing.T) {
						argv := append(append([]any{"/usr/bin/nsenter", "-t", "1", "-n"}, ctx...), target...)
						a := Action{Name: "nsenter_unknown", Description: "nsenter unknown", Risk: "read", Timeout: "1s", MaxOutput: 1024, AllowInterpreter: allow}
						if mode == "exec" {
							a.Exec = argv
						} else {
							a.Steps = []Step{{Name: "one", Exec: argv}}
						}
						if got := CheckHost(a); got.Supported {
							t.Errorf("%v: accepted; cwd/PATH after nsenter -w/-W/-e are unknown", argv)
						}
					})
				}
			}
		}
	}
}
