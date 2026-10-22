package catalog

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHostLocalWrapperTargets(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "check")
	alias := filepath.Join(dir, "alias")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/sh", alias); err != nil {
		t.Fatal(err)
	}
	wrappers := [][]any{
		{}, {"/usr/bin/env"}, {"/usr/bin/timeout", "1"}, {"/usr/bin/nice", "-n", "1"},
		{"/usr/bin/ionice", "-c", "2"}, {"/usr/bin/stdbuf", "-oL"}, {"/usr/bin/xargs", "-r"},
		{"/usr/bin/env", "/usr/bin/timeout", "1", "/usr/bin/nice"},
	}
	for i, wrapper := range wrappers {
		for _, target := range []string{script, alias, "/usr/bin/true"} {
			for _, allow := range []bool{false, true} {
				a := Action{Name: "wrapped", Description: "wrapped", Risk: "read", Timeout: "1s", MaxOutput: 1024, AllowInterpreter: allow}
				a.Exec = append(append([]any{}, wrapper...), target)
				want := allow || target == "/usr/bin/true"
				if support := CheckHost(a); support.Supported != want {
					t.Errorf("wrapper=%d target=%s allow=%t: supported=%t want=%t reason=%s", i, target, allow, support.Supported, want, support.Reason)
				}
			}
		}
	}
	for _, mode := range []string{"step", "fallback"} {
		a := Action{Name: "wrapped", Description: "wrapped", Risk: "read", Timeout: "1s", MaxOutput: 1024}
		if mode == "step" {
			a.Steps = []Step{{Name: "one", Exec: []any{"/usr/bin/env", script}}}
		} else {
			a.Exec = []any{dir + "/missing", script}
			a.ExecFallbacks = []string{"/usr/bin/env"}
		}
		if CheckHost(a).Supported {
			t.Errorf("%s accepted nested script", mode)
		}
	}
}

func TestHostWrapperResolutionContext(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "true"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, argv := range [][]any{
		{"/usr/bin/env", "PATH=" + dir, "true"},
		{"/usr/bin/env", "--chdir", dir, "./true"},
		{"/usr/bin/env", "-C" + dir, "PATH=.", "/usr/bin/nice", "true"},
	} {
		a := Action{Name: "context", Description: "context", Risk: "read", Timeout: "1s", MaxOutput: 1024, Exec: argv}
		if CheckHost(a).Supported {
			t.Errorf("accepted script selected by wrapper context: %v", argv)
		}
	}
	t.Setenv("PATH", dir)
	a := Action{Name: "context", Description: "context", Risk: "read", Timeout: "1s", MaxOutput: 1024, Exec: []any{"/usr/bin/env", "true"}}
	if s := CheckHost(a); !s.Supported {
		t.Errorf("must resolve fixed execution PATH, not ambient PATH: %+v", s)
	}
	// A namespace boundary keeps existing name-only checks for its target.
	a.Exec = []any{"/usr/sbin/chroot", dir, "/does/not/exist"}
	if _, err := os.Stat("/usr/sbin/chroot"); err != nil {
		a.Exec[0] = "/usr/bin/chroot"
	}
	if s := CheckHost(a); !s.Supported {
		t.Errorf("chroot target incorrectly inspected on host: %+v", s)
	}
}

func TestHostWrapperFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0700); err != nil {
		t.Fatal(err)
	}
	a := Action{Name: "fifo", Description: "fifo", Risk: "read", Timeout: "1s", MaxOutput: 1024, Exec: []any{"/usr/bin/env", path}}
	done := make(chan HostSupport, 1)
	go func() { done <- CheckHost(a) }()
	select {
	case s := <-done:
		if s.Supported {
			t.Error("nested FIFO accepted")
		}
	case <-time.After(300 * time.Millisecond):
		f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("cleanup failed")
		}
		t.Error("nested FIFO blocked")
	}
}

func TestHostEnvContextMatchesExecution(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for _, d := range []string{"first/second", "second"} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	elf, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("first/second/check", elf, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("second/check", []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/usr/bin/env", "-C", "first", "-C", "second", "/usr/bin/pwd").Output()
	if err != nil || strings.TrimSpace(string(out)) != dir+"/second" {
		t.Fatalf("env fixture cwd=%q err=%v", out, err)
	}
	a := Action{Name: "context", Description: "context", Risk: "read", Timeout: "1s", MaxOutput: 1024, Exec: []any{"/usr/bin/env", "-C", "first", "-C", "second", "./check"}}
	if s := CheckHost(a); s.Supported {
		t.Errorf("repeated env -C inspected wrong executable: %+v; want unsupported script", s)
	}
	if err := os.WriteFile("trusted", elf, 0700); err != nil {
		t.Fatal(err)
	}
	a.Exec = []any{"/usr/bin/env", "PATH=", "trusted"}
	if s := CheckHost(a); !s.Supported {
		t.Errorf("empty PATH must inspect cwd executable: %+v", s)
	}
}
