package executor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/redact"
)

func helperAction(mode string) catalog.Action {
	return catalog.Action{Name: "helper", Description: "helper", Risk: "read", Exec: []any{os.Args[0], "-test.run=TestProcessHelper", "--", mode}, Timeout: "5s", MaxOutput: 1024}
}

func TestProcessHelper(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			switch os.Args[i+1] {
			case "env":
				fmt.Print(strings.Join(os.Environ(), "\n"))
			case "output":
				fmt.Print("password=" + strings.Repeat("s", 2000) + "\n" + strings.Repeat("x", 2000))
				fmt.Fprint(os.Stderr, strings.Repeat("e", 2000))
			case "parent":
				child := exec.Command(os.Args[0], "-test.run=TestProcessHelper", "--", "child")
				child.Stdout = os.Stdout
				child.Stderr = os.Stderr
				if err := child.Start(); err != nil {
					os.Exit(2)
				}
				fmt.Printf("%d\n", child.Process.Pid)
				time.Sleep(time.Hour)
			case "escape", "detach":
				child := exec.Command(os.Args[0], "-test.run=TestProcessHelper", "--", "child")
				child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
				child.Stdout = os.Stdout
				child.Stderr = os.Stderr
				if err := child.Start(); err != nil {
					os.Exit(2)
				}
				if err := os.WriteFile(os.Args[i+2], []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
					os.Exit(2)
				}
				if os.Args[i+1] == "detach" {
					// Like a daemon started without closing inherited output.
					fmt.Print("started\n")
					os.Exit(0)
				}
				time.Sleep(time.Hour)
			case "child":
				time.Sleep(time.Hour)
			case "exit":
				os.Exit(7)
			case "long":
				fmt.Print(strings.Repeat("x", redact.DefaultMaxLine+1))
			}
			os.Exit(0)
		}
	}
}

// Security 5: remove every inherited variable and fix the four allowed variables.
func TestSecurity5Environment(t *testing.T) {
	t.Setenv("ALLOWOPS_ATTACK_SECRET", "must-not-leak")
	t.Setenv("PATH", "/attacker")
	t.Setenv("LD_PRELOAD", "evil")
	r, err := Run(context.Background(), helperAction("env"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "PATH=/usr/sbin:/usr/bin:/sbin:/bin\nLANG=C.UTF-8\nPAGER=cat\nSYSTEMD_PAGER="
	if r.Stdout != want || r.ExitCode != 0 {
		t.Fatalf("got %#v, want %q", r, want)
	}
}

// Security 6: a deadline kills the entire process group, including descendants holding output pipes.
func TestSecurity6ProcessGroupTimeout(t *testing.T) {
	a := helperAction("parent")
	// The parent is the race-instrumented test binary; allow it time to start and print the child PID under load.
	a.Timeout = "2s"
	start := time.Now()
	r, err := Run(context.Background(), a, nil, nil)
	if err == nil || r.ExitCode != -1 || time.Since(start) > 5*time.Second {
		t.Fatalf("%#v err=%v elapsed=%v", r, err, time.Since(start))
	}
	pid, err := strconv.Atoi(strings.TrimSpace(r.Stdout))
	if err != nil {
		t.Fatalf("missing child PID: %q", r.Stdout)
	}
	defer func() { _ = syscall.Kill(pid, syscall.SIGKILL) }()
	for i := 0; i < 50; i++ {
		data, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if os.IsNotExist(readErr) || (readErr == nil && strings.Contains(string(data), ") Z ")) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("child %d remained alive", pid)
}

// A descendant that leaves the process group survives the deadline kill and
// keeps the output pipes open; the run must still end shortly after the kill.
func TestEscapedDescendantDoesNotHoldRunOpen(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Cleanup(func() {
		if data, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(string(data)); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	a := helperAction("escape")
	a.Exec = append(a.Exec, pidFile)
	a.Timeout = "2s"
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), a, nil, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("run with a killed parent reported success")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("run still waits for output pipes held by an escaped descendant")
	}
}

// A command that exits 0 after starting a descendant outside its process group
// that keeps the output pipes open succeeded; only its output may be incomplete.
func TestDetachedDescendantKeepsSuccessfulExit(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Cleanup(func() {
		if data, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(string(data)); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	a := helperAction("detach")
	a.Exec = append(a.Exec, pidFile)
	a.Timeout = "60s"
	type outcome struct {
		r   Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		r, err := Run(context.Background(), a, nil, nil)
		done <- outcome{r, err}
	}()
	select {
	case o := <-done:
		if o.err != nil || o.r.ExitCode != 0 {
			t.Fatalf("exit_code=%d error=%v; want 0 and no error", o.r.ExitCode, o.err)
		}
		if o.r.Stdout != "started\n" || !o.r.Truncated {
			t.Fatalf("stdout=%q truncated=%v; want the output written before exit, marked truncated", o.r.Stdout, o.r.Truncated)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run still waits for output pipes held by a detached descendant")
	}
}

// Security 7: independently cap stdout and stderr after complete-line redaction.
func TestSecurity7RedactBeforeTruncate(t *testing.T) {
	r, err := Run(context.Background(), helperAction("output"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || len(r.Stdout) != 1024 || len(r.Stderr) != 1024 || !strings.HasPrefix(r.Stdout, "[REDACTED:") || strings.Contains(r.Stdout, "ssss") {
		t.Fatalf("%#v", r)
	}
	for _, tc := range []struct {
		s string
		n int64
	}{{"1KB", 1024}, {"2MB", 2097152}, {"42", 42}} {
		n, err := catalog.ParseSize(tc.s)
		if err != nil || n != tc.n {
			t.Fatalf("%s => %d %v", tc.s, n, err)
		}
	}
}

func TestExitAndOverlongOutput(t *testing.T) {
	r, err := Run(context.Background(), helperAction("exit"), nil, nil)
	if err != nil || r.ExitCode != 7 {
		t.Fatalf("%#v %v", r, err)
	}
	r, err = Run(context.Background(), helperAction("long"), nil, nil)
	if err == nil || r.Stdout != "" {
		t.Fatalf("length=%d err=%v", len(r.Stdout), err)
	}
	a := helperAction("env")
	a.Timeout = "0s"
	if _, err := Run(context.Background(), a, nil, nil); err == nil {
		t.Fatal("accepted unbounded execution")
	}
}
