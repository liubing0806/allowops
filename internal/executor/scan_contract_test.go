package executor

import (
	"context"
	"errors"
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
)

func TestScanContractProcess(t *testing.T) {
	for i, arg := range os.Args {
		if arg != "--scan-fixture" || i+3 >= len(os.Args) {
			continue
		}
		mode, path, release := os.Args[i+1], os.Args[i+2], os.Args[i+3]
		if mode == "parent-exit" || mode == "parent-signal" {
			child := exec.Command(os.Args[0], "-test.run=^TestScanContractProcess$", "--", "--scan-fixture", "writer", path, release)
			child.Stdout = os.Stdout
			child.Stderr = os.Stderr
			if child.Start() != nil {
				os.Exit(20)
			}
			if os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
				os.Exit(21)
			}
			if mode == "parent-signal" {
				_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
				os.Exit(23)
			}
			os.Exit(7)
		}
		if mode == "writer" {
			for {
				if _, err := os.Stat(release); err == nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
		} else if os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
			os.Exit(22)
		}
		fmt.Print("one\ntwo\nthree\n")
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
}

func TestScanContractPreservesPreexistingSignal(t *testing.T) {
	for _, mode := range []string{"exec", "stop", "continue"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path, release := filepath.Join(dir, "pid"), filepath.Join(dir, "release")
			a := scanAction()
			a.Exec = []any{os.Args[0], "-test.run=^TestScanContractProcess$", "--", "--scan-fixture", "parent-signal", path, release}
			if mode != "exec" {
				a.Steps = []catalog.Step{{Name: "signalled", Exec: a.Exec}, {Name: "next", Exec: []any{"/usr/bin/printf", `next\n`}}}
				a.Exec = nil
				a.OnError = mode
			}
			r, err := RunWithCallbacks(context.Background(), a, nil, nil, nil, Callbacks{Started: func() error { waitScanProcessZombie(t, path); return os.WriteFile(release, []byte("release"), 0600) }})
			if err != nil || r.ExitCode != -1 || !r.ScanLimitReached {
				t.Errorf("preexisting SIGKILL with later scan: %+v err=%v; want signal exit -1/nil/scan_limit", r, err)
			}
			if mode != "exec" && (len(r.Steps) != 2 || r.Steps[1].Skipped != (mode == "stop")) {
				t.Errorf("signal %s steps=%+v", mode, r.Steps)
			}
		})
	}
}

func scanAction() catalog.Action {
	return catalog.Action{Name: "scan", Description: "scan contract", Risk: "read", Exec: []any{"/usr/bin/printf", `one\ntwo\nthree\n`}, Timeout: "5s", MaxOutput: 1024, MaxScan: 8}
}

func TestScanContractControlledSuccess(t *testing.T) {
	for _, mode := range []string{"exec", "stop", "continue"} {
		t.Run(mode, func(t *testing.T) {
			a := scanAction()
			if mode != "exec" {
				a.Steps = []catalog.Step{{Name: "capped", Exec: a.Exec}, {Name: "next", Exec: []any{"/usr/bin/printf", `next\n`}}}
				a.Exec = nil
				a.OnError = mode
			}
			var callbacks []StepResult
			r, err := RunWithCallbacks(context.Background(), a, nil, nil, nil, Callbacks{StepCompleted: func(s StepResult, err error) error { callbacks = append(callbacks, s); return err }})
			if err != nil || r.ExitCode != 0 || !r.ScanLimitReached {
				t.Errorf("scan-only result=%+v err=%v; want exit0/nil/scan_limit", r, err)
			}
			if mode == "exec" {
				if r.Stdout != "one\ntwo\n" {
					t.Errorf("stdout=%q", r.Stdout)
				}
			} else if len(callbacks) != 2 || callbacks[1].Skipped || callbacks[1].Stdout != "next\n" || callbacks[0].ExitCode == nil || *callbacks[0].ExitCode != 0 {
				t.Errorf("scan-only step callbacks=%+v; want both executed and first exit0", callbacks)
			}
		})
	}
}

func waitScanProcessZombie(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid := strings.TrimSpace(string(data))
			stat, err := os.ReadFile("/proc/" + pid + "/stat")
			if err == nil {
				p := strings.LastIndex(string(stat), ") ")
				if p >= 0 && string(stat[p+2:p+3]) == "Z" {
					return
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("fixture process did not reach zombie state before bounded deadline")
}

func TestScanContractPreservesNonzeroExit(t *testing.T) {
	for _, mode := range []string{"exec", "stop", "continue"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path, release := filepath.Join(dir, "pid"), filepath.Join(dir, "release")
			a := scanAction()
			a.Exec = []any{os.Args[0], "-test.run=^TestScanContractProcess$", "--", "--scan-fixture", "parent-exit", path, release}
			if mode != "exec" {
				a.Steps = []catalog.Step{{Name: "nonzero", Exec: a.Exec}, {Name: "next", Exec: []any{"/usr/bin/printf", `next\n`}}}
				a.Exec = nil
				a.OnError = mode
			}
			r, err := RunWithCallbacks(context.Background(), a, nil, nil, nil, Callbacks{Started: func() error { waitScanProcessZombie(t, path); return os.WriteFile(release, []byte("release"), 0600) }})
			if err != nil || r.ExitCode != 7 || !r.ScanLimitReached {
				t.Errorf("real nonzero exit with scan: %+v err=%v; want exit7/nil/scan_limit", r, err)
			}
			if mode != "exec" && (len(r.Steps) != 2 || r.Steps[1].Skipped != (mode == "stop")) {
				t.Errorf("%s steps=%+v", mode, r.Steps)
			}
		})
	}
}

func TestScanContractPreservesContextAndCallbackErrors(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout", "callback"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "pid")
			a := scanAction()
			a.Exec = []any{os.Args[0], "-test.run=^TestScanContractProcess$", "--", "--scan-fixture", "wait", path, "unused"}
			ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
			defer cancel()
			sentinel := errors.New("callback failure")
			want := error(context.Canceled)
			if mode == "timeout" {
				want = context.DeadlineExceeded
			}
			if mode == "callback" {
				want = sentinel
			}
			r, err := RunWithCallbacks(ctx, a, nil, nil, nil, Callbacks{Started: func() error {
				waitScanProcessZombie(t, path)
				switch mode {
				case "cancel":
					cancel()
				case "timeout":
					<-ctx.Done()
				case "callback":
					return sentinel
				}
				return nil
			}})
			if !r.ScanLimitReached || !errors.Is(err, want) {
				t.Errorf("scan with %s: %+v err=%v; want %v", mode, r, err, want)
			}
		})
	}
}
