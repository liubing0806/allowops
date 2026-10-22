package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// childrenOf returns the pids whose parent is ppid, read from /proc.
func childrenOf(ppid int) []int {
	entries, _ := os.ReadDir("/proc")
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		// The command name may contain spaces; fields resume after the last ')'.
		rest := strings.Fields(string(data[bytes.LastIndexByte(data, ')')+1:]))
		if len(rest) > 1 && rest[1] == strconv.Itoa(ppid) {
			pids = append(pids, pid)
		}
	}
	return pids
}

func TestCatalogTryStopsActionOnInterrupt(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "allowops")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build allowops: %v\n%s", err, output)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "actions"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte("catalog_id: signal_test\nschema_version: 1\ndefaults: {timeout: 60s, max_output: 1KB}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "actions", "nap.yaml"), []byte("name: nap\ndescription: sleep\nrisk: read\nexec: [/bin/sleep, '47']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cli := exec.Command(binary, "catalog", "try", "nap", "--dir", dir)
	var stdout bytes.Buffer
	cli.Stdout = &stdout
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	var sleeper int
	t.Cleanup(func() {
		_ = cli.Process.Kill()
		_ = cli.Wait()
		if sleeper != 0 {
			_ = syscall.Kill(sleeper, syscall.SIGKILL)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for sleeper == 0 && time.Now().Before(deadline) {
		if pids := childrenOf(cli.Process.Pid); len(pids) > 0 {
			sleeper = pids[0]
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if sleeper == 0 {
		t.Fatal("action process did not start")
	}
	if err := cli.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cli.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("CLI did not exit after SIGINT")
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(sleeper, 0); err == syscall.ESRCH {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("action process %d still running after SIGINT; stdout: %s", sleeper, stdout.String())
}
