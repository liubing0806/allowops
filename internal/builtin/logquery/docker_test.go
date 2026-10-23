package logquery

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testImage is a local image; tests never pull.
const testImage = "alpine:latest"

// realDocker uses the local Docker daemon at socket. Without one the test is
// skipped, unless ALLOWOPS_REQUIRE_DOCKER=1.
func realDocker(t *testing.T, socket string) func(args ...string) string {
	t.Helper()
	probe, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		if os.Getenv("ALLOWOPS_REQUIRE_DOCKER") == "1" {
			t.Fatalf("local Docker required: %v", err)
		}
		t.Skipf("local Docker unavailable: %v", err)
	}
	probe.Close()
	previous := dockerSocket
	dockerSocket = socket
	t.Cleanup(func() { dockerSocket = previous })
	return func(args ...string) string {
		t.Helper()
		out, err := exec.Command("docker", append([]string{"-H", "unix://" + socket}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
}

// startContainer runs script in a new container and removes it afterwards.
func startContainer(t *testing.T, docker func(...string) string, extra []string, script string) string {
	t.Helper()
	suffix := make([]byte, 4)
	rand.Read(suffix)
	name := "allowops-logquery-" + hex.EncodeToString(suffix)
	args := append([]string{"run", "-d", "--pull", "never", "--network", "none", "--name", name}, extra...)
	docker(append(args, testImage, "sh", "-c", script)...)
	t.Cleanup(func() { exec.Command("docker", "-H", "unix://"+dockerSocket, "rm", "-f", name).Run() })
	return name
}

func waitFor(t *testing.T, what string, ready func() bool) {
	t.Helper()
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if ready() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestDockerUntilWithLimit reproduces design 1.3 on the local Docker: A1..A1000,
// a 4 second pause, B1..B1000. until is 2 seconds after A1000.
func TestDockerUntilWithLimit(t *testing.T) {
	docker := realDocker(t, "/var/run/docker.sock")
	script := `i=1; while [ $i -le 1000 ]; do echo A$i; i=$((i+1)); done; sleep 4; ` +
		`i=1; while [ $i -le 1000 ]; do echo B$i; i=$((i+1)); done; sleep 600`
	name := startContainer(t, docker, nil, script)
	var logs string
	waitFor(t, "B1000", func() bool {
		logs = docker("logs", "-t", name)
		return strings.Contains(logs, " B1000\n")
	})
	var a1000 time.Time
	scanner := bufio.NewScanner(strings.NewReader(logs))
	for scanner.Scan() {
		if stamp, text, _ := strings.Cut(scanner.Text(), " "); text == "A1000" {
			a1000, _ = time.Parse(time.RFC3339Nano, stamp)
		}
	}
	if a1000.IsZero() {
		t.Fatalf("A1000 not found in docker logs -t")
	}
	mid2 := a1000.Add(2 * time.Second).Format(time.RFC3339Nano)
	tail := docker("logs", "--until", mid2, "--tail", "500", name)
	t.Logf("docker logs --until %s --tail 500: %d lines", mid2, strings.Count(tail, "\n"))

	cfg := Config{Mode: ModeSearch, Sources: map[string]Source{"web": {Type: TypeContainerStdout, Container: name}}}
	p := Params{Source: "web", Since: a1000.Add(-10 * time.Minute).Format(time.RFC3339Nano), Until: mid2, Limit: 500}
	out, err := search(t, cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	got := texts(out.Records)
	if fmt.Sprint(got) != fmt.Sprint(series("A", 1000, 501)) || !out.HasMore || out.Matched != 1000 {
		t.Fatalf("log_query until=%s limit=500: %d records, matched %d, first %v last %v", mid2, len(got), out.Matched, got[:min(1, len(got))], got[max(0, len(got)-1):])
	}
	t.Logf("log_query until=%s limit=500 desc: %d records, %s .. %s, matched=%d, scanned_bytes=%d", mid2, len(got), got[0], got[len(got)-1], out.Matched, out.ScannedBytes)
	p.Cursor = out.NextCursor
	if out, err = search(t, cfg, p); err != nil || fmt.Sprint(texts(out.Records)) != fmt.Sprint(series("A", 500, 1)) || out.HasMore {
		t.Fatalf("second page: %v %d records", err, len(out.Records))
	}
	asc := Params{Source: "web", Since: mid2, Until: a1000.Add(time.Minute).Format(time.RFC3339Nano), Limit: 500, Order: "asc"}
	if out, err = search(t, cfg, asc); err != nil || fmt.Sprint(texts(out.Records)) != fmt.Sprint(series("B", 1, 500)) {
		t.Fatalf("asc since=mid2: %v %d records", err, len(out.Records))
	}
}

// TestDockerContainerFileBindMount reads a log file in a bind mount and
// rejects a symlink to /etc/passwd created inside the container.
func TestDockerContainerFileBindMount(t *testing.T) {
	docker := realDocker(t, "/var/run/docker.sock")
	host := t.TempDir()
	if err := os.Chmod(host, 0o777); err != nil {
		t.Fatal(err)
	}
	writeRecords(t, filepath.Join(host, "app.log"), 0, 9)
	name := startContainer(t, docker, []string{"-v", host + ":/opt/app/logs"}, "sleep 600")
	setNow(t, base.Add(20*time.Minute))
	cfg := containerFileConfig()
	cfg.Sources["files"] = withContainer(cfg.Sources["files"], name)
	out, err := search(t, cfg, Params{Source: "files", Since: "30m"})
	if err != nil || out.Matched != 10 || out.Records[0].File != "/opt/app/logs/app.log" {
		t.Fatalf("bind mount: %v %+v", err, out)
	}
	docker("exec", name, "ln", "-s", "/etc/passwd", "/opt/app/logs/passwd.log")
	if _, err := search(t, cfg, Params{Source: "files", Since: "30m"}); reasonOf(err) != CodePathOutsideRoots {
		t.Fatalf("symlink to /etc/passwd: %v", err)
	}
}

// TestDockerContainerFileOverlay2 needs a Docker daemon with the overlay2
// storage driver at ALLOWOPS_TEST_OVERLAY2_SOCKET and root to read its
// MergedDir. Files are written inside the container, outside any mount.
func TestDockerContainerFileOverlay2(t *testing.T) {
	socket := os.Getenv("ALLOWOPS_TEST_OVERLAY2_SOCKET")
	if socket == "" || os.Geteuid() != 0 {
		t.Skip("set ALLOWOPS_TEST_OVERLAY2_SOCKET to an overlay2 Docker daemon and run as root")
	}
	docker := realDocker(t, socket)
	if driver := strings.TrimSpace(docker("info", "--format", "{{.Driver}}")); driver != "overlay2" {
		t.Fatalf("daemon storage driver %s, want overlay2", driver)
	}
	var content strings.Builder
	for i := 0; i <= 9; i++ {
		content.WriteString(line(base.Add(time.Duration(i)*time.Minute), fmt.Sprintf("record %d", i)))
	}
	script := "mkdir -p /opt/app/logs && printf '%s' \"$LOG\" > /opt/app/logs/app.log && sleep 600"
	name := startContainer(t, docker, []string{"-e", "LOG=" + content.String()}, script)
	waitFor(t, "app.log", func() bool { return strings.Contains(docker("exec", name, "ls", "/opt/app/logs"), "app.log") })
	setNow(t, base.Add(20*time.Minute))
	cfg := containerFileConfig()
	cfg.Sources["files"] = withContainer(cfg.Sources["files"], name)
	out, err := search(t, cfg, Params{Source: "files", Since: "30m"})
	if err != nil || out.Matched != 10 || out.Records[0].File != "/opt/app/logs/app.log" {
		t.Fatalf("overlay2: %v %+v", err, out)
	}
	t.Logf("overlay2: matched=%d first=%q", out.Matched, out.Records[0].Text)
	docker("exec", name, "ln", "-s", "/etc/passwd", "/opt/app/logs/passwd.log")
	if _, err := search(t, cfg, Params{Source: "files", Since: "30m"}); reasonOf(err) != CodePathOutsideRoots {
		t.Fatalf("symlink to /etc/passwd: %v", err)
	}
}

func withContainer(s Source, name string) Source {
	s.Container = name
	return s
}
