//go:build linux

package jvmperfdata

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/jvmtarget"
)

// TestRealJVM runs the handler against real HotSpot JVMs (Docker containers and a
// systemd unit) and checks that the JVMs get no signal. It needs root, Docker, systemd and the
// eclipse-temurin images, and is skipped unless ALLOWOPS_REAL_JVM=1:
//
//	go test -c -o /tmp/jvmperfdata.test ./internal/builtin/jvmperfdata
//	sudo -n env ALLOWOPS_REAL_JVM=1 /tmp/jvmperfdata.test -test.run TestRealJVM -test.v
func TestRealJVM(t *testing.T) {
	if os.Getenv("ALLOWOPS_REAL_JVM") != "1" {
		t.Skip("set ALLOWOPS_REAL_JVM=1 to run against real JVMs (root, Docker and systemd required)")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	const mainClass = "com.example.sample.Sample"
	const decoyDir = "/var/tmp/hsp-st1-decoy"
	classes := compileSample(t)
	decoy := filepath.Join(decoyDir, "hsperfdata_root", "1")
	if err := os.MkdirAll(filepath.Dir(decoy), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(decoyDir) })
	decoyData, err := os.ReadFile(filepath.Join(sampleDir(), "jdk8-parallel.hsperf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(decoy, decoyData, 0o644); err != nil {
		t.Fatal(err)
	}

	type jvmCase struct {
		name    string
		image   string
		user    string
		jvmArgs []string
		// tmpLink makes /tmp in the container an absolute symbolic link to the decoy directory.
		tmpLink bool
		// version is the expected prefix of java.version; empty when stderr must name the reason.
		version string
		stderr  string
	}
	cases := []jvmCase{
		{name: "jdk8", image: "eclipse-temurin:8-jre", version: "1.8.0"},
		{name: "jdk11", image: "eclipse-temurin:11-jre", version: "11."},
		{name: "jdk17", image: "eclipse-temurin:17-jre", version: "17."},
		{name: "jdk21", image: "eclipse-temurin:21-jre", version: "21."},
		{name: "jdk21-zgc", image: "eclipse-temurin:21-jre", jvmArgs: []string{"-XX:+UseZGC"}, version: "21."},
		{name: "jdk17-nobody", image: "eclipse-temurin:17-jre", user: "nobody", version: "17."},
		{name: "jdk17-tmp-link", image: "eclipse-temurin:17-jre", tmpLink: true, version: "17."},
		{name: "jdk17-no-perfdata", image: "eclipse-temurin:17-jre", jvmArgs: []string{"-XX:-UsePerfData"}, stderr: "publishes hsperfdata"},
		{name: "jdk17-no-shared-mem", image: "eclipse-temurin:17-jre", jvmArgs: []string{"-XX:+PerfDisableSharedMem"}, stderr: "publishes hsperfdata"},
		{name: "jdk8-no-perfdata", image: "eclipse-temurin:8-jre", jvmArgs: []string{"-XX:-UsePerfData"}, stderr: "publishes hsperfdata"},
	}
	for _, c := range cases {
		args := []string{"run", "-d", "--name", "hsp-st1-" + c.name, "-v", classes + ":/app:ro"}
		if c.user != "" {
			args = append(args, "--user", c.user)
		}
		java := append([]string{"java", "-Xms64m", "-Xmx256m"}, c.jvmArgs...)
		java = append(java, "-cp", "/app", mainClass, "--token=CANARY-must-not-appear")
		if c.tmpLink {
			script := fmt.Sprintf("mkdir -p %[1]s && rm -rf /tmp && ln -s %[1]s /tmp && exec %s", decoyDir, strings.Join(java, " "))
			args = append(args, "--entrypoint", "sh", c.image, "-c", script)
		} else {
			args = append(args, c.image)
			args = append(args, java...)
		}
		name := "hsp-st1-" + c.name
		t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
		docker(t, args...)
	}
	// A control JVM that is attached to on purpose proves that the checks below can see an attach.
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "hsp-st1-control").Run() })
	docker(t, "run", "-d", "--name", "hsp-st1-control", "-v", classes+":/app:ro", "eclipse-temurin:17-jdk", "java", "-cp", "/app", mainClass)
	time.Sleep(8 * time.Second) // JVM start-up and the sample's System.gc()

	resolver := jvmtarget.NewResolver()
	run := func(target jvmtarget.Target) (Result, error) {
		cfg := Config{Targets: map[string]jvmtarget.Target{target.Name: target}}
		return RunWith(context.Background(), resolver, cfg, Params{Target: target.Name})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			name := "hsp-st1-" + c.name
			target := jvmtarget.Target{Name: "web", Container: name, MainClass: mainClass}
			for i := 0; i < 3; i++ {
				r, err := run(target)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(r.Stdout+r.Stderr, "CANARY") || strings.Contains(r.Stdout+r.Stderr, mainClass) {
					t.Fatalf("output discloses the command line:\n%s\n%s", r.Stdout, r.Stderr)
				}
				if c.version == "" {
					if r.ExitCode != 1 || r.Stdout != "" || !strings.Contains(r.Stderr, c.stderr) {
						t.Fatalf("result = %+v; want exit 1 and stderr naming %s", r, c.stderr)
					}
					continue
				}
				var out struct {
					PID int `json:"pid"`
					JVM struct {
						Version string `json:"version"`
					} `json:"jvm"`
					Heap struct {
						Used int64 `json:"used"`
					} `json:"heap"`
					GC struct {
						Collectors []struct {
							Name string `json:"name"`
						} `json:"collectors"`
					} `json:"gc"`
					Threads struct {
						Live, Daemon int64
					} `json:"threads"`
					Classes struct {
						Loaded int64 `json:"loaded"`
					} `json:"classes"`
				}
				if r.ExitCode != 0 || json.Unmarshal([]byte(r.Stdout), &out) != nil {
					t.Fatalf("result = %+v", r)
				}
				if !strings.HasPrefix(out.JVM.Version, c.version) || out.Heap.Used <= 0 || out.Threads.Live < 3 || out.Threads.Daemon < 1 || out.Classes.Loaded < 100 {
					t.Fatalf("summary = %+v; want java.version %s*", out, c.version)
				}
				if i == 0 {
					t.Logf("pid=%d java.version=%s heap.used=%d threads=%+v classes=%d collectors=%d", out.PID, out.JVM.Version, out.Heap.Used, out.Threads, out.Classes.Loaded, len(out.GC.Collectors))
				}
			}
			assertNoAttach(t, name, false)
			if c.tmpLink {
				// A reader that follows the container's absolute symlink in the host's root reaches the host decoy.
				pid := docker(t, "inspect", "-f", "{{.State.Pid}}", name)
				naive, err := os.ReadFile("/proc/" + strings.TrimSpace(pid) + "/root/tmp/hsperfdata_root/1")
				if err != nil || !bytes.Equal(naive, decoyData) {
					t.Fatalf("control: a plain read through /proc/<pid>/root did not reach the host decoy (err=%v); the test proves nothing", err)
				}
				t.Log("control: a plain read through /proc/<pid>/root reaches the host decoy (JDK 8 data); the handler reported the container's JVM instead")
			}
		})
	}

	// The container with two JVM options at once is unaffected by other containers with the same main class
	// and an unknown container is reported, not guessed.
	r, err := run(jvmtarget.Target{Name: "web", Container: "hsp-st1-no-such-container", MainClass: mainClass})
	if err != nil || r.ExitCode != 1 || !strings.Contains(r.Stderr, "no-such-container") {
		t.Errorf("unknown container: %+v, %v", r, err)
	}
	r, err = run(jvmtarget.Target{Name: "web", Container: "hsp-st1-jdk17", MainClass: "com.example.Other"})
	if err != nil || r.ExitCode != 1 || !strings.Contains(r.Stderr, "no JVM matches") {
		t.Errorf("other main class: %+v, %v", r, err)
	}

	t.Run("control-detects-attach", func(t *testing.T) {
		assertNoAttach(t, "hsp-st1-control", false)
		// jstat -class reads the same hsperfdata file; the class count must agree with it.
		r, err := run(jvmtarget.Target{Name: "control", Container: "hsp-st1-control", MainClass: mainClass})
		if err != nil || r.ExitCode != 0 {
			t.Fatalf("result = %+v, %v", r, err)
		}
		var got struct {
			Classes struct {
				Loaded int64 `json:"loaded"`
			} `json:"classes"`
		}
		if err := json.Unmarshal([]byte(r.Stdout), &got); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(docker(t, "exec", "hsp-st1-control", "jstat", "-class", "1")), "\n")
		fields := strings.Fields(lines[len(lines)-1])
		jstatLoaded, err := strconv.ParseInt(fields[0], 10, 64)
		if len(lines) < 2 || err != nil || got.Classes.Loaded != jstatLoaded {
			t.Fatalf("handler classes.loaded = %d; jstat -class says %q", got.Classes.Loaded, lines)
		}
		t.Logf("classes.loaded = %d, jstat -class Loaded = %d", got.Classes.Loaded, jstatLoaded)
		assertNoAttach(t, "hsp-st1-control", false)
		docker(t, "exec", "hsp-st1-control", "jcmd", "1", "VM.uptime")
		if !hasAttachFiles(t, "hsp-st1-control") {
			t.Fatal("control: jcmd left no .java_pid file, so the absence checks prove nothing")
		}
		docker(t, "kill", "--signal=QUIT", "hsp-st1-control")
		time.Sleep(time.Second)
		if !strings.Contains(docker(t, "logs", "hsp-st1-control"), "Full thread dump") {
			t.Fatal("control: SIGQUIT printed no thread dump, so the absence checks prove nothing")
		}
	})

	t.Run("systemd", func(t *testing.T) {
		// PrivateTmp hides /tmp and /var/tmp from the unit, so the JRE and the classes live elsewhere.
		work, err := os.MkdirTemp("/opt", "hsp-st1-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(work)
		if err := os.Chmod(work, 0o755); err != nil {
			t.Fatal(err)
		}
		docker(t, "create", "--name", "hsp-st1-extract", "eclipse-temurin:17-jre")
		defer exec.Command("docker", "rm", "-f", "hsp-st1-extract").Run()
		docker(t, "cp", "hsp-st1-extract:/opt/java/openjdk", work)
		if err := exec.Command("cp", "-r", classes, filepath.Join(work, "classes")).Run(); err != nil {
			t.Fatal(err)
		}
		unit := "hsp-st1-api.service"
		// A failed transient unit of an earlier run stays loaded until it is reset.
		exec.Command("systemctl", "stop", unit).Run()
		exec.Command("systemctl", "reset-failed", unit).Run()
		defer exec.Command("systemctl", "reset-failed", unit).Run()
		out, err := exec.Command("systemd-run", "--unit="+unit, "--property=PrivateTmp=yes", "--property=WorkingDirectory=/",
			filepath.Join(work, "openjdk", "bin", "java"), "-Xms64m", "-Xmx256m", "-cp", filepath.Join(work, "classes"), mainClass, "--token=CANARY-must-not-appear").CombinedOutput()
		if err != nil {
			t.Fatalf("systemd-run: %v: %s", err, out)
		}
		defer exec.Command("systemctl", "stop", unit).Run()
		time.Sleep(6 * time.Second)
		mainPID := strings.TrimSpace(strings.TrimPrefix(runOut(t, "systemctl", "show", "--property=MainPID", "--", unit), "MainPID="))
		target := jvmtarget.Target{Name: "api", SystemdUnit: unit}
		for i := 0; i < 3; i++ {
			r, err := run(target)
			if err != nil || r.ExitCode != 0 {
				t.Fatalf("result = %+v, %v", r, err)
			}
			var got struct {
				PID int `json:"pid"`
				JVM struct {
					Version string `json:"version"`
				} `json:"jvm"`
			}
			if err := json.Unmarshal([]byte(r.Stdout), &got); err != nil || strconv.Itoa(got.PID) != mainPID || !strings.HasPrefix(got.JVM.Version, "17.") {
				t.Fatalf("output = %s (MainPID %s)", r.Stdout, mainPID)
			}
			if strings.Contains(r.Stdout, "CANARY") {
				t.Fatal("output discloses the command line")
			}
		}
		// PrivateTmp: the file is not in the host's /tmp, only in the unit's mount namespace.
		if _, err := os.Stat("/tmp/hsperfdata_root/" + mainPID); err == nil {
			t.Error("the host's /tmp has the JVM's hsperfdata, so PrivateTmp did not take effect")
		}
		if dumps := runOut(t, "journalctl", "-u", unit, "--no-pager", "-o", "cat"); strings.Contains(dumps, "Full thread dump") {
			t.Errorf("the unit's JVM printed a thread dump:\n%s", dumps)
		}
		if runOut(t, "find", "/proc/"+mainPID+"/root/tmp", "-maxdepth", "1", "(", "-name", ".java_pid*", "-o", "-name", ".attach_pid*", ")") != "" {
			t.Error("attach files in the unit's /tmp")
		}
		// A stopped unit is a stderr report.
		exec.Command("systemctl", "stop", unit).Run()
		r, err := run(target)
		if err != nil || r.ExitCode != 1 || r.Stderr == "" {
			t.Errorf("stopped unit: %+v, %v", r, err)
		}
	})
}

// sampleDir is the testdata directory of the PerfData parser, found from this file so that a
// compiled test binary can run from any directory.
func sampleDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "jvmtarget", "perfdata", "testdata")
}

func compileSample(t *testing.T) string {
	t.Helper()
	src := filepath.Join(sampleDir(), "src")
	out := t.TempDir()
	docker(t, "run", "--rm", "-v", src+":/src:ro", "-v", out+":/out", "eclipse-temurin:21-jdk",
		"javac", "--release", "8", "-Xlint:-options", "-d", "/out", "/src/com/example/sample/Sample.java")
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("chmod", "-R", "a+rX", out).Run(); err != nil {
		t.Fatal(err)
	}
	return out
}

// assertNoAttach checks that nothing attached to or signalled the JVM of the container:
// no attach socket or trigger file and no thread dump on its standard output.
func assertNoAttach(t *testing.T, container string, want bool) {
	t.Helper()
	if got := hasAttachFiles(t, container); got != want {
		t.Errorf("%s: attach files present = %v", container, got)
	}
	logs := docker(t, "logs", container)
	for _, marker := range []string{"Full thread dump", "Attach Listener", "Heap\n"} {
		if strings.Contains(logs, marker) != want {
			t.Errorf("%s: output contains %q = %v\n%s", container, marker, !want, logs)
		}
	}
}

func hasAttachFiles(t *testing.T, container string) bool {
	t.Helper()
	out := docker(t, "exec", container, "find", "/tmp", "/var/tmp", "-maxdepth", "3", "(", "-name", ".java_pid*", "-o", "-name", ".attach_pid*", ")", "-print")
	return strings.TrimSpace(out) != ""
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	return runOut(t, "docker", args...)
}

func runOut(t *testing.T, name string, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr.String())
	}
	// docker logs writes the container's stderr to stderr.
	return stdout.String() + stderr.String()
}
