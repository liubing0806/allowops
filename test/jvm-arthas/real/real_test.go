// Package real runs the jvm_arthas builtin against the JVMs of the local Docker environment
// in test/jvm-arthas (Temurin 8, 11, 17 and 21).
//
// The tests start no container themselves. Bring the environment up first and run the tests as
// root, because attaching to a JVM needs root:
//
//	make real-test
//
// Without ALLOWOPS_REAL_ARTHAS=1, or without root, every test is skipped. The tests put the
// five Arthas files into /usr/share/allowops/arthas/4.3.5 on the host when that directory is
// missing, and remove them at the end.
package real

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/builtin/jvmarthas"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/executor"
	"github.com/liubing0806/allowops/internal/jvmtarget"
)

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

var (
	enabled    = os.Getenv("ALLOWOPS_REAL_ARTHAS") == "1"
	project    = envOr("COMPOSE_PROJECT_NAME", "jvm-arthas")
	portPrefix = envOr("JA_PORT_PREFIX", "18")
	// envRoot is test/jvm-arthas, the directory of the Compose environment.
	envRoot = envOr("JA_ROOT", "..")
	// evidenceDir receives the output of every call when it is set.
	evidenceDir = os.Getenv("JA_EVIDENCE")
	// examplesDir holds the example catalog.
	examplesDir = envOr("JA_EXAMPLES", "../../../examples/catalog")
)

const (
	arthasDirInTarget = "/opt/arthas-minlog"
	mainClass         = "/app/app.jar"
)

// service is one JVM of the Compose environment.
type service struct{ name, suffix string }

func (s service) container() string { return project + "-" + s.name + "-1" }
func (s service) pingURL() string   { return "http://127.0.0.1:" + portPrefix + s.suffix + "/ping" }
func (s service) hotURL(calls int) string {
	return "http://127.0.0.1:" + portPrefix + s.suffix + "/hot?calls=" + strconv.Itoa(calls)
}

var services = []service{{"jdk8", "008"}, {"jdk11", "011"}, {"jdk17", "017"}, {"jdk21", "021"}}

var jdk17 = services[2]

func TestMain(m *testing.M) {
	if os.Getenv("JA_HELPER") == "1" {
		helperMain()
		return
	}
	code := m.Run()
	cleanupHost()
	os.Exit(code)
}

// setup skips the test unless the environment is available and installs the Arthas package on the host.
func setup(t *testing.T) {
	t.Helper()
	if !enabled {
		t.Skip("ALLOWOPS_REAL_ARTHAS=1 is not set")
	}
	if os.Geteuid() != 0 {
		t.Skip("the real-environment tests run as root")
	}
	installPackage(t)
}

var host struct {
	once sync.Once
	err  error
	// installed is true when the tests copied the Arthas files, false when the host had them.
	installed bool
	removeAll []string
}

// installPackage copies the Arthas files to the default directory of the host, unless it exists.
func installPackage(t *testing.T) {
	t.Helper()
	host.once.Do(func() {
		if _, err := os.Stat(jvmarthas.DefaultDir); err == nil {
			return
		}
		host.installed = true
		if _, err := os.Stat("/usr/share/allowops"); err != nil {
			host.removeAll = append(host.removeAll, "/usr/share/allowops")
		} else {
			host.removeAll = append(host.removeAll, jvmarthas.DefaultDir)
		}
		if _, err := os.Stat("/var/lib/allowops-exec"); err != nil {
			host.removeAll = append(host.removeAll, "/var/lib/allowops-exec")
		}
		if err := os.MkdirAll(jvmarthas.DefaultDir, 0o755); err != nil {
			host.err = err
			return
		}
		for _, name := range jvmarthas.FileNames {
			data, err := os.ReadFile(filepath.Join(envRoot, "run", "arthas-minlog", name))
			if err != nil {
				host.err = err
				return
			}
			if err := os.WriteFile(filepath.Join(jvmarthas.DefaultDir, name), data, 0o644); err != nil {
				host.err = err
				return
			}
		}
	})
	if host.err != nil {
		t.Fatalf("installing the Arthas files: %v", host.err)
	}
}

func cleanupHost() {
	for _, p := range host.removeAll {
		os.RemoveAll(p)
	}
}

// sums returns the SHA-256 of the five files that are mounted into the containers.
func sums() map[string]string {
	out := map[string]string{}
	for _, name := range jvmarthas.FileNames {
		data, err := os.ReadFile(filepath.Join(envRoot, "run", "arthas-minlog", name))
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(data)
		out[name] = hex.EncodeToString(sum[:])
	}
	return out
}

func targetOf(s service) jvmtarget.Target {
	return jvmtarget.Target{Name: s.name, Container: s.container(), MainClass: mainClass}
}

func config(kind arthas.Kind) jvmarthas.Config {
	targets := map[string]jvmtarget.Target{}
	for _, s := range services {
		targets[s.name] = targetOf(s)
	}
	c := jvmarthas.Config{Command: kind, Targets: targets, ArthasDir: arthasDirInTarget, SHA256: sums()}
	if kind == arthas.KindSysprop {
		c.SyspropKeys = []string{"java.version", "user.timezone"}
	}
	return c
}

// request holds the arguments that every test uses for a command.
func request(kind arthas.Kind) arthas.Request {
	r := arthas.Request{Kind: kind}
	switch kind {
	case arthas.KindThreadTop:
		r.Top = 3
	case arthas.KindThreadInfo:
		r.ThreadID = 1
	case arthas.KindClassInfo:
		r.Class = "java.lang.String"
	case arthas.KindMethodInfo:
		r.Class, r.Method = "java.lang.String", "length"
	case arthas.KindSysprop:
		r.Key = "java.version"
	}
	return r
}

func docker(t testing.TB, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func ping(s service) error {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(s.pingURL())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != "pong" {
		return fmt.Errorf("ping: status %d, body %q", resp.StatusCode, body)
	}
	return nil
}

// restart gives the service a new JVM, so the attach counter of an earlier test does not apply.
func restart(t testing.TB, s service) {
	t.Helper()
	docker(t, "restart", "-t", "10", s.container())
	deadline := time.Now().Add(150 * time.Second)
	for {
		err := ping(s)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not answer after the restart: %v", s.name, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	// The JVM publishes its counters a moment after the first request is served.
	time.Sleep(2 * time.Second)
}

// snapshot is what a call must leave as it found it.
type snapshot struct {
	pid  int
	pids []int
}

func take(t testing.TB, s service) snapshot {
	t.Helper()
	out := docker(t, "top", s.container(), "-eo", "pid,args")
	var snap snapshot
	for _, line := range strings.Split(out, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		snap.pids = append(snap.pids, pid)
		if snap.pid == 0 && (f[1] == "java" || strings.HasSuffix(f[1], "/java")) {
			snap.pid = pid
		}
	}
	sort.Ints(snap.pids)
	if snap.pid == 0 {
		t.Fatalf("no java process in %s:\n%s", s.name, out)
	}
	return snap
}

func arthasThreads(pid int) int {
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return -1
	}
	n := 0
	for _, task := range tasks {
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/comm", pid, task.Name()))
		if err == nil && strings.HasPrefix(string(comm), "arthas-") {
			n++
		}
	}
	return n
}

// listening returns the ports in the range of Arthas that the process has open, from its network namespace.
func listening(pid int) []int {
	var ports []int
	for _, file := range []string{"tcp", "tcp6"} {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, file))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != "0A" {
				continue
			}
			i := strings.LastIndex(f[1], ":")
			port, err := strconv.ParseUint(f[1][i+1:], 16, 32)
			if err == nil && port >= jvmarthas.DefaultHTTPPortMin && port <= jvmarthas.DefaultHTTPPortMax {
				ports = append(ports, int(port))
			}
		}
	}
	return ports
}

func waitListening(t testing.TB, pid int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for len(listening(pid)) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no Arthas port opened within %s", within)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// postCheck verifies the state after a call: the same JVM runs, nothing listens on an Arthas port,
// no thread is named arthas-, the container has no new process and the application still answers.
func postCheck(t testing.TB, s service, before snapshot) {
	t.Helper()
	after := take(t, s)
	if after.pid != before.pid {
		t.Errorf("%s: the JVM changed from pid %d to %d", s.name, before.pid, after.pid)
	}
	if !slices.Equal(after.pids, before.pids) {
		t.Errorf("%s: processes of the container before %v, after %v", s.name, before.pids, after.pids)
	}
	if n := arthasThreads(after.pid); n != 0 {
		t.Errorf("%s: %d threads named arthas- remain", s.name, n)
	}
	if ports := listening(after.pid); len(ports) > 0 {
		t.Errorf("%s: ports %v are still open", s.name, ports)
	}
	if err := ping(s); err != nil {
		t.Errorf("%s: %v", s.name, err)
	}
}

func evidence(name, text string) {
	if evidenceDir == "" {
		return
	}
	dir := filepath.Join(evidenceDir, "real")
	if os.MkdirAll(dir, 0o755) == nil {
		os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644)
	}
}

// row returns the value of a row of the call section of the output.
func row(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			return ""
		}
		if k, v, ok := strings.Cut(line, "\t"); ok && k == key {
			return v
		}
	}
	return ""
}

func body(out string) string {
	_, rest, _ := strings.Cut(out, "\n\n")
	return rest
}

func newEnv(t testing.TB) jvmarthas.Env {
	t.Helper()
	env := jvmarthas.NewEnv()
	env.StateDir = filepath.Join(t.TempDir(), "arthas")
	return env
}

func runWith(ctx context.Context, env jvmarthas.Env, cfg jvmarthas.Config, s service, req arthas.Request) (jvmarthas.Result, error) {
	return jvmarthas.RunWith(ctx, env, cfg, jvmarthas.Params{Target: s.name, Request: req}, nil)
}

var examples struct {
	once sync.Once
	c    *catalog.Catalog
	err  error
}

// exampleAction returns the example action with its targets and Arthas directory pointed at the environment.
func exampleAction(t testing.TB, name string) catalog.Action {
	t.Helper()
	examples.once.Do(func() { examples.c, examples.err = catalog.Load(examplesDir) })
	if examples.err != nil {
		t.Fatal(examples.err)
	}
	a, ok := examples.c.Actions[name]
	if !ok {
		t.Fatalf("no example action %s", name)
	}
	data, err := json.Marshal(a.BuiltinConfig)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	targets := map[string]any{}
	for _, s := range services {
		targets[s.name] = map[string]any{"container": s.container(), "main_class": mainClass}
	}
	cfg["targets"] = targets
	cfg["arthas_dir"] = arthasDirInTarget
	a.BuiltinConfig = cfg
	return a
}

func TestCapabilityFollowsThePackage(t *testing.T) {
	if !enabled || os.Geteuid() != 0 {
		t.Skip("real-environment test")
	}
	a := exampleAction(t, "jvm_arthas_version")
	// Tests that ran before this one may have copied the files; they are moved away for the first check.
	away := jvmarthas.DefaultDir + ".away"
	if _, err := os.Stat(jvmarthas.DefaultDir); err == nil {
		if !host.installed {
			t.Skip("the Arthas package is installed on this host already")
		}
		if err := os.Rename(jvmarthas.DefaultDir, away); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Rename(away, jvmarthas.DefaultDir) })
	}
	if support := catalog.CheckHost(a); support.Supported {
		t.Errorf("the host without the package supports jvm_arthas: %+v", support)
	} else {
		t.Logf("without the package: %+v", support)
	}
	if _, err := os.Stat(away); err == nil {
		if err := os.Rename(away, jvmarthas.DefaultDir); err != nil {
			t.Fatal(err)
		}
	} else {
		installPackage(t)
	}
	if support := catalog.CheckHost(a); !support.Supported {
		t.Errorf("the host with the package does not support jvm_arthas: %+v", support)
	}
}

func TestExampleChecksumsMatchThePackage(t *testing.T) {
	if !enabled {
		t.Skip("real-environment test")
	}
	want := sums()
	for _, name := range []string{"jvm_arthas_version", "jvm_arthas_dashboard"} {
		got := exampleAction(t, name).BuiltinConfig["sha256"].(map[string]any)
		for file, sum := range want {
			if got[file] != sum {
				t.Errorf("%s: %s is %v in the example, %s in the package", name, file, got[file], sum)
			}
		}
	}
}

// referenceHandlerID is the id of the thread "Reference Handler", which every JVM has and which exists for
// as long as the JVM runs; Spring Boot ends the main thread after the start.
var referenceHandlerID = map[string]int{"jdk8": 2, "jdk11": 2, "jdk17": 2, "jdk21": 9}

// actionCases are the 12 example actions with their arguments and texts that the output must contain.
var actionCases = []struct {
	name   string
	params func(s service) map[string]any
	want   []string
}{
	{"jvm_arthas_dashboard", nil, []string{"# runtime", "# memory", "# gc"}},
	{"jvm_arthas_thread_top", func(service) map[string]any { return map[string]any{"top": 3} }, []string{"# busy threads"}},
	{"jvm_arthas_thread_blocking", nil, []string{"# blocking lock"}},
	{"jvm_arthas_thread_info", func(s service) map[string]any { return map[string]any{"thread_id": referenceHandlerID[s.name]} }, []string{"Reference Handler"}},
	{"jvm_arthas_memory", nil, []string{"# memory", "metaspace"}},
	{"jvm_arthas_jvm", nil, []string{"# RUNTIME", "VM-NAME"}},
	{"jvm_arthas_class_info", func(service) map[string]any { return map[string]any{"class": "java.lang.String"} }, []string{"# class java.lang.String", "final,public"}},
	{"jvm_arthas_method_info", func(service) map[string]any {
		return map[string]any{"class": "java.lang.String", "method": "length"}
	}, []string{"# methods", "length"}},
	{"jvm_arthas_classloader_tree", nil, []string{"# classloaders", "BootstrapClassLoader"}},
	{"jvm_arthas_classloader_list", nil, []string{"# classloaders", "BootstrapClassLoader"}},
	{"jvm_arthas_sysprop", func(service) map[string]any { return map[string]any{"key": "java.version"} }, []string{"java.version"}},
	{"jvm_arthas_version", nil, []string{"version\t" + arthas.Version}},
}

func TestExampleActionsOnEveryJDK(t *testing.T) {
	setup(t)
	for _, s := range services {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			for _, tc := range actionCases {
				a := exampleAction(t, tc.name)
				params := map[string]any{"target": s.name}
				if tc.params != nil {
					for k, v := range tc.params(s) {
						params[k] = v
					}
				}
				// A new JVM resets the attach counter; the interval and count checks have their own tests.
				restart(t, s)
				before := take(t, s)
				started := time.Now()
				res, err := executor.RunWithCallbacks(context.Background(), a, params, nil, nil, executor.Callbacks{})
				took := time.Since(started)
				evidence(s.name+"-"+tc.name+".txt", fmt.Sprintf("exit %d, err %v, took %s\n--- stdout\n%s--- stderr\n%s", res.ExitCode, err, took.Round(time.Millisecond), res.Stdout, res.Stderr))
				if err != nil || res.ExitCode != 0 || res.Stderr != "" {
					t.Errorf("%s: err=%v exit=%d stderr=%q", tc.name, err, res.ExitCode, res.Stderr)
				}
				if got := row(res.Stdout, "status"); got != jvmarthas.StatusOK {
					t.Errorf("%s: status %q\n%s", tc.name, got, res.Stdout)
				}
				if got := row(res.Stdout, "attach"); got != "1 of 5" {
					t.Errorf("%s: attach row %q, want %q", tc.name, got, "1 of 5")
				}
				if got := row(res.Stdout, "cleanup"); got != "ok" {
					t.Errorf("%s: cleanup row %q", tc.name, got)
				}
				if got := row(res.Stdout, "pid"); got != strconv.Itoa(before.pid) {
					t.Errorf("%s: pid row %q, the JVM is %d", tc.name, got, before.pid)
				}
				if strings.TrimSpace(body(res.Stdout)) == "" {
					t.Errorf("%s: no Arthas output", tc.name)
				}
				for _, w := range tc.want {
					if !strings.Contains(res.Stdout, w) {
						t.Errorf("%s: the output does not contain %q", tc.name, w)
					}
				}
				postCheck(t, s, before)
				t.Logf("%s %s: %s", s.name, tc.name, took.Round(time.Millisecond))
			}
		})
	}
}
