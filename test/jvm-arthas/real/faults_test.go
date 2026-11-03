package real

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/builtin/jvmarthas"
	"github.com/liubing0806/allowops/internal/executor"
	"github.com/liubing0806/allowops/internal/jvmtarget/perfdata"
)

// helperConfig is what a helper process needs to run one call.
type helperConfig struct {
	Kind     arthas.Kind `json:"kind"`
	Service  string      `json:"service"`
	StateDir string      `json:"state_dir"`
}

func serviceNamed(name string) service {
	for _, s := range services {
		if s.name == name {
			return s
		}
	}
	panic("unknown service " + name)
}

// helperMain runs one call in a process of its own, so that a test can kill that process.
func helperMain() {
	var hc helperConfig
	if err := json.Unmarshal([]byte(os.Getenv("JA_HELPER_CONFIG")), &hc); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	s := serviceNamed(hc.Service)
	env := jvmarthas.NewEnv()
	env.StateDir = hc.StateDir
	res, err := jvmarthas.RunWith(context.Background(), env, config(hc.Kind), jvmarthas.Params{Target: s.name, Request: request(hc.Kind)}, nil)
	fmt.Print(res.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func startHelper(t *testing.T, s service, kind arthas.Kind, stateDir string) *exec.Cmd {
	t.Helper()
	data, err := json.Marshal(helperConfig{Kind: kind, Service: s.name, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "JA_HELPER=1", "JA_HELPER_CONFIG="+string(data))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

// killMidCall starts a call in a process of its own and kills that process with SIGKILL as soon as
// the Arthas server listens.
func killMidCall(t *testing.T, s service, stateDir string) {
	t.Helper()
	cmd := startHelper(t, s, arthas.KindDashboard, stateDir)
	pid := take(t, s).pid
	waitListening(t, pid, 30*time.Second)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
}

func sessionRecords(stateDir string) []string {
	names, _ := filepath.Glob(filepath.Join(stateDir, "*.session"))
	return names
}

// perJDK runs fn once for every JVM, one after the other, each on a new JVM of the service.
func perJDK(t *testing.T, fn func(t *testing.T, s service)) {
	setup(t)
	for _, s := range services {
		t.Run(s.name, func(t *testing.T) {
			restart(t, s)
			fn(t, s)
		})
	}
}

// later moves the clock of a call forward, so the interval between attaches passes without waiting.
func later(env jvmarthas.Env, d time.Duration) jvmarthas.Env {
	env.Now = func() time.Time { return time.Now().Add(d) }
	return env
}

func TestCallEndedByItsDeadline(t *testing.T) {
	perJDK(t, func(t *testing.T, s service) {
		env := newEnv(t)
		// The deadlines fall in different steps of the call: before the attach, during it, while
		// the server starts and while the command runs (dashboard needs about five seconds).
		// Every call attaches to a new JVM, so the limits on attaches do not apply.
		var before snapshot
		for i, d := range []time.Duration{50 * time.Millisecond, 400 * time.Millisecond, 900 * time.Millisecond, 2 * time.Second, 4 * time.Second} {
			if i > 0 {
				restart(t, s)
			}
			before = take(t, s)
			ctx, cancel := context.WithTimeout(context.Background(), d)
			res, err := runWith(ctx, env, config(arthas.KindDashboard), s, request(arthas.KindDashboard))
			cancel()
			evidence(fmt.Sprintf("%s-deadline-%s.txt", s.name, d), fmt.Sprintf("err %v, exit %d\n%s%s", err, res.ExitCode, res.Stdout, res.Stderr))
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("deadline %s: err = %v, want a deadline error", d, err)
			}
			if got := row(res.Stdout, "status"); got != jvmarthas.StatusTimeout {
				t.Errorf("deadline %s: status %q, want %q\n%s", d, got, jvmarthas.StatusTimeout, res.Stdout)
			}
			got := row(res.Stdout, "cleanup")
			if got != "ok" && got != "" {
				t.Errorf("deadline %s: cleanup %q", d, got)
			}
			if got == "" {
				// The call found no server. An agent that the ended attach loads later would run on, so
				// the JVM is watched for longer than the call watched it.
				time.Sleep(10 * time.Second)
			}
			postCheck(t, s, before)
			t.Logf("deadline %s: status %s, attach %q, cleanup %q", d, row(res.Stdout, "status"), row(res.Stdout, "attach"), row(res.Stdout, "cleanup"))
		}
		// Nothing of the ended calls is left: the next call is not refused for an earlier session.
		res, err := runWith(context.Background(), later(env, 5*time.Minute), config(arthas.KindVersion), s, request(arthas.KindVersion))
		if err != nil || row(res.Stdout, "status") != jvmarthas.StatusOK {
			t.Errorf("call after the deadlines: err=%v\n%s%s", err, res.Stdout, res.Stderr)
		}
		postCheck(t, s, before)
	})
}

func TestExecutionTimeoutOfTheCommand(t *testing.T) {
	perJDK(t, func(t *testing.T, s service) {
		cfg := config(arthas.KindDashboard)
		cfg.ExecTimeout = time.Second
		before := take(t, s)
		res, err := runWith(context.Background(), newEnv(t), cfg, s, request(arthas.KindDashboard))
		evidence(s.name+"-exec-timeout.txt", fmt.Sprintf("err %v, exit %d\n%s%s", err, res.ExitCode, res.Stdout, res.Stderr))
		if err != nil {
			t.Fatal(err)
		}
		if got := row(res.Stdout, "status"); got != jvmarthas.StatusTimeout || res.ExitCode != 1 {
			t.Errorf("status %q, exit %d\n%s", got, res.ExitCode, res.Stdout)
		}
		if got := row(res.Stdout, "cleanup"); got != "ok" {
			t.Errorf("cleanup %q", got)
		}
		postCheck(t, s, before)
	})
}

func TestCancelledCall(t *testing.T) {
	perJDK(t, func(t *testing.T, s service) {
		env := newEnv(t)
		before := take(t, s)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		type outcome struct {
			res jvmarthas.Result
			err error
		}
		done := make(chan outcome, 1)
		go func() {
			res, err := runWith(ctx, env, config(arthas.KindDashboard), s, request(arthas.KindDashboard))
			done <- outcome{res, err}
		}()
		waitListening(t, before.pid, 30*time.Second)
		cancel()
		got := <-done
		evidence(s.name+"-cancel.txt", fmt.Sprintf("err %v, exit %d\n%s%s", got.err, got.res.ExitCode, got.res.Stdout, got.res.Stderr))
		if !errors.Is(got.err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", got.err)
		}
		if status := row(got.res.Stdout, "status"); status != jvmarthas.StatusCancelled {
			t.Errorf("status %q, want %q\n%s", status, jvmarthas.StatusCancelled, got.res.Stdout)
		}
		if c := row(got.res.Stdout, "cleanup"); c != "ok" {
			t.Errorf("cleanup %q", c)
		}
		if n := len(sessionRecords(env.StateDir)); n != 0 {
			t.Errorf("%d session records remain after the clean-up", n)
		}
		postCheck(t, s, before)
	})
}

func TestKilledCallLeavesAServerThatRecoveryEnds(t *testing.T) {
	perJDK(t, func(t *testing.T, s service) {
		env := newEnv(t)
		before := take(t, s)
		killMidCall(t, s, env.StateDir)
		// SIGKILL leaves the Arthas server and its record behind.
		if len(listening(before.pid)) == 0 || arthasThreads(before.pid) == 0 {
			t.Errorf("after the kill: ports %v, %d arthas- threads; the server should still run", listening(before.pid), arthasThreads(before.pid))
		}
		if n := len(sessionRecords(env.StateDir)); n != 1 {
			t.Fatalf("%d session records after the kill, want 1", n)
		}
		rec, err := jvmarthas.Recover(context.Background(), env)
		evidence(s.name+"-recover.txt", fmt.Sprintf("err %v, %+v (%s)", err, rec, rec))
		if err != nil || rec.Cleaned != 1 || len(rec.Failed) != 0 {
			t.Errorf("recovery: %+v, err %v", rec, err)
		}
		if n := len(sessionRecords(env.StateDir)); n != 0 {
			t.Errorf("%d session records after the recovery", n)
		}
		postCheck(t, s, before)
	})
}

func TestNextCallEndsTheServerOfAKilledCall(t *testing.T) {
	perJDK(t, func(t *testing.T, s service) {
		env := newEnv(t)
		before := take(t, s)
		killMidCall(t, s, env.StateDir)
		res, err := runWith(context.Background(), later(env, 5*time.Minute), config(arthas.KindVersion), s, request(arthas.KindVersion))
		evidence(s.name+"-after-kill.txt", fmt.Sprintf("err %v, exit %d\n%s%s", err, res.ExitCode, res.Stdout, res.Stderr))
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("err=%v exit=%d\n%s%s", err, res.ExitCode, res.Stdout, res.Stderr)
		}
		if got := row(res.Stdout, "earlier_sessions"); got != "cleaned 1" {
			t.Errorf("earlier_sessions %q, want %q\n%s", got, "cleaned 1", res.Stdout)
		}
		if got := row(res.Stdout, "attach"); got != "2 of 5" {
			t.Errorf("attach %q, want %q", got, "2 of 5")
		}
		postCheck(t, s, before)
	})
}

func TestSecondCallOnTheSameJVMIsRefused(t *testing.T) {
	setup(t)
	s := jdk17
	restart(t, s)
	env := newEnv(t)
	before := take(t, s)
	type outcome struct {
		res jvmarthas.Result
		err error
	}
	first := make(chan outcome, 1)
	go func() {
		res, err := runWith(context.Background(), env, config(arthas.KindDashboard), s, request(arthas.KindDashboard))
		first <- outcome{res, err}
	}()
	waitListening(t, before.pid, 30*time.Second)
	res, err := runWith(context.Background(), later(env, 5*time.Minute), config(arthas.KindVersion), s, request(arthas.KindVersion))
	evidence("jdk17-busy.txt", fmt.Sprintf("err %v, exit %d\n%s%s", err, res.ExitCode, res.Stdout, res.Stderr))
	if err != nil || res.ExitCode != 1 || row(res.Stdout, "status") != jvmarthas.StatusBusy {
		t.Errorf("second call: err=%v exit=%d\n%s%s", err, res.ExitCode, res.Stdout, res.Stderr)
	}
	got := <-first
	if got.err != nil || row(got.res.Stdout, "status") != jvmarthas.StatusOK {
		t.Errorf("first call: err=%v\n%s%s", got.err, got.res.Stdout, got.res.Stderr)
	}
	postCheck(t, s, before)
}

// burn keeps the JVM busy with requests until stop is called.
func burn(s service, workers, calls int) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	client := http.Client{Timeout: 30 * time.Second}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.hotURL(calls), nil)
				if resp, err := client.Do(req); err == nil {
					resp.Body.Close()
				}
			}
		}()
	}
	return func() { cancel(); wg.Wait() }
}

func TestGuardAbortsACallOnHighCPU(t *testing.T) {
	setup(t)
	s := jdk17
	restart(t, s)
	before := take(t, s)
	cfg := config(arthas.KindDashboard)
	cfg.Guard = jvmarthas.Guard{MaxCPUPercent: 100, Settle: time.Second}
	stop := burn(s, 3, 200000)
	res, err := runWith(context.Background(), newEnv(t), cfg, s, request(arthas.KindDashboard))
	stop()
	evidence("jdk17-guard-cpu.txt", fmt.Sprintf("err %v, exit %d\n%s%s", err, res.ExitCode, res.Stdout, res.Stderr))
	if err != nil {
		t.Fatal(err)
	}
	if got := row(res.Stdout, "status"); got != jvmarthas.StatusAborted || row(res.Stdout, "check") != jvmarthas.GuardCPU || res.ExitCode != 1 {
		t.Errorf("status %q, check %q, exit %d\n%s", got, row(res.Stdout, "check"), res.ExitCode, res.Stdout)
	}
	if got := row(res.Stdout, "cleanup"); got != "ok" {
		t.Errorf("cleanup %q", got)
	}
	t.Logf("guard: status %s, check %s, reason %s", row(res.Stdout, "status"), row(res.Stdout, "check"), row(res.Stdout, "reason"))
	postCheck(t, s, before)
}

func TestGuardLeavesACallAloneBelowItsThreshold(t *testing.T) {
	setup(t)
	s := jdk17
	restart(t, s)
	before := take(t, s)
	cfg := config(arthas.KindDashboard)
	// Forty CPUs: no call reaches it. The settle time is short, so the checks run during the command.
	cfg.Guard = jvmarthas.Guard{MaxCPUPercent: 4000, MaxGCPerSecond: 1000, Settle: time.Second}
	res, err := runWith(context.Background(), newEnv(t), cfg, s, request(arthas.KindDashboard))
	evidence("jdk17-guard-quiet.txt", fmt.Sprintf("err %v, exit %d\n%s%s", err, res.ExitCode, res.Stdout, res.Stderr))
	if err != nil || row(res.Stdout, "status") != jvmarthas.StatusOK {
		t.Errorf("err=%v\n%s%s", err, res.Stdout, res.Stderr)
	}
	postCheck(t, s, before)
}

func TestFilesThatDoNotMatchAreRefusedBeforeTheAttach(t *testing.T) {
	setup(t)
	s := jdk17
	restart(t, s)
	before := take(t, s)

	bad := filepath.Join(t.TempDir(), "arthas-bad")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range jvmarthas.FileNames {
		data, err := os.ReadFile(filepath.Join(envRoot, "run", "arthas-minlog", name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "logback.xml" {
			data = append(data, []byte("\n<!-- changed -->\n")...)
		}
		if err := os.WriteFile(filepath.Join(bad, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	docker(t, "cp", bad, s.container()+":/tmp/arthas-bad")

	for _, tc := range []struct{ name, dir, mention string }{
		{"changed file", "/tmp/arthas-bad", "logback.xml"},
		{"missing directory", "/opt/no-such-arthas", "no-such-arthas"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnv(t)
			cfg := config(arthas.KindVersion)
			cfg.ArthasDir = tc.dir
			res, err := runWith(context.Background(), env, cfg, s, request(arthas.KindVersion))
			evidence("jdk17-files-"+strings.ReplaceAll(tc.name, " ", "-")+".txt", fmt.Sprintf("err %v, exit %d\n%s%s", err, res.ExitCode, res.Stdout, res.Stderr))
			if err != nil || res.ExitCode != 1 {
				t.Errorf("err=%v exit=%d", err, res.ExitCode)
			}
			if row(res.Stdout, "status") != jvmarthas.StatusRefused || row(res.Stdout, "check") != jvmarthas.CheckArthasFiles {
				t.Errorf("status %q, check %q\n%s", row(res.Stdout, "status"), row(res.Stdout, "check"), res.Stdout)
			}
			if !strings.Contains(row(res.Stdout, "reason"), tc.mention) {
				t.Errorf("reason %q does not mention %q", row(res.Stdout, "reason"), tc.mention)
			}
			if row(res.Stdout, "attach") != "" {
				t.Errorf("attach row %q: the call attached", row(res.Stdout, "attach"))
			}
			if counts, _ := filepath.Glob(filepath.Join(env.StateDir, "*.count")); len(counts) != 0 {
				t.Errorf("attach counters %v: an attach was counted", counts)
			}
			if sockets := docker(t, "exec", s.container(), "sh", "-c", "ls /tmp/.java_pid* 2>/dev/null | wc -l"); strings.TrimSpace(sockets) != "0" {
				t.Errorf("the JVM has an attach socket: %s", sockets)
			}
			postCheck(t, s, before)
		})
	}
}

// perfSummary reads the jvm_perfdata example action for the service and returns its JSON.
func perfSummary(t *testing.T, s service) map[string]any {
	t.Helper()
	a := exampleAction(t, "jvm_perfdata")
	targets := map[string]any{s.name: map[string]any{"container": s.container(), "main_class": mainClass}}
	a.BuiltinConfig = map[string]any{"targets": targets, "timeout": "5s"}
	res, err := executor.RunWithCallbacks(context.Background(), a, map[string]any{"target": s.name}, nil, nil, executor.Callbacks{})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("jvm_perfdata: err=%v exit=%d %s%s", err, res.ExitCode, res.Stdout, res.Stderr)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("jvm_perfdata output: %v\n%s", err, res.Stdout)
	}
	return out
}

func memoryUse(t *testing.T, s service) string {
	t.Helper()
	return strings.TrimSpace(docker(t, "stats", "--no-stream", "--format", "{{.MemUsage}}", s.container()))
}

// The container has 1 GiB and the memory of the JVM grows with every attach, so the memory check refuses
// the sixth call before the count does. The limit is raised for this test, so that the count is reached.
func TestAttachCountAndIntervalLimits(t *testing.T) {
	setup(t)
	s := jdk17
	restart(t, s)
	docker(t, "update", "--memory", "2g", "--memory-swap", "2g", s.container())
	t.Cleanup(func() {
		if out, err := exec.Command("docker", "update", "--memory", "1g", "--memory-swap", "1g", s.container()).CombinedOutput(); err != nil {
			t.Errorf("restoring the memory limit: %v\n%s", err, out)
		}
	})
	before := take(t, s)
	env := newEnv(t)
	cfg := config(arthas.KindJVM)
	var log strings.Builder
	note := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		log.WriteString(line + "\n")
		t.Log(line)
	}
	defer func() { evidence("jdk17-attach-limits.txt", log.String()) }()

	note("start: memory %s, metaspace %v", memoryUse(t, s), perfSummary(t, s)["metaspace"])
	res, err := runWith(context.Background(), env, cfg, s, request(arthas.KindJVM))
	if err != nil || row(res.Stdout, "status") != jvmarthas.StatusOK {
		t.Fatalf("first call: err=%v\n%s%s", err, res.Stdout, res.Stderr)
	}
	note("attach 1: memory %s, metaspace %v", memoryUse(t, s), perfSummary(t, s)["metaspace"])

	// A second call at once is refused for the interval.
	res, err = runWith(context.Background(), env, cfg, s, request(arthas.KindJVM))
	note("second call at once: %s %s %s", row(res.Stdout, "status"), row(res.Stdout, "check"), row(res.Stdout, "reason"))
	if err != nil || row(res.Stdout, "status") != jvmarthas.StatusRefused || row(res.Stdout, "check") != jvmarthas.CheckAttachInterval {
		t.Errorf("second call: err=%v\n%s", err, res.Stdout)
	}

	// Attaches 2 to 5 pass when the interval has passed.
	for i := 2; i <= jvmarthas.DefaultMaxAttaches; i++ {
		res, err = runWith(context.Background(), later(env, time.Duration(i)*2*time.Minute), cfg, s, request(arthas.KindJVM))
		if err != nil || row(res.Stdout, "status") != jvmarthas.StatusOK {
			t.Fatalf("attach %d: err=%v\n%s%s", i, err, res.Stdout, res.Stderr)
		}
		if want := fmt.Sprintf("%d of %d", i, jvmarthas.DefaultMaxAttaches); row(res.Stdout, "attach") != want {
			t.Errorf("attach row %q, want %q", row(res.Stdout, "attach"), want)
		}
		note("attach %d: memory %s, metaspace %v", i, memoryUse(t, s), perfSummary(t, s)["metaspace"])
	}

	// The sixth is refused for the count.
	res, err = runWith(context.Background(), later(env, 20*time.Minute), cfg, s, request(arthas.KindJVM))
	note("attach 6: %s %s %s", row(res.Stdout, "status"), row(res.Stdout, "check"), row(res.Stdout, "reason"))
	if err != nil || row(res.Stdout, "status") != jvmarthas.StatusRefused || row(res.Stdout, "check") != jvmarthas.CheckAttachCount {
		t.Errorf("sixth call: err=%v\n%s", err, res.Stdout)
	}
	postCheck(t, s, before)

	// A new JVM has a new counter.
	restart(t, s)
	res, err = runWith(context.Background(), later(env, 30*time.Minute), cfg, s, request(arthas.KindJVM))
	if err != nil || row(res.Stdout, "status") != jvmarthas.StatusOK || row(res.Stdout, "attach") != "1 of 5" {
		t.Errorf("call on the restarted JVM: err=%v\n%s", err, res.Stdout)
	}
}

var gcTime = regexp.MustCompile(`^sun\.gc\.collector\.(\d+)\.(name|invocations|time)$`)

// The guard reads the garbage collection count and time from hsperfdata; the counters must exist on every JDK.
func TestGCCountersExistOnEveryJDK(t *testing.T) {
	perJDK(t, func(t *testing.T, s service) {
		pid := take(t, s).pid
		files, _ := filepath.Glob(fmt.Sprintf("/proc/%d/root/tmp/hsperfdata_*/*", pid))
		if len(files) != 1 {
			t.Fatalf("hsperfdata files: %v", files)
		}
		data, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatal(err)
		}
		pd, err := perfdata.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		times := 0
		for name, e := range pd.Entries {
			m := gcTime.FindStringSubmatch(name)
			if m == nil {
				continue
			}
			if m[2] == "time" {
				times++
			}
			if e.Kind == perfdata.KindText {
				lines = append(lines, name+"="+e.Text)
			} else {
				lines = append(lines, name+"="+strconv.FormatInt(e.Long, 10))
			}
		}
		if times == 0 {
			t.Errorf("no sun.gc.collector.N.time counter")
		}
		freq, _ := pd.Entries["sun.os.hrt.frequency"]
		lines = append(lines, "sun.os.hrt.frequency="+strconv.FormatInt(freq.Long, 10))
		sort.Strings(lines)
		strs := strings.Join(lines, "\n")
		evidence(s.name+"-gc-counters.txt", strs+"\n")
		t.Logf("%s:\n%s", s.name, strs)
	})
}
