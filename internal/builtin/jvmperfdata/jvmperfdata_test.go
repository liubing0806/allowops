package jvmperfdata

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/jvmtarget"
)

func sampleFile(t *testing.T, replace ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "jvmtarget", "perfdata", "testdata", "jdk17-g1.hsperf"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(replace); i += 2 {
		if len(replace[i]) != len(replace[i+1]) || !bytes.Contains(data, []byte(replace[i])) {
			t.Fatalf("cannot replace %q with %q", replace[i], replace[i+1])
		}
		data = bytes.Replace(data, []byte(replace[i]), []byte(replace[i+1]), 1)
	}
	return data
}

// fakeHost builds a procfs with one process that the unit "api.service" maps to.
type fakeHost struct {
	t     *testing.T
	proc  string
	root  string
	pid   int
	stats string
}

func newFakeHost(t *testing.T, perfdata []byte) *fakeHost {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHost{t: t, proc: filepath.Join(base, "proc"), root: filepath.Join(base, "root"), pid: 4242}
	dir := filepath.Join(h.proc, fmt.Sprint(h.pid))
	for _, d := range []string{filepath.Join(dir, "ns"), filepath.Join(h.proc, "self", "ns"), filepath.Join(h.root, "tmp", "hsperfdata_app")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.stats = filepath.Join(dir, "stat")
	h.setStart(900)
	uid := os.Getuid()
	write(t, filepath.Join(dir, "status"), fmt.Sprintf("Name:\tjava\nNSpid:\t%d\nUid:\t%d\t%d\t%d\t%d\n", h.pid, uid, uid, uid, uid))
	if err := os.Symlink(h.root, filepath.Join(dir, "root")); err != nil {
		t.Fatal(err)
	}
	if perfdata != nil {
		write(t, filepath.Join(h.root, "tmp", "hsperfdata_app", fmt.Sprint(h.pid)), string(perfdata))
	}
	return h
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (h *fakeHost) setStart(start int) {
	write(h.t, h.stats, fmt.Sprintf("%d (java) S 1 1 1 0 -1 4194560 10 0 0 0 1 2 0 0 20 0 5 0 %d 1000 2000 1 1 1\n", h.pid, start))
}

func (h *fakeHost) resolver() *jvmtarget.Resolver {
	return &jvmtarget.Resolver{
		Proc:    jvmtarget.Proc{Root: h.proc},
		MainPID: func(context.Context, string) (int, error) { return h.pid, nil },
	}
}

func config() Config {
	return Config{Targets: map[string]jvmtarget.Target{
		"api": {Name: "api", SystemdUnit: "api.service"},
		"web": {Name: "web", Container: "shop-web", MainClass: "com.example.shop.Main"},
	}}
}

func TestRunPrintsSummary(t *testing.T) {
	h := newFakeHost(t, sampleFile(t))
	r, err := RunWith(context.Background(), h.resolver(), config(), Params{Target: "api"})
	if err != nil || r.ExitCode != 0 || r.Stderr != "" {
		t.Fatalf("result = %+v, %v", r, err)
	}
	var out struct {
		Target string `json:"target"`
		PID    int    `json:"pid"`
		JVM    struct {
			Version string `json:"version"`
		} `json:"jvm"`
		Heap struct {
			Used int64 `json:"used"`
		} `json:"heap"`
		GC struct {
			Collectors []struct {
				Name        string `json:"name"`
				Invocations int64  `json:"invocations"`
			} `json:"collectors"`
		} `json:"gc"`
		Threads struct {
			Live, Daemon, Peak int64
		} `json:"threads"`
		Classes struct {
			Loaded int64 `json:"loaded"`
		} `json:"classes"`
	}
	if err := json.Unmarshal([]byte(r.Stdout), &out); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, r.Stdout)
	}
	if out.Target != "api" || out.PID != 4242 || out.JVM.Version != "17.0.20.1" || out.Heap.Used != 3619120 || out.Classes.Loaded != 500 {
		t.Errorf("output = %+v", out)
	}
	if len(out.GC.Collectors) != 3 || out.GC.Collectors[0].Name != "G1 young collection pauses" {
		t.Errorf("collectors = %+v", out.GC.Collectors)
	}
	if !strings.HasSuffix(r.Stdout, "\n") {
		t.Error("output does not end in a newline")
	}
}

// Anything that can hold a secret stays out of the output, even when the
// JVM's arguments, command line and properties are full of them.
func TestRunNeverPrintsArgumentsOrCommand(t *testing.T) {
	h := newFakeHost(t, sampleFile(t,
		"-Xms64m -Xmx256m", "-Dtok=CANARY-xxx", // java.rt.vmArgs
		"--note=hello", "--tok=CANARY", // sun.rt.javaCommand
		"/app", "/CAN", // java.property.java.class.path
	))
	r, err := RunWith(context.Background(), h.resolver(), config(), Params{Target: "api"})
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("result = %+v, %v", r, err)
	}
	for _, forbidden := range []string{"CANARY", "-Dtok", "--tok", "com.example", "Sample", "/CAN", "vmArgs", "javaCommand"} {
		if strings.Contains(r.Stdout, forbidden) || strings.Contains(r.Stderr, forbidden) {
			t.Errorf("output contains %q:\n%s", forbidden, r.Stdout)
		}
	}
}

func TestRunReportsMissingHsperfdata(t *testing.T) {
	h := newFakeHost(t, nil) // -XX:-UsePerfData leaves no file
	r, err := RunWith(context.Background(), h.resolver(), config(), Params{Target: "api"})
	if err != nil {
		t.Fatal(err)
	}
	if r.ExitCode != 1 || r.Stdout != "" {
		t.Errorf("result = %+v", r)
	}
	for _, want := range []string{"hsperfdata", "UsePerfData", "PerfDisableSharedMem", "api"} {
		if !strings.Contains(r.Stderr, want) {
			t.Errorf("stderr %q lacks %q", r.Stderr, want)
		}
	}
}

func TestRunReportsOperatorErrorsOnStderr(t *testing.T) {
	h := newFakeHost(t, sampleFile(t))
	resolver := h.resolver()
	resolver.MainPID = func(context.Context, string) (int, error) {
		return 0, fmt.Errorf("unit api.service has no main process: %w", jvmtarget.ErrNotRunning)
	}
	r, err := RunWith(context.Background(), resolver, config(), Params{Target: "api"})
	if err != nil || r.ExitCode != 1 || !strings.Contains(r.Stderr, "no main process") {
		t.Errorf("stopped unit: %+v, %v", r, err)
	}
	// A pid that now belongs to another process.
	resolver = h.resolver()
	resolver.MainPID = func(context.Context, string) (int, error) { return 31337, nil }
	r, err = RunWith(context.Background(), resolver, config(), Params{Target: "api"})
	if err != nil || r.ExitCode != 1 || !strings.Contains(r.Stderr, "replaced") {
		t.Errorf("vanished process: %+v, %v", r, err)
	}
	// A target outside the allowlist.
	for _, name := range []string{"db", "", "../etc", "4242", "/proc/1/root"} {
		r, err = RunWith(context.Background(), h.resolver(), config(), Params{Target: name})
		if err != nil || r.ExitCode != 1 || r.Stdout != "" || !strings.Contains(r.Stderr, "api, web") {
			t.Errorf("target %q: %+v, %v", name, r, err)
		}
	}
}

func TestRunHonoursTimeout(t *testing.T) {
	h := newFakeHost(t, sampleFile(t))
	resolver := h.resolver()
	resolver.MainPID = func(ctx context.Context, _ string) (int, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	cfg := config()
	cfg.Timeout = 50 * time.Millisecond
	start := time.Now()
	_, err := RunWith(context.Background(), resolver, cfg, Params{Target: "api"})
	if err == nil || time.Since(start) > 3*time.Second {
		t.Errorf("err = %v after %v", err, time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunWith(ctx, h.resolver(), config(), Params{Target: "api"}); err == nil {
		t.Error("a cancelled context was ignored")
	}
}

func TestConfigValidate(t *testing.T) {
	if err := config().Validate(); err != nil {
		t.Fatal(err)
	}
	if got := config().TargetNames(); len(got) != 2 || got[0] != "api" || got[1] != "web" {
		t.Errorf("names = %v", got)
	}
	tooMany := Config{Targets: map[string]jvmtarget.Target{}}
	for i := 0; i <= MaxTargets; i++ {
		name := fmt.Sprintf("t%d", i)
		tooMany.Targets[name] = jvmtarget.Target{Name: name, SystemdUnit: name + ".service"}
	}
	for name, cfg := range map[string]Config{
		"no targets":       {},
		"empty targets":    {Targets: map[string]jvmtarget.Target{}},
		"too many targets": tooMany,
		"invalid target":   {Targets: map[string]jvmtarget.Target{"a": {Name: "a", SystemdUnit: "--user.service"}}},
		"name mismatch":    {Targets: map[string]jvmtarget.Target{"a": {Name: "b", SystemdUnit: "a.service"}}},
		"negative timeout": {Targets: config().Targets, Timeout: -time.Second},
		"long timeout":     {Targets: config().Targets, Timeout: 11 * time.Second},
	} {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	ok := config()
	ok.Timeout = 10 * time.Second
	if err := ok.Validate(); err != nil {
		t.Errorf("10s timeout: %v", err)
	}
}
