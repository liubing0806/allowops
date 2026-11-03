package jvmarthas

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/jvmtarget"
)

func noSecrets(t *testing.T, res Result) {
	t.Helper()
	for _, text := range []string{res.Stdout, res.Stderr} {
		if strings.Contains(text, rigPassword) {
			t.Errorf("the output holds the Arthas password:\n%s", text)
		}
	}
}

// wantEnded checks what every call leaves behind after a clean shutdown: no server, no record.
func (r *rig) wantEnded() {
	r.t.Helper()
	if r.host.listening[r.server.port] || r.host.threads != 0 {
		r.t.Errorf("a server is left: listening = %v, threads = %d", r.host.listening, r.host.threads)
	}
	if _, err := r.state().ReadRecord(r.key); !errors.Is(err, fs.ErrNotExist) {
		r.t.Errorf("the session record is still there: %v", err)
	}
	lock, err := r.state().TryLock(r.key)
	if err != nil {
		r.t.Errorf("the lock is still held: %v", err)
		return
	}
	lock.Unlock()
}

func (r *rig) wantNoAttach() {
	r.t.Helper()
	if n := r.jvm.attachCount(); n != 0 {
		r.t.Errorf("the JVM was attached to %d times", n)
	}
	if c, _ := r.state().Counter(r.key); c.Attaches != 0 {
		r.t.Errorf("attach counter = %d, want 0", c.Attaches)
	}
	if _, err := r.state().ReadRecord(r.key); !errors.Is(err, fs.ErrNotExist) {
		r.t.Errorf("a session record exists: %v", err)
	}
}

var cleanupActions = []string{"interrupt_job", "close_session", "exec:reset", "exec:stop"}

func TestRunSucceeds(t *testing.T) {
	r := newRig(t)
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitSuccess || res.Stderr != "" {
		t.Fatalf("exit code %d, stderr %q\n%s", res.ExitCode, res.Stderr, res.Stdout)
	}
	for key, want := range map[string]string{
		"command": "version", "target": "api", "pid": "4242", "status": StatusOK, "attach": "1 of 5", "cleanup": "ok",
	} {
		if got := mustRow(t, res.Stdout, key); got != want {
			t.Errorf("row %s = %q, want %q", key, got, want)
		}
	}
	if !strings.HasPrefix(res.Stdout, "# call\n") || !strings.Contains(res.Stdout, "\n\n# version\nversion\t4.3.5\n") {
		t.Errorf("output:\n%s", res.Stdout)
	}
	want := append([]string{"init_session", "exec:version"}, cleanupActions...)
	if got := r.server.seen(); !slices.Equal(got, want) {
		t.Errorf("Arthas requests = %v, want %v", got, want)
	}
	jar, opts := r.agent()
	if jar != DefaultDir+"/arthas-agent.jar" || opts["core"] != DefaultDir+"/arthas-core.jar" {
		t.Errorf("agent = %q, core = %q", jar, opts["core"])
	}
	for key, want := range map[string]string{
		"httpPort": "18563", "ip": "127.0.0.1", "telnetPort": "-1", "localConnectionNonAuth": "false", "password": rigPassword,
	} {
		if opts[key] != want {
			t.Errorf("agent option %s = %q, want %q", key, opts[key], want)
		}
	}
	disabled := strings.Split(opts["disabledCommands"], ",")
	for _, name := range []string{"version", "reset", "stop"} {
		if slices.Contains(disabled, name) {
			t.Errorf("%s is disabled", name)
		}
	}
	if !slices.Contains(disabled, "ognl") {
		t.Error("ognl is not disabled")
	}
	r.wantEnded()
	if c, _ := r.state().Counter(r.key); c.Attaches != 1 {
		t.Errorf("attach counter = %d, want 1", c.Attaches)
	}
	noSecrets(t, res)
}

func TestRunWritesTheSessionRecordBeforeTheCommand(t *testing.T) {
	r := newRig(t)
	seen := make(chan Record, 1)
	r.server.onExec = func(w http.ResponseWriter, req *http.Request, command string) bool {
		rec, err := r.state().ReadRecord(r.key)
		if err != nil {
			t.Errorf("no record during the command: %v", err)
		}
		seen <- rec
		return false
	}
	if _, err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := <-seen
	if rec.Port != 18563 || rec.Password != rigPassword || rec.SessionID != "sid-1" || rec.Command != "version" || rec.Target != "api" {
		t.Errorf("record = %+v", rec)
	}
	if !rec.Deadline.After(rec.Created) {
		t.Errorf("deadline %s is not after the creation time %s", rec.Deadline, rec.Created)
	}
}

func TestRunMasksTheOutput(t *testing.T) {
	r := newRig(t)
	mask := func(s string) string { return strings.ReplaceAll(s, "4.3.5", "[MASKED]") }
	res, err := RunWith(context.Background(), r.env, r.cfg, r.params(), mask)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Stdout, "4.3.5") || !strings.Contains(res.Stdout, "[MASKED]") {
		t.Errorf("output:\n%s", res.Stdout)
	}
}

func TestRunRefusesBeforeTheAttach(t *testing.T) {
	tests := []struct {
		name   string
		change func(*rig)
		status string
		check  string
	}{
		{"memory", func(r *rig) { r.host.headroom = 10 << 20 }, StatusRefused, CheckMemoryHeadroom},
		{"jdk 7", func(r *rig) { r.jvm.perf = perf(setText("java.property.java.version", "1.7.0_80")) }, StatusUnsupported, CheckJVMVersion},
		{"architecture", func(r *rig) { r.env.Arch = "arm64" }, StatusUnsupported, CheckArchitecture},
		{"attach count", func(r *rig) {
			for i := 0; i < 5; i++ {
				r.state().AddAttach(r.key, time.Now().Add(-time.Hour), 0)
			}
		}, StatusRefused, CheckAttachCount},
		{"attach interval", func(r *rig) { r.state().AddAttach(r.key, time.Now().Add(-5*time.Second), 0) }, StatusRefused, CheckAttachInterval},
		{"attach disabled", func(r *rig) { r.jvm.checkErr = jvmtarget.ErrAttachDisabled }, StatusUnsupported, CheckAttachState},
		{"no instrument module", func(r *rig) { r.jvm.checkErr = jvmtarget.ErrNoInstrument }, StatusUnsupported, CheckAttachState},
		{"SIGQUIT not caught", func(r *rig) { r.jvm.checkErr = jvmtarget.ErrSigQuitNotCaught }, StatusUnsupported, CheckAttachState},
		{"Arthas already running", func(r *rig) { r.jvm.checkErr = jvmtarget.ErrArthasRunning }, StatusRefused, CheckAttachState},
		{"unusable attach socket", func(r *rig) { r.jvm.checkErr = jvmtarget.ErrBadAttachSocket }, StatusRefused, CheckAttachState},
		{"changed checksum", func(r *rig) { r.cfg.SHA256 = goodSHA() }, StatusRefused, CheckArthasFiles},
		{"files cannot be opened", func(r *rig) { r.host.rootErr = errors.New("no mount namespace") }, StatusRefused, CheckArthasFiles},
		{"directory without the files", func(r *rig) { r.cfg.ArthasDir = "/opt/missing" }, StatusRefused, CheckArthasFiles},
		{"no free port", func(r *rig) { r.host.pickErr = jvmtarget.ErrNoFreePort }, StatusRefused, CheckPortRange},
		{"thread count of thread -b", func(r *rig) {
			r.cfg.Command = arthas.KindThreadBlocking
			r.jvm.perf = perf(setLong("java.threads.live", 1001))
		}, StatusRefused, CheckThreadCount},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			tc.change(r)
			before, _ := r.state().Counter(r.key)
			res, err := r.run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != builtin.ExitFailure {
				t.Errorf("exit code %d, want %d", res.ExitCode, builtin.ExitFailure)
			}
			if got := mustRow(t, res.Stdout, "status"); got != tc.status {
				t.Errorf("status = %q, want %q", got, tc.status)
			}
			if got := mustRow(t, res.Stdout, "check"); got != tc.check {
				t.Errorf("check = %q, want %q", got, tc.check)
			}
			if mustRow(t, res.Stdout, "reason") == "" || !strings.Contains(res.Stderr, "jvm_arthas") {
				t.Errorf("stdout:\n%s\nstderr: %q", res.Stdout, res.Stderr)
			}
			if _, ok := rowOf(res.Stdout, "attach"); ok {
				t.Error("an attach row appears although no attach was made")
			}
			if n := r.jvm.attachCount(); n != 0 {
				t.Errorf("the JVM was attached to %d times", n)
			}
			after, _ := r.state().Counter(r.key)
			if after != before {
				t.Errorf("counter changed from %+v to %+v", before, after)
			}
			if _, err := r.state().ReadRecord(r.key); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a session record exists: %v", err)
			}
			if got := r.server.seen(); len(got) != 0 {
				t.Errorf("Arthas received %v", got)
			}
			noSecrets(t, res)
		})
	}
}

func TestRunSecondCallInsideTheIntervalIsRefused(t *testing.T) {
	r := newRig(t)
	if res, err := r.run(context.Background()); err != nil || res.ExitCode != 0 {
		t.Fatalf("first call: %v\n%s", err, res.Stdout)
	}
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if mustRow(t, res.Stdout, "check") != CheckAttachInterval {
		t.Errorf("second call:\n%s", res.Stdout)
	}
	if n := r.jvm.attachCount(); n != 1 {
		t.Errorf("attach count = %d, want 1", n)
	}
}

// hsperfdata updates sun.gc.metaspace.used at a collection only, so the metaspace that an attach loads is missing
// from it until the next collection. Each attach since the collection count last changed counts 20 MiB.
func TestRunCountsTheMetaspaceOfTheAttachesSinceTheLastCollection(t *testing.T) {
	tests := []struct {
		name string
		// collections is the sum of the collector invocations that each of the three calls sees.
		collections [3]int64
		// third is the check that refuses the third call; empty when it passes.
		third string
	}{
		{"no collection since the first attach", [3]int64{41, 41, 41}, CheckMetaspace},
		{"a collection between the first two attaches", [3]int64{41, 42, 42}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			now := time.Now()
			r.env.Now = func() time.Time { return now }
			for i, n := range tc.collections {
				// 256 MiB of MaxMetaspaceSize and 170 MiB in use leave 86 MiB, 64 MiB are required: one attach
				// that is not counted yet fits, two do not. perf() has one full collection; the young ones make up the rest.
				r.jvm.perf = perf(setText("java.rt.vmArgs", "-XX:MaxMetaspaceSize=256m"), setLong("sun.gc.metaspace.used", 170<<20),
					setLong("sun.gc.collector.0.invocations", n-1))
				r.host.root = openTestRoot(t, r.base) // a call closes the root it opened
				res, err := r.run(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				want, check := StatusOK, ""
				if i == 2 && tc.third != "" {
					want, check = StatusRefused, tc.third
				}
				if got, _ := rowOf(res.Stdout, "status"); got != want {
					t.Fatalf("call %d: status %q, want %q\n%s", i+1, got, want, res.Stdout)
				}
				if got, _ := rowOf(res.Stdout, "check"); got != check {
					t.Errorf("call %d: check %q, want %q", i+1, got, check)
				}
				now = now.Add(2 * time.Minute)
			}
		})
	}
}

func TestRunBusyReturnsAtOnce(t *testing.T) {
	r := newRig(t)
	lock, err := r.state().TryLock(r.key)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Unlock()
	start := time.Now()
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("the call waited %s for the lock", d)
	}
	if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusBusy {
		t.Errorf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	if n := r.jvm.attachCount(); n != 0 {
		t.Errorf("the JVM was attached to %d times", n)
	}
	// The lock of the other call is still held.
	if _, err := r.state().TryLock(r.key); !errors.Is(err, ErrBusy) {
		t.Errorf("the other call lost its lock: %v", err)
	}
}

func TestRunFailsBeforeLockingWhenTheTargetIsGone(t *testing.T) {
	r := newRig(t)
	r.resolver.err = jvmtarget.ErrNotRunning
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusFailed {
		t.Errorf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	if !strings.Contains(mustRow(t, res.Stdout, "reason"), "not running") {
		t.Errorf("reason does not name the cause:\n%s", res.Stdout)
	}
}

func TestRunRejectsBadParameters(t *testing.T) {
	r := newRig(t)
	r.cfg.Command = arthas.KindThreadInfo
	for name, p := range map[string]Params{
		"unknown target":           {Target: "other", Request: arthas.Request{ThreadID: 1}},
		"missing thread id":        {Target: "api", Request: arthas.Request{}},
		"argument of another kind": {Target: "api", Request: arthas.Request{ThreadID: 1, Class: "java.lang.String"}},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := RunWith(context.Background(), r.env, r.cfg, p, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != builtin.ExitFailure || !strings.Contains(res.Stderr, "jvm_arthas") {
				t.Errorf("exit code %d, stderr %q", res.ExitCode, res.Stderr)
			}
			r.wantNoAttach()
		})
	}
}

func TestRunIgnoresTheKindOfTheRequest(t *testing.T) {
	r := newRig(t)
	p := r.params()
	p.Request.Kind = arthas.KindDashboard
	res, err := RunWith(context.Background(), r.env, r.cfg, p, nil)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("%v\n%s", err, res.Stdout)
	}
	if got := mustRow(t, res.Stdout, "command"); got != "version" {
		t.Errorf("command = %q, want the one of the configuration", got)
	}
}

func TestRunAttachFailureWithoutAServerEndsWithoutCleanup(t *testing.T) {
	r := newRig(t)
	r.failAttach = true
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusFailed {
		t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	if !strings.Contains(mustRow(t, res.Stdout, "reason"), "attach") {
		t.Errorf("reason does not say that the attach failed:\n%s", res.Stdout)
	}
	if got := mustRow(t, res.Stdout, "attach"); got != "1 of 5" {
		t.Errorf("a failed attach counts: attach row = %q", got)
	}
	if c, _ := r.state().Counter(r.key); c.Attaches != 1 {
		t.Errorf("attach counter = %d, want 1", c.Attaches)
	}
	if got := r.server.seen(); len(got) != 0 {
		t.Errorf("Arthas received %v", got)
	}
	r.wantEnded()
}

func TestRunAttachErrorAfterTheServerStartedStillShutsItDown(t *testing.T) {
	r := newRig(t)
	r.jvm.attachErr = errors.New("the reply was lost")
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusFailed {
		t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	if got := mustRow(t, res.Stdout, "cleanup"); got != "ok" {
		t.Errorf("cleanup = %q", got)
	}
	if got := r.server.seen(); !slices.Equal(got, cleanupActions[2:]) {
		// No session exists, so the two session steps are skipped.
		t.Errorf("Arthas requests = %v, want %v", got, cleanupActions[2:])
	}
	r.wantEnded()
}

// A cancelled attach can still load the agent. Its threads exist at once, its HTTP port opens a
// moment later, and the clean-up has to reach it then: nothing else stops that server.
func TestRunShutsDownAServerThatOpensItsPortAfterTheAttachEnded(t *testing.T) {
	r := newRig(t)
	r.jvm.attachErr = errors.New("the call ended")
	start := r.jvm.onAttach
	r.jvm.onAttach = func(req jvmtarget.AttachRequest) error {
		r.host.mu.Lock()
		r.host.threads = 3
		r.host.mu.Unlock()
		time.AfterFunc(100*time.Millisecond, func() { start(req) })
		return nil
	}
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusFailed {
		t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	if got := mustRow(t, res.Stdout, "cleanup"); got != "ok" {
		t.Errorf("cleanup = %q, want ok:\n%s", got, res.Stdout)
	}
	r.wantEnded()
}

func TestRunServerThatDoesNotListenIsHandled(t *testing.T) {
	r := newRig(t)
	r.jvm.onAttach = func(jvmtarget.AttachRequest) error { return nil } // attach "works", nothing listens
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusFailed {
		t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	if !strings.Contains(mustRow(t, res.Stdout, "reason"), "port") {
		t.Errorf("reason does not mention the port:\n%s", res.Stdout)
	}
	r.wantEnded()
}

func TestRunCommandTimeout(t *testing.T) {
	r := newRig(t)
	r.server.onExec = func(w http.ResponseWriter, req *http.Request, command string) bool {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"state":"INTERRUPTED","message":"timeout","sessionId":"sid-1","body":{"jobId":1,"jobStatus":"TERMINATED","timeExpired":true,"results":[]}}`))
		return true
	}
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusTimeout {
		t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	if got := mustRow(t, res.Stdout, "cleanup"); got != "ok" {
		t.Errorf("cleanup = %q", got)
	}
	r.wantEnded()
}

func TestRunReportsACommandThatFailed(t *testing.T) {
	r := newRig(t)
	r.server.onExec = func(w http.ResponseWriter, req *http.Request, command string) bool {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"state":"SUCCEEDED","sessionId":"sid-1","body":{"jobId":1,"jobStatus":"TERMINATED","results":[{"type":"status","statusCode":-1,"message":"No such thread"}]}}`))
		return true
	}
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusFailed {
		t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	if !strings.Contains(mustRow(t, res.Stdout, "reason"), "No such thread") {
		t.Errorf("reason does not carry the message of Arthas:\n%s", res.Stdout)
	}
	r.wantEnded()
}

// Arthas answers thread -b with status 1 when no thread blocks another; that is the result of the
// command, not a failure of the call.
func TestRunReportsNoBlockingThreadAsAnAnswer(t *testing.T) {
	r := newRig(t)
	r.cfg.Command = arthas.KindThreadBlocking
	r.server.onExec = func(w http.ResponseWriter, req *http.Request, command string) bool {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"state":"SUCCEEDED","sessionId":"sid-1","body":{"jobId":1,"jobStatus":"TERMINATED","results":[{"type":"status","statusCode":1,"message":"No most blocking thread found!"}]}}`))
		return true
	}
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitSuccess || res.Stderr != "" || mustRow(t, res.Stdout, "status") != StatusOK {
		t.Fatalf("exit code %d, stderr %q\n%s", res.ExitCode, res.Stderr, res.Stdout)
	}
	if !strings.Contains(res.Stdout, "\n# blocking lock\nnone\n") {
		t.Errorf("the output does not say that no thread blocks:\n%s", res.Stdout)
	}
	r.wantEnded()
}

func TestRunKeepsOtherFailuresOfThreadBlockingAsFailures(t *testing.T) {
	r := newRig(t)
	r.cfg.Command = arthas.KindThreadBlocking
	r.server.onExec = func(w http.ResponseWriter, req *http.Request, command string) bool {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"state":"SUCCEEDED","sessionId":"sid-1","body":{"jobId":1,"jobStatus":"TERMINATED","results":[{"type":"status","statusCode":1,"message":"something else"}]}}`))
		return true
	}
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusFailed {
		t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	r.wantEnded()
}

// blockingCommand makes the command wait until the caller of the HTTP request goes away.
func blockingCommand(started chan<- struct{}) func(http.ResponseWriter, *http.Request, string) bool {
	return func(w http.ResponseWriter, req *http.Request, command string) bool {
		started <- struct{}{}
		<-req.Context().Done()
		return true
	}
}

func TestRunCancelAndDeadlineStillCleanUp(t *testing.T) {
	tests := []struct {
		name   string
		ctx    func() (context.Context, context.CancelFunc, <-chan struct{})
		status string
		want   error
	}{
		{"cancel", func() (context.Context, context.CancelFunc, <-chan struct{}) {
			ctx, cancel := context.WithCancel(context.Background())
			return ctx, cancel, nil
		}, StatusCancelled, context.Canceled},
		{"deadline", func() (context.Context, context.CancelFunc, <-chan struct{}) {
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			return ctx, cancel, nil
		}, StatusTimeout, context.DeadlineExceeded},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			started := make(chan struct{}, 1)
			r.server.onExec = blockingCommand(started)
			ctx, cancel, _ := tc.ctx()
			defer cancel()
			if tc.name == "cancel" {
				go func() { <-started; cancel() }()
			}
			res, err := r.run(ctx)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != tc.status {
				t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
			}
			if got := mustRow(t, res.Stdout, "cleanup"); got != "ok" {
				t.Errorf("cleanup = %q", got)
			}
			got := r.server.seen()
			if len(got) < 4 || !slices.Equal(got[len(got)-2:], []string{"exec:reset", "exec:stop"}) {
				t.Errorf("Arthas requests = %v, want the clean-up sequence at the end", got)
			}
			r.wantEnded()
		})
	}
}

// earlyDeadline reports a deadline that its timer has not enforced yet. Every context with a
// deadline is like this for a moment: the client sets the deadline of the context on the
// connection, that deadline can fire first, and ctx.Err() is still nil when the read fails.
type earlyDeadline struct {
	context.Context
	deadline time.Time
}

func (c earlyDeadline) Deadline() (time.Time, bool) { return c.deadline, true }

func TestRunReportsTheDeadlineWhenTheConnectionTimesOutFirst(t *testing.T) {
	r := newRig(t)
	started := make(chan struct{}, 1)
	r.server.onExec = blockingCommand(started)
	timer, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx := earlyDeadline{Context: timer, deadline: time.Now().Add(150 * time.Millisecond)}
	res, err := r.run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context deadline exceeded\n%s", err, res.Stdout)
	}
	if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusTimeout {
		t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	if got := mustRow(t, res.Stdout, "cleanup"); got != "ok" {
		t.Errorf("cleanup = %q", got)
	}
	r.wantEnded()
}

func TestRunGuardAbortsTheCommand(t *testing.T) {
	tests := []struct {
		name   string
		change func(*rig)
		check  string
	}{
		{"cpu", func(r *rig) {
			r.cfg.Guard = Guard{MaxCPUPercent: 100, Settle: time.Millisecond}
			r.host.cpuStep = 100000
		}, GuardCPU},
		{"health check", func(r *rig) {
			r.cfg.Guard = Guard{Settle: time.Millisecond, Health: &HealthCheck{URL: "http://127.0.0.1:8080/health", AllowedPrefixes: []string{"http://127.0.0.1:8080/"}}}
			r.env.Probe = func(context.Context, HealthCheck) error { return errors.New("HTTP 503") }
		}, GuardHealth},
		{"a threshold that cannot be evaluated", func(r *rig) {
			r.cfg.Guard = Guard{MaxCPUPercent: 100}
			r.host.cpuErr = errors.New("no such process")
		}, GuardSampling},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			tc.change(r)
			started := make(chan struct{}, 1)
			r.server.onExec = blockingCommand(started)
			res, err := r.run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusAborted {
				t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
			}
			if got := mustRow(t, res.Stdout, "check"); got != tc.check {
				t.Errorf("check = %q, want %q", got, tc.check)
			}
			if got := mustRow(t, res.Stdout, "cleanup"); got != "ok" {
				t.Errorf("cleanup = %q", got)
			}
			if mustRow(t, res.Stdout, "reason") == "" {
				t.Error("no reason")
			}
			r.wantEnded()
		})
	}
}

func TestRunCleanupFailureKeepsTheRecord(t *testing.T) {
	r := newRig(t)
	r.server.ignoreStop = true
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitFailure {
		t.Errorf("exit code %d, want failure: a server is still running", res.ExitCode)
	}
	if got := mustRow(t, res.Stdout, "status"); got != StatusOK {
		t.Errorf("status = %q: the command itself worked", got)
	}
	if got := mustRow(t, res.Stdout, "cleanup"); !strings.HasPrefix(got, "failed") {
		t.Errorf("cleanup = %q", got)
	}
	if !strings.Contains(res.Stdout, "version\t4.3.5") {
		t.Errorf("the result of the command is missing:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "cleanup") {
		t.Errorf("stderr = %q", res.Stderr)
	}
	rec, err := r.state().ReadRecord(r.key)
	if err != nil {
		t.Fatalf("the record is needed for the recovery: %v", err)
	}
	if rec.Password != rigPassword || rec.Port != 18563 {
		t.Errorf("record = %+v", rec)
	}
	lock, err := r.state().TryLock(r.key)
	if err != nil {
		t.Fatalf("the lock is held after the call: %v", err)
	}
	lock.Unlock()
	noSecrets(t, res)
}

func TestRunRecoversAnEarlierSessionOfTheSameJVMFirst(t *testing.T) {
	r := newRig(t)
	r.leaveRecord(18570, true)
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	if got := mustRow(t, res.Stdout, "earlier_sessions"); !strings.Contains(got, "cleaned 1") {
		t.Errorf("earlier_sessions = %q", got)
	}
	want := append(append([]string{}, cleanupActions...), append([]string{"init_session", "exec:version"}, cleanupActions...)...)
	if got := r.server.seen(); !slices.Equal(got, want) {
		t.Errorf("Arthas requests = %v, want %v", got, want)
	}
	r.wantEnded()
}

func TestRunRefusesWhileAnEarlierSessionCannotBeEnded(t *testing.T) {
	r := newRig(t)
	r.server.ignoreStop = true
	r.leaveRecord(18570, true)
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusRefused || mustRow(t, res.Stdout, "check") != CheckPreviousSession {
		t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	if n := r.jvm.attachCount(); n != 0 {
		t.Errorf("the JVM was attached to %d times", n)
	}
	if _, err := r.state().ReadRecord(r.key); err != nil {
		t.Errorf("the record must stay for the next recovery: %v", err)
	}
	noSecrets(t, res)
}

func TestRunSweepsTheRecordsOfOtherJVMs(t *testing.T) {
	r := newRig(t)
	gone := Record{
		Version: 1, BootID: r.key.BootID, PID: 999, StartTime: 5, Target: "other", Command: "version", Port: 18570, Password: rigPassword,
		Created: time.Now().Add(-time.Hour), Deadline: time.Now().Add(-time.Hour),
	}
	if err := r.state().WriteRecord(gone); err != nil {
		t.Fatal(err)
	}
	res, err := r.run(context.Background())
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("%v\n%s", err, res.Stdout)
	}
	if got := mustRow(t, res.Stdout, "earlier_sessions"); !strings.Contains(got, "stale 1") {
		t.Errorf("earlier_sessions = %q", got)
	}
	if _, err := r.state().ReadRecord(gone.Key()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the record of the exited process is still there: %v", err)
	}
}

func TestRunStateDirectoryProblemStopsTheCall(t *testing.T) {
	r := newRig(t)
	r.env.StateDir = "relative/path"
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusFailed {
		t.Errorf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	if n := r.jvm.attachCount(); n != 0 {
		t.Errorf("the JVM was attached to %d times", n)
	}
}

func TestRunExpiredContextDoesNotStart(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := r.run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	if res.ExitCode != builtin.ExitFailure {
		t.Errorf("exit code %d", res.ExitCode)
	}
	if n := r.jvm.attachCount(); n != 0 {
		t.Errorf("the JVM was attached to %d times", n)
	}
}

func TestRunUsesTheOwnerOfTheStateDirectory(t *testing.T) {
	r := newRig(t)
	r.env.StateOwner = uint32(os.Getuid()) + 1
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitFailure {
		t.Errorf("a state directory of another user was accepted:\n%s", res.Stdout)
	}
	if n := r.jvm.attachCount(); n != 0 {
		t.Errorf("the JVM was attached to %d times", n)
	}
}
