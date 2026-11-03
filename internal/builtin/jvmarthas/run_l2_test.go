package jvmarthas

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/builtin"
)

// Results of the scripted jobs of the fake server; JOB is the job ID.
const (
	l2Command   = `{"type":"command","jobId":JOB,"state":"SCHEDULED","command":"watch"}`
	l2AffectOK  = `{"type":"enhancer","jobId":JOB,"success":true,"effect":{"classCount":1,"methodCount":1,"cost":20,"listenerId":1}}`
	l2OverLimit = `{"type":"enhancer","jobId":JOB,"success":false,"effect":{"classCount":0,"methodCount":0,"cost":21,"listenerId":7,` +
		`"overLimitMsg":"The number of matched classes is 2, greater than the limit value 1. Try to change the limit with option '-m <arg>'."}}`
	l2TooManyMethods = `{"type":"enhancer","jobId":JOB,"success":true,"effect":{"classCount":1,"methodCount":6,"cost":20,"listenerId":1}}`
	l2Watch          = `{"type":"watch","jobId":JOB,"ts":"2026-10-26 10:00:00.000","cost":0.5,"className":"demo.HotService","methodName":"work",` +
		`"accessPoint":"AtExit","value":"@ArrayList[\n    @Integer[7],\n]"}`
	l2Stack  = `{"type":"stack","jobId":JOB,"ts":"2026-10-26 10:00:00.000","threadName":"main","threadId":"1","stackTrace":[]}`
	l2Ended  = `{"type":"status","jobId":JOB,"statusCode":0}`
	l2Failed = `{"type":"status","jobId":JOB,"statusCode":-1,"message":"enhance failed"}`
)

const watchText = "watch demo.HotService work {params,returnObj} -n 1 -x 1 -m 1 --timeout 30"

// newL2Rig returns a rig for an L2 command on demo.HotService.work.
func newL2Rig(t *testing.T, kind arthas.Kind) *rig {
	t.Helper()
	r := newRig(t)
	r.cfg.Command = kind
	r.cfg.ClassPrefixes = []string{"demo."}
	r.env.CPUWindow = 20 * time.Millisecond
	r.env.JobGrace = time.Second
	r.host.cpuLimit = 4
	r.request = arthas.Request{Class: "demo.HotService", Method: "work", Count: 1}
	switch kind {
	case arthas.KindWatch:
		r.request.Express, r.request.Expand = "params,returnObj", 1
	case arthas.KindMonitor:
		r.request.Cycle = 5
	case arthas.KindJad:
		r.request.Method, r.request.Count = "", 0
	}
	return r
}

// requests returns the Arthas requests of the rig without the pulls.
func (r *rig) requests() []string {
	var out []string
	for _, a := range r.server.seen() {
		if a != "pull_results" {
			out = append(out, a)
		}
	}
	return out
}

var l2Cleanup = []string{"interrupt_job", "close_session", "exec:reset", "exec:reset", "exec:stop"}

func TestRunWatchSucceeds(t *testing.T) {
	r := newL2Rig(t, arthas.KindWatch)
	r.server.jobs = [][][]string{{{l2Command, l2AffectOK}, {}, {l2Watch}, {l2Ended}}}
	r.server.resets = []int{1, 0}
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitSuccess || res.Stderr != "" {
		t.Fatalf("exit code %d, stderr %q\n%s", res.ExitCode, res.Stderr, res.Stdout)
	}
	for key, want := range map[string]string{
		"command": "watch", "status": StatusOK, "affect": "classes 1, methods 1", "enhanced_classes": "0 (reset restored 1)", "cleanup": "ok",
	} {
		if got := mustRow(t, res.Stdout, key); got != want {
			t.Errorf("row %s = %q, want %q", key, got, want)
		}
	}
	if got := mustRow(t, res.Stdout, "cpu_before"); !strings.HasSuffix(got, "% of the CPU limit (4.00 CPUs) over 0s") {
		t.Errorf("cpu_before = %q", got)
	}
	if !strings.Contains(res.Stdout, "\n\n# watch\ntime\t2026-10-26 10:00:00.000\n") || !strings.Contains(res.Stdout, "value\n  @ArrayList[\n      @Integer[7],\n  ]\n") {
		t.Errorf("output:\n%s", res.Stdout)
	}
	want := append([]string{"init_session", "exec:options disable-sub-class true", "exec:options object-size-limit 8192", "async_exec:" + watchText}, l2Cleanup...)
	if got := r.requests(); !slices.Equal(got, want) {
		t.Errorf("Arthas requests = %q\nwant %q", got, want)
	}
	_, opts := r.agent()
	disabled := strings.Split(opts["disabledCommands"], ",")
	for _, name := range []string{"watch", "options", "reset", "stop"} {
		if slices.Contains(disabled, name) {
			t.Errorf("%s is disabled", name)
		}
	}
	for _, name := range []string{"trace", "stack", "monitor", "jad", "ognl", "version"} {
		if !slices.Contains(disabled, name) {
			t.Errorf("%s is not disabled", name)
		}
	}
	if opts["sessionTimeout"] != "70" {
		t.Errorf("sessionTimeout = %q, want 70 (10s exec timeout + 30s enhancement + 30s)", opts["sessionTimeout"])
	}
	r.wantEnded()
	noSecrets(t, res)
}

func TestRunWritesARecordThatCoversTheEnhancement(t *testing.T) {
	r := newL2Rig(t, arthas.KindTrace)
	seen := make(chan Record, 1)
	r.server.onExec = func(w http.ResponseWriter, req *http.Request, command string) bool {
		if strings.HasPrefix(command, "options ") {
			rec, err := r.state().ReadRecord(r.key)
			if err != nil {
				t.Errorf("no record during the setup: %v", err)
			}
			select {
			case seen <- rec:
			default:
			}
		}
		return false
	}
	r.server.jobs = [][][]string{{{l2Command, l2AffectOK, l2Ended}}}
	r.server.resets = []int{1, 0}
	if _, err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := <-seen
	if d := rec.Deadline.Sub(rec.Created); d != 10*time.Second+30*time.Second+recordLifetime {
		t.Errorf("record lifetime %s", d)
	}
}

// An enhancement that matches more than one class: RunJob stops at the enhancer result, and the
// clean-up interrupts the job and resets.
func TestRunFailsAndResetsWhenTheEnhancementIsOverTheLimit(t *testing.T) {
	r := newL2Rig(t, arthas.KindWatch)
	r.server.jobs = [][][]string{{{l2Command, l2OverLimit}, {l2Failed}}}
	r.server.interruptOK = true
	r.server.resets = []int{0, 0}
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != builtin.ExitFailure || mustRow(t, res.Stdout, "status") != StatusFailed || mustRow(t, res.Stdout, "check") != CheckAffect {
		t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
	want := "the enhancement failed: The number of matched classes is 2, greater than the limit value 1. Try to change the limit with option '-m <arg>'."
	if got := mustRow(t, res.Stdout, "reason"); got != want {
		t.Errorf("reason = %q", got)
	}
	if got := mustRow(t, res.Stdout, "affect"); got != "classes 0, methods 0" {
		t.Errorf("affect = %q", got)
	}
	if got := mustRow(t, res.Stdout, "enhanced_classes"); got != "0 (reset restored 0)" {
		t.Errorf("enhanced_classes = %q", got)
	}
	if !strings.Contains(res.Stderr, "jvm_arthas: failed (affect): the enhancement failed: The number of matched classes is 2") {
		t.Errorf("stderr = %q", res.Stderr)
	}
	reqs := r.requests()
	if i := slices.Index(reqs, "async_exec:"+watchText); i < 0 || !slices.Equal(reqs[i+1:], l2Cleanup) {
		t.Errorf("Arthas requests = %q", reqs)
	}
	r.wantEnded()
}

func TestRunFailsWhenTheEnhancementAffectsTooManyMethods(t *testing.T) {
	r := newL2Rig(t, arthas.KindTrace)
	r.server.jobs = [][][]string{{{l2Command, l2TooManyMethods}, {l2Ended}}}
	r.server.interruptOK = true
	r.server.resets = []int{1, 0}
	res, _ := r.run(context.Background())
	if mustRow(t, res.Stdout, "check") != CheckAffect || mustRow(t, res.Stdout, "reason") != "the enhancement affected 6 methods, the limit is 5" {
		t.Fatalf("output:\n%s", res.Stdout)
	}
	if got := mustRow(t, res.Stdout, "enhanced_classes"); got != "0 (reset restored 1)" {
		t.Errorf("enhanced_classes = %q", got)
	}
	r.wantEnded()
}

func TestRunWithoutAnEnhancerResult(t *testing.T) {
	r := newL2Rig(t, arthas.KindStack)
	r.server.jobs = [][][]string{{{l2Command, l2Stack, l2Ended}}}
	r.server.resets = []int{1, 0}
	res, err := r.run(context.Background())
	if err != nil || res.ExitCode != builtin.ExitSuccess {
		t.Fatalf("exit code %d, %v\n%s", res.ExitCode, err, res.Stdout)
	}
	if got := mustRow(t, res.Stdout, "affect"); got != "not reported: the job ended before Arthas reported the enhancement" {
		t.Errorf("affect = %q", got)
	}
	if !strings.Contains(res.Stdout, "\n\n# stack\n") {
		t.Errorf("output:\n%s", res.Stdout)
	}
}

func TestRunFailsWhenTheResetRestoredMoreThanOneClass(t *testing.T) {
	r := newL2Rig(t, arthas.KindStack)
	r.server.jobs = [][][]string{{{l2Command, l2Stack, l2Ended}}}
	r.server.resets = []int{2, 0}
	res, _ := r.run(context.Background())
	if mustRow(t, res.Stdout, "status") != StatusFailed || mustRow(t, res.Stdout, "check") != CheckAffect ||
		mustRow(t, res.Stdout, "reason") != "the reset restored 2 classes, the limit is 1" || res.ExitCode != builtin.ExitFailure {
		t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
	}
}

func TestRunFailsWhenNoEnhancedClassCannotBeConfirmed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		resets []int
		row    string
	}{
		{"second reset restored a class", []int{1, 1}, "unconfirmed: a second reset still restored 1 classes (reset restored 1)"},
		{"second reset without a count", []int{1, -1}, "unconfirmed: the confirming reset reported no class count"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newL2Rig(t, arthas.KindWatch)
			r.server.jobs = [][][]string{{{l2Command, l2AffectOK, l2Watch, l2Ended}}}
			r.server.resets = tc.resets
			res, _ := r.run(context.Background())
			if mustRow(t, res.Stdout, "status") != StatusFailed || mustRow(t, res.Stdout, "check") != CheckEnhancedClasses || res.ExitCode != builtin.ExitFailure {
				t.Fatalf("exit code %d\n%s", res.ExitCode, res.Stdout)
			}
			if got := mustRow(t, res.Stdout, "enhanced_classes"); got != tc.row {
				t.Errorf("enhanced_classes = %q", got)
			}
		})
	}
}

func TestRunJobThatDoesNotEndIsATimeout(t *testing.T) {
	r := newL2Rig(t, arthas.KindWatch)
	r.cfg.EnhanceDuration = time.Second
	r.server.jobs = [][][]string{{{l2Command, l2AffectOK, l2Watch}}}
	r.server.interruptOK = true
	r.server.resets = []int{1, 0}
	start := time.Now()
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 2*time.Second {
		t.Errorf("the call ended after %s, before the enhancement and the grace time", elapsed)
	}
	if mustRow(t, res.Stdout, "status") != StatusTimeout || mustRow(t, res.Stdout, "reason") != "the job did not end within 2s of the start of the enhancement" {
		t.Fatalf("output:\n%s", res.Stdout)
	}
	// What the job produced before is shown.
	if !strings.Contains(res.Stdout, "\n\n# watch\ntime\t") {
		t.Errorf("output:\n%s", res.Stdout)
	}
	reqs := r.requests()
	if !slices.Equal(reqs[len(reqs)-len(l2Cleanup):], l2Cleanup) {
		t.Errorf("Arthas requests = %q", reqs)
	}
	r.wantEnded()
}

func TestRunGuardAbortsTheJob(t *testing.T) {
	r := newL2Rig(t, arthas.KindWatch)
	r.cfg.Guard.MaxGCPerSecond = 100
	r.jvm.perfErr = errors.New("hsperfdata gone")
	r.server.jobs = [][][]string{{{l2Command, l2AffectOK}}}
	r.server.interruptOK = true
	r.server.resets = []int{1, 0}
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if mustRow(t, res.Stdout, "status") != StatusAborted || mustRow(t, res.Stdout, "check") != GuardSampling {
		t.Fatalf("output:\n%s", res.Stdout)
	}
	if got := mustRow(t, res.Stdout, "enhanced_classes"); got != "0 (reset restored 1)" {
		t.Errorf("enhanced_classes = %q", got)
	}
	r.wantEnded()
}

func TestGuardSettlesForAtLeastFiveSecondsOnL2(t *testing.T) {
	for _, tc := range []struct {
		level  int
		settle time.Duration
		want   time.Duration
	}{
		{1, 0, 0}, {1, time.Second, time.Second}, {2, 0, DefaultSettle}, {2, time.Second, DefaultSettle}, {2, 20 * time.Second, 20 * time.Second},
	} {
		c := &call{cfg: Config{Guard: Guard{MaxCPUPercent: 100, Settle: tc.settle}}, cmd: arthas.Command{Level: tc.level}}
		if got := c.guardConfig(); got.Settle != tc.want || got.MaxCPUPercent != 100 {
			t.Errorf("level %d, settle %s: %+v", tc.level, tc.settle, got)
		}
	}
}

func TestRunFailsWhenTheSetupFails(t *testing.T) {
	r := newL2Rig(t, arthas.KindWatch)
	r.server.onExec = func(w http.ResponseWriter, req *http.Request, command string) bool {
		if command != "options object-size-limit 8192" {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"state":"SUCCEEDED","body":{"jobId":4,"results":[{"type":"options","jobId":4,"changeResult":{"name":"object-size-limit","afterValue":10485760}},{"type":"status","jobId":4,"statusCode":0}]}}`))
		return true
	}
	res, _ := r.run(context.Background())
	if mustRow(t, res.Stdout, "status") != StatusFailed || !strings.HasPrefix(mustRow(t, res.Stdout, "reason"), "setup: options object-size-limit 8192: Arthas reports object-size-limit = 10485760") {
		t.Fatalf("output:\n%s", res.Stdout)
	}
	if reqs := r.requests(); slices.ContainsFunc(reqs, func(a string) bool { return strings.HasPrefix(a, "async_exec") }) {
		t.Errorf("the command ran after a failed setup: %q", reqs)
	}
	r.wantEnded()
}

func TestRunJadSucceeds(t *testing.T) {
	r := newL2Rig(t, arthas.KindJad)
	r.server.onExec = func(w http.ResponseWriter, req *http.Request, command string) bool {
		if command != "jad --source-only demo.HotService" {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"state":"SUCCEEDED","sessionId":"sid-1","body":{"jobId":5,"jobStatus":"TERMINATED","results":[` +
			`{"type":"jad","jobId":5,"source":"package demo;\n\npublic class HotService {\n    private String password = \"hunter2\";\n}\n"},` +
			`{"type":"status","jobId":5,"statusCode":0}]}}`))
		return true
	}
	mask := func(s string) string { return strings.ReplaceAll(s, "hunter2", "[REDACTED]") }
	res, err := RunWith(context.Background(), r.env, r.cfg, r.params(), mask)
	if err != nil || res.ExitCode != builtin.ExitSuccess {
		t.Fatalf("exit code %d, %v\n%s%s", res.ExitCode, err, res.Stdout, res.Stderr)
	}
	if got := mustRow(t, res.Stdout, "enhanced_classes"); got != "0 (reset restored 0)" {
		t.Errorf("enhanced_classes = %q", got)
	}
	if _, ok := rowOf(res.Stdout, "affect"); ok {
		t.Error("jad has an affect row")
	}
	if !strings.Contains(res.Stdout, "\n\n# jad\nsource\n  package demo;\n") || strings.Contains(res.Stdout, "hunter2") {
		t.Errorf("output:\n%s", res.Stdout)
	}
	want := append([]string{"init_session", "exec:jad --source-only demo.HotService"}, l2Cleanup...)
	if got := r.requests(); !slices.Equal(got, want) {
		t.Errorf("Arthas requests = %q", got)
	}
	_, opts := r.agent()
	if disabled := strings.Split(opts["disabledCommands"], ","); slices.Contains(disabled, "jad") || !slices.Contains(disabled, "options") {
		t.Errorf("disabledCommands = %q", opts["disabledCommands"])
	}
	r.wantEnded()
}

func TestRunL2RejectsClassesOutsideThePrefixesWithoutAttaching(t *testing.T) {
	for _, class := range []string{"com.example.Other", "java.lang.String", "demo.*", "demo.A;reset"} {
		r := newL2Rig(t, arthas.KindWatch)
		r.request.Class = class
		res, err := r.run(context.Background())
		if err != nil || res.ExitCode != builtin.ExitFailure || res.Stdout != "" || !strings.HasPrefix(res.Stderr, "jvm_arthas: arthas: ") {
			t.Errorf("%s: exit code %d, %v, stdout %q, stderr %q", class, res.ExitCode, err, res.Stdout, res.Stderr)
		}
		r.wantNoAttach()
	}
}

// One test per refusal of the CPU check.
func TestRunL2RefusesABusyJVM(t *testing.T) {
	r := newL2Rig(t, arthas.KindWatch)
	r.host.cpuLimit = 1
	r.host.cpuStep = 100 // one CPU second per reading, in a window of 20ms
	res, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if mustRow(t, res.Stdout, "status") != StatusRefused || mustRow(t, res.Stdout, "check") != CheckCPUUsage {
		t.Fatalf("output:\n%s", res.Stdout)
	}
	if reason := mustRow(t, res.Stdout, "reason"); !strings.Contains(reason, "of its CPU limit (1.00 CPUs)") || !strings.HasSuffix(reason, "an L2 command needs it below 50%") {
		t.Errorf("reason = %q", reason)
	}
	if _, ok := rowOf(res.Stdout, "cpu_before"); !ok {
		t.Error("no cpu_before row")
	}
	r.wantNoAttach()
}

func TestRunL2RefusesWithALowerConfiguredCPUShare(t *testing.T) {
	r := newL2Rig(t, arthas.KindTrace)
	r.env.CPUWindow = 200 * time.Millisecond
	r.host.cpuLimit = 1
	r.host.cpuStep = 2 // 20ms of CPU in at least 200ms: at most 10%
	r.server.jobs = [][][]string{{{l2Command, l2AffectOK, l2Ended}}}
	r.server.resets = []int{1, 0}
	res, _ := r.run(context.Background())
	if mustRow(t, res.Stdout, "status") != StatusOK {
		t.Fatalf("default share: output:\n%s", res.Stdout)
	}
	r = newL2Rig(t, arthas.KindTrace)
	r.env.CPUWindow = 200 * time.Millisecond
	r.host.cpuLimit = 1
	r.host.cpuStep = 2
	r.cfg.Checks.MaxCPUPercent = 1
	res, _ = r.run(context.Background())
	if mustRow(t, res.Stdout, "status") != StatusRefused || mustRow(t, res.Stdout, "check") != CheckCPUUsage || !strings.HasSuffix(mustRow(t, res.Stdout, "reason"), "below 1%") {
		t.Fatalf("share 1%%: output:\n%s", res.Stdout)
	}
	r.wantNoAttach()
}

func TestRunL2RefusesWhenTheCPULimitIsUnknown(t *testing.T) {
	r := newL2Rig(t, arthas.KindJad)
	r.host.cpuLimitErr = errors.New("malformed cpu.max")
	res, _ := r.run(context.Background())
	if mustRow(t, res.Stdout, "check") != CheckCPUUsage || mustRow(t, res.Stdout, "reason") != "cannot read the CPU limit of process 4242: malformed cpu.max" {
		t.Fatalf("output:\n%s", res.Stdout)
	}
	r.wantNoAttach()
}

func TestRunL2RefusesWhenTheCPUTimeIsUnknown(t *testing.T) {
	r := newL2Rig(t, arthas.KindMonitor)
	r.host.cpuErr = errors.New("no such process")
	res, _ := r.run(context.Background())
	if mustRow(t, res.Stdout, "check") != CheckCPUUsage || mustRow(t, res.Stdout, "reason") != "cannot read the CPU time of process 4242: no such process" {
		t.Fatalf("output:\n%s", res.Stdout)
	}
	r.wantNoAttach()
}

func TestRunL2CancelledDuringTheCPUCheck(t *testing.T) {
	r := newL2Rig(t, arthas.KindWatch)
	r.env.CPUWindow = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	res, err := r.run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || mustRow(t, res.Stdout, "status") != StatusTimeout {
		t.Fatalf("%v\n%s", err, res.Stdout)
	}
	r.wantNoAttach()
}

func TestRunL1SkipsTheCPUCheck(t *testing.T) {
	r := newRig(t)
	r.host.cpuLimitErr = errors.New("unused")
	res, err := r.run(context.Background())
	if err != nil || mustRow(t, res.Stdout, "status") != StatusOK {
		t.Fatalf("%v\n%s", err, res.Stdout)
	}
	for _, key := range []string{"cpu_before", "affect", "enhanced_classes"} {
		if _, ok := rowOf(res.Stdout, key); ok {
			t.Errorf("L1 output has a %s row", key)
		}
	}
	if got := r.requests(); slices.Contains(got, "exec:options disable-sub-class true") || strings.Count(strings.Join(got, ","), "exec:reset") != 1 {
		t.Errorf("Arthas requests = %q", got)
	}
}
