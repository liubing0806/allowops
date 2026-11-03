//go:build linux

package arthas

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestRealArthasL2 runs the L2 commands on the four JDKs of test/jvm-arthas with one attach per
// JDK. It checks what the L2 design relies on:
//
//   - the enhancer result arrives through pull_results right after async_exec, and -m 1 makes
//     Arthas refuse an enhancement that matches a class and its subclass (overLimitMsg);
//   - the setup commands take effect: disable-sub-class keeps the match to the class itself,
//     object-size-limit cuts a watch value;
//   - --timeout ends a job that matched nothing;
//   - after interrupt_job, reset restores exactly the enhanced class and a second reset finds
//     nothing, and the live bytecode no longer calls Arthas (the /diag/live endpoint of the
//     sample application);
//   - jad leaves no enhanced class and writes the class file under the Arthas log directory;
//   - after the clean-up no port, no arthas- thread and no other thread of Arthas is left, and
//     the application answers.
//
// The responses of jdk8 and jdk17 are stored in testdata with ALLOWOPS_ARTHAS_UPDATE_TESTDATA=1.
// A job response is assembled from the pull_results bodies: the results of the job, in order.
func TestRealArthasL2(t *testing.T) {
	requireRealEnv(t)
	for _, svc := range []string{"jdk8", "jdk11", "jdk17", "jdk21"} {
		t.Run(svc, func(t *testing.T) { realL2Run(t, newRealTarget(t, svc), svc) })
	}
}

// realL2Enabled are the Arthas commands behind the L2 kinds and their setup.
var realL2Enabled = []string{"watch", "trace", "stack", "monitor", "jad", "options"}

// bodies returns the bodies of all HTTP responses read since the last call, in order, and
// clears the tap.
func (d *tapDial) bodies(t *testing.T) [][]byte {
	t.Helper()
	d.mu.Lock()
	raw := bytes.Clone(d.buf.Bytes())
	d.buf.Reset()
	d.mu.Unlock()
	r := bufio.NewReader(bytes.NewReader(raw))
	var out [][]byte
	for {
		if _, err := r.Peek(1); err != nil {
			return out
		}
		resp, err := http.ReadResponse(r, nil)
		if err != nil {
			t.Fatalf("tap: %v", err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("tap: %v", err)
		}
		out = append(out, b)
	}
}

// jobEnvelope assembles an exec envelope from the pull_results bodies of a job.
func jobEnvelope(t *testing.T, session string, id int, bodies [][]byte) []byte {
	t.Helper()
	var results []json.RawMessage
	for _, b := range bodies {
		var env struct {
			Body struct {
				Results []json.RawMessage `json:"results"`
			} `json:"body"`
		}
		if json.Unmarshal(b, &env) != nil {
			continue
		}
		for _, r := range env.Body.Results {
			var head struct {
				JobID int `json:"jobId"`
			}
			if json.Unmarshal(r, &head) == nil && head.JobID == id {
				results = append(results, r)
			}
		}
	}
	out, err := json.Marshal(map[string]any{
		"state": "SUCCEEDED", "sessionId": session,
		"body": map[string]any{"jobId": id, "jobStatus": "TERMINATED", "timeExpired": false, "results": results},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// loadL2 calls the methods the L2 cases watch, about a hundred times a second.
func (tg *realTarget) loadL2(t *testing.T) (stop func()) {
	t.Helper()
	if tg.ip == "" {
		t.Fatal("no container address")
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				case <-time.After(20 * time.Millisecond):
				}
				for _, p := range []string{"/work", "/hot?calls=1", "/diag/threads"} {
					if resp, err := client.Get("http://" + tg.ip + ":8080" + p); err == nil {
						resp.Body.Close()
					}
				}
			}
		}()
	}
	var once sync.Once
	return func() { once.Do(func() { close(done); wg.Wait() }) }
}

// appGet sends one GET request to the sample application and decodes the JSON answer into v.
func (tg *realTarget) appGet(t *testing.T, path string, v any) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get("http://" + tg.ip + ":8080" + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", path, resp.StatusCode)
	}
	if v != nil {
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
	}
}

// liveEnhanced reports whether HotService.work still calls into Arthas.
func (tg *realTarget) liveEnhanced(t *testing.T) bool {
	t.Helper()
	var live struct {
		Enhanced *bool `json:"enhanced"`
	}
	tg.appGet(t, "/diag/live", &live)
	if live.Enhanced == nil {
		t.Fatal("/diag/live has no enhanced field")
	}
	return *live.Enhanced
}

func realL2Run(t *testing.T, tg *realTarget, jdk string) {
	if n := tg.arthasThreads(t); n != 0 {
		t.Fatalf("%s already runs Arthas (%d arthas- threads); restart the container", tg.container, n)
	}
	password, err := NewPassword()
	if err != nil {
		t.Fatal(err)
	}
	tg.attach(t, AgentConfig{
		AgentJar: realAgentJar, CoreJar: realCoreJar, HTTPPort: realHTTPPort, Password: password,
		Enabled: realL2Enabled, SessionTimeout: 5 * time.Minute,
	})
	attached := true
	t.Cleanup(func() {
		if !attached {
			return
		}
		if c, err := NewClient(Config{Dial: tg.dial(realHTTPPort), Password: password}); err == nil {
			c.Cleanup(context.Background(), "", CleanupOptions{})
		}
	})
	tap := &tapDial{dial: tg.dial(realHTTPPort)}
	c, err := NewClient(Config{Dial: tap.Dial, Password: password, MaxResponseBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, err := c.OpenSession(ctx)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	tap.bodies(t)
	record := func(name string, body []byte) {
		// A job that is still running has no status to render.
		if (jdk == "jdk8" || jdk == "jdk17") && name != "watch_running" {
			saveTestdata(t, jdk, name, body)
		}
	}
	stopLoad := tg.loadL2(t)
	defer stopLoad()

	policy := Policy{ClassPrefixes: []string{"demo."}, Enhance: 5 * time.Second}
	// follow starts a command that Setup has prepared and collects its job.
	follow := func(name string, cmd Command, wait time.Duration) (*Job, error) {
		t.Helper()
		fctx, cancel := context.WithTimeout(ctx, wait)
		defer cancel()
		j, err := c.RunJob(fctx, s, cmd)
		if j == nil {
			t.Fatalf("%s: RunJob %q: %v", name, cmd.Text, err)
		}
		record(name, jobEnvelope(t, s.ID, j.ID, tap.bodies(t)))
		return j, err
	}
	// job builds, sets up and runs an enhancing command.
	job := func(name string, req Request, pol Policy) (Command, *Job, error) {
		t.Helper()
		cmd, err := Build(req, pol)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := c.Setup(ctx, s.ID, cmd); err != nil {
			t.Fatalf("%s: Setup: %v", name, err)
		}
		tap.bodies(t)
		j, err := follow(name, cmd, cmd.Enhance+15*time.Second)
		return cmd, j, err
	}
	wantJob := func(name string, j *Job, err error, results int) string {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: Follow: %v", name, err)
		}
		if !j.Ended || j.Code != 0 {
			t.Errorf("%s: ended %v, status %d %q", name, j.Ended, j.Code, j.Message)
		}
		// When a result ends the job before Arthas appended the enhancer result, Arthas drops
		// the enhancer result (EnhancerCommand.enhance, ProcessImpl.appendResult).
		switch {
		case j.Affect == nil && len(j.Results) > 0:
			t.Logf("%s: no enhancer result, the job ended first with %d results", name, len(j.Results))
		case j.Affect == nil || *j.Affect != (Affect{Success: true, Classes: 1, Methods: 1}):
			t.Errorf("%s: affect %+v, want one class and one method", name, j.Affect)
		}
		// -n ends the job after the n-th result; invocations that end at the same time in
		// other threads can add a result or two.
		if len(j.Results) < results || len(j.Results) > results+2 || results == 0 && len(j.Results) > 0 {
			t.Errorf("%s: %d results, want %d", name, len(j.Results), results)
		}
		kind, _, _ := strings.Cut(name, "_")
		text, err := Render(Kind(kind), j.Response())
		if err != nil {
			t.Errorf("%s: Render: %v", name, err)
		}
		return text
	}
	// reset restores the enhanced classes and checks their number; a second reset must find none.
	reset := func(name string, want int) {
		t.Helper()
		if step := c.reset(ctx, 5*time.Second); step.Err != nil || step.Restored != want {
			t.Errorf("%s: reset restored %d (%v), want %d", name, step.Restored, step.Err, want)
		}
		if step := c.reset(ctx, 5*time.Second); step.Err != nil || step.Restored != 0 {
			t.Errorf("%s: second reset restored %d (%v), want 0", name, step.Restored, step.Err)
		}
		tap.bodies(t)
	}

	// watch: two results, objects expanded to depth 2.
	_, j, err := job("watch", Request{Kind: KindWatch, Class: "demo.HotService", Method: "work", Express: "params,returnObj", Expand: 2, Count: 2}, policy)
	text := wantJob("watch", j, err, 2)
	if strings.Count(text, "# watch\n") != 2 || !strings.Contains(text, "  @ArrayList[") || !strings.Contains(text, "@Integer[") {
		t.Errorf("watch: %s", text)
	}
	reset("watch", 1)
	if tg.liveEnhanced(t) {
		t.Error("watch: HotService.work still calls Arthas after reset")
	}

	// watch with the smallest object-size-limit: the setup command takes effect.
	pol := policy
	pol.ObjectSizeLimit = MinObjectSizeLimit
	_, j, err = job("watch_size_limit", Request{Kind: KindWatch, Class: "demo.DiagController", Method: "threadNames", Express: "returnObj", Expand: 2, Count: 1}, pol)
	text = wantJob("watch_size_limit", j, err, 1)
	if !strings.Contains(text, "Object size exceeds size limit: 256") {
		t.Errorf("watch_size_limit: the value was not cut: %s", text)
	}
	reset("watch_size_limit", 1)

	// trace: the call of HotService.work inside ApiController.hot.
	_, j, err = job("trace", Request{Kind: KindTrace, Class: "demo.ApiController", Method: "hot", Count: 1}, policy)
	text = wantJob("trace", j, err, 1)
	if !strings.Contains(text, "# trace tree\n") || !strings.Contains(text, "\tcall\tdemo.HotService.work\t") {
		t.Errorf("trace: %s", text)
	}
	reset("trace", 1)

	// stack: the stack of a thread that called HotService.work.
	_, j, err = job("stack", Request{Kind: KindStack, Class: "demo.HotService", Method: "work", Count: 1}, policy)
	text = wantJob("stack", j, err, 1)
	if !strings.Contains(text, "at demo.HotService.work(HotService.java:") || !strings.Contains(text, "at demo.ApiController.") {
		t.Errorf("stack: %s", text)
	}
	reset("stack", 1)

	// monitor: two periods of one second.
	_, j, err = job("monitor", Request{Kind: KindMonitor, Class: "demo.HotService", Method: "work", Count: 2, Cycle: 1}, policy)
	text = wantJob("monitor", j, err, 2)
	if !strings.Contains(text, "# monitor\ntime\tclass\tmethod\t") || !strings.Contains(text, "\tdemo.HotService\twork\t") {
		t.Errorf("monitor: %s", text)
	}
	reset("monitor", 1)

	// A condition that never holds: --timeout ends the job without a result.
	pol = policy
	pol.Enhance = 2 * time.Second
	start := time.Now()
	_, j, err = job("watch_none", Request{Kind: KindWatch, Class: "demo.HotService", Method: "work", Express: "params", Expand: 1, Count: 1, MinCost: 100000}, pol)
	text = wantJob("watch_none", j, err, 0)
	if elapsed := time.Since(start); elapsed < 2*time.Second || elapsed > 6*time.Second {
		t.Errorf("watch_none: the job ended after %s, want about 2s", elapsed)
	}
	if text != "# watch\nresults\t0\n" {
		t.Errorf("watch_none: %q", text)
	}
	reset("watch_none", 1)

	// Without disable-sub-class an interface and its proxy class match, and -m 1 makes Arthas refuse.
	if _, err := c.exec(ctx, s.ID, "options disable-sub-class false", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	tap.bodies(t)
	over := Command{Kind: KindWatch, Name: "watch", Text: "watch demo.ItemRepository findById -n 1 -m 1 --timeout 5", Enhance: 5 * time.Second, MaxMethods: 5, Level: 2, built: true}
	j, err = follow("watch_over_limit", over, 20*time.Second)
	var ae *AffectError
	if !errors.As(err, &ae) || !strings.Contains(ae.Affect.Message, "greater than the limit value 1") || ae.Affect.Success {
		t.Errorf("watch_over_limit: %v, affect %+v", err, j.Affect)
	}
	if err := c.InterruptJob(ctx, s.ID); err != nil && !errors.Is(err, ErrNoForegroundJob) {
		t.Errorf("watch_over_limit: interrupt: %v", err)
	}
	tap.bodies(t)
	reset("watch_over_limit", 0)

	// With disable-sub-class only the interface matches, and it has no method body to enhance.
	_, j, err = job("watch_no_method", Request{Kind: KindWatch, Class: "demo.ItemRepository", Method: "findById", Express: "params", Expand: 1, Count: 1}, policy)
	if !errors.As(err, &ae) || ae.Affect.Success || ae.Affect.Methods != 0 || !strings.Contains(ae.Affect.Message, "No class or method is affected") {
		t.Errorf("watch_no_method: %v, affect %+v", err, j.Affect)
	}
	if err := c.InterruptJob(ctx, s.ID); err != nil && !errors.Is(err, ErrNoForegroundJob) {
		t.Errorf("watch_no_method: interrupt: %v", err)
	}
	tap.bodies(t)
	// Arthas retransformed the interface and restores it.
	reset("watch_no_method", 1)

	// A job that is still running: the class is enhanced until interrupt_job and reset.
	cmd, err := Build(Request{Kind: KindWatch, Class: "demo.HotService", Method: "work", Express: "params", Expand: 1, Count: 1, MinCost: 100000}, Policy{ClassPrefixes: []string{"demo."}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Setup(ctx, s.ID, cmd); err != nil {
		t.Fatal(err)
	}
	j, err = follow("watch_running", cmd, 3*time.Second)
	if !errors.Is(err, context.DeadlineExceeded) || j.Affect == nil || !j.Affect.Success || j.Ended {
		t.Errorf("watch_running: %v, %+v", err, j)
	}
	if !tg.liveEnhanced(t) {
		t.Error("watch_running: HotService.work does not call Arthas while the job runs")
	}
	if err := c.InterruptJob(ctx, s.ID); err != nil {
		t.Errorf("watch_running: interrupt: %v", err)
	}
	tap.bodies(t)
	reset("watch_running", 1)
	if tg.liveEnhanced(t) {
		t.Error("watch_running: HotService.work still calls Arthas after interrupt_job and reset")
	}

	// jad: a synchronous command that leaves no enhanced class.
	jad := func(name string, req Request) (*ExecResponse, string, error) {
		t.Helper()
		cmd, err := Build(req, policy)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp, err := c.Exec(ctx, s.ID, cmd)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		bodies := tap.bodies(t)
		record(name, bodies[len(bodies)-1])
		text, err := Render(KindJad, resp)
		return resp, text, err
	}
	_, text, err = jad("jad", Request{Kind: KindJad, Class: "demo.HotService"})
	if err != nil || !strings.Contains(text, "# jad\nsource\n") || !strings.Contains(text, "  public class HotService {") {
		t.Errorf("jad: %q, %v", text, err)
	}
	_, text, err = jad("jad_method", Request{Kind: KindJad, Class: "demo.HotService", Method: "work"})
	if err != nil || !strings.Contains(text, "public long work(int seed)") || strings.Contains(text, "class HotService") {
		t.Errorf("jad_method: %q, %v", text, err)
	}
	_, _, err = jad("jad_missing", Request{Kind: KindJad, Class: "demo.NoSuchClass"})
	var ce *CommandError
	if !errors.As(err, &ce) || ce.Message != "No class found for: demo.NoSuchClass" {
		t.Errorf("jad_missing: %v", err)
	}
	reset("jad", 0)
	out, err := exec.Command("docker", "exec", tg.container, "sh", "-c", `find / -path /proc -prune -o -path '*/classdump/*/demo/HotService.class' -print 2>/dev/null`).Output()
	t.Logf("class files written by jad: %q (%v)", strings.TrimSpace(string(out)), err)
	if !strings.Contains(string(out), "/classdump/") {
		t.Error("jad: no class file under a classdump directory")
	}

	// The clean-up of the product: every step, a confirming reset, then the server is gone.
	stopLoad()
	res := c.Cleanup(ctx, s.ID, CleanupOptions{ConfirmReset: true})
	for _, st := range res.Steps {
		t.Logf("cleanup %-13s sent=%-5v elapsed=%-6s note=%q err=%v", st.Name, st.Sent, st.Elapsed.Round(time.Millisecond), st.Note, st.Err)
	}
	if err := res.Err(); err != nil {
		t.Errorf("cleanup: %v", err)
	}
	if restored, left, err := res.Enhanced(); restored != 0 || left != 0 || err != nil {
		t.Errorf("Enhanced() = %d, %d, %v; want 0, 0", restored, left, err)
	}
	attached = false
	t.Logf("stopped %s after stop", tg.waitStopped(t, realHTTPPort, 15*time.Second).Round(time.Millisecond))
	for _, filter := range []string{"arthas", "ResultDistributor", "Timer-for-arthas"} {
		var names []string
		tg.appGet(t, "/diag/threads?filter="+filter, &names)
		if len(names) > 0 {
			t.Errorf("threads named %q after stop: %q", filter, names)
		}
	}
	tg.appGet(t, "/ping", nil)
}
