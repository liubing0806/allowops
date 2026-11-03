package arthas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// jobServer is a fake Arthas that runs scripted background jobs. Every async_exec takes the
// next entry of jobs: the batches that the following pull_results requests return, one batch per
// request, with JOB in each result replaced by the job ID. A pull with nothing queued returns no
// result at once.
type jobServer struct {
	*fakeArthas
	mu      sync.Mutex
	jobs    [][][]string
	started int
	pending [][]string
	// exec answers exec requests by command; a missing command fails the test.
	exec map[string]string
}

const firstJobID = 11

func newJobServer(t *testing.T, jobs ...[][]string) *jobServer {
	t.Helper()
	s := &jobServer{jobs: jobs}
	s.fakeArthas = newFakeArthas(t, func(w http.ResponseWriter, req map[string]any) string {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch req["action"] {
		case "init_session":
			return `{"state":"SUCCEEDED","sessionId":"sess-1","consumerId":"cons-1"}`
		case "async_exec":
			if s.started == len(s.jobs) {
				t.Errorf("unexpected async_exec %v", req["command"])
				return `{"state":"FAILED","message":"no job left"}`
			}
			id := firstJobID + s.started
			for _, batch := range s.jobs[s.started] {
				var out []string
				for _, r := range batch {
					out = append(out, strings.ReplaceAll(r, "JOB", fmt.Sprint(id)))
				}
				s.pending = append(s.pending, out)
			}
			s.started++
			return fmt.Sprintf(`{"state":"SCHEDULED","sessionId":"sess-1","body":{"jobId":%d,"jobStatus":"READY"}}`, id)
		case "pull_results":
			if req["sessionId"] != "sess-1" || req["consumerId"] != "cons-1" {
				t.Errorf("pull_results without the session and consumer: %v", req)
			}
			var batch []string
			if len(s.pending) > 0 {
				batch, s.pending = s.pending[0], s.pending[1:]
			}
			return `{"state":"SUCCEEDED","sessionId":"sess-1","consumerId":"cons-1","body":{"results":[` + strings.Join(batch, ",") + `]}}`
		case "exec":
			cmd, _ := req["command"].(string)
			if body, ok := s.exec[cmd]; ok {
				return body
			}
			t.Errorf("unexpected exec %q", cmd)
			return `{"state":"FAILED","message":"unexpected"}`
		}
		t.Errorf("unexpected request %v", req)
		return `{"state":"FAILED"}`
	})
	return s
}

func (s *jobServer) count(action string) int {
	n := 0
	for _, r := range s.seen() {
		if r["action"] == action {
			n++
		}
	}
	return n
}

var testSession = Session{ID: "sess-1", ConsumerID: "cons-1"}

const (
	jobCommand    = `{"type":"command","jobId":JOB,"state":"SCHEDULED","command":"watch"}`
	jobAffectOK   = `{"type":"enhancer","jobId":JOB,"success":true,"effect":{"classCount":1,"methodCount":1,"cost":20,"listenerId":1}}`
	jobAffectBusy = `{"type":"enhancer","jobId":JOB,"success":false,"message":"someone else is enhancing classes, pls. wait."}`
	jobWatch      = `{"type":"watch","jobId":JOB,"ts":"2026-10-26 10:00:00.000","cost":0.5,"className":"demo.HotService","methodName":"work","accessPoint":"AtExit","value":"@Integer[1]"}`
	jobStack      = `{"type":"stack","jobId":JOB,"ts":"2026-10-26 10:00:00.000","threadName":"main","threadId":"1","stackTrace":[]}`
	jobEnded      = `{"type":"status","jobId":JOB,"statusCode":0}`
	jobFailed     = `{"type":"status","jobId":JOB,"statusCode":-1,"message":"enhance failed"}`
)

// recordedEnhancer returns the enhancer result of a recorded job with JOB as its job ID.
func recordedEnhancer(t *testing.T, jdk, name string) string {
	t.Helper()
	for _, r := range loadResponse(t, jdk, name).Results {
		if r.Type != "enhancer" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(r.Raw, &m); err != nil {
			t.Fatal(err)
		}
		m["jobId"] = "JOB"
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Replace(string(b), `"JOB"`, "JOB", 1)
	}
	t.Fatalf("%s/%s has no enhancer result", jdk, name)
	return ""
}

func watchCommand(t *testing.T) Command {
	t.Helper()
	cmd, err := Build(Request{Kind: KindWatch, Class: "demo.HotService", Method: "work", Express: "params", Expand: 1, Count: 2}, l2Policy)
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestOpenSession(t *testing.T) {
	s := newJobServer(t)
	got, err := s.client(t, nil).OpenSession(context.Background())
	if err != nil || got != testSession {
		t.Fatalf("OpenSession() = %+v, %v", got, err)
	}
	noConsumer := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string {
		return `{"state":"SUCCEEDED","sessionId":"sess-1"}`
	})
	if _, err := noConsumer.client(t, nil).OpenSession(context.Background()); err == nil {
		t.Fatal("OpenSession accepted a response without a consumer ID")
	}
}

func TestAsyncExec(t *testing.T) {
	s := newJobServer(t, [][]string{})
	c := s.client(t, nil)
	cmd := watchCommand(t)
	id, err := c.AsyncExec(context.Background(), testSession, cmd)
	if err != nil || id != firstJobID {
		t.Fatalf("AsyncExec() = %d, %v", id, err)
	}
	req := s.seen()[0]
	if req["command"] != cmd.Text || req["sessionId"] != "sess-1" {
		t.Errorf("request = %v", req)
	}
	if _, ok := req["execTimeout"]; ok {
		t.Errorf("async_exec carries execTimeout: %v", req)
	}
	if _, err := c.AsyncExec(context.Background(), testSession, Command{Text: "watch * * -n 1"}); err == nil {
		t.Error("AsyncExec accepted a command not built by Build")
	}
	if _, err := c.AsyncExec(context.Background(), Session{}, cmd); err == nil {
		t.Error("AsyncExec accepted an empty session")
	}
	if n := len(s.seen()); n != 1 {
		t.Errorf("%d requests, want 1", n)
	}
	for _, body := range []string{
		`{"state":"FAILED","message":"no session"}`,
		`{"state":"SUCCEEDED","body":{"jobId":3}}`,
		`{"state":"SCHEDULED","body":{}}`,
	} {
		f := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string { return body })
		if id, err := f.client(t, nil).AsyncExec(context.Background(), testSession, cmd); err == nil {
			t.Errorf("AsyncExec accepted %s as job %d", body, id)
		}
	}
}

func TestPullResultsNeedsTheConsumer(t *testing.T) {
	s := newJobServer(t)
	if _, err := s.client(t, nil).PullResults(context.Background(), Session{ID: "sess-1"}); err == nil {
		t.Fatal("PullResults without a consumer ID")
	}
	if n := len(s.seen()); n != 0 {
		t.Errorf("%d requests, want 0", n)
	}
}

func TestRunJobCollectsTheResultsOfItsJob(t *testing.T) {
	other := `{"type":"watch","jobId":99,"value":"@String[other]"}`
	s := newJobServer(t, [][]string{
		{jobCommand, jobAffectOK, other, `{"type":"input_status","jobId":JOB,"inputStatus":"DISABLED"}`},
		{},
		{jobWatch, jobWatch},
		{jobEnded},
	})
	job, err := s.client(t, nil).RunJob(context.Background(), testSession, watchCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	if job.ID != firstJobID || !job.Ended || job.Code != 0 || len(job.Results) != 2 || job.Dropped != 0 {
		t.Fatalf("job = %+v", job)
	}
	if job.Affect == nil || *job.Affect != (Affect{Success: true, Classes: 1, Methods: 1}) || job.Affect.String() != "classes 1, methods 1" {
		t.Errorf("affect = %+v", job.Affect)
	}
	text, err := Render(KindWatch, job.Response())
	if err != nil || strings.Count(text, "# watch\n") != 2 || strings.Contains(text, "other") {
		t.Errorf("Render = %q, %v", text, err)
	}
	if n := s.count("async_exec"); n != 1 {
		t.Errorf("%d async_exec requests, want 1", n)
	}
}

func TestRunJobStopsAtAnEnhancementOverTheLimit(t *testing.T) {
	for _, jdk := range []string{"jdk8", "jdk17"} {
		t.Run(jdk, func(t *testing.T) {
			s := newJobServer(t, [][]string{{jobCommand, recordedEnhancer(t, jdk, "watch_over_limit")}, {jobFailed}})
			job, err := s.client(t, nil).RunJob(context.Background(), testSession, watchCommand(t))
			var ae *AffectError
			if !errors.As(err, &ae) {
				t.Fatalf("RunJob() = %+v, %v; want an AffectError", job, err)
			}
			want := "the enhancement failed: The number of matched classes is 2, greater than the limit value 1."
			if !strings.HasPrefix(ae.Error(), want) || ae.Affect.Success {
				t.Errorf("error %q, affect %+v", ae.Error(), ae.Affect)
			}
			// RunJob returns at the enhancer result; the caller interrupts the job and resets.
			if job.Ended || s.count("pull_results") != 1 || s.count("async_exec") != 1 {
				t.Errorf("job %+v after %d pulls", job, s.count("pull_results"))
			}
		})
	}
}

func TestRunJobRetriesABusyEnhancement(t *testing.T) {
	s := newJobServer(t,
		[][]string{{jobCommand, jobAffectBusy}, {jobFailed}},
		[][]string{{jobCommand, jobAffectOK, jobStack, jobEnded}},
	)
	start := time.Now()
	job, err := s.client(t, nil).RunJob(context.Background(), testSession, watchCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	if job.ID != firstJobID+1 || job.Affect == nil || !job.Affect.Success || len(job.Results) != 1 || !job.Ended {
		t.Errorf("job = %+v", job)
	}
	if n := s.count("async_exec"); n != 2 {
		t.Errorf("%d async_exec requests, want 2", n)
	}
	if elapsed := time.Since(start); elapsed < busyPause {
		t.Errorf("started again after %s, want at least %s", elapsed, busyPause)
	}
}

func TestRunJobGivesUpAfterThreeBusyEnhancements(t *testing.T) {
	busy := [][]string{{jobCommand, jobAffectBusy}, {jobFailed}}
	s := newJobServer(t, busy, busy, busy)
	job, err := s.client(t, nil).RunJob(context.Background(), testSession, watchCommand(t))
	var ae *AffectError
	if !errors.As(err, &ae) || !ae.Affect.Busy() || !strings.Contains(err.Error(), "someone else is enhancing classes") {
		t.Fatalf("RunJob() = %+v, %v", job, err)
	}
	if n := s.count("async_exec"); n != busyAttempts {
		t.Errorf("%d async_exec requests, want %d", n, busyAttempts)
	}
}

// When the n-th result ends the job before Arthas appends the enhancer result, the enhancer
// result is lost; the job still counts as done.
func TestRunJobWithoutAnEnhancerResult(t *testing.T) {
	s := newJobServer(t, [][]string{{jobCommand, jobStack, jobEnded}})
	job, err := s.client(t, nil).RunJob(context.Background(), testSession, watchCommand(t))
	if err != nil || job.Affect != nil || len(job.Results) != 1 || !job.Ended {
		t.Fatalf("RunJob() = %+v, %v", job, err)
	}
}

func TestRunJobAcceptsOnlyEnhancingCommands(t *testing.T) {
	s := newJobServer(t)
	cmd, err := Build(Request{Kind: KindJad, Class: "demo.HotService"}, l2Policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.client(t, nil).RunJob(context.Background(), testSession, cmd); err == nil {
		t.Fatal("RunJob accepted jad")
	}
	if n := len(s.seen()); n != 0 {
		t.Errorf("%d requests, want 0", n)
	}
}

func TestFollowEndsWithTheContext(t *testing.T) {
	s := newJobServer(t, [][]string{{jobCommand, jobAffectOK}})
	c := s.client(t, nil)
	id, err := c.AsyncExec(context.Background(), testSession, watchCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	job, err := c.Follow(ctx, testSession, id, nil)
	if !errors.Is(err, context.DeadlineExceeded) || job.Affect == nil || job.Ended {
		t.Fatalf("Follow() = %+v, %v", job, err)
	}
}

func TestFollowKeepsAtMostMaxJobResults(t *testing.T) {
	var batches [][]string
	for range 6 {
		batch := make([]string, 10)
		for i := range batch {
			batch[i] = jobWatch
		}
		batches = append(batches, batch)
	}
	s := newJobServer(t, append(batches, []string{jobEnded}))
	job, err := s.client(t, nil).RunJob(context.Background(), testSession, watchCommand(t))
	if err != nil || len(job.Results) != maxJobResults || job.Dropped != 60-maxJobResults || !job.Ended {
		t.Fatalf("RunJob() = %d results, %d dropped, %v", len(job.Results), job.Dropped, err)
	}
}

func TestFollowRejectsMalformedResults(t *testing.T) {
	for _, r := range []string{
		`{"type":"enhancer","jobId":JOB}`,
		`{"type":"enhancer","jobId":JOB,"success":true}`,
		`{"type":"enhancer","jobId":JOB,"success":"yes"}`,
		`{"type":"status","jobId":JOB,"statusCode":"x"}`,
	} {
		s := newJobServer(t, [][]string{{r}})
		if job, err := s.client(t, nil).RunJob(context.Background(), testSession, watchCommand(t)); err == nil {
			t.Errorf("%s accepted: %+v", r, job)
		}
	}
}

func TestJobResponseAddsTheStatus(t *testing.T) {
	job := &Job{ID: 4, Results: []Result{{Type: "watch", Raw: json.RawMessage(`{"type":"watch"}`)}}, Ended: true, Code: -1, Message: "boom"}
	resp := job.Response()
	if code, msg, found := resp.Status(); !found || code != -1 || msg != "boom" || len(resp.Results) != 2 || len(job.Results) != 1 {
		t.Fatalf("Response() = %+v", resp)
	}
	job.Ended = false
	if _, _, found := job.Response().Status(); found {
		t.Error("a running job has a status")
	}
}

func TestCheckAffect(t *testing.T) {
	cmd := Command{MaxMethods: 3}
	for _, c := range []struct {
		a      Affect
		reason string
	}{
		{Affect{Success: true, Classes: 1, Methods: 1}, ""},
		{Affect{Success: true, Classes: 1, Methods: 3}, ""},
		{Affect{Success: true, Classes: 1, Methods: 4}, "the enhancement affected 4 methods, the limit is 3"},
		{Affect{Success: true, Classes: 2, Methods: 2}, "the enhancement affected 2 classes, the limit is 1"},
		{Affect{Success: true, Classes: 0, Methods: 0}, "the enhancement affected 0 classes, the limit is 1"},
		{Affect{Success: true, Classes: 1, Methods: 0}, "the enhancement affected no method"},
		{Affect{Success: false, Classes: 1, Methods: 1}, "the enhancement failed"},
		{Affect{Success: false, Message: "No class or method is affected"}, "the enhancement failed: No class or method is affected"},
	} {
		err := cmd.CheckAffect(c.a)
		var ae *AffectError
		switch {
		case c.reason == "" && err != nil:
			t.Errorf("%+v: %v", c.a, err)
		case c.reason != "" && (!errors.As(err, &ae) || ae.Reason != c.reason || ae.Affect != c.a):
			t.Errorf("%+v: %v, want %q", c.a, err, c.reason)
		}
	}
}

func TestParseAffectReadsRecordedResults(t *testing.T) {
	for _, jdk := range []string{"jdk8", "jdk17"} {
		for _, c := range []struct {
			name string
			want Affect
		}{
			{"watch", Affect{Success: true, Classes: 1, Methods: 1}},
			{"watch_over_limit", Affect{Message: "The number of matched classes is 2, greater than the limit value 1. Try to change the limit with option '-m <arg>'."}},
			{"watch_no_method", Affect{Classes: 1, Message: "No class or method is affected"}},
		} {
			raw := strings.Replace(recordedEnhancer(t, jdk, c.name), "JOB", "1", 1)
			got, err := parseAffect(json.RawMessage(raw))
			if err != nil || got != c.want {
				t.Errorf("%s/%s: %+v, %v; want %+v", jdk, c.name, got, err, c.want)
			}
		}
	}
	got, err := parseAffect(json.RawMessage(`{"success":false,"message":"\u001b[31mbad\u001b[m thing "}`))
	if err != nil || got.Message != "bad thing" {
		t.Errorf("colour sequences: %+v, %v", got, err)
	}
}

func TestAffectBusy(t *testing.T) {
	busy := Affect{Message: enhancerBusy}
	if !busy.Busy() {
		t.Error("busy enhancement not recognised")
	}
	for _, a := range []Affect{{Success: true, Message: enhancerBusy}, {Classes: 1, Message: enhancerBusy}, {Message: "other"}} {
		if a.Busy() {
			t.Errorf("%+v counted as busy", a)
		}
	}
}

func optionsResult(name, value string) string {
	return `{"state":"SUCCEEDED","sessionId":"sess-1","body":{"jobId":5,"jobStatus":"TERMINATED","results":[` +
		`{"type":"options","jobId":5,"changeResult":{"name":"` + name + `","beforeValue":false,"afterValue":` + value + `}},` +
		`{"type":"status","jobId":5,"statusCode":0}]}}`
}

func TestSetupSendsTheOptionsInOrder(t *testing.T) {
	s := newJobServer(t)
	s.exec = map[string]string{
		"options disable-sub-class true": optionsResult("disable-sub-class", "true"),
		"options object-size-limit 8192": optionsResult("object-size-limit", "8192"),
	}
	cmd := watchCommand(t)
	if err := s.client(t, nil).Setup(context.Background(), "sess-1", cmd); err != nil {
		t.Fatal(err)
	}
	var sent []string
	for _, r := range s.seen() {
		if r["sessionId"] != "sess-1" {
			t.Errorf("setup outside the session: %v", r)
		}
		sent = append(sent, r["command"].(string))
	}
	if strings.Join(sent, "|") != strings.Join(cmd.Setup, "|") {
		t.Errorf("sent %q, want %q", sent, cmd.Setup)
	}
}

func TestSetupChecksTheOptionResults(t *testing.T) {
	statusFailed := `{"state":"SUCCEEDED","body":{"jobId":5,"results":[{"type":"status","jobId":5,"statusCode":1,"message":"options: unknown"}]}}`
	for name, body := range map[string]string{
		"other value":  optionsResult("disable-sub-class", "false"),
		"other option": optionsResult("unsafe", "true"),
		"no result":    `{"state":"SUCCEEDED","body":{"jobId":5,"results":[{"type":"status","jobId":5,"statusCode":0}]}}`,
		"status":       statusFailed,
		"state":        `{"state":"REFUSED","message":"command options is not enabled"}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := newJobServer(t)
			s.exec = map[string]string{"options disable-sub-class true": body}
			cmd, err := Build(Request{Kind: KindTrace, Class: "demo.HotService", Method: "work", Count: 1}, l2Policy)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.client(t, nil).Setup(context.Background(), "sess-1", cmd); err == nil {
				t.Fatal("Setup accepted the answer")
			}
		})
	}
	s := newJobServer(t)
	if err := s.client(t, nil).Setup(context.Background(), "sess-1", Command{Setup: []string{"options unsafe true"}}); err == nil || len(s.seen()) != 0 {
		t.Errorf("Setup ran a command not built by Build: %v", err)
	}
}

// resetServer answers each reset with the next class count of counts; a negative count leaves
// the count out.
func resetServer(t *testing.T, counts ...int) *fakeArthas {
	t.Helper()
	var mu sync.Mutex
	return newFakeArthas(t, func(w http.ResponseWriter, req map[string]any) string {
		if req["command"] == "stop" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return ""
		}
		if req["command"] != "reset" {
			return `{"state":"SUCCEEDED"}`
		}
		mu.Lock()
		defer mu.Unlock()
		n := counts[0]
		counts = counts[1:]
		affect := fmt.Sprintf(`{"classCount":%d,"methodCount":%d}`, n, n)
		if n < 0 {
			affect = `{}`
		}
		return `{"state":"SUCCEEDED","body":{"jobId":9,"results":[{"jobId":9,"type":"reset","affect":` + affect + `},{"jobId":9,"statusCode":0,"type":"status"}]}}`
	})
}

func TestCleanupConfirmReset(t *testing.T) {
	f := resetServer(t, 1, 0)
	res := f.client(t, nil).Cleanup(context.Background(), "sess-1", CleanupOptions{ConfirmReset: true})
	want := []string{StepInterruptJob, StepCloseSession, StepReset, StepConfirmReset, StepStop}
	var names []string
	for _, s := range res.Steps {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != strings.Join(want, ",") || res.Err() != nil {
		t.Fatalf("steps %q, %v", names, res.Err())
	}
	if restored, left, err := res.Enhanced(); restored != 1 || left != 0 || err != nil {
		t.Errorf("Enhanced() = %d, %d, %v", restored, left, err)
	}
	if got := actions(f); strings.Join(got, ",") != "interrupt_job,close_session,reset,reset,stop" {
		t.Errorf("requests %v", got)
	}
	for _, s := range res.Steps {
		if (s.Name == StepReset || s.Name == StepConfirmReset) != (s.Restored >= 0) {
			t.Errorf("step %s restored %d", s.Name, s.Restored)
		}
	}
}

func TestCleanupConfirmResetReportsWhatStayed(t *testing.T) {
	f := resetServer(t, 2, 1)
	res := f.client(t, nil).Cleanup(context.Background(), "sess-1", CleanupOptions{ConfirmReset: true})
	if restored, left, err := res.Enhanced(); restored != 2 || left != 1 || err != nil {
		t.Errorf("Enhanced() = %d, %d, %v", restored, left, err)
	}
	f = resetServer(t, 1, -1)
	res = f.client(t, nil).Cleanup(context.Background(), "sess-1", CleanupOptions{ConfirmReset: true})
	if _, left, err := res.Enhanced(); left != -1 || err == nil {
		t.Errorf("a confirming reset without a count: %d, %v", left, err)
	}
	f = cleanupServer(t, map[string]string{"reset": `{"state":"FAILED","message":"boom"}`}, "eof")
	res = f.client(t, nil).Cleanup(context.Background(), "sess-1", CleanupOptions{ConfirmReset: true})
	if restored, left, err := res.Enhanced(); restored != -1 || left != -1 || err == nil {
		t.Errorf("failed resets: %d, %d, %v", restored, left, err)
	}
	f = resetServer(t, 1)
	res = f.client(t, nil).Cleanup(context.Background(), "sess-1", CleanupOptions{})
	if len(res.Steps) != 4 {
		t.Errorf("steps %+v", res.Steps)
	}
	if _, _, err := res.Enhanced(); err == nil {
		t.Error("Enhanced() without a confirming reset")
	}
}
