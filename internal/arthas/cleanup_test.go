package arthas

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// cleanupServer answers the four clean-up requests. stop closes the connection
// without a response, as Arthas does.
func cleanupServer(t *testing.T, answers map[string]string, stopMode string) *fakeArthas {
	t.Helper()
	return newFakeArthas(t, func(w http.ResponseWriter, req map[string]any) string {
		key, _ := req["action"].(string)
		if key == "exec" {
			key, _ = req["command"].(string)
		}
		if key == "stop" {
			switch stopMode {
			case "eof":
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					conn.Close()
				}
				return ""
			case "partial":
				conn, buf, err := w.(http.Hijacker).Hijack()
				if err == nil {
					buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{\"state\"")
					buf.Flush()
					conn.Close()
				}
				return ""
			case "rst":
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					conn.(*net.TCPConn).SetLinger(0) // close sends RST
					conn.Close()
				}
				return ""
			}
		}
		if a, ok := answers[key]; ok {
			return a
		}
		return `{"state":"SUCCEEDED"}`
	})
}

func requireSteps(t *testing.T, res CleanupResult) {
	t.Helper()
	if len(res.Steps) != 4 {
		t.Fatalf("steps = %+v, want 4", res.Steps)
	}
}

func actions(f *fakeArthas) []string {
	var out []string
	for _, r := range f.seen() {
		a, _ := r["action"].(string)
		if a == "exec" {
			a = r["command"].(string)
		}
		out = append(out, a)
	}
	return out
}

const resetOK = `{"state":"SUCCEEDED","body":{"jobId":9,"jobStatus":"TERMINATED","timeExpired":false,"results":[` +
	`{"jobId":9,"type":"reset","affect":{"classCount":2,"methodCount":3,"cost":1,"listenerId":0}},{"jobId":9,"statusCode":0,"type":"status"}]}}`

func TestCleanupRunsTheFourStepsInOrder(t *testing.T) {
	f := cleanupServer(t, map[string]string{
		"interrupt_job": `{"state":"SUCCEEDED","body":{"jobId":3,"jobStatus":"TERMINATED"}}`,
		"reset":         resetOK,
	}, "eof")
	res := f.client(t, nil).Cleanup(context.Background(), "sess-1", CleanupOptions{})
	requireSteps(t, res)
	want := []string{"interrupt_job", "close_session", "reset", "stop"}
	if got := actions(f); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("requests = %v, want %v", got, want)
	}
	if len(res.Steps) != 4 {
		t.Fatalf("steps = %+v", res.Steps)
	}
	for i, s := range res.Steps {
		if s.Name != want[i] || !s.Sent || s.Err != nil {
			t.Errorf("step %d = %+v", i, s)
		}
	}
	if err := res.Err(); err != nil {
		t.Errorf("Err() = %v", err)
	}
	reqs := f.seen()
	if reqs[0]["sessionId"] != "sess-1" || reqs[1]["sessionId"] != "sess-1" {
		t.Errorf("interrupt_job and close_session must carry the session: %v", reqs[:2])
	}
	for _, r := range reqs[2:] {
		if _, ok := r["sessionId"]; ok {
			t.Errorf("reset and stop run after the session is closed: %v", r)
		}
		if ms, _ := r["execTimeout"].(float64); ms <= 0 || ms > 60000 {
			t.Errorf("execTimeout = %v", r["execTimeout"])
		}
	}
	if !strings.Contains(res.Steps[2].Note, "2") {
		t.Errorf("reset note = %q, want the restored class count", res.Steps[2].Note)
	}
}

func TestCleanupRunsWhenTheContextIsAlreadyCancelled(t *testing.T) {
	f := cleanupServer(t, map[string]string{"reset": resetOK}, "eof")
	c := f.client(t, nil)
	inner := c.cfg.Dial
	c.cfg.Dial = func(ctx context.Context) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return inner(ctx)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := c.Cleanup(ctx, "sess-1", CleanupOptions{})
	requireSteps(t, res)
	if err := res.Err(); err != nil {
		t.Fatalf("Err() = %v; steps %+v", err, res.Steps)
	}
	if got := actions(f); len(got) != 4 {
		t.Fatalf("requests = %v", got)
	}
}

func TestCleanupKeepsGoingAfterAFailedStep(t *testing.T) {
	f := cleanupServer(t, map[string]string{
		"interrupt_job": `{"state":"FAILED","message":"boom"}`,
		"close_session": `{"state":"FAILED","message":"boom"}`,
		"reset":         `{"state":"FAILED","message":"Exec command failed:java.lang.IllegalArgumentException: reset: command not found"}`,
	}, "eof")
	res := f.client(t, nil).Cleanup(context.Background(), "sess-1", CleanupOptions{})
	if got := actions(f); len(got) != 4 {
		t.Fatalf("requests = %v", got)
	}
	requireSteps(t, res)
	for _, i := range []int{0, 1, 2} {
		if res.Steps[i].Err == nil {
			t.Errorf("step %d has no error: %+v", i, res.Steps[i])
		}
	}
	if !errors.Is(res.Steps[2].Err, ErrCommandNotFound) {
		t.Errorf("reset error = %v", res.Steps[2].Err)
	}
	if !res.Steps[3].Sent || res.Steps[3].Err != nil {
		t.Errorf("stop = %+v", res.Steps[3])
	}
	if err := res.Err(); err == nil || !strings.Contains(err.Error(), "reset") {
		t.Errorf("Err() = %v, want an error that names the reset step", err)
	}
}

func TestCleanupTreatsMissingJobAndSessionAsDone(t *testing.T) {
	f := cleanupServer(t, map[string]string{
		"interrupt_job": `{"state":"FAILED","message":"no foreground job is running"}`,
		"close_session": `{"state":"FAILED","message":"session not found: sess-1"}`,
		"reset":         resetOK,
	}, "eof")
	res := f.client(t, nil).Cleanup(context.Background(), "sess-1", CleanupOptions{})
	if err := res.Err(); err != nil {
		t.Fatalf("Err() = %v; steps %+v", err, res.Steps)
	}
	requireSteps(t, res)
	if !strings.Contains(res.Steps[0].Note, "no foreground job") {
		t.Errorf("note = %q", res.Steps[0].Note)
	}
}

func TestCleanupWithoutSessionSkipsTheSessionSteps(t *testing.T) {
	f := cleanupServer(t, map[string]string{"reset": resetOK}, "eof")
	res := f.client(t, nil).Cleanup(context.Background(), "", CleanupOptions{})
	if got := actions(f); strings.Join(got, ",") != "reset,stop" {
		t.Fatalf("requests = %v", got)
	}
	requireSteps(t, res)
	if res.Steps[0].Sent || res.Steps[1].Sent || res.Err() != nil {
		t.Fatalf("steps = %+v, err %v", res.Steps, res.Err())
	}
}

func TestCleanupStopAnswers(t *testing.T) {
	cases := map[string]struct {
		mode string
		sent bool
		fail bool
	}{
		"closed without a response": {"eof", true, false},
		"closed in the middle":      {"reset", true, false},
		"normal response":           {"", true, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := cleanupServer(t, map[string]string{"reset": resetOK, "stop": `{"state":"SUCCEEDED"}`}, c.mode)
			res := f.client(t, nil).Cleanup(context.Background(), "s", CleanupOptions{})
			requireSteps(t, res)
			stop := res.Steps[3]
			if stop.Sent != c.sent || (stop.Err != nil) != c.fail {
				t.Fatalf("stop = %+v", stop)
			}
		})
	}
}

func TestCleanupStopWithUnreachableServerIsAnError(t *testing.T) {
	f := cleanupServer(t, nil, "eof")
	c := f.client(t, nil)
	f.Close() // nothing listens any more: every dial fails
	res := c.Cleanup(context.Background(), "s", CleanupOptions{StepTimeout: time.Second})
	requireSteps(t, res)
	for _, s := range res.Steps {
		if s.Sent || s.Err == nil {
			t.Errorf("step %+v, want an error and Sent=false", s)
		}
	}
	if res.Err() == nil {
		t.Error("Err() is nil")
	}
}

func TestCleanupStepsHaveTheirOwnTimeout(t *testing.T) {
	var once sync.Once
	f := newFakeArthas(t, func(w http.ResponseWriter, req map[string]any) string {
		if req["action"] == "interrupt_job" {
			once.Do(func() { time.Sleep(600 * time.Millisecond) })
		}
		return `{"state":"SUCCEEDED"}`
	})
	start := time.Now()
	res := f.client(t, nil).Cleanup(context.Background(), "s", CleanupOptions{Budget: 10 * time.Second, StepTimeout: 200 * time.Millisecond})
	requireSteps(t, res)
	if res.Steps[0].Err == nil {
		t.Errorf("slow step has no error: %+v", res.Steps[0])
	}
	for _, i := range []int{1, 2} {
		if res.Steps[i].Err != nil {
			t.Errorf("step %d after the slow step: %+v", i, res.Steps[i])
		}
	}
	if len(f.seen()) != 4 {
		t.Errorf("requests = %v", actions(f))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %s", d)
	}
}

func TestCleanupBudgetBoundsTheWholeSequence(t *testing.T) {
	release := make(chan struct{})
	f := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string {
		<-release
		return ""
	})
	t.Cleanup(func() { close(release) })
	start := time.Now()
	res := f.client(t, nil).Cleanup(context.Background(), "s", CleanupOptions{Budget: 300 * time.Millisecond, StepTimeout: time.Second})
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %s with a 300ms budget", d)
	}
	requireSteps(t, res)
	for _, s := range res.Steps {
		if s.Err == nil {
			t.Errorf("step %+v has no error", s)
		}
	}
}
