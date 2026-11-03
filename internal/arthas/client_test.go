package arthas

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testPassword = "s3cretPasswordForTests0123456789"

// fakeArthas is an httptest server that behaves like the Arthas HTTP API: it
// checks Basic authentication and hands the decoded JSON request to a handler.
type fakeArthas struct {
	*httptest.Server
	mu       sync.Mutex
	requests []map[string]any
	// handle returns the JSON body of the response; it may also write to w itself and return "".
	handle func(w http.ResponseWriter, req map[string]any) string
}

func newFakeArthas(t *testing.T, handle func(w http.ResponseWriter, req map[string]any) string) *fakeArthas {
	t.Helper()
	f := &fakeArthas{handle: handle}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "arthas" || pass != testPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="arthas"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api" {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
			return
		}
		data, _ := io.ReadAll(r.Body)
		var req map[string]any
		if err := json.Unmarshal(data, &req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.requests = append(f.requests, req)
		f.mu.Unlock()
		if body := f.handle(w, req); body != "" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			io.WriteString(w, body)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeArthas) seen() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.requests...)
}

func (f *fakeArthas) client(t *testing.T, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", f.Listener.Addr().String())
		},
		Password: testPassword,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustBuild(t *testing.T, req Request) Command {
	t.Helper()
	cmd, err := Build(req, testPolicy)
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

const execOK = `{"sessionId":"sess-1","state":"SUCCEEDED","body":{"command":"version","jobId":7,"jobStatus":"TERMINATED","timeExpired":false,` +
	`"results":[{"jobId":7,"type":"version","version":"4.3.5"},{"jobId":7,"statusCode":0,"type":"status"}]}}`

func TestNewClientValidatesConfig(t *testing.T) {
	dial := func(context.Context) (net.Conn, error) { return nil, errors.New("unused") }
	for name, cfg := range map[string]Config{
		"no dial":            {Password: testPassword},
		"no password":        {Dial: dial},
		"negative max":       {Dial: dial, Password: testPassword, MaxResponseBytes: -1},
		"negative timeout":   {Dial: dial, Password: testPassword, RequestTimeout: -time.Second},
		"negative grace":     {Dial: dial, Password: testPassword, ExecGrace: -time.Second},
		"colon in user name": {Dial: dial, Password: testPassword, Username: "a:b"},
	} {
		if _, err := NewClient(cfg); err == nil {
			t.Errorf("%s: NewClient succeeded", name)
		}
	}
	if _, err := NewClient(Config{Dial: dial, Password: testPassword}); err != nil {
		t.Errorf("defaults rejected: %v", err)
	}
}

func TestInitSession(t *testing.T) {
	f := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string {
		return `{"state":"SUCCEEDED","sessionId":"sess-1","consumerId":"cons-1"}`
	})
	id, err := f.client(t, nil).InitSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != "sess-1" {
		t.Fatalf("session = %q", id)
	}
	if got := f.seen(); len(got) != 1 || got[0]["action"] != "init_session" {
		t.Fatalf("requests = %v", got)
	}
}

func TestInitSessionWithoutSessionIDIsAnError(t *testing.T) {
	f := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string { return `{"state":"SUCCEEDED"}` })
	if id, err := f.client(t, nil).InitSession(context.Background()); err == nil {
		t.Fatalf("session = %q, want an error", id)
	}
}

func TestExec(t *testing.T) {
	f := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string { return execOK })
	resp, err := f.client(t, nil).Exec(context.Background(), "sess-1", mustBuild(t, Request{Kind: KindVersion}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.SessionID != "sess-1" || resp.JobID != 7 || resp.JobStatus != "TERMINATED" || resp.TimeExpired {
		t.Fatalf("response = %+v", resp)
	}
	if len(resp.Results) != 2 || resp.Results[0].Type != "version" || resp.Results[1].Type != "status" {
		t.Fatalf("results = %+v", resp.Results)
	}
	if !strings.Contains(string(resp.Results[0].Raw), `"version":"4.3.5"`) {
		t.Errorf("raw = %s", resp.Results[0].Raw)
	}
	if code, msg, found := resp.Status(); !found || code != 0 || msg != "" {
		t.Errorf("Status() = %d, %q, %v", code, msg, found)
	}
	req := f.seen()[0]
	if req["action"] != "exec" || req["command"] != "version" || req["sessionId"] != "sess-1" || req["execTimeout"] != float64(30000) {
		t.Fatalf("request = %v", req)
	}
}

func TestExecTimeoutIsSentInMilliseconds(t *testing.T) {
	f := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string { return execOK })
	cmd, err := Build(Request{Kind: KindMemory}, Policy{ExecTimeout: 2500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client(t, nil).Exec(context.Background(), "", cmd); err != nil {
		t.Fatal(err)
	}
	req := f.seen()[0]
	if req["execTimeout"] != float64(2500) {
		t.Fatalf("execTimeout = %v", req["execTimeout"])
	}
	if _, ok := req["sessionId"]; ok {
		t.Errorf("an empty session ID must not be sent: %v", req)
	}
}

func TestExecRefusesCommandsNotBuiltByBuild(t *testing.T) {
	f := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string { return execOK })
	c := f.client(t, nil)
	for _, cmd := range []Command{
		{},
		{Kind: KindVersion, Name: "version", Text: "version", ExecTimeout: time.Second},
		{Kind: KindMemory, Name: "ognl", Text: "ognl @java.lang.Runtime@getRuntime()", ExecTimeout: time.Second},
	} {
		if _, err := c.Exec(context.Background(), "", cmd); err == nil {
			t.Errorf("Exec accepted %+v", cmd)
		}
	}
	if n := len(f.seen()); n != 0 {
		t.Fatalf("%d requests reached the server", n)
	}
}

func TestWrongPasswordIsUnauthorized(t *testing.T) {
	f := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string { return execOK })
	c := f.client(t, func(cfg *Config) { cfg.Password = "wrongPasswordWrongPassword12345" })
	_, err := c.Exec(context.Background(), "", mustBuild(t, Request{Kind: KindVersion}))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Exec error = %v, want ErrUnauthorized", err)
	}
	if strings.Contains(err.Error(), "wrongPassword") {
		t.Errorf("the error shows the password: %v", err)
	}
	if _, err := c.InitSession(context.Background()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("InitSession error = %v, want ErrUnauthorized", err)
	}
	if err := c.CloseSession(context.Background(), "x"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("CloseSession error = %v, want ErrUnauthorized", err)
	}
}

func TestResponseLimit(t *testing.T) {
	big := `{"state":"SUCCEEDED","sessionId":"` + strings.Repeat("a", 4096) + `"}`
	for name, serve := range map[string]func(http.ResponseWriter, map[string]any) string{
		"content length": func(http.ResponseWriter, map[string]any) string { return big },
		"chunked": func(w http.ResponseWriter, _ map[string]any) string {
			w.Header().Set("Content-Type", "application/json")
			for i := 0; i < len(big); i += 512 {
				io.WriteString(w, big[i:min(i+512, len(big))])
				w.(http.Flusher).Flush()
			}
			return ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeArthas(t, serve)
			c := f.client(t, func(cfg *Config) { cfg.MaxResponseBytes = 1024 })
			if _, err := c.InitSession(context.Background()); !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("error = %v, want ErrResponseTooLarge", err)
			}
		})
	}
}

func TestResponseJustWithinTheLimit(t *testing.T) {
	body := `{"state":"SUCCEEDED","sessionId":"s"}`
	f := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string { return body })
	c := f.client(t, func(cfg *Config) { cfg.MaxResponseBytes = int64(len(body)) })
	if _, err := c.InitSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	c = f.client(t, func(cfg *Config) { cfg.MaxResponseBytes = int64(len(body)) - 1 })
	if _, err := c.InitSession(context.Background()); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
}

// The server listens inside the target and is not trusted to answer with a bounded head:
// http.ReadResponse takes a status line and header lines of any length. The client stops reading
// once the response passes its limit, instead of buffering whatever the server sends until the
// request times out.
func TestResponseHeadLimit(t *testing.T) {
	const flood = 64 << 20
	for name, prefix := range map[string]string{
		"status line": "HTTP/1.1 200 ",
		"header":      "HTTP/1.1 200 OK\r\nX-Filler: ",
	} {
		t.Run(name, func(t *testing.T) {
			var written atomic.Int64
			c, err := NewClient(Config{
				Dial: func(context.Context) (net.Conn, error) {
					client, server := net.Pipe()
					go func() {
						defer server.Close()
						go io.Copy(io.Discard, server) // the request
						if _, err := io.WriteString(server, prefix); err != nil {
							return
						}
						chunk := []byte(strings.Repeat("a", 32<<10))
						for written.Load() < flood {
							n, err := server.Write(chunk)
							written.Add(int64(n))
							if err != nil {
								return
							}
						}
					}()
					return client, nil
				},
				Password:         testPassword,
				MaxResponseBytes: 1 << 20,
				RequestTimeout:   30 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.InitSession(context.Background())
			if !errors.Is(err, ErrResponseTooLarge) {
				t.Errorf("error = %v, want ErrResponseTooLarge", err)
			}
			if n := written.Load(); n > 4<<20 {
				t.Errorf("the client read %d bytes of a response limited to %d", n, 1<<20)
			}
		})
	}
}

func TestRequestTimeout(t *testing.T) {
	release := make(chan struct{})
	f := newFakeArthas(t, func(w http.ResponseWriter, _ map[string]any) string {
		<-release
		return ""
	})
	t.Cleanup(func() { close(release) })
	c := f.client(t, func(cfg *Config) { cfg.RequestTimeout = 100 * time.Millisecond })
	start := time.Now()
	_, err := c.InitSession(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want a deadline error", err)
	}
	var re *RequestError
	if !errors.As(err, &re) || !re.Written {
		t.Fatalf("error = %#v, want a RequestError with Written", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s", d)
	}
}

func TestExecWaitsForExecTimeoutPlusGrace(t *testing.T) {
	f := newFakeArthas(t, func(w http.ResponseWriter, _ map[string]any) string {
		time.Sleep(300 * time.Millisecond)
		return execOK
	})
	// RequestTimeout alone would cut the request off; exec uses execTimeout + grace.
	c := f.client(t, func(cfg *Config) { cfg.RequestTimeout = 50 * time.Millisecond; cfg.ExecGrace = time.Second })
	cmd, err := Build(Request{Kind: KindVersion}, Policy{ExecTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(context.Background(), "", cmd); err != nil {
		t.Fatal(err)
	}
	// Once the grace is over, the call gives up.
	c = f.client(t, func(cfg *Config) { cfg.ExecGrace = 10 * time.Millisecond })
	cmd, _ = Build(Request{Kind: KindVersion}, Policy{ExecTimeout: 50 * time.Millisecond})
	if _, err := c.Exec(context.Background(), "", cmd); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want a deadline error", err)
	}
}

func TestContextCancelStopsTheRequest(t *testing.T) {
	release := make(chan struct{})
	f := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string {
		<-release
		return ""
	})
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, err := f.client(t, nil).Exec(ctx, "", mustBuild(t, Request{Kind: KindVersion}))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s", d)
	}
}

func TestDialFailure(t *testing.T) {
	boom := errors.New("no route")
	c, err := NewClient(Config{
		Dial:     func(context.Context) (net.Conn, error) { return nil, boom },
		Password: testPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.InitSession(context.Background())
	var re *RequestError
	if !errors.As(err, &re) || re.Written || !errors.Is(err, boom) {
		t.Fatalf("error = %#v, want a RequestError that wraps the dial error and has Written=false", err)
	}
}

func TestStateErrors(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		state string
		is    []error
	}{
		{"interrupted", `{"state":"INTERRUPTED","message":"The job is exceeded time limit, force interrupt","body":{"jobId":3,"jobStatus":"STOPPED","timeExpired":true,"timeout":50,` +
			`"results":[{"jobId":3,"type":"thread","all":false}]}}`, "INTERRUPTED", []error{ErrInterrupted}},
		{"failed", `{"state":"FAILED","message":"Exec command failed:java.lang.IllegalArgumentException: sc: command not found"}`, "FAILED", []error{ErrFailed, ErrCommandNotFound}},
		{"failed other", `{"state":"FAILED","message":"Exec command failed:java.lang.NullPointerException"}`, "FAILED", []error{ErrFailed}},
		{"refused", `{"state":"REFUSED","message":"Another job is running.","body":{"command":"jvm"}}`, "REFUSED", []error{ErrRefused}},
		{"no job", `{"state":"FAILED","message":"no foreground job is running"}`, "FAILED", []error{ErrFailed, ErrNoForegroundJob}},
		{"no session", `{"state":"FAILED","message":"session not found: 1234"}`, "FAILED", []error{ErrFailed, ErrSessionNotFound}},
		{"scheduled", `{"state":"SCHEDULED","body":{}}`, "SCHEDULED", nil},
		{"unknown", `{"state":"SOMETHING","message":"?"}`, "SOMETHING", nil},
		{"no state", `{"message":"?"}`, "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string { return c.body })
			_, err := f.client(t, nil).Exec(context.Background(), "s", mustBuild(t, Request{Kind: KindThreadTop, Top: 1}))
			var se *StateError
			if !errors.As(err, &se) {
				t.Fatalf("error = %v, want a StateError", err)
			}
			if se.State != c.state || se.Action != "exec" {
				t.Errorf("StateError = %+v", se)
			}
			for _, want := range c.is {
				if !errors.Is(err, want) {
					t.Errorf("errors.Is(%v, %v) = false", err, want)
				}
			}
			for _, other := range []error{ErrInterrupted, ErrFailed, ErrRefused, ErrCommandNotFound, ErrNoForegroundJob, ErrSessionNotFound} {
				if !containsErr(c.is, other) && errors.Is(err, other) {
					t.Errorf("errors.Is(%v, %v) = true", err, other)
				}
			}
			if c.state == "INTERRUPTED" {
				if se.Response == nil || !se.Response.TimeExpired || len(se.Response.Results) != 1 {
					t.Errorf("partial response = %+v", se.Response)
				}
			}
		})
	}
}

func containsErr(list []error, e error) bool {
	for _, x := range list {
		if x == e {
			return true
		}
	}
	return false
}

func TestExecStatusWithNonZeroCode(t *testing.T) {
	body := `{"state":"SUCCEEDED","body":{"jobId":4,"jobStatus":"TERMINATED","timeExpired":false,` +
		`"results":[{"jobId":4,"message":"No most blocking thread found!","statusCode":1,"type":"status"}]}}`
	f := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string { return body })
	resp, err := f.client(t, nil).Exec(context.Background(), "s", mustBuild(t, Request{Kind: KindThreadBlocking}))
	if err != nil {
		t.Fatal(err)
	}
	if code, msg, found := resp.Status(); !found || code != 1 || msg != "No most blocking thread found!" {
		t.Fatalf("Status() = %d, %q, %v", code, msg, found)
	}
}

func TestBadResponses(t *testing.T) {
	for name, serve := range map[string]func(http.ResponseWriter, map[string]any) string{
		"not json": func(http.ResponseWriter, map[string]any) string { return "<html>oops</html>" },
		"http 500": func(w http.ResponseWriter, _ map[string]any) string {
			http.Error(w, "boom", http.StatusInternalServerError)
			return ""
		},
		"results is not an array": func(http.ResponseWriter, map[string]any) string {
			return `{"state":"SUCCEEDED","body":{"results":{"a":1}}}`
		},
		"result without type": func(http.ResponseWriter, map[string]any) string {
			return `{"state":"SUCCEEDED","body":{"results":[{"jobId":1}]}}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeArthas(t, serve)
			if resp, err := f.client(t, nil).Exec(context.Background(), "s", mustBuild(t, Request{Kind: KindVersion})); err == nil {
				t.Fatalf("Exec succeeded: %+v", resp)
			}
		})
	}
}

func TestInterruptJobAndCloseSession(t *testing.T) {
	f := newFakeArthas(t, func(_ http.ResponseWriter, req map[string]any) string {
		if req["action"] == "interrupt_job" {
			return `{"state":"SUCCEEDED","body":{"jobId":3,"jobStatus":"TERMINATED"}}`
		}
		return `{"state":"SUCCEEDED"}`
	})
	c := f.client(t, nil)
	if err := c.InterruptJob(context.Background(), "sess-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseSession(context.Background(), "sess-1"); err != nil {
		t.Fatal(err)
	}
	got := f.seen()
	if len(got) != 2 || got[0]["action"] != "interrupt_job" || got[0]["sessionId"] != "sess-1" ||
		got[1]["action"] != "close_session" || got[1]["sessionId"] != "sess-1" {
		t.Fatalf("requests = %v", got)
	}
	if err := c.InterruptJob(context.Background(), ""); err == nil {
		t.Error("InterruptJob without a session ID succeeded")
	}
	if err := c.CloseSession(context.Background(), ""); err == nil {
		t.Error("CloseSession without a session ID succeeded")
	}
}

func TestInterruptJobMapsNoJob(t *testing.T) {
	f := newFakeArthas(t, func(http.ResponseWriter, map[string]any) string {
		return `{"state":"FAILED","message":"no foreground job is running"}`
	})
	if err := f.client(t, nil).InterruptJob(context.Background(), "s"); !errors.Is(err, ErrNoForegroundJob) {
		t.Fatalf("error = %v", err)
	}
}
