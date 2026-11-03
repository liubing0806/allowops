package jvmarthas

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/jvmtarget"
)

const (
	rigPassword = "abcdefghijklmnopqrstuvwxyz012345"
	rigPID      = 4242
	rigStart    = 777
)

// fakeServer is the Arthas HTTP API of one JVM. It is started by the attach of the fake JVM.
type fakeServer struct {
	t    *testing.T
	host *fakeHost
	*httptest.Server

	mu       sync.Mutex
	running  bool
	port     int
	password string
	actions  []string
	// ignoreStop makes the stop command a no-op, so that the server keeps running.
	ignoreStop bool
	// onExec handles the exec of a command other than reset, stop and options; it returns true when it wrote the response.
	onExec func(w http.ResponseWriter, r *http.Request, command string) bool
	// jobs are the scripted background jobs: every async_exec takes the next entry, the batches
	// that the following pull_results requests return, with JOB replaced by the job ID.
	jobs    [][][]string
	pending [][]string
	nextJob int
	// resets are the class counts of the reset answers, in order; 0 when they run out, and no
	// count for a negative entry.
	resets []int
	// interruptOK makes interrupt_job succeed, as it does while a job runs.
	interruptOK bool
}

const versionReply = `{"state":"SUCCEEDED","sessionId":"sid-1","body":{"jobId":1,"jobStatus":"TERMINATED","timeExpired":false,` +
	`"results":[{"type":"version","version":"4.3.5"},{"type":"status","statusCode":0}]}}`

func newFakeServer(t *testing.T, host *fakeHost) *fakeServer {
	s := &fakeServer{t: t, host: host}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

func (s *fakeServer) start(port int, password string) {
	s.mu.Lock()
	s.running, s.port, s.password = true, port, password
	s.mu.Unlock()
	s.host.mu.Lock()
	if s.host.listening == nil {
		s.host.listening = map[int]bool{}
	}
	s.host.listening[port] = true
	s.host.threads = 3
	s.host.mu.Unlock()
}

func (s *fakeServer) halt() {
	s.mu.Lock()
	s.running = false
	port := s.port
	s.mu.Unlock()
	s.host.mu.Lock()
	delete(s.host.listening, port)
	s.host.threads = 0
	s.host.mu.Unlock()
}

func (s *fakeServer) isRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// seen returns the actions received so far: init_session, exec:<command>, interrupt_job, close_session.
func (s *fakeServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.actions...)
}

func (s *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	running, password := s.running, s.password
	s.mu.Unlock()
	if !running {
		s.drop(w)
		return
	}
	if _, pass, ok := r.BasicAuth(); !ok || pass != password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	data, _ := io.ReadAll(r.Body)
	var req struct {
		Action     string `json:"action"`
		Command    string `json:"command"`
		SessionID  string `json:"sessionId"`
		ConsumerID string `json:"consumerId"`
	}
	if err := json.Unmarshal(data, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action := req.Action
	if action == "exec" || action == "async_exec" {
		action += ":" + req.Command
	}
	s.mu.Lock()
	s.actions = append(s.actions, action)
	ignoreStop, onExec := s.ignoreStop, s.onExec
	s.mu.Unlock()
	reply := func(body string) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}
	switch req.Action {
	case "init_session":
		reply(`{"state":"SUCCEEDED","sessionId":"sid-1","consumerId":"cid-1","body":{}}`)
	case "interrupt_job":
		s.mu.Lock()
		ok := s.interruptOK
		s.mu.Unlock()
		if ok {
			reply(`{"state":"SUCCEEDED","body":{"jobId":10,"jobStatus":"TERMINATED"}}`)
			return
		}
		reply(`{"state":"FAILED","message":"no foreground job is running"}`)
	case "async_exec":
		reply(s.asyncExec())
	case "pull_results":
		if req.SessionID != "sid-1" || req.ConsumerID != "cid-1" {
			http.Error(w, "pull_results without session and consumer", http.StatusBadRequest)
			return
		}
		reply(s.pull())
	case "close_session":
		reply(`{"state":"SUCCEEDED"}`)
	case "exec":
		switch req.Command {
		case "reset":
			s.mu.Lock()
			n := 0
			if len(s.resets) > 0 {
				n, s.resets = s.resets[0], s.resets[1:]
			}
			s.mu.Unlock()
			affect := fmt.Sprintf(`{"classCount":%d}`, n)
			if n < 0 {
				affect = `{}`
			}
			reply(`{"state":"SUCCEEDED","body":{"jobId":2,"jobStatus":"TERMINATED","results":[{"type":"reset","affect":` + affect + `},{"type":"status","statusCode":0}]}}`)
		case "stop":
			if ignoreStop {
				reply(`{"state":"SUCCEEDED","body":{"jobId":3,"jobStatus":"TERMINATED","results":[{"type":"status","statusCode":0}]}}`)
				return
			}
			s.halt()
			s.drop(w)
		default:
			if onExec != nil && onExec(w, r, req.Command) {
				return
			}
			if words := strings.Fields(req.Command); len(words) == 3 && words[0] == "options" {
				// Build sends only true, false and numbers, which are JSON values as they are.
				reply(`{"state":"SUCCEEDED","sessionId":"sid-1","body":{"jobId":4,"jobStatus":"TERMINATED","results":[` +
					`{"type":"options","jobId":4,"changeResult":{"name":"` + words[1] + `","beforeValue":null,"afterValue":` + words[2] + `}},` +
					`{"type":"status","jobId":4,"statusCode":0}]}}`)
				return
			}
			reply(versionReply)
		}
	default:
		http.Error(w, "unexpected action "+req.Action, http.StatusBadRequest)
	}
}

// asyncExec schedules the next scripted job.
func (s *fakeServer) asyncExec() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextJob == len(s.jobs) {
		s.t.Errorf("async_exec without a scripted job")
		return `{"state":"FAILED","message":"no job"}`
	}
	id := 10 + s.nextJob
	for _, batch := range s.jobs[s.nextJob] {
		var out []string
		for _, r := range batch {
			out = append(out, strings.ReplaceAll(r, "JOB", strconv.Itoa(id)))
		}
		s.pending = append(s.pending, out)
	}
	s.nextJob++
	return fmt.Sprintf(`{"state":"SCHEDULED","sessionId":"sid-1","body":{"jobId":%d,"jobStatus":"READY"}}`, id)
}

// pull returns the next batch of results, or none.
func (s *fakeServer) pull() string {
	s.mu.Lock()
	var batch []string
	if len(s.pending) > 0 {
		batch, s.pending = s.pending[0], s.pending[1:]
	}
	s.mu.Unlock()
	return `{"state":"SUCCEEDED","sessionId":"sid-1","consumerId":"cid-1","body":{"results":[` + strings.Join(batch, ",") + `]}}`
}

// drop closes the connection without a response, as Arthas does when it stops.
func (s *fakeServer) drop(w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		conn.Close()
	}
}

// rig is a call environment made of fakes.
type rig struct {
	t        *testing.T
	env      Env
	host     *fakeHost
	jvm      *fakeJVM
	resolver *fakeResolver
	proc     *Process
	server   *fakeServer
	cfg      Config
	key      Key
	base     string
	// attachOpts holds the parsed options of the last agent argument.
	mu         sync.Mutex
	agentJar   string
	agentOpts  map[string]string
	sums       map[string]string
	stateDir   string
	failAttach bool
	// request holds the arguments of the call.
	request arthas.Request
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t}
	r.base = t.TempDir()
	r.sums = arthasTree(t, r.base, DefaultDir)
	r.host = &fakeHost{
		startTimes: map[int]uint64{rigPID: rigStart},
		listening:  map[int]bool{},
		headroom:   1 << 30,
		cpu:        map[int]uint64{},
		root:       openTestRoot(t, r.base),
	}
	r.server = newFakeServer(t, r.host)
	r.jvm = &fakeJVM{perf: perf()}
	r.jvm.onAttach = r.onAttach
	r.jvm.dial = func(ctx context.Context, port int) (net.Conn, error) {
		if !r.server.isRunning() || port != r.server.port {
			return nil, &net.OpError{Op: "dial", Err: os.ErrNotExist}
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", r.server.Listener.Addr().String())
	}
	r.proc = &Process{PID: rigPID, NSPid: 1, StartTime: rigStart, EUID: 1000, JVM: r.jvm}
	r.resolver = &fakeResolver{proc: r.proc, known: map[int]*Process{rigPID: r.proc}}
	r.key = Key{BootID: testKey.BootID, PID: rigPID, StartTime: rigStart}
	r.stateDir = filepath.Join(t.TempDir(), "arthas")
	r.cfg = Config{
		Command: arthas.KindVersion,
		Targets: map[string]jvmtarget.Target{"api": {Name: "api", SystemdUnit: "api.service"}},
		SHA256:  r.sums,
	}
	r.env = Env{
		Resolver: r.resolver, Host: r.host, StateDir: r.stateDir, StateOwner: uint32(os.Getuid()),
		Now: time.Now, NewPassword: func() (string, error) { return rigPassword, nil },
		Cleanup:  arthas.CleanupOptions{Budget: 3 * time.Second, StepTimeout: time.Second},
		StopWait: 300 * time.Millisecond, PollEvery: 5 * time.Millisecond, SampleEvery: 5 * time.Millisecond,
		ListenWait: 300 * time.Millisecond, AttachSettle: 50 * time.Millisecond,
		Arch:  "amd64",
		Probe: func(context.Context, HealthCheck) error { return nil },
	}
	return r
}

// onAttach starts the fake server with the port and password of the agent argument.
func (r *rig) onAttach(req jvmtarget.AttachRequest) error {
	jar, options, _ := strings.Cut(req.Agent, "=")
	opts := map[string]string{}
	for i, part := range strings.Split(options, ";") {
		if i == 0 {
			opts["core"] = part
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		opts[k] = v
	}
	r.mu.Lock()
	r.agentJar, r.agentOpts = jar, opts
	fail := r.failAttach
	r.mu.Unlock()
	if fail {
		return os.ErrDeadlineExceeded
	}
	port, _ := strconv.Atoi(opts["httpPort"])
	r.server.start(port, opts["password"])
	return nil
}

func (r *rig) agent() (string, map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.agentJar, r.agentOpts
}

func (r *rig) params() Params { return Params{Target: "api", Request: r.request} }

func (r *rig) run(ctx context.Context) (Result, error) {
	r.t.Helper()
	return RunWith(ctx, r.env, r.cfg, r.params(), nil)
}

// state opens the state directory of the rig for inspection.
func (r *rig) state() *State {
	r.t.Helper()
	s, err := OpenState(r.stateDir, uint32(os.Getuid()))
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { s.Close() })
	return s
}

// leaveRecord writes a record as a call that died would leave it, and starts the server it describes.
func (r *rig) leaveRecord(port int, startServer bool) Record {
	r.t.Helper()
	now := time.Now()
	rec := Record{
		Version: 1, BootID: r.key.BootID, PID: r.key.PID, StartTime: r.key.StartTime, Target: "api", Command: "version",
		Port: port, Password: rigPassword, SessionID: "sid-1", Created: now.Add(-time.Minute), Deadline: now.Add(-30 * time.Second),
	}
	if err := r.state().WriteRecord(rec); err != nil {
		r.t.Fatal(err)
	}
	if startServer {
		r.server.start(port, rigPassword)
	}
	return rec
}

// rowOf returns the value of a row of the call section, and whether the row exists.
func rowOf(out, key string) (string, bool) {
	call, _, _ := strings.Cut(out, "\n\n")
	for _, line := range strings.Split(call, "\n") {
		if k, v, ok := strings.Cut(line, "\t"); ok && k == key {
			return v, true
		}
	}
	return "", false
}

func mustRow(t *testing.T, out, key string) string {
	t.Helper()
	v, ok := rowOf(out, key)
	if !ok {
		t.Fatalf("no %q row in\n%s", key, out)
	}
	return v
}
