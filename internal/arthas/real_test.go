//go:build linux

package arthas

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The real Arthas tests drive Arthas 4.3.5 inside the containers of
// test/jvm-arthas. They need root (SIGQUIT to the target, setns into its
// network namespace), Docker and the environment of that directory, and are
// skipped unless ALLOWOPS_REAL_ARTHAS=1:
//
//	cd test/jvm-arthas && COMPOSE_PROJECT_NAME=jvm-arthas-s2b JA_PORT_PREFIX=32 make build tools
//	COMPOSE_PROJECT_NAME=jvm-arthas-s2b JA_PORT_PREFIX=32 docker compose up -d jdk8 jdk17
//	go test -c -o /tmp/arthas.test ./internal/arthas
//	sudo -n env ALLOWOPS_REAL_ARTHAS=1 COMPOSE_PROJECT_NAME=jvm-arthas-s2b /tmp/arthas.test -test.run TestRealArthas -test.v
//
// ALLOWOPS_ARTHAS_UPDATE_TESTDATA=1 rewrites testdata/<jdk>/*.json with the
// responses of the run. JA_DIR (default ../../test/jvm-arthas) and JA_ATTACH
// (default $JA_DIR/bin/ja-attach) locate the environment and the attach tool.
//
// The attach tool and the namespace-entering dial function exist only here:
// the product code gets its own, reviewed implementations.

const (
	realHTTPPort  = 18563
	realAgentJar  = "/opt/arthas-minlog/arthas-agent.jar"
	realCoreJar   = "/opt/arthas-minlog/arthas-core.jar"
	realUpdateEnv = "ALLOWOPS_ARTHAS_UPDATE_TESTDATA"
)

func requireRealEnv(t *testing.T) {
	t.Helper()
	if os.Getenv("ALLOWOPS_REAL_ARTHAS") != "1" {
		t.Skip("set ALLOWOPS_REAL_ARTHAS=1 to run against real Arthas servers (root, Docker and test/jvm-arthas required)")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

func jaDir() string {
	if d := os.Getenv("JA_DIR"); d != "" {
		return d
	}
	return "../../test/jvm-arthas"
}

type realTarget struct {
	svc       string
	container string
	pid       int
	nsPath    string
	ip        string
}

func newRealTarget(t *testing.T, svc string) *realTarget {
	t.Helper()
	project := os.Getenv("COMPOSE_PROJECT_NAME")
	if project == "" {
		project = "jvm-arthas"
	}
	return newRealTargetIn(t, svc, project+"-"+svc+"-1")
}

func newRealTargetIn(t *testing.T, svc, container string) *realTarget {
	t.Helper()
	tg := &realTarget{svc: svc, container: container}
	out, err := exec.Command("docker", "top", tg.container, "-eo", "pid,args").CombinedOutput()
	if err != nil {
		t.Fatalf("docker top %s: %v\n%s\nstart the environment first (see the comment at the top of real_test.go)", tg.container, err, out)
	}
	for _, line := range strings.Split(string(out), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.HasSuffix(fields[1], "java") {
			tg.pid, _ = strconv.Atoi(fields[0])
			break
		}
	}
	if tg.pid == 0 {
		t.Fatalf("no java process in %s:\n%s", tg.container, out)
	}
	tg.nsPath = fmt.Sprintf("/proc/%d/ns/net", tg.pid)
	if ip, err := exec.Command("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container).Output(); err == nil {
		tg.ip = strings.TrimSpace(string(ip))
	}
	return tg
}

// load sends requests to the sample application until the returned function is
// called, so that threads have something to do while a command samples them.
func (tg *realTarget) load(t *testing.T) (stop func()) {
	t.Helper()
	if tg.ip == "" {
		t.Fatal("no container address")
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				if resp, err := client.Get("http://" + tg.ip + ":8080/work"); err == nil {
					resp.Body.Close()
				}
			}
		}()
	}
	return func() { close(done); wg.Wait() }
}

// dial connects to 127.0.0.1:port inside the network namespace of the target.
// setns changes the thread, so the whole dial runs on a locked OS thread of its
// own; a locked thread that is not unlocked dies with its goroutine, which
// returns it to the host namespace.
func (tg *realTarget) dial(port int) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		type result struct {
			conn net.Conn
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			runtime.LockOSThread()
			f, err := os.Open(tg.nsPath)
			if err != nil {
				ch <- result{err: err}
				return
			}
			defer f.Close()
			if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
				ch <- result{err: fmt.Errorf("setns: %w", err)}
				return
			}
			var d net.Dialer
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			ch <- result{conn, err}
		}()
		r := <-ch
		return r.conn, r.err
	}
}

// attach loads Arthas with the argument of cfg and returns once the agent has started.
func (tg *realTarget) attach(t *testing.T, cfg AgentConfig) {
	t.Helper()
	arg, err := cfg.Argument()
	if err != nil {
		t.Fatal(err)
	}
	options, _ := cfg.Options()
	// ja-attach joins "<agent>=<core>;<options>" itself.
	rest := strings.TrimPrefix(options, cfg.CoreJar+";")
	if arg != cfg.AgentJar+"="+cfg.CoreJar+";"+rest {
		t.Fatalf("argument %q is not what ja-attach builds from the options", arg)
	}
	tg.loadOptions(t, cfg.AgentJar, cfg.CoreJar, rest)
}

// loadOptions runs ja-attach with the agent options that follow the core jar.
// Passing them in a file keeps the password out of the process list.
func (tg *realTarget) loadOptions(t *testing.T, agentJar, coreJar, options string) {
	t.Helper()
	tool := os.Getenv("JA_ATTACH")
	if tool == "" {
		tool = filepath.Join(jaDir(), "bin", "ja-attach")
	}
	optsFile := filepath.Join(t.TempDir(), "opts")
	if err := os.WriteFile(optsFile, []byte(options), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(tool, "load", "-pid", strconv.Itoa(tg.pid), "-agent", agentJar, "-core", coreJar,
		"-opts-file", optsFile, "-file-owner", "target", "-conn-user", "target").Output()
	if err != nil {
		t.Fatalf("ja-attach load: %v\n%s", err, out)
	}
	var res struct {
		OK    bool   `json:"ok"`
		Stage string `json:"stage"`
		Error string `json:"error"`
		Reply string `json:"reply"`
	}
	if err := json.Unmarshal(out, &res); err != nil || !res.OK {
		t.Fatalf("attach failed (stage %s): %s %s\n%s", res.Stage, res.Error, res.Reply, out)
	}
}

// arthasThreads counts the threads of the target whose name starts with "arthas-".
func (tg *realTarget) arthasThreads(t *testing.T) int {
	t.Helper()
	dirs, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/comm", tg.pid))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range dirs {
		if b, err := os.ReadFile(p); err == nil && strings.HasPrefix(string(b), "arthas-") {
			n++
		}
	}
	return n
}

// waitStopped waits until nothing listens on the Arthas port and no arthas-
// thread is left. It returns how long that took.
func (tg *realTarget) waitStopped(t *testing.T, port int, limit time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := tg.dial(port)(ctx)
		cancel()
		if err == nil {
			conn.Close()
		}
		threads := tg.arthasThreads(t)
		if err != nil && threads == 0 {
			return time.Since(start)
		}
		if time.Since(start) > limit {
			t.Fatalf("Arthas is still there %s after stop: dial error %v, %d arthas- threads", limit, err, threads)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// tapDial wraps a dial function and keeps the bytes read from the connections,
// so that a test can store the HTTP response body as Arthas sent it.
type tapDial struct {
	dial func(context.Context) (net.Conn, error)
	mu   sync.Mutex
	buf  bytes.Buffer
}

type tapConn struct {
	net.Conn
	tap *tapDial
}

func (c tapConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.tap.mu.Lock()
	c.tap.buf.Write(p[:n])
	c.tap.mu.Unlock()
	return n, err
}

func (d *tapDial) Dial(ctx context.Context) (net.Conn, error) {
	conn, err := d.dial(ctx)
	if err != nil {
		return nil, err
	}
	return tapConn{conn, d}, nil
}

// lastBody returns the body of the last HTTP response read and clears the tap.
func (d *tapDial) lastBody(t *testing.T) []byte {
	t.Helper()
	d.mu.Lock()
	raw := bytes.Clone(d.buf.Bytes())
	d.buf.Reset()
	d.mu.Unlock()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("tap holds no HTTP response: %v", err)
	}
	defer resp.Body.Close()
	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read tapped body: %v", err)
	}
	return body.Bytes()
}

func saveTestdata(t *testing.T, jdk, name string, body []byte) {
	t.Helper()
	if os.Getenv(realUpdateEnv) != "1" {
		return
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		t.Fatalf("testdata %s: %v", name, err)
	}
	pretty.WriteByte('\n')
	dir := filepath.Join("testdata", jdk)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, name+".json")
	if err := os.WriteFile(file, pretty.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	// The run needs root; the files belong to whoever owns the package directory.
	if st, err := os.Stat("."); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(dir, int(sys.Uid), int(sys.Gid))
			_ = os.Chown(file, int(sys.Uid), int(sys.Gid))
		}
	}
}

var realSyspropKeys = []string{"java.version", "user.dir", "no.such.key"}

// realEnabled are the Arthas commands behind the L1 kinds.
var realEnabled = []string{"dashboard", "thread", "memory", "jvm", "sc", "sm", "classloader", "logger", "sysprop", "version"}

func TestRealArthas(t *testing.T) {
	requireRealEnv(t)
	for _, svc := range []string{"jdk8", "jdk17"} {
		t.Run(svc, func(t *testing.T) { realRun(t, newRealTarget(t, svc), svc) })
	}
}

// realServer is a target with Arthas loaded and a client for it.
type realServer struct {
	tg       *realTarget
	password string
	tap      *tapDial
	client   *Client
	session  string
	attached bool
}

// startArthas loads Arthas with the L1 commands enabled, opens a session and
// registers a clean-up that ends the server if the test did not.
func startArthas(t *testing.T, tg *realTarget) *realServer {
	t.Helper()
	if n := tg.arthasThreads(t); n != 0 {
		t.Fatalf("%s already runs Arthas (%d arthas- threads); restart the container", tg.container, n)
	}
	password, err := NewPassword()
	if err != nil {
		t.Fatal(err)
	}
	tg.attach(t, AgentConfig{
		AgentJar: realAgentJar, CoreJar: realCoreJar, HTTPPort: realHTTPPort, Password: password,
		Enabled: realEnabled, SessionTimeout: 5 * time.Minute,
	})
	srv := &realServer{tg: tg, password: password, attached: true}
	t.Cleanup(func() {
		if !srv.attached {
			return
		}
		// A failed run must not leave Arthas in the container for the next one.
		c, err := NewClient(Config{Dial: tg.dial(realHTTPPort), Password: password})
		if err == nil {
			c.Cleanup(context.Background(), "", CleanupOptions{})
		}
	})
	srv.tap = &tapDial{dial: tg.dial(realHTTPPort)}
	srv.client, err = NewClient(Config{Dial: srv.tap.Dial, Password: password, MaxResponseBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	srv.session, err = srv.client.InitSession(context.Background())
	if err != nil {
		t.Fatalf("InitSession: %v", err)
	}
	srv.tap.lastBody(t)
	return srv
}

// startBlocker runs testdata/Blocker.java in a new container of the given JDK
// and waits until its threads are in place.
func startBlocker(t *testing.T, jdk string) *realTarget {
	t.Helper()
	project := os.Getenv("COMPOSE_PROJECT_NAME")
	if project == "" {
		project = "jvm-arthas"
	}
	name := fmt.Sprintf("%s-blocker%s", project, jdk)
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	arthasDir, err := filepath.Abs(filepath.Join(jaDir(), "run", "arthas-minlog"))
	if err != nil {
		t.Fatal(err)
	}
	exec.Command("docker", "rm", "-f", name).Run()
	out, err := exec.Command("docker", "run", "-d", "--name", name, "--pull", "never", "--user", "10001:10001",
		"-v", testdata+":/blk:ro", "-v", arthasDir+":/opt/arthas-minlog:ro",
		"eclipse-temurin:"+jdk+"-jdk", "sh", "-c", "mkdir -p /tmp/b && javac -d /tmp/b /blk/Blocker.java && exec java -Xmx64m -cp /tmp/b Blocker").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		if strings.Contains(string(logs), "ready") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the blocker did not start:\n%s", logs)
		}
	}
	return newRealTargetIn(t, "blocker"+jdk, name)
}

func TestRealArthasThreadBlocking(t *testing.T) {
	requireRealEnv(t)
	for _, jdk := range []string{"8", "17"} {
		t.Run("jdk"+jdk, func(t *testing.T) {
			tg := startBlocker(t, jdk)
			srv := startArthas(t, tg)
			cmd := mustBuild(t, Request{Kind: KindThreadBlocking})
			resp, err := srv.client.Exec(context.Background(), srv.session, cmd)
			if err != nil {
				t.Fatal(err)
			}
			saveTestdata(t, "jdk"+jdk, "thread_blocking", srv.tap.lastBody(t))
			if code, msg, _ := resp.Status(); code != 0 {
				t.Fatalf("status = %d %q, results %v", code, msg, resultTypes(resp))
			}
			text, err := Render(KindThreadBlocking, resp)
			if err != nil || !strings.Contains(text, "lock-holder") {
				t.Errorf("Render = %q, %v; want the lock holder", text, err)
			}
			var found bool
			for _, r := range resp.Results {
				if r.Type == "thread" && strings.Contains(string(r.Raw), "lock-holder") {
					found = true
				}
			}
			if !found {
				t.Errorf("the lock holder is not in the result: %v", resultTypes(resp))
			}
			res := srv.client.Cleanup(context.Background(), srv.session, CleanupOptions{})
			if err := res.Err(); err != nil {
				t.Errorf("cleanup: %v", err)
			}
			srv.attached = false
			tg.waitStopped(t, realHTTPPort, 15*time.Second)
		})
	}
}

// TestRealArthasWithoutResetAndStop loads Arthas with reset and stop in
// disabledCommands, which AgentConfig never produces, and shows what that
// costs: both commands answer "command not found", the clean-up sequence ends
// with two errors, and the server, its port and its threads stay in the JVM.
// The HTTP API has no request that ends the server, so AgentConfig keeps both
// commands enabled. A container of its own is used because Arthas cannot be
// ended in it; it is removed at the end.
func TestRealArthasWithoutResetAndStop(t *testing.T) {
	requireRealEnv(t)
	for _, jdk := range []string{"8", "17"} {
		t.Run("jdk"+jdk, func(t *testing.T) {
			tg := startBlocker(t, jdk)
			ctx := context.Background()
			password, err := NewPassword()
			if err != nil {
				t.Fatal(err)
			}
			cfg := AgentConfig{
				AgentJar: realAgentJar, CoreJar: realCoreJar, HTTPPort: realHTTPPort, Password: password,
				Enabled: realEnabled, SessionTimeout: 5 * time.Minute,
			}
			options, err := cfg.Options()
			if err != nil {
				t.Fatal(err)
			}
			kept, _ := DisabledCommands(realEnabled)
			from := ";disabledCommands=" + strings.Join(kept, ",") + ";"
			to := ";disabledCommands=" + strings.Join(append(slices.Clone(kept), "reset", "stop"), ",") + ";"
			if !strings.Contains(options, from) {
				t.Fatalf("options hold no %q: %q", from, options)
			}
			tg.loadOptions(t, cfg.AgentJar, cfg.CoreJar, strings.TrimPrefix(strings.Replace(options, from, to, 1), cfg.CoreJar+";"))

			c, err := NewClient(Config{Dial: tg.dial(realHTTPPort), Password: password})
			if err != nil {
				t.Fatal(err)
			}
			session, err := c.InitSession(ctx)
			if err != nil {
				t.Fatalf("InitSession: %v", err)
			}
			if _, err := c.Exec(ctx, session, mustBuild(t, Request{Kind: KindVersion})); err != nil {
				t.Fatalf("version: %v", err)
			}

			for _, name := range []string{"reset", "stop"} {
				if _, err := c.exec(ctx, session, name, 5*time.Second); !errors.Is(err, ErrCommandNotFound) {
					t.Errorf("exec %s = %v, want a command-not-found error", name, err)
				}
			}
			// What else could end a server? The shell commands of the session do not.
			for _, name := range []string{"quit", "shutdown"} {
				_, err := c.exec(ctx, session, name, 5*time.Second)
				t.Logf("exec %s: %v", name, err)
			}
			session2, err := c.InitSession(ctx)
			if err != nil {
				t.Fatalf("InitSession after quit: %v", err)
			}

			res := c.Cleanup(ctx, session2, CleanupOptions{})
			for _, s := range res.Steps {
				t.Logf("cleanup %-13s sent=%-5v elapsed=%-6s note=%q err=%v", s.Name, s.Sent, s.Elapsed.Round(time.Millisecond), s.Note, s.Err)
			}
			byName := map[string]CleanupStep{}
			for _, s := range res.Steps {
				byName[s.Name] = s
			}
			for _, name := range []string{StepInterruptJob, StepCloseSession} {
				if err := byName[name].Err; err != nil {
					t.Errorf("%s: %v", name, err)
				}
			}
			for _, name := range []string{StepReset, StepStop} {
				if s := byName[name]; !errors.Is(s.Err, ErrCommandNotFound) || !s.Sent {
					t.Errorf("%s: sent=%v err=%v, want a command-not-found error", name, s.Sent, s.Err)
				}
			}

			time.Sleep(2 * time.Second)
			threads := tg.arthasThreads(t)
			conn, err := tg.dial(realHTTPPort)(ctx)
			if err == nil {
				conn.Close()
			}
			t.Logf("2 s after the clean-up: %d arthas- threads, dial error %v", threads, err)
			if threads == 0 || err != nil {
				t.Errorf("Arthas is gone after a clean-up without reset and stop: %d threads, dial error %v", threads, err)
			}
			session3, err := c.InitSession(ctx)
			if err != nil {
				t.Fatalf("InitSession after the clean-up: %v", err)
			}
			if _, err := c.Exec(ctx, session3, mustBuild(t, Request{Kind: KindVersion})); err != nil {
				t.Errorf("version after the clean-up: %v", err)
			}
		})
	}
}

func realRun(t *testing.T, tg *realTarget, jdk string) {
	srv := startArthas(t, tg)
	c, tap, session := srv.client, srv.tap, srv.session
	ctx := context.Background()

	policy := Policy{SyspropKeys: realSyspropKeys}
	run := func(name string, req Request) *ExecResponse {
		t.Helper()
		cmd, err := Build(req, policy)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp, err := c.Exec(ctx, session, cmd)
		if err != nil {
			t.Fatalf("%s (%s): %v", name, cmd.Text, err)
		}
		saveTestdata(t, jdk, name, tap.lastBody(t))
		if len(resp.Results) == 0 {
			t.Fatalf("%s: no results", name)
		}
		// A failed command is a *CommandError; nothing else may go wrong.
		var ce *CommandError
		if _, err := Render(req.Kind, resp); err != nil && !errors.As(err, &ce) {
			t.Errorf("%s: Render: %v", name, err)
		}
		return resp
	}
	wantStatus := func(name string, resp *ExecResponse, code int, message string) {
		t.Helper()
		got, msg, found := resp.Status()
		if !found || got != code || !strings.Contains(msg, message) {
			t.Errorf("%s: status = %d %q (found %v), want %d %q", name, got, msg, found, code, message)
		}
	}
	wantType := func(name string, resp *ExecResponse, typ string) {
		t.Helper()
		for _, r := range resp.Results {
			if r.Type == typ {
				return
			}
		}
		t.Errorf("%s: no %q result in %v", name, typ, resultTypes(resp))
	}

	// Every L1 command.
	stopLoad := tg.load(t)
	defer stopLoad()
	resp := run("version", Request{Kind: KindVersion})
	wantType("version", resp, "version")
	wantStatus("version", resp, 0, "")
	if !strings.Contains(string(resp.Results[0].Raw), Version) {
		t.Errorf("version result = %s, want Arthas %s", resp.Results[0].Raw, Version)
	}

	resp = run("dashboard", Request{Kind: KindDashboard})
	wantType("dashboard", resp, "dashboard")
	wantStatus("dashboard", resp, 0, "")
	var dash struct {
		Threads []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"threads"`
	}
	for _, r := range resp.Results {
		if r.Type == "dashboard" {
			if err := json.Unmarshal(r.Raw, &dash); err != nil {
				t.Fatal(err)
			}
		}
	}
	var threadID int64
	for _, th := range dash.Threads {
		if th.Name == "Reference Handler" {
			threadID = th.ID
		}
	}
	if threadID == 0 {
		t.Fatalf("no Reference Handler thread in the dashboard: %+v", dash.Threads)
	}

	resp = run("thread_top", Request{Kind: KindThreadTop, Top: 3})
	wantType("thread_top", resp, "thread")
	wantStatus("thread_top", resp, 0, "")

	resp = run("thread_info", Request{Kind: KindThreadInfo, ThreadID: threadID})
	wantType("thread_info", resp, "thread")
	wantStatus("thread_info", resp, 0, "")

	resp = run("thread_info_missing", Request{Kind: KindThreadInfo, ThreadID: 987654})
	wantStatus("thread_info_missing", resp, 1, "987654")

	// The sample application has no blocked thread: Arthas reports a status
	// message instead of a result.
	resp = run("thread_blocking_none", Request{Kind: KindThreadBlocking})
	wantStatus("thread_blocking_none", resp, 1, "No most blocking thread found")

	for name, kind := range map[string]Kind{"memory": KindMemory, "jvm": KindJVM, "logger": KindLogger,
		"classloader_tree": KindClassLoaderTree, "classloader_list": KindClassLoaderList} {
		resp = run(name, Request{Kind: kind})
		wantStatus(name, resp, 0, "")
		wantType(name, resp, map[Kind]string{KindMemory: "memory", KindJVM: "jvm", KindLogger: "logger",
			KindClassLoaderTree: "classloader", KindClassLoaderList: "classloader"}[kind])
	}

	resp = run("class_info", Request{Kind: KindClassInfo, Class: "demo.HotService"})
	wantType("class_info", resp, "sc")
	wantStatus("class_info", resp, 0, "")
	resp = run("class_info_nested", Request{Kind: KindClassInfo, Class: "java.util.Map$Entry"})
	wantType("class_info_nested", resp, "sc")
	wantStatus("class_info_nested", resp, 0, "")
	resp = run("class_info_missing", Request{Kind: KindClassInfo, Class: "no.such.Clazz"})
	wantStatus("class_info_missing", resp, 0, "")
	resp = run("method_info", Request{Kind: KindMethodInfo, Class: "demo.HotService", Method: "work"})
	wantType("method_info", resp, "sm")
	wantStatus("method_info", resp, 0, "")
	resp = run("method_info_all", Request{Kind: KindMethodInfo, Class: "demo.HotService"})
	wantType("method_info_all", resp, "sm")
	wantStatus("method_info_all", resp, 0, "")

	resp = run("sysprop", Request{Kind: KindSysprop, Key: "java.version"})
	wantType("sysprop", resp, "sysprop")
	wantStatus("sysprop", resp, 0, "")
	resp = run("sysprop_missing", Request{Kind: KindSysprop, Key: "no.such.key"})
	wantStatus("sysprop_missing", resp, 1, "no.such.key")

	// A password that is not the one in the agent argument.
	bad, err := NewClient(Config{Dial: tg.dial(realHTTPPort), Password: "wrongPasswordWrongPassword12345"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.InitSession(ctx); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("wrong password: error = %v, want ErrUnauthorized", err)
	}

	// Commands that were disabled are unknown to Arthas, not just refused.
	for _, text := range []string{"ognl 1", "watch demo.HotService work", "sysenv", "vmtool --action getInstances", "heapdump /tmp/x.hprof", "auth x"} {
		_, err := c.exec(ctx, session, text, 5*time.Second)
		if !errors.Is(err, ErrCommandNotFound) {
			t.Errorf("%q: error = %v, want ErrCommandNotFound", text, err)
		}
	}
	tap.lastBody(t)

	// execTimeout: dashboard -n 1 takes about five seconds.
	short, err := Build(Request{Kind: KindDashboard}, Policy{ExecTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = c.Exec(ctx, session, short)
	var se *StateError
	if !errors.Is(err, ErrInterrupted) || !errors.As(err, &se) || se.Response == nil || !se.Response.TimeExpired {
		t.Fatalf("dashboard with a 1s execTimeout: error = %v, want ErrInterrupted with a response that has timeExpired", err)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("the interrupted dashboard took %s", d)
	}
	saveTestdata(t, jdk, "dashboard_interrupted", tap.lastBody(t))
	if err := c.InterruptJob(ctx, session); !errors.Is(err, ErrNoForegroundJob) {
		t.Errorf("InterruptJob after the job ended: error = %v, want ErrNoForegroundJob", err)
	}
	// The session still works.
	if _, err := c.Exec(ctx, session, mustBuild(t, Request{Kind: KindVersion})); err != nil {
		t.Errorf("version after the interrupted job: %v", err)
	}

	// The clean-up runs although the caller's context is gone.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	res := c.Cleanup(cancelled, session, CleanupOptions{})
	for _, s := range res.Steps {
		t.Logf("cleanup %-13s sent=%-5v %-8s err=%v note=%q", s.Name, s.Sent, s.Elapsed.Round(time.Millisecond), s.Err, s.Note)
	}
	if err := res.Err(); err != nil {
		t.Errorf("cleanup: %v", err)
	}
	srv.attached = false
	took := tg.waitStopped(t, realHTTPPort, 15*time.Second)
	t.Logf("port closed and no arthas- thread %s after the clean-up started", took.Round(100*time.Millisecond))
	if _, err := c.InitSession(ctx); err == nil {
		t.Error("InitSession works after stop")
	}
}

func resultTypes(r *ExecResponse) []string {
	var out []string
	for _, x := range r.Results {
		out = append(out, x.Type)
	}
	return out
}
