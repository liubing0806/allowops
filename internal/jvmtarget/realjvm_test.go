//go:build linux

package jvmtarget

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The real JVM tests attach to the JVMs of test/jvm-arthas. They need root, Docker, the images of
// that environment and its Arthas files. They are skipped unless ALLOWOPS_REAL_JVM=1:
//
//	COMPOSE_PROJECT_NAME=jvm-arthas-s2a JA_PORT_PREFIX=28 make -C test/jvm-arthas up-all
//	go test -c -o /tmp/jvmtarget.test ./internal/jvmtarget
//	sudo -n env ALLOWOPS_REAL_JVM=1 ALLOWOPS_JVM_ARTHAS_PROJECT=jvm-arthas-s2a /tmp/jvmtarget.test -test.run TestRealAttach -test.v
//
// ALLOWOPS_JVM_ARTHAS_PROJECT is the compose project name; the container of a service is
// <project>-<service>-1. A case whose container is not running is skipped.
func realEnvironment(t *testing.T) string {
	t.Helper()
	if os.Getenv("ALLOWOPS_REAL_JVM") != "1" {
		t.Skip("set ALLOWOPS_REAL_JVM=1 to attach to the JVMs of test/jvm-arthas (root and Docker required)")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	project := os.Getenv("ALLOWOPS_JVM_ARTHAS_PROJECT")
	if project == "" {
		project = "jvm-arthas"
	}
	return project
}

const (
	realMainClass = "/app/app.jar"
	realAgentDir  = "/opt/arthas-minlog"
	realPortLow   = 18500
	realPortHigh  = 18599
)

func dockerOut(t *testing.T, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String() + stderr.String()
}

// realTarget is one running container of the test environment.
type realTarget struct {
	t         *testing.T
	container string
	resolver  *Resolver
	ip        string
}

func containerIP(t *testing.T, container string) string {
	t.Helper()
	return strings.TrimSpace(dockerOut(t, "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container))
}

// restart restarts the container, killing it when kill is set, and waits for the JVM. A JVM
// that was started again has no attach listener, except one that runs with -Xrs. The JVM is
// waited for until it can be found by its main class, unless the container has no hsperfdata.
func (rt *realTarget) restart(kill, resolvable bool) {
	rt.t.Helper()
	started := func() int { return strings.Count(dockerOut(rt.t, "logs", rt.container), "Started DemoApplication") }
	before := started()
	if kill {
		dockerOut(rt.t, "kill", rt.container)
		dockerOut(rt.t, "start", rt.container)
	} else {
		dockerOut(rt.t, "restart", "-t", "2", rt.container)
	}
	rt.ip = containerIP(rt.t, rt.container)
	deadline := time.Now().Add(90 * time.Second)
	for {
		var err error
		if started() <= before {
			// The application has not started: the JVM may still be replacing the files of the one before.
			err = errors.New("the application has not started")
		} else if resolvable {
			_, err = rt.resolve()
		} else {
			_, err = rt.resolver.identify(rt.javaPID())
		}
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			rt.t.Fatalf("the JVM of %s did not come back: %v", rt.container, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// fresh restarts the container so that its JVM has not started an attach listener.
func (rt *realTarget) fresh() { rt.t.Helper(); rt.restart(false, true) }

func newRealTarget(t *testing.T, project, service string) *realTarget {
	t.Helper()
	name := project + "-" + service + "-1"
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output()
	if err != nil || strings.TrimSpace(string(out)) != "true" {
		t.Skipf("container %s is not running", name)
	}
	return &realTarget{t: t, container: name, resolver: NewResolver(), ip: containerIP(t, name)}
}

func (rt *realTarget) resolve() (*JVM, error) {
	return rt.resolver.Resolve(context.Background(), Target{Name: "app", Container: rt.container, MainClass: realMainClass})
}

func (rt *realTarget) mustResolve() *JVM {
	rt.t.Helper()
	j, err := rt.resolve()
	if err != nil {
		rt.t.Fatal(err)
	}
	return j
}

// javaPID finds the java process of the container on the host, for containers whose JVM publishes
// no hsperfdata and so cannot be resolved by main class.
func (rt *realTarget) javaPID() int {
	rt.t.Helper()
	lines := strings.Split(dockerOut(rt.t, "top", rt.container, "-eo", "pid,args"), "\n")
	for _, line := range lines[1:] {
		pid, args, _ := strings.Cut(strings.TrimSpace(line), " ")
		if strings.HasPrefix(strings.TrimSpace(args), "java ") {
			n, err := strconv.Atoi(pid)
			if err != nil {
				rt.t.Fatal(err)
			}
			return n
		}
	}
	return 0
}

func (rt *realTarget) threadDumps() int {
	return strings.Count(dockerOut(rt.t, "logs", rt.container), "Full thread dump")
}

// attachFiles lists the attach trigger files in the container. The sockets .java_pid* belong to the JVM.
func (rt *realTarget) attachFiles() string {
	out, _ := exec.Command("docker", "exec", "-u", "0", rt.container, "sh", "-c", "ls /tmp/.attach_pid* /app/.attach_pid* /.attach_pid* 2>/dev/null").Output()
	return strings.TrimSpace(string(out))
}

func (rt *realTarget) socketExists(nspid int) bool {
	return exec.Command("docker", "exec", "-u", "0", rt.container, "test", "-S", "/tmp/.java_pid"+strconv.Itoa(nspid)).Run() == nil
}

// agentArgument is the argument Arthas gets: the agent jar, the core jar and the options.
func agentArgument(port int, password string) string {
	return fmt.Sprintf("%[1]s/arthas-agent.jar=%[1]s/arthas-core.jar;telnetPort=-1;httpPort=%[2]d;ip=127.0.0.1;password=%[3]s;localConnectionNonAuth=false;sessionTimeout=300",
		realAgentDir, port, password)
}

func newPassword(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	f, err := os.Open("/dev/urandom")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := io.ReadFull(f, b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}

// arthasHTTP sends one request to the Arthas HTTP API in the JVM's network namespace.
func arthasHTTP(ctx context.Context, j *JVM, port int, password, body string) (int, string, error) {
	client := &http.Client{Timeout: 40 * time.Second, Transport: &http.Transport{
		DialContext:       func(ctx context.Context, _, _ string) (net.Conn, error) { return j.DialTCP(ctx, port) },
		DisableKeepAlives: true,
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://arthas/api", strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if password != "" {
		req.SetBasicAuth("arthas", password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(data), nil
}

// stopArthas stops the Arthas server and waits until its port is closed and its threads are gone.
func stopArthas(t *testing.T, j *JVM, port int, password string) {
	t.Helper()
	ctx := context.Background()
	if listening, _ := j.resolver.Proc.IsListening(j.PID, port); listening {
		// The connection ends without an answer when the server stops: "unexpected EOF" is normal.
		arthasHTTP(ctx, j, port, password, `{"action":"exec","command":"stop"}`)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		n, err := j.resolver.Proc.ArthasThreads(j.PID)
		listening, err2 := j.resolver.Proc.IsListening(j.PID, port)
		if err == nil && err2 == nil && n == 0 && !listening {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Arthas did not stop: %d threads (%v), listening %v (%v)", n, err, listening, err2)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func waitListening(t *testing.T, j *JVM, port int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if ok, err := j.resolver.Proc.IsListening(j.PID, port); err == nil && ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing listens on port %d of the JVM", port)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// recordAttachFileOwner records, for every signal of an attach, the owner of the attach file at that moment.
func recordAttachFileOwner(t *testing.T, j *JVM) *[]string {
	t.Helper()
	var owners []string
	prev := pidfdSendSignal
	pidfdSendSignal = func(fd int, sig unix.Signal, info *unix.Siginfo, flags int) error {
		for _, dir := range []string{"/tmp", "/app"} {
			path := fmt.Sprintf("%s/%d/root%s/.attach_pid%d", j.resolver.Proc.Root, j.PID, dir, j.NSPid)
			var st unix.Stat_t
			if unix.Lstat(path, &st) == nil {
				owners = append(owners, fmt.Sprintf("%s uid=%d gid=%d mode=%o", dir, st.Uid, st.Gid, st.Mode&0o7777))
			}
		}
		return prev(fd, sig, info, flags)
	}
	t.Cleanup(func() { pidfdSendSignal = prev })
	return &owners
}

// checkLoaded is what every successful attach must show: the agent answers on its port in the JVM's
// network namespace, the host cannot reach that port, and nothing is left in the container.
func checkLoaded(t *testing.T, rt *realTarget, j *JVM, port int, password string, dumpsBefore int) {
	t.Helper()
	waitListening(t, j, port)
	if n, err := j.resolver.Proc.ArthasThreads(j.PID); err != nil || n == 0 {
		t.Errorf("arthas threads = %d, %v", n, err)
	}
	// Without the password the server answers 401: the connection itself is made.
	status, _, err := arthasHTTP(context.Background(), j, port, "", `{"action":"exec","command":"version"}`)
	if err != nil || status != http.StatusUnauthorized {
		t.Errorf("request without password: status %d, %v; want 401", status, err)
	}
	status, body, err := arthasHTTP(context.Background(), j, port, password, `{"action":"exec","command":"version"}`)
	if err != nil || status != http.StatusOK || !strings.Contains(body, "4.3.5") {
		t.Errorf("version: status %d, %v, body %.200s", status, err, body)
	}
	// Control: the server listens on 127.0.0.1 of the container only, so DialTCP reached it by entering the namespace.
	if rt.ip != "" {
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(rt.ip, strconv.Itoa(port)), time.Second); err == nil {
			c.Close()
			t.Errorf("the host reaches %s:%d without entering the namespace", rt.ip, port)
		}
	}
	if files := rt.attachFiles(); files != "" {
		t.Errorf("attach files left in the container: %s", files)
	}
	if dumps := rt.threadDumps(); dumps != dumpsBefore {
		t.Errorf("the JVM printed %d thread dumps", dumps-dumpsBefore)
	}
	// No thread of this test binary keeps another user or namespace.
	assertNoThreadWithOtherIDs(t)
}

func attachRequest(port int, password string) AttachRequest {
	return AttachRequest{Agent: agentArgument(port, password), SocketWait: 10 * time.Second, ReplyWait: 30 * time.Second}
}

func TestRealAttach(t *testing.T) {
	project := realEnvironment(t)

	// Plain attach of each JDK, the target user is uid 10001.
	for _, c := range []struct{ svc, version string }{
		{"jdk8", "1.8.0"}, {"jdk11", "11."}, {"jdk17", "17."}, {"jdk21", "21."},
		{"rofs8", "1.8.0"}, {"rofs17", "17."}, {"pid1-17", "17."}, {"root8", "1.8.0"}, {"root17", "17."},
	} {
		t.Run(c.svc, func(t *testing.T) {
			rt := newRealTarget(t, project, c.svc)
			rt.fresh()
			j := rt.mustResolve()
			data, err := j.ReadPerfData(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if version, _ := data.Text("java.property.java.version"); !strings.HasPrefix(version, c.version) {
				t.Fatalf("java.version = %q; want %s*", version, c.version)
			}
			port, err := j.resolver.Proc.PickPort(j.PID, realPortLow, realPortHigh)
			if err != nil {
				t.Fatal(err)
			}
			password := newPassword(t)
			t.Cleanup(func() { stopArthas(t, j, port, password) })
			dumps := rt.threadDumps()
			owners := recordAttachFileOwner(t, j)
			status, _ := j.resolver.Proc.Status(j.PID)

			res, err := j.Attach(context.Background(), attachRequest(port, password))
			if err != nil {
				t.Fatalf("Attach: %v\nresult: %+v", err, res)
			}
			t.Logf("nspid=%d euid=%d egid=%d signal=%s files=%v owners=%v return code=%d message=%q",
				j.NSPid, status.EUID, status.EGID, res.Signal, res.AttachFiles, *owners, res.ReturnCode, res.Message)
			if res.Signal != "pidfd" || len(res.AttachFiles) != 1 || res.ReturnCode != 0 || len(res.Leftover) != 0 {
				t.Errorf("result = %+v", res)
			}
			wantOwner := fmt.Sprintf("uid=%d gid=%d", status.EUID, status.EGID)
			if len(*owners) != 1 || !strings.Contains((*owners)[0], wantOwner) {
				t.Errorf("attach file owners at the signal: %v; want %s", *owners, wantOwner)
			}
			checkLoaded(t, rt, j, port, password, dumps)
		})
	}

	// JDK 8 closes the connection of any peer that is not its own user, root included.
	t.Run("jdk8-root-connection-fails", func(t *testing.T) {
		rt := newRealTarget(t, project, "jdk8")
		rt.fresh()
		j := rt.mustResolve()
		port, _ := j.resolver.Proc.PickPort(j.PID, realPortLow, realPortHigh)
		password := newPassword(t)
		t.Cleanup(func() { stopArthas(t, j, port, password) })
		st, err := j.prepare(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer st.root.Close()
		if st.SocketExists {
			t.Fatal("the attach socket of a JVM that was just started exists already")
		}
		res := &AttachResult{ReturnCode: -1}
		// Signal, wait for the socket, then connect as root.
		err = j.attach(context.Background(), st, res, attachRequest(port, password), 0, 0)
		t.Logf("as root: %v", err)
		if !errors.Is(err, ErrAttachRefused) {
			t.Errorf("root connection to a JDK 8 JVM: %v; want ErrAttachRefused", err)
		}
		if res.Signal != "pidfd" || rt.attachFiles() != "" {
			t.Errorf("signal %q, attach files %q", res.Signal, rt.attachFiles())
		}
		if n, _ := j.resolver.Proc.ArthasThreads(j.PID); n != 0 {
			t.Errorf("%d Arthas threads after the refused connection", n)
		}
		// The socket exists now. With the identity of the target the same load works, and needs no signal.
		res2, err := j.Attach(context.Background(), attachRequest(port, password))
		if err != nil {
			t.Fatalf("Attach as the target: %v", err)
		}
		if res2.Signal != "" || !res2.Check.SocketExists {
			t.Errorf("second attach: %+v", res2)
		}
		checkLoaded(t, rt, j, port, password, rt.threadDumps())
	})

	// A second attach after stop reuses the listener of the JVM and needs no signal.
	t.Run("jdk17-attach-stop-attach", func(t *testing.T) {
		rt := newRealTarget(t, project, "jdk17")
		rt.fresh()
		j := rt.mustResolve()
		for i := 0; i < 3; i++ {
			port, err := j.resolver.Proc.PickPort(j.PID, realPortLow, realPortHigh)
			if err != nil {
				t.Fatal(err)
			}
			password := newPassword(t)
			res, err := j.Attach(context.Background(), attachRequest(port, password))
			if err != nil {
				t.Fatalf("round %d: %v\n%+v", i, err, res)
			}
			if i > 0 && (res.Signal != "" || len(res.AttachFiles) != 0) {
				t.Errorf("round %d: signal %q, files %v", i, res.Signal, res.AttachFiles)
			}
			// An instance that runs refuses the next attach before anything is sent.
			waitListening(t, j, port)
			if _, err := j.CheckAttach(context.Background()); !errors.Is(err, ErrArthasRunning) {
				t.Errorf("round %d: CheckAttach with Arthas running: %v", i, err)
			}
			stopArthas(t, j, port, password)
			if _, err := j.CheckAttach(context.Background()); err != nil {
				t.Errorf("round %d: CheckAttach after stop: %v", i, err)
			}
		}
	})

	// -Xrs: no SIGQUIT handler, but the listener exists from the start of the JVM.
	for _, svc := range []string{"xrs8", "xrs17"} {
		t.Run(svc, func(t *testing.T) {
			rt := newRealTarget(t, project, svc)
			rt.fresh()
			j := rt.mustResolve()
			status, err := j.resolver.Proc.Status(j.PID)
			if err != nil || status.CatchesSIGQUIT() {
				t.Fatalf("status = %+v, %v; want a JVM that does not catch SIGQUIT", status, err)
			}
			// The listener of a JVM with -Xrs starts with the JVM.
			for deadline := time.Now().Add(20 * time.Second); !rt.socketExists(j.NSPid); {
				if time.Now().After(deadline) {
					t.Fatal("the JVM did not start an attach listener")
				}
				time.Sleep(100 * time.Millisecond)
			}
			port, _ := j.resolver.Proc.PickPort(j.PID, realPortLow, realPortHigh)
			password := newPassword(t)
			dumps := rt.threadDumps()
			res, err := j.Attach(context.Background(), attachRequest(port, password))
			if err != nil {
				t.Fatalf("Attach: %v\n%+v", err, res)
			}
			if res.Signal != "" || !res.Check.SocketExists || len(res.AttachFiles) != 0 {
				t.Errorf("result = %+v; the socket exists, so no signal and no file", res)
			}
			checkLoaded(t, rt, j, port, password, dumps)
			stopArthas(t, j, port, password)

			// Without the socket a SIGQUIT would end this JVM, so nothing is sent.
			dockerOut(t, "exec", "-u", "0", rt.container, "rm", "-f", "/tmp/.java_pid"+strconv.Itoa(j.NSPid))
			res, err = j.Attach(context.Background(), attachRequest(port, password))
			if !errors.Is(err, ErrSigQuitNotCaught) {
				t.Errorf("without the socket: %v; want ErrSigQuitNotCaught", err)
			}
			if res.Signal != "" || rt.attachFiles() != "" {
				t.Errorf("signal %q, attach files %q", res.Signal, rt.attachFiles())
			}
			time.Sleep(500 * time.Millisecond)
			if out := dockerOut(t, "inspect", "-f", "{{.State.Running}}", rt.container); strings.TrimSpace(out) != "true" {
				t.Errorf("the container stopped")
			}
			if got := rt.threadDumps(); got != dumps {
				t.Errorf("thread dumps %d -> %d", dumps, got)
			}
		})
	}

	// -XX:+DisableAttachMechanism: refused before the signal, which would only print a thread dump.
	for _, svc := range []string{"noattach8", "noattach17"} {
		t.Run(svc, func(t *testing.T) {
			rt := newRealTarget(t, project, svc)
			rt.fresh()
			j := rt.mustResolve()
			dumps := rt.threadDumps()
			res, err := j.Attach(context.Background(), attachRequest(18563, "x"))
			if !errors.Is(err, ErrAttachDisabled) {
				t.Fatalf("err = %v; want ErrAttachDisabled", err)
			}
			t.Logf("refused: %v", err)
			if res.Signal != "" || len(res.AttachFiles) != 0 || rt.attachFiles() != "" || rt.threadDumps() != dumps {
				t.Errorf("signal %q, files %v / %q, thread dumps %d -> %d", res.Signal, res.AttachFiles, rt.attachFiles(), dumps, rt.threadDumps())
			}
			if rt.socketExists(j.NSPid) {
				t.Error("an attach socket exists, so something signalled the JVM")
			}
		})
	}

	// A read-only root file system and a read-only /tmp: no place for the attach file.
	t.Run("rofsnotmp17", func(t *testing.T) {
		rt := newRealTarget(t, project, "rofsnotmp17")
		rt.restart(false, false)
		dumps := rt.threadDumps()
		// The JVM has no hsperfdata, because /tmp is read-only, so it cannot be found by its main class.
		if _, err := rt.resolve(); err == nil {
			t.Error("a JVM without hsperfdata was resolved by its main class")
		}
		j, err := rt.resolver.identify(rt.javaPID())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := j.Attach(context.Background(), attachRequest(18563, "x")); err == nil {
			t.Fatal("attached to a JVM without a place for the attach file")
		} else {
			t.Logf("Attach: %v", err)
		}
		// The check of the attach file location itself, without the hsperfdata that this JVM lacks.
		root, err := OpenRoot(j.rootPath())
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		status, err := j.resolver.Proc.Status(j.PID)
		if err != nil {
			t.Fatal(err)
		}
		files, err := j.createAttachFiles(&attachState{status: status, root: root})
		if !errors.Is(err, ErrNoAttachFile) {
			for _, f := range files {
				f.Remove()
			}
			t.Fatalf("createAttachFiles: %v; want ErrNoAttachFile", err)
		}
		t.Logf("createAttachFiles: %v", err)
		if rt.attachFiles() != "" || rt.threadDumps() != dumps || rt.socketExists(j.NSPid) {
			t.Errorf("attach files %q, thread dumps %d -> %d", rt.attachFiles(), dumps, rt.threadDumps())
		}
	})
}

// A JVM that was resolved and then restarted is not signalled: its pid may be the same, its start time is not.
func TestRealAttachRefusesARestartedJVM(t *testing.T) {
	project := realEnvironment(t)
	rt := newRealTarget(t, project, "jdk17")
	j := rt.mustResolve()
	stale := *j
	stale.StartTime++
	if _, err := stale.Attach(context.Background(), attachRequest(18563, "x")); !errors.Is(err, ErrProcessChanged) {
		t.Errorf("err = %v; want ErrProcessChanged", err)
	}
	if _, err := stale.DialTCP(context.Background(), 8080); !errors.Is(err, ErrProcessChanged) {
		t.Errorf("DialTCP: %v; want ErrProcessChanged", err)
	}
}

// DialTCP reaches the application's port inside the container, whatever address the container has.
func TestRealDialTCPEntersTheNamespace(t *testing.T) {
	project := realEnvironment(t)
	rt := newRealTarget(t, project, "jdk17")
	j := rt.mustResolve()
	conn, err := j.DialTCP(context.Background(), 8080)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
	var body bytes.Buffer
	io.Copy(&body, conn)
	if !strings.HasPrefix(body.String(), "HTTP/1.") {
		t.Errorf("response = %.200q", body.String())
	}
	if c, err := j.DialTCP(context.Background(), 9); err == nil {
		c.Close()
		t.Error("a closed port accepted a connection")
	}
	assertNoThreadWithOtherIDs(t)
}

// A JVM that was killed leaves its attach socket in /tmp. The JVM that starts in its place has the
// same pid in the container and removes that socket when it starts, so once the application is up the
// attach needs the signal again. Before that the connection to the stale socket is refused.
func TestRealAttachAfterKill(t *testing.T) {
	project := realEnvironment(t)
	rt := newRealTarget(t, project, "jdk17")
	rt.fresh()
	j := rt.mustResolve()
	port, _ := j.resolver.Proc.PickPort(j.PID, realPortLow, realPortHigh)
	password := newPassword(t)
	if res, err := j.Attach(context.Background(), attachRequest(port, password)); err != nil {
		t.Fatalf("first Attach: %v\n%+v", err, res)
	}
	stopArthas(t, j, port, password)
	if !rt.socketExists(j.NSPid) {
		t.Fatal("the JVM has no socket after the attach")
	}

	rt.restart(true, true)
	j = rt.mustResolve()
	t.Logf("socket after the kill and the start of the application: %v", rt.socketExists(j.NSPid))
	port, _ = j.resolver.Proc.PickPort(j.PID, realPortLow, realPortHigh)
	password = newPassword(t)
	t.Cleanup(func() { stopArthas(t, j, port, password) })
	dumps := rt.threadDumps()
	res, err := j.Attach(context.Background(), attachRequest(port, password))
	if err != nil {
		t.Fatalf("Attach: %v\n%+v", err, res)
	}
	if res.Signal != "pidfd" || len(res.AttachFiles) != 1 || len(res.Leftover) != 0 {
		t.Errorf("result = %+v", res)
	}
	checkLoaded(t, rt, j, port, password, dumps)
}
