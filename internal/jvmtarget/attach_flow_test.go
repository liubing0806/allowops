package jvmtarget

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// blockTmp makes the attach file impossible in /tmp by putting a file of that name there.
func (e *attachEnv) blockTmp() {
	e.t.Helper()
	writeFile(e.t, filepath.Join(e.tmp, ".attach_pid7"), "stale")
}

func TestAttachFallsBackToTheWorkingDirectory(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		e := newAttachEnv(t, attachOpts{})
		e.blockTmp()
		var seen []string
		prev := pidfdSendSignal
		pidfdSendSignal = func(fd int, sig unix.Signal, info *unix.Siginfo, flags int) error {
			seen = e.attachFiles()
			return prev(fd, sig, info, flags)
		}
		res, err := e.attach(testAgent)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.AttachFiles) != 1 || res.AttachFiles[0] != "/app/.attach_pid7" {
			t.Errorf("attach files = %v; want the working directory's", res.AttachFiles)
		}
		if len(seen) != 2 {
			t.Errorf("files at the signal: %v; want the stale one and the new one", seen)
		}
		if left := e.attachFiles(); len(left) != 1 || !strings.HasSuffix(left[0], "/tmp/.attach_pid7") {
			t.Errorf("files left: %v; want only the stale file, which was not ours", left)
		}
		if got, _ := os.ReadFile(filepath.Join(e.tmp, ".attach_pid7")); string(got) != "stale" {
			t.Errorf("the stale file changed: %q", got)
		}
	})
}

func TestAttachRefusesWhenNeitherLocationTakesTheFile(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		stale := func(e *attachEnv) { writeFile(t, filepath.Join(e.root, "app", ".attach_pid7"), "stale") }
		outside := func(e *attachEnv) string {
			dir := filepath.Join(e.h.base, "outside")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			return dir
		}
		setCwd := func(e *attachEnv, target string) {
			path := filepath.Join(e.h.proc, "4242", "cwd")
			os.Remove(path)
			if target != "" {
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
		}
		cases := map[string]func(e *attachEnv){
			"both blocked": func(e *attachEnv) { e.blockTmp(); stale(e) },
			"no working directory": func(e *attachEnv) {
				e.blockTmp()
				setCwd(e, "")
			},
			"relative working directory": func(e *attachEnv) {
				e.blockTmp()
				setCwd(e, "app")
			},
			"deleted working directory": func(e *attachEnv) {
				e.blockTmp()
				setCwd(e, "/app (deleted)")
			},
			"working directory is a link out of the root": func(e *attachEnv) {
				e.blockTmp()
				dir := outside(e)
				if err := os.Symlink(dir, filepath.Join(e.root, "cwdlink")); err != nil {
					t.Fatal(err)
				}
				setCwd(e, "/cwdlink")
				// The control: by the host's rules the link leads to a directory where the file could be made.
				writeFile(t, filepath.Join(e.root, "cwdlink", "control"), "x")
				if _, err := os.Stat(filepath.Join(dir, "control")); err != nil {
					t.Fatalf("control: %v", err)
				}
				os.Remove(filepath.Join(dir, "control"))
			},
			"working directory is a file": func(e *attachEnv) {
				e.blockTmp()
				writeFile(t, filepath.Join(e.root, "afile"), "x")
				setCwd(e, "/afile")
			},
			"working directory is missing": func(e *attachEnv) {
				e.blockTmp()
				setCwd(e, "/gone")
			},
		}
		for name, setup := range cases {
			t.Run(strings.ReplaceAll(name, " ", "_"), func(t *testing.T) {
				e := newAttachEnv(t, attachOpts{})
				setup(e)
				before := e.attachFiles()
				res, err := e.attach(testAgent)
				if !errors.Is(err, ErrNoAttachFile) {
					t.Fatalf("err = %v; want ErrNoAttachFile", err)
				}
				if e.signalCount() != 0 || len(res.AttachFiles) != 0 || res.Signal != "" {
					t.Errorf("%d signals, result %+v", e.signalCount(), res)
				}
				if after := e.attachFiles(); len(after) != len(before) {
					t.Errorf("attach files before %v, after %v", before, after)
				}
				if _, _, dumps := e.listener.seen(); dumps != 0 || e.listener.listening() {
					t.Errorf("the JVM was woken: %d thread dumps", dumps)
				}
			})
		}
	})
}

// With /tmp missing and no working directory there is no place for the file either.
func TestAttachWithoutTmpAndWithoutAWorkingDirectory(t *testing.T) {
	e := newAttachEnv(t, attachOpts{noCwd: true})
	// The hsperfdata of the JVM is read from /tmp, so the directory stays; only the attach file is refused there.
	e.blockTmp()
	if _, err := e.attach(testAgent); !errors.Is(err, ErrNoAttachFile) || e.signalCount() != 0 {
		t.Errorf("err = %v, %d signals", err, e.signalCount())
	}
}

// HotSpot's own attach client runs as the JVM's user, so it makes the attach file only where that
// user may create files. allowops-exec is root and must not do more. Otherwise the JVM's user can
// have a file of its own made in a directory that it cannot write: it takes the name in /tmp first,
// so that the working directory is used, and the JVM's working directory can be any directory.
// Run as root, or in a user namespace that maps more ids than root, from the package directory:
//
//	go test -c -o /tmp/jvmtarget.test .
//	unshare --map-auto --map-root-user /tmp/jvmtarget.test -test.run TestAttachFileNeedsThePermissionOfTheJVMsUser
func TestAttachFileNeedsThePermissionOfTheJVMsUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root, or a user namespace with more mapped ids")
	}
	const uid, gid = 4321, 4321
	eachResolver(t, func(t *testing.T) {
		e := newAttachEnv(t, attachOpts{})
		app := filepath.Join(e.root, "app")
		if err := os.Chmod(e.tmp, 0o1777); err != nil {
			t.Fatal(err)
		}
		// The JVM's user took the name in /tmp; /app belongs to root and only root may write it.
		taken := filepath.Join(e.tmp, ".attach_pid7")
		writeFile(t, taken, "")
		if err := os.Lchown(taken, uid, gid); err != nil {
			t.Fatal(err)
		}
		root, err := OpenRoot(e.jvm.rootPath())
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		st := &attachState{status: Status{UID: uid, EUID: uid, GID: gid, EGID: gid}, root: root}
		paths := func(files []*CreatedFile) []string {
			var out []string
			for _, f := range files {
				out = append(out, f.Path)
				f.Remove()
			}
			return out
		}
		created, err := e.jvm.createAttachFiles(st)
		if made := paths(created); !errors.Is(err, ErrNoAttachFile) {
			t.Errorf("err = %v, files %v; want ErrNoAttachFile: the JVM's user may not create files in /app", err, made)
		}
		if _, err := os.Lstat(filepath.Join(app, ".attach_pid7")); err == nil {
			t.Error("the attach file was made in /app")
		}

		// Where the user may create files, the file is made, and it is the user's.
		if err := os.Remove(taken); err != nil {
			t.Fatal(err)
		}
		var owner uint32
		created, err = e.jvm.createAttachFiles(st)
		if err == nil {
			var info unix.Stat_t
			if err := unix.Lstat(taken, &info); err != nil {
				t.Fatal(err)
			}
			owner = info.Uid
		}
		if made := paths(created); err != nil || len(made) != 1 || made[0] != "/tmp/.attach_pid7" || owner != uid {
			t.Errorf("err = %v, files %v, owner %d; want /tmp/.attach_pid7 of uid %d", err, made, owner, uid)
		}
	})
}

func TestAttachArgumentIsCheckedBeforeAnythingHappens(t *testing.T) {
	jar := "/opt/arthas/arthas-agent.jar="
	long := func(n int) string { return jar + strings.Repeat("a", n-len(jar)) }
	for name, c := range map[string]struct {
		arg string
		ok  bool
	}{
		"1024 bytes":      {long(1024), true},
		"1025 bytes":      {long(1025), false},
		"4000 bytes":      {long(4000), false},
		"empty":           {"", false},
		"NUL":             {jar + "a\x00b", false},
		"relative jar":    {"arthas-agent.jar=x", false},
		"control in jar":  {"/opt/a\nb.jar=x", false},
		"no options":      {"/opt/arthas/arthas-agent.jar", true},
		"empty options":   {"/opt/arthas/arthas-agent.jar=", true},
		"newline options": {"/opt/arthas/arthas-agent.jar=a\nb", true},
	} {
		t.Run(strings.ReplaceAll(name, " ", "_"), func(t *testing.T) {
			e := newAttachEnv(t, attachOpts{})
			res, err := e.attach(c.arg)
			if c.ok {
				if err != nil {
					t.Fatal(err)
				}
				if requests, _, _ := e.listener.seen(); len(requests) != 1 || !strings.Contains(requests[0], c.arg) {
					t.Errorf("request = %q", requests)
				}
				return
			}
			if !errors.Is(err, ErrAgentArgument) {
				t.Fatalf("err = %v; want ErrAgentArgument", err)
			}
			if strings.Contains(err.Error(), "aaaa") || strings.Contains(err.Error(), "b.jar") {
				t.Errorf("the error quotes the argument: %v", err)
			}
			if e.signalCount() != 0 || len(e.attachFiles()) != 0 || e.listener.listening() || res.Check != nil {
				t.Errorf("%d signals, attach files %v, result %+v", e.signalCount(), e.attachFiles(), res)
			}
		})
	}
}

// The process was replaced after the checks and before the signal. The attach file made for the
// old process is removed again.
func TestAttachSendsNoSignalWhenTheStartTimeChanged(t *testing.T) {
	for name, pidfd := range map[string]bool{"pidfd": true, "kill": false} {
		t.Run(name, func(t *testing.T) {
			e := newAttachEnv(t, attachOpts{})
			prev := pidfdOpen
			pidfdOpen = func(pid, flags int) (int, error) {
				e.h.setStart(testPID, e.jvm.StartTime+1) // the pid now belongs to another process
				if !pidfd {
					return -1, unix.ENOSYS
				}
				return prev(pid, flags)
			}
			res, err := e.attach(testAgent)
			if !errors.Is(err, ErrProcessChanged) {
				t.Fatalf("err = %v; want ErrProcessChanged", err)
			}
			if e.signalCount() != 0 || res.Signal != "" {
				t.Errorf("%d signals sent", e.signalCount())
			}
			if left := e.attachFiles(); len(left) != 0 {
				t.Errorf("attach files left: %v", left)
			}
		})
	}
}

func TestAttachSendsNoSignalWhenThePidIsGone(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	pidfdOpen = func(pid, flags int) (int, error) { return -1, unix.ESRCH }
	if _, err := e.attach(testAgent); !errors.Is(err, ErrProcessChanged) || e.signalCount() != 0 {
		t.Errorf("err = %v, %d signals", err, e.signalCount())
	}
	// The same in the fallback: kill finds no process.
	pidfdOpen = func(pid, flags int) (int, error) { return -1, unix.ENOSYS }
	killProcess = func(pid int, sig syscall.Signal) error { return syscall.ESRCH }
	if _, err := e.attach(testAgent); !errors.Is(err, ErrProcessChanged) {
		t.Errorf("fallback: err = %v", err)
	}
}

func TestAttachFallsBackToKillWithoutPidfd(t *testing.T) {
	for name, err := range map[string]error{"ENOSYS": unix.ENOSYS, "EPERM": unix.EPERM} {
		t.Run(name, func(t *testing.T) {
			e := newAttachEnv(t, attachOpts{})
			pidfdOpen = func(pid, flags int) (int, error) { return -1, err }
			res, aerr := e.attach(testAgent)
			if aerr != nil {
				t.Fatal(aerr)
			}
			if res.Signal != "kill" || len(e.signals) != 1 || e.signals[0] != "kill" {
				t.Errorf("signal = %q, %v", res.Signal, e.signals)
			}
		})
	}
	t.Run("other errors stop the attach", func(t *testing.T) {
		e := newAttachEnv(t, attachOpts{})
		pidfdOpen = func(pid, flags int) (int, error) { return -1, unix.EMFILE }
		if _, err := e.attach(testAgent); !errors.Is(err, unix.EMFILE) || e.signalCount() != 0 {
			t.Errorf("err = %v, %d signals", err, e.signalCount())
		}
		if left := e.attachFiles(); len(left) != 0 {
			t.Errorf("attach files left: %v", left)
		}
	})
	t.Run("pidfd_send_signal without kernel support", func(t *testing.T) {
		e := newAttachEnv(t, attachOpts{})
		pidfdSendSignal = func(fd int, sig unix.Signal, info *unix.Siginfo, flags int) error { return unix.ENOSYS }
		res, err := e.attach(testAgent)
		if err != nil || res.Signal != "kill" {
			t.Errorf("signal = %q, %v", res.Signal, err)
		}
	})
}

// A child process that records the SIGQUIT it gets, in a fake procfs entry of its own.
type quitChild struct {
	pid  int
	file string
}

func startQuitChild(t *testing.T) quitChild {
	t.Helper()
	file := filepath.Join(t.TempDir(), "quits")
	cmd := exec.Command("sh", "-c", `trap 'echo QUIT >> "$1"' QUIT; echo ready; while :; do sleep 0.05; done`, "sh", file)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("child: %q, %v", line, err)
	}
	return quitChild{pid: cmd.Process.Pid, file: file}
}

func (c quitChild) quits(t *testing.T, wait time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(wait)
	for {
		data, _ := os.ReadFile(c.file)
		if n := strings.Count(string(data), "QUIT"); n > 0 || time.Now().After(deadline) {
			return n
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The real system calls, against a real process.
func TestSendSignalReachesTheProcess(t *testing.T) {
	for _, mode := range []string{"pidfd", "kill"} {
		t.Run(mode, func(t *testing.T) {
			child := startQuitChild(t)
			h := newShortHost(t)
			h.addProcess(process{pid: child.pid})
			r := h.resolver()
			start, err := r.Proc.StartTime(child.pid)
			if err != nil {
				t.Fatal(err)
			}
			j := &JVM{PID: child.pid, StartTime: start, resolver: r}
			if mode == "kill" {
				pidfdOpen = func(int, int) (int, error) { return -1, unix.ENOSYS }
				t.Cleanup(func() { pidfdOpen = unix.PidfdOpen })
			} else if fd, err := unix.PidfdOpen(os.Getpid(), 0); err != nil {
				t.Skipf("this kernel has no pidfd_open: %v", err)
			} else {
				unix.Close(fd)
			}
			method, err := r.sendSignal(j, unix.SIGQUIT)
			if err != nil || method != mode {
				t.Fatalf("method = %q, %v", method, err)
			}
			if n := child.quits(t, 3*time.Second); n != 1 {
				t.Errorf("the child got %d SIGQUIT", n)
			}
		})
	}
}

func TestSendSignalChecksTheStartTimeAgainstARealProcess(t *testing.T) {
	for _, mode := range []string{"pidfd", "kill"} {
		t.Run(mode, func(t *testing.T) {
			child := startQuitChild(t)
			h := newShortHost(t)
			h.addProcess(process{pid: child.pid})
			r := h.resolver()
			start, _ := r.Proc.StartTime(child.pid)
			j := &JVM{PID: child.pid, StartTime: start, resolver: r}
			h.setStart(child.pid, start+5) // the pid belongs to another process
			if mode == "kill" {
				pidfdOpen = func(int, int) (int, error) { return -1, unix.ENOSYS }
				t.Cleanup(func() { pidfdOpen = unix.PidfdOpen })
			}
			if _, err := r.sendSignal(j, unix.SIGQUIT); !errors.Is(err, ErrProcessChanged) {
				t.Fatalf("err = %v; want ErrProcessChanged", err)
			}
			if n := child.quits(t, 300*time.Millisecond); n != 0 {
				t.Errorf("the child got %d SIGQUIT", n)
			}
		})
	}
}

func TestAttachReplies(t *testing.T) {
	long := strings.Repeat("x", 2000)
	for name, c := range map[string]struct {
		reply   string
		wantErr string // empty: success
		code    int
		message string
	}{
		"success":                 {reply: "0\nreturn code: 0\n", code: 0},
		"success, no code":        {reply: "0\n", code: -1},
		"success, no newline":     {reply: "0", code: -1},
		"no final newline":        {reply: "0\nreturn code: 0", code: 0},
		"JDK 8 style":             {reply: "0\n0\n", code: 0},
		"JDK 8 style, error":      {reply: "0\n100\n", wantErr: "returned 100", code: 100},
		"agent returned an error": {reply: "0\nreturn code: 100\n", wantErr: "returned 100", code: 100},
		"number after other text": {reply: "0\nsomething else\n0\n", wantErr: "unexpected answer: something else"},
		"status 1":                {reply: "1\nCould not find agent library\n", wantErr: "status 1: Could not find agent library"},
		"negative status":         {reply: "-1\nboom", wantErr: "status -1: boom"},
		"empty":                   {reply: "", wantErr: "without an answer"},
		"blank":                   {reply: "\n\n", wantErr: "without an answer"},
		"not a number":            {reply: "ok\nreturn code: 0\n", wantErr: "unexpected answer"},
		"code is not a number":    {reply: "0\nreturn code: x\n", wantErr: "unexpected return code"},
		"status 0, other text":    {reply: "0\nsomething else\n", wantErr: "unexpected answer: something else"},
		"echoes the whole arg":    {reply: "1\nbad agent " + testAgent + "\n", wantErr: "bad agent <agent>"},
		"echoes the options":      {reply: "1\nbad options telnetPort=-1;httpPort=18563;password=SECRETpw123 here\n", wantErr: "bad options <options> here"},
		"control characters":      {reply: "1\nbad\x01\x1b[31m\xffnews\n", wantErr: "bad??[31m?news"},
		"long message":            {reply: "1\n" + long, wantErr: "..."},
	} {
		t.Run(strings.ReplaceAll(name, " ", "_"), func(t *testing.T) {
			e := newAttachEnv(t, attachOpts{})
			e.listener.reply = c.reply
			res, err := e.attach(testAgent)
			if c.wantErr == "" {
				if err != nil || res.ReturnCode != c.code {
					t.Fatalf("result = %+v, %v", res, err)
				}
				return
			}
			if !errors.Is(err, ErrAttachRefused) || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v; want ErrAttachRefused containing %q", err, c.wantErr)
			}
			for _, secret := range []string{"SECRETpw123", "telnetPort", "arthas-agent.jar"} {
				if strings.Contains(err.Error(), secret) || strings.Contains(res.Message, secret) {
					t.Errorf("the error or the message shows %q: %v / %q", secret, err, res.Message)
				}
			}
			if len(res.Message) > maxJavaMessage+3 {
				t.Errorf("message of %d bytes", len(res.Message))
			}
			if c.code != 0 && res.ReturnCode != c.code {
				t.Errorf("ReturnCode = %d; want %d", res.ReturnCode, c.code)
			}
			// The attach file is gone also when the load failed.
			if left := e.attachFiles(); len(left) != 0 {
				t.Errorf("attach files left: %v", left)
			}
		})
	}
}

func TestAttachWhenTheJVMDoesNotAnswer(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	e.listener.hang = true
	start := time.Now()
	_, err := e.attach(testAgent)
	if err == nil || time.Since(start) > 4*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
	// The load command was sent: the JVM can still load the agent after the wait.
	if !errors.Is(err, ErrLoadUnanswered) {
		t.Errorf("err = %v; want ErrLoadUnanswered", err)
	}
	if left := e.attachFiles(); len(left) != 0 {
		t.Errorf("attach files left: %v", left)
	}
}

func TestAttachWhenTheJVMClosesTheConnection(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	e.listener.closeAtOnce = true
	_, err := e.attach(testAgent)
	if !errors.Is(err, ErrAttachRefused) {
		t.Errorf("err = %v; want ErrAttachRefused", err)
	}
	if errors.Is(err, ErrLoadUnanswered) {
		t.Errorf("err = %v; a closed connection is an answer", err)
	}
}

func TestAttachWhenTheSocketNeverAppears(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	// A JVM that gets the signal but finds no attach file (here: it looks elsewhere) only prints a thread dump.
	prev := pidfdSendSignal
	pidfdSendSignal = func(fd int, sig unix.Signal, info *unix.Siginfo, flags int) error {
		e.mu.Lock()
		e.signals = append(e.signals, "pidfd")
		e.mu.Unlock()
		return nil
	}
	defer func() { pidfdSendSignal = prev }()
	start := time.Now()
	res, err := e.attach(testAgent)
	if !errors.Is(err, ErrAttachTimeout) {
		t.Fatalf("err = %v; want ErrAttachTimeout", err)
	}
	if time.Since(start) < 400*time.Millisecond || time.Since(start) > 3*time.Second {
		t.Errorf("waited %v for a 500 ms limit", time.Since(start))
	}
	if res.Signal != "pidfd" || len(res.AttachFiles) != 1 {
		t.Errorf("result = %+v", res)
	}
	if left := e.attachFiles(); len(left) != 0 {
		t.Errorf("attach files left: %v", left)
	}
}

func TestAttachStopsWaitingWhenTheContextEnds(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	pidfdSendSignal = func(int, unix.Signal, *unix.Siginfo, int) error { return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := e.jvm.Attach(ctx, AttachRequest{Agent: testAgent, SocketWait: time.Minute})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Errorf("err = %v after %v", err, time.Since(start))
	}
	if left := e.attachFiles(); len(left) != 0 {
		t.Errorf("attach files left: %v", left)
	}
}

func TestAttachStopsWhenTheProcessIsReplacedWhileWaiting(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	pidfdSendSignal = func(int, unix.Signal, *unix.Siginfo, int) error {
		e.h.setStart(testPID, e.jvm.StartTime+9)
		return nil
	}
	start := time.Now()
	if _, err := e.attach(testAgent); !errors.Is(err, ErrProcessChanged) || time.Since(start) > 400*time.Millisecond {
		t.Errorf("err = %v after %v", err, time.Since(start))
	}
	if left := e.attachFiles(); len(left) != 0 {
		t.Errorf("attach files left: %v", left)
	}
}

func TestAttachStopsWhenTheProcessIsReplacedBeforeTheConnection(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	e.listener.start()
	e.jvm.resolver.beforeConnect = func() { e.h.setStart(testPID, e.jvm.StartTime+9) }
	if _, err := e.attach(testAgent); !errors.Is(err, ErrProcessChanged) {
		t.Errorf("err = %v; want ErrProcessChanged", err)
	}
	if requests, peers, _ := e.listener.seen(); len(requests)+len(peers) != 0 {
		t.Errorf("a connection was made: %q %v", requests, peers)
	}
}

func TestAttachReportsAFileThatCannotBeRemoved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes files from any directory")
	}
	e := newAttachEnv(t, attachOpts{})
	prev := pidfdSendSignal
	pidfdSendSignal = func(fd int, sig unix.Signal, info *unix.Siginfo, flags int) error {
		err := prev(fd, sig, info, flags)
		// The directory becomes read-only once the JVM has seen the file.
		os.Chmod(e.tmp, 0o555)
		return err
	}
	t.Cleanup(func() { os.Chmod(e.tmp, 0o755) })
	res, err := e.attach(testAgent)
	if err == nil || !strings.Contains(err.Error(), "removing the attach file") {
		t.Fatalf("err = %v", err)
	}
	if len(res.Leftover) != 1 || res.Leftover[0] != "/tmp/.attach_pid7" {
		t.Errorf("leftover = %v", res.Leftover)
	}
}

func TestCheckAttachSendsAndCreatesNothing(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	check, err := e.jvm.CheckAttach(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if check.SocketExists || check.JavaHome != "/opt/java/openjdk" || check.PerfData == nil || check.EUID != uint32(os.Getuid()) || check.EGID != uint32(os.Getgid()) {
		t.Errorf("check = %+v", check)
	}
	if e.signalCount() != 0 || len(e.attachFiles()) != 0 || e.listener.listening() {
		t.Errorf("%d signals, attach files %v", e.signalCount(), e.attachFiles())
	}
	e.listener.start()
	if check, err := e.jvm.CheckAttach(context.Background()); err != nil || !check.SocketExists {
		t.Errorf("with a socket: %+v, %v", check, err)
	}
	e.h.setStart(testPID, e.jvm.StartTime+1)
	if _, err := e.jvm.CheckAttach(context.Background()); !errors.Is(err, ErrProcessChanged) {
		t.Errorf("replaced process: %v", err)
	}
}

// onLockedThread runs f on a thread that ends with it, so a changed thread is never reused.
func TestOnLockedThreadEndsTheThread(t *testing.T) {
	tid, err := onLockedThread(func() (int, error) { return unix.Gettid(), nil })
	if err != nil {
		t.Fatal(err)
	}
	path := "/proc/self/task/" + strconv.Itoa(tid)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("thread %d still exists", tid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The Go runtime cannot end the main thread of the process. A locked goroutine that finishes
// on it leaves the thread parked for good with the state the goroutine gave it, which is
// then the state of the process as ps and /proc/<pid> report it.
func TestOnLockedThreadLeavesTheMainThreadAlone(t *testing.T) {
	const changed = "locked-thread"
	mainComm := func() string {
		data, err := os.ReadFile("/proc/self/task/" + strconv.Itoa(os.Getpid()) + "/comm")
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(data))
	}
	original := mainComm()
	for i := 0; i < 300; i++ {
		_, err := onLockedThread(func() (struct{}, error) {
			// The name of a thread is thread state that needs no privilege to change.
			return struct{}{}, os.WriteFile("/proc/thread-self/comm", []byte(changed), 0)
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := mainComm(); got != original {
			t.Fatalf("after %d calls the main thread is called %q; it was %q", i+1, got, original)
		}
	}
}

// Changing the ids of the locked thread leaves the process, and so all other threads, as it was.
func TestSwitchIdentityChangesOnlyTheLockedThread(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	got, err := onLockedThread(func() ([2]uint32, error) {
		if err := switchIdentity(uid, gid); err != nil {
			return [2]uint32{}, err
		}
		return [2]uint32{uint32(unix.Geteuid()), uint32(unix.Getegid())}, nil
	})
	if err != nil || got != [2]uint32{uid, gid} {
		t.Fatalf("ids = %v, %v", got, err)
	}
	if os.Geteuid() == 0 {
		// As root: the thread becomes the target while this goroutine's thread stays root.
		other, err := onLockedThread(func() ([2]uint32, error) {
			if err := switchIdentity(12345, 23456); err != nil {
				return [2]uint32{}, err
			}
			return [2]uint32{uint32(unix.Geteuid()), uint32(unix.Getegid())}, nil
		})
		if err != nil || other != [2]uint32{12345, 23456} {
			t.Fatalf("root switch: %v, %v", other, err)
		}
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			t.Errorf("the process ids changed: %d/%d", os.Geteuid(), os.Getegid())
		}
		assertNoThreadWithOtherIDs(t)
		return
	}
	// Not root: another user is refused, and the process is unchanged.
	if _, err := onLockedThread(func() (int, error) { return 0, switchIdentity(uid+1, gid) }); !errors.Is(err, unix.EPERM) {
		t.Errorf("switch to another user: %v; want EPERM", err)
	}
}

// assertNoThreadWithOtherIDs waits for the threads of this process to have the process's ids.
func assertNoThreadWithOtherIDs(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		bad := threadsWithOtherIDs(t)
		if len(bad) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("threads with other ids: %v", bad)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func threadsWithOtherIDs(t *testing.T) []string {
	t.Helper()
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	for _, task := range tasks {
		data, err := os.ReadFile("/proc/self/task/" + task.Name() + "/status")
		if err != nil {
			continue // the thread ended
		}
		for _, line := range strings.Split(string(data), "\n") {
			want := ""
			switch {
			case strings.HasPrefix(line, "Uid:"):
				want = strconv.Itoa(os.Getuid())
			case strings.HasPrefix(line, "Gid:"):
				want = strconv.Itoa(os.Getgid())
			default:
				continue
			}
			// "Uid: real effective saved filesystem"
			if fields := strings.Fields(line); len(fields) != 5 || fields[1] != want || fields[2] != want || fields[3] != want || fields[4] != want {
				bad = append(bad, fmt.Sprintf("thread %s: %s", task.Name(), line))
			}
		}
	}
	return bad
}
