package jvmtarget

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	testAgent = "/opt/arthas/arthas-agent.jar=telnetPort=-1;httpPort=18563;password=SECRETpw123"
	testNSPid = 7
	testPID   = 4242
)

// newShortHost is newHost with a short base directory: unix socket paths are limited to 107 bytes.
func newShortHost(t *testing.T) *host {
	t.Helper()
	parent := ""
	if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
		parent = "/dev/shm" // short, and not below /tmp, which some tests make a link in the fake root
	}
	dir, err := os.MkdirTemp(parent, "ja")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	base, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := &host{t: t, base: base, proc: filepath.Join(base, "proc")}
	if err := os.MkdirAll(filepath.Join(h.proc, "self", "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("pid:[1]", filepath.Join(h.proc, "self", "ns", "pid")); err != nil {
		t.Fatal(err)
	}
	return h
}

// perfWith returns a JDK 17 hsperfdata sample in which the value of a counter is replaced by
// a value that is at most as long.
func perfWith(t *testing.T, replacements ...string) []byte {
	t.Helper()
	data := jvmFile(t, sampleCommand)
	for i := 0; i < len(replacements); i += 2 {
		name, value := replacements[i], replacements[i+1]
		at := bytes.Index(data, []byte(name+"\x00"))
		if at < 0 {
			t.Fatalf("sample has no counter %s", name)
		}
		// The value follows the name; the old value is the first printable run after it.
		start := at + len(name) + 1
		for start < len(data) && data[start] == 0 {
			start++
		}
		end := start
		for end < len(data) && data[end] != 0 {
			end++
		}
		if len(value) > end-start {
			t.Fatalf("%s: %q is longer than the sample's value %q", name, value, data[start:end])
		}
		copy(data[start:end], append([]byte(value), make([]byte, end-start-len(value))...))
	}
	return data
}

type attachOpts struct {
	perf   []byte
	sigCgt uint64
	// noCwd leaves the process without a cwd link.
	noCwd bool
	// noInstrument leaves out the library of java.instrument.
	noInstrument bool
	// tmpLinkToHost makes /tmp of the container an absolute link to e.hostDir, a directory of
	// the host. The directory of that name inside the root, which the JVM sees as /tmp, is a different one.
	tmpLinkToHost bool
}

// attachEnv is a fake JVM process: a procfs entry, a root directory with /tmp, /app (the working
// directory) and a Java home, and a stand-in for the attach listener of the JVM.
type attachEnv struct {
	t        *testing.T
	h        *host
	root     string
	tmp      string // the directory that is /tmp for the JVM, as a path of the host
	hostDir  string // with tmpLinkToHost: the host's directory that /tmp names
	jvm      *JVM
	listener *fakeListener
	mu       sync.Mutex
	signals  []string // how the signals were sent
}

func newAttachEnv(t *testing.T, o attachOpts) *attachEnv {
	t.Helper()
	h := newShortHost(t)
	root := h.newRoot("c")
	if err := os.MkdirAll(filepath.Join(root, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := process{pid: testPID, nspid: []int{testPID, testNSPid}, root: root, ns: "pid:[2]", sigCgt: o.sigCgt}
	if !o.noCwd {
		p.cwd = "/app"
	}
	h.addProcess(p)
	fakeThreads(t, h.proc, testPID, "java", "GC Thread#0")
	if o.perf == nil {
		o.perf = jvmFile(t, sampleCommand)
	}
	tmp := filepath.Join(root, "tmp")
	hostDir := ""
	if !o.tmpLinkToHost {
		h.jvm(testPID, o.perf)
	} else {
		hostDir = filepath.Join(h.base, "hostdir")
		tmp = filepath.Join(root, hostDir)
		if err := os.MkdirAll(hostDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(root, "tmp")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(hostDir, filepath.Join(root, "tmp")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(tmp, "hsperfdata_app", fmt.Sprint(testNSPid)), string(o.perf))
	}
	if !o.noInstrument {
		writeFile(t, filepath.Join(root, "opt", "java", "openjdk", "lib", "libinstrument.so"), "ELF")
	}
	r := h.resolver()
	start, err := r.Proc.StartTime(testPID)
	if err != nil {
		t.Fatal(err)
	}
	e := &attachEnv{t: t, h: h, root: root, tmp: tmp, hostDir: hostDir}
	e.jvm = &JVM{PID: testPID, NSPid: testNSPid, StartTime: start, EUID: uint32(os.Getuid()), resolver: r}
	e.listener = &fakeListener{env: e, reply: "0\nreturn code: 0\n"}
	t.Cleanup(e.listener.close)

	// No signal reaches a real process: the fake listener reacts to the call instead.
	prevOpen, prevSend, prevKill := pidfdOpen, pidfdSendSignal, killProcess
	t.Cleanup(func() { pidfdOpen, pidfdSendSignal, killProcess = prevOpen, prevSend, prevKill })
	pidfdOpen = func(pid, flags int) (int, error) {
		if pid != testPID {
			t.Errorf("pidfd_open(%d)", pid)
		}
		return unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	}
	pidfdSendSignal = func(fd int, sig unix.Signal, info *unix.Siginfo, flags int) error {
		e.deliver("pidfd", sig)
		return nil
	}
	killProcess = func(pid int, sig syscall.Signal) error {
		if pid != testPID {
			t.Errorf("kill(%d)", pid)
		}
		e.deliver("kill", unix.Signal(sig))
		return nil
	}
	return e
}

func (e *attachEnv) deliver(method string, sig unix.Signal) {
	if sig != unix.SIGQUIT {
		e.t.Errorf("signal %d", sig)
	}
	e.mu.Lock()
	e.signals = append(e.signals, method)
	e.mu.Unlock()
	e.listener.onQuit()
}

func (e *attachEnv) signalCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.signals)
}

func (e *attachEnv) attach(arg string) (*AttachResult, error) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return e.jvm.Attach(ctx, AttachRequest{Agent: arg, SocketWait: 500 * time.Millisecond, ReplyWait: 2 * time.Second})
}

// attachFiles lists the attach trigger files anywhere in the fake host, also outside the root.
func (e *attachEnv) attachFiles() []string {
	var found []string
	filepath.WalkDir(e.h.base, func(path string, d os.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), ".attach_pid") {
			found = append(found, strings.TrimPrefix(path, e.h.base))
		}
		return nil
	})
	return found
}

// fakeListener plays the attach listener of a JVM: on SIGQUIT it looks for the attach file the way
// HotSpot does, and starts to listen on /tmp/.java_pid<pid> only when it finds one.
type fakeListener struct {
	env   *attachEnv
	reply string
	// hang leaves the connection unanswered.
	hang bool
	// closeAtOnce closes the connection without reading, as JDK 8 does for a foreign user.
	closeAtOnce bool

	mu       sync.Mutex
	ln       *net.UnixListener
	requests []string
	peers    []unix.Ucred
	dumps    int // SIGQUIT without an attach file: the JVM prints a thread dump
	wg       sync.WaitGroup
	done     chan struct{}
}

func (f *fakeListener) onQuit() {
	for _, dir := range []string{filepath.Join(f.env.root, "app"), f.env.tmp} {
		path := filepath.Join(dir, fmt.Sprintf(".attach_pid%d", testNSPid))
		info, err := os.Lstat(path)
		if err == nil && info.Sys().(*syscall.Stat_t).Uid == uint32(os.Getuid()) {
			f.start()
			return
		}
	}
	f.mu.Lock()
	f.dumps++
	f.mu.Unlock()
}

// start makes the socket as HotSpot does: under a temporary name, then renamed.
func (f *fakeListener) start() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln != nil {
		return
	}
	final := filepath.Join(f.env.tmp, fmt.Sprintf(".java_pid%d", testNSPid))
	tmp := final + ".tmp"
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: tmp, Net: "unix"})
	if err != nil {
		f.env.t.Error(err)
		return
	}
	ln.SetUnlinkOnClose(false)
	if err := os.Rename(tmp, final); err != nil {
		f.env.t.Error(err)
		return
	}
	f.ln = ln
	f.done = make(chan struct{})
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			conn, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				f.serve(conn)
			}()
		}
	}()
}

func (f *fakeListener) serve(conn *net.UnixConn) {
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err == nil {
		raw.Control(func(fd uintptr) {
			if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
				f.mu.Lock()
				f.peers = append(f.peers, *cred)
				f.mu.Unlock()
			}
		})
	}
	if f.closeAtOnce {
		return
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var req []byte
	buf := make([]byte, 4096)
	for bytes.Count(req, []byte{0}) < 5 {
		n, err := conn.Read(buf)
		req = append(req, buf[:n]...)
		if err != nil {
			break
		}
	}
	f.mu.Lock()
	f.requests = append(f.requests, string(req))
	f.mu.Unlock()
	if f.hang {
		select {
		case <-f.done:
		case <-time.After(5 * time.Second):
		}
		return
	}
	conn.Write([]byte(f.reply))
}

func (f *fakeListener) close() {
	f.mu.Lock()
	ln, done := f.ln, f.done
	f.mu.Unlock()
	if ln != nil {
		close(done)
		ln.Close()
	}
	f.wg.Wait()
}

func (f *fakeListener) seen() (requests []string, peers []unix.Ucred, dumps int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...), append([]unix.Ucred(nil), f.peers...), f.dumps
}

func (f *fakeListener) listening() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ln != nil
}

func TestAttachLoadsTheAgentAndRemovesTheAttachFile(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		e := newAttachEnv(t, attachOpts{})
		res, err := e.attach(testAgent)
		if err != nil {
			t.Fatal(err)
		}
		if res.Signal != "pidfd" || e.signalCount() != 1 {
			t.Errorf("signal = %q, %d signals; want one through a pidfd", res.Signal, e.signalCount())
		}
		if res.ReturnCode != 0 || res.Check == nil || res.Check.SocketExists || res.Check.JavaHome != "/opt/java/openjdk" {
			t.Errorf("result = %+v", res)
		}
		if len(res.AttachFiles) != 1 || res.AttachFiles[0] != "/tmp/.attach_pid7" || len(res.Leftover) != 0 {
			t.Errorf("attach files = %v, leftover %v; want /tmp/.attach_pid7 and none left", res.AttachFiles, res.Leftover)
		}
		if left := e.attachFiles(); len(left) != 0 {
			t.Errorf("attach files left: %v", left)
		}
		requests, peers, dumps := e.listener.seen()
		want := "1\x00load\x00instrument\x00false\x00" + testAgent + "\x00"
		if len(requests) != 1 || requests[0] != want {
			t.Errorf("request = %q; want %q", requests, want)
		}
		if len(peers) != 1 || peers[0].Uid != uint32(os.Getuid()) || peers[0].Gid != uint32(os.Getgid()) || dumps != 0 {
			t.Errorf("peers = %+v, thread dumps = %d", peers, dumps)
		}
	})
}

// Between the check and the signal the file is where HotSpot looks, owned by the JVM's user.
func TestAttachFileExistsWhenTheSignalIsSent(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	var existed bool
	prev := pidfdSendSignal
	pidfdSendSignal = func(fd int, sig unix.Signal, info *unix.Siginfo, flags int) error {
		info2, err := os.Lstat(filepath.Join(e.tmp, ".attach_pid7"))
		existed = err == nil && info2.Mode().IsRegular() && info2.Size() == 0 && info2.Sys().(*syscall.Stat_t).Uid == uint32(os.Getuid())
		return prev(fd, sig, info, flags)
	}
	if _, err := e.attach(testAgent); err != nil {
		t.Fatal(err)
	}
	if !existed {
		t.Error("no attach file when the signal was sent")
	}
}

func TestAttachWithAnExistingSocketSendsNoSignalAndCreatesNoFile(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	e.listener.start()
	res, err := e.attach(testAgent)
	if err != nil {
		t.Fatal(err)
	}
	if res.Signal != "" || e.signalCount() != 0 || len(res.AttachFiles) != 0 || !res.Check.SocketExists {
		t.Errorf("result = %+v, %d signals", res, e.signalCount())
	}
	if requests, _, _ := e.listener.seen(); len(requests) != 1 {
		t.Errorf("requests = %q", requests)
	}
}

// -Xrs: the JVM does not catch SIGQUIT but its listener may exist already.
func TestAttachWithoutSigQuitHandler(t *testing.T) {
	e := newAttachEnv(t, attachOpts{sigCgt: 0x1cc8})
	_, err := e.attach(testAgent)
	if !errors.Is(err, ErrSigQuitNotCaught) {
		t.Fatalf("err = %v; want ErrSigQuitNotCaught", err)
	}
	if e.signalCount() != 0 || len(e.attachFiles()) != 0 {
		t.Errorf("%d signals, attach files %v", e.signalCount(), e.attachFiles())
	}
	e.listener.start()
	if res, err := e.attach(testAgent); err != nil || e.signalCount() != 0 || res.ReturnCode != 0 {
		t.Errorf("with a socket: %+v, %v, %d signals", res, err, e.signalCount())
	}
}

func TestAttachRefusesAJVMThatDisallowsAttach(t *testing.T) {
	caps := "1100000000000000000000000000000000000000000000000000000000000000"
	for name, value := range map[string]string{"disabled": "0" + caps[1:], "empty": "", "other": "x1"} {
		t.Run(name, func(t *testing.T) {
			e := newAttachEnv(t, attachOpts{perf: perfWith(t, "sun.rt.jvmCapabilities", value)})
			res, err := e.attach(testAgent)
			if !errors.Is(err, ErrAttachDisabled) {
				t.Fatalf("err = %v; want ErrAttachDisabled", err)
			}
			if e.signalCount() != 0 || len(e.attachFiles()) != 0 || e.listener.listening() || len(res.AttachFiles) != 0 {
				t.Errorf("signals %d, attach files %v", e.signalCount(), e.attachFiles())
			}
		})
	}
	// A control: the same sample with the capability string intact attaches.
	e := newAttachEnv(t, attachOpts{perf: perfWith(t, "sun.rt.jvmCapabilities", caps)})
	if _, err := e.attach(testAgent); err != nil {
		t.Errorf("control: %v", err)
	}
}

func TestAttachRefusesARuntimeWithoutInstrument(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		e := newAttachEnv(t, attachOpts{noInstrument: true})
		home := filepath.Join(e.root, "opt", "java", "openjdk")
		check := func(name string, want bool) {
			t.Helper()
			_, err := e.jvm.CheckAttach(context.Background())
			if want && err != nil {
				t.Errorf("%s: %v", name, err)
			}
			if !want && !errors.Is(err, ErrNoInstrument) {
				t.Errorf("%s: err = %v; want ErrNoInstrument", name, err)
			}
		}
		check("empty runtime", false)
		writeFile(t, filepath.Join(home, "release"), "JAVA_VERSION=\"17\"\nMODULES=\"java.base java.logging java.xml\"\n")
		check("release without the module", false)
		writeFile(t, filepath.Join(home, "release"), "MODULES=\"java.base java.instrument.extra\"\n")
		check("a module with a longer name", false)
		writeFile(t, filepath.Join(home, "release"), "JAVA_VERSION=\"17\"\nMODULES=\"java.base java.instrument java.xml\"\n")
		check("release with the module", true)
		os.Remove(filepath.Join(home, "release"))
		check("release removed", false)
		writeFile(t, filepath.Join(home, "lib", "amd64", "libinstrument.so"), "ELF")
		check("JDK 8 layout", true)
		os.RemoveAll(filepath.Join(home, "lib"))
		writeFile(t, filepath.Join(home, "lib", "libinstrument.so"), "ELF")
		check("JDK 9 layout", true)
		// The library as a directory, or as a link to a file of the host, is not the library.
		os.RemoveAll(filepath.Join(home, "lib"))
		if err := os.MkdirAll(filepath.Join(home, "lib", "libinstrument.so"), 0o755); err != nil {
			t.Fatal(err)
		}
		check("a directory", false)
		os.RemoveAll(filepath.Join(home, "lib"))
		hostLib := filepath.Join(e.h.base, "hostlib.so")
		writeFile(t, hostLib, "ELF")
		if err := os.MkdirAll(filepath.Join(home, "lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(hostLib, filepath.Join(home, "lib", "libinstrument.so")); err != nil {
			t.Fatal(err)
		}
		check("an absolute link to the host", false)
	})
}

// java.home may itself be a link, as /usr/lib/jvm/default-java is; it is resolved inside the root.
func TestAttachFindsInstrumentThroughLinks(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		e := newAttachEnv(t, attachOpts{noInstrument: true})
		writeFile(t, filepath.Join(e.root, "usr", "lib", "jvm", "real", "lib", "libinstrument.so"), "ELF")
		if err := os.MkdirAll(filepath.Join(e.root, "opt", "java"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/usr/lib/jvm/real", filepath.Join(e.root, "opt", "java", "openjdk")); err != nil {
			t.Fatal(err)
		}
		if _, err := e.jvm.CheckAttach(context.Background()); err != nil {
			t.Errorf("home through an absolute link: %v", err)
		}
	})
}

func TestAttachRefusesAJVMWithArthasThreads(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	fakeThreads(t, e.h.proc, testPID, "java", "arthas-NettyWeb", "arthas-timer")
	res, err := e.attach(testAgent)
	if !errors.Is(err, ErrArthasRunning) {
		t.Fatalf("err = %v; want ErrArthasRunning", err)
	}
	if e.signalCount() != 0 || len(e.attachFiles()) != 0 || len(res.AttachFiles) != 0 {
		t.Errorf("%d signals, attach files %v", e.signalCount(), e.attachFiles())
	}
	fakeThreads(t, e.h.proc, testPID, "java", "C1 CompilerThre")
	if _, err := e.attach(testAgent); err != nil {
		t.Errorf("after the threads are gone: %v", err)
	}
}

// Anything but a socket of the JVM's user at the name of the socket stops the attach.
func TestAttachRefusesAnUnusableSocket(t *testing.T) {
	outsideSock := func(e *attachEnv) (string, *int) {
		path := filepath.Join(e.h.base, "o.sock")
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		accepted := new(int)
		var mu sync.Mutex
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				*accepted++
				mu.Unlock()
				c.Close()
			}
		}()
		return path, accepted
	}
	cases := map[string]func(e *attachEnv, sock string){
		"regular file": func(e *attachEnv, sock string) { writeFile(t, sock, "x") },
		"directory":    func(e *attachEnv, sock string) { os.Mkdir(sock, 0o755) },
		"link to a socket of the host": func(e *attachEnv, sock string) {
			path, _ := outsideSock(e)
			os.Symlink(path, sock)
		},
		"link to a file inside the root": func(e *attachEnv, sock string) {
			writeFile(t, filepath.Join(e.root, "tmp", "other"), "x")
			os.Symlink("/tmp/other", sock)
		},
		"dangling link": func(e *attachEnv, sock string) { os.Symlink("/nowhere", sock) },
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			e := newAttachEnv(t, attachOpts{})
			plant(e, filepath.Join(e.root, "tmp", ".java_pid7"))
			res, err := e.attach(testAgent)
			if !errors.Is(err, ErrBadAttachSocket) {
				t.Fatalf("err = %v; want ErrBadAttachSocket", err)
			}
			if e.signalCount() != 0 || len(e.attachFiles()) != 0 || len(res.AttachFiles) != 0 {
				t.Errorf("%d signals, attach files %v", e.signalCount(), e.attachFiles())
			}
		})
	}
	t.Run("socket of another user", func(t *testing.T) {
		e := newAttachEnv(t, attachOpts{})
		e.listener.start()
		writeFile(t, filepath.Join(e.h.proc, "4242", "status"),
			fmt.Sprintf("NSpid:\t4242\t7\nUid:\t%[1]d\t%[1]d\t%[1]d\t%[1]d\nGid:\t%[2]d\t%[2]d\t%[2]d\t%[2]d\nSigCgt:\t0000000000005ccf\n", os.Getuid()+1, os.Getgid()))
		_, err := e.attach(testAgent)
		if !errors.Is(err, ErrBadAttachSocket) {
			t.Fatalf("err = %v; want ErrBadAttachSocket", err)
		}
		if requests, peers, _ := e.listener.seen(); len(requests)+len(peers) != 0 || e.signalCount() != 0 {
			t.Errorf("the socket was used: %q %v, %d signals", requests, peers, e.signalCount())
		}
	})
}

// The descriptor is opened and checked, then the name is swapped for a link to a socket that the
// container does not own: the connection still goes to the socket that was checked.
func TestAttachConnectsToTheSocketItChecked(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	e.listener.start()
	hostSock := filepath.Join(e.h.base, "host.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: hostSock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	hostConns := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
			hostConns <- struct{}{}
		}
	}()
	e.jvm.resolver.beforeConnect = func() {
		sock := filepath.Join(e.tmp, ".java_pid7")
		os.Remove(sock)
		if err := os.Symlink(hostSock, sock); err != nil {
			t.Error(err)
		}
		// Control: connecting by the name now reaches the other socket.
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Errorf("control: %v", err)
			return
		}
		c.Close()
		<-hostConns
	}
	res, err := e.attach(testAgent)
	if err != nil || res.ReturnCode != 0 {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if requests, _, _ := e.listener.seen(); len(requests) != 1 {
		t.Errorf("the checked socket got %d requests", len(requests))
	}
	select {
	case <-hostConns:
		t.Error("the other socket got a connection from Attach")
	case <-time.After(100 * time.Millisecond):
	}
}

// A /tmp that is an absolute link to a path of the host leads to the container's directory of
// that name, so the file is not made in the host's.
func TestAttachMakesTheFileInsideTheRootWhenTmpIsAnAbsoluteLink(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		e := newAttachEnv(t, attachOpts{tmpLinkToHost: true})
		// The control: following the link by the host's rules reaches the host directory.
		writeFile(t, filepath.Join(e.root, "tmp", "control"), "x")
		if _, err := os.Stat(filepath.Join(e.hostDir, "control")); err != nil {
			t.Fatalf("control: %v", err)
		}
		os.Remove(filepath.Join(e.hostDir, "control"))
		res, err := e.attach(testAgent)
		if err != nil {
			t.Fatal(err)
		}
		if res.Signal == "" || len(e.attachFiles()) != 0 {
			t.Errorf("signal %q, attach files left %v", res.Signal, e.attachFiles())
		}
		if entries, _ := os.ReadDir(e.hostDir); len(entries) != 0 {
			t.Errorf("the host directory has files: %v", entries)
		}
		if requests, _, _ := e.listener.seen(); len(requests) != 1 {
			t.Errorf("requests = %q", requests)
		}
	})
}
