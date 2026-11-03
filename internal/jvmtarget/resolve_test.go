package jvmtarget

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/jvmtarget/perfdata"
)

const (
	sampleCommand = "com.example.sample.Sample --note=hello"
	sampleClass   = "com.example.sample.Sample"
)

// jvmFile returns a real JDK 17 hsperfdata sample whose sun.rt.javaCommand is
// replaced by command (at most as long as the original).
func jvmFile(t *testing.T, command string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("perfdata", "testdata", "jdk17-g1.hsperf"))
	if err != nil {
		t.Fatal(err)
	}
	if len(command) > len(sampleCommand) {
		t.Fatalf("command %q is longer than the sample's", command)
	}
	padded := append([]byte(command), make([]byte, len(sampleCommand)-len(command))...)
	if !bytes.Contains(data, []byte(sampleCommand)) {
		t.Fatal("sample lacks the original command")
	}
	return bytes.Replace(data, []byte(sampleCommand), padded, 1)
}

// host is a fake procfs plus the container root directories it points to.
type host struct {
	t    *testing.T
	base string
	proc string
}

func newHost(t *testing.T) *host {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
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

type process struct {
	pid   int
	start uint64
	nspid []int // as in /proc/<pid>/status; first element is pid
	euid  uint32
	ns    string
	root  string
	// egid defaults to the test's group, sigCgt to the mask of a JVM that handles SIGQUIT.
	egid   uint32
	sigCgt uint64
	// cwd is the target of the cwd link: a path inside the process's root.
	cwd string
}

func (h *host) addProcess(p process) {
	h.t.Helper()
	if p.nspid == nil {
		p.nspid = []int{p.pid}
	}
	if p.start == 0 {
		p.start = 1000 + uint64(p.pid)
	}
	if p.ns == "" {
		p.ns = "pid:[1]"
	}
	if p.euid == 0 {
		p.euid = uint32(os.Getuid())
	}
	dir := filepath.Join(h.proc, fmt.Sprint(p.pid))
	if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
		h.t.Fatal(err)
	}
	writeFile(h.t, filepath.Join(dir, "stat"), statLine(p.pid, "java", p.start))
	ids := make([]string, len(p.nspid))
	for i, id := range p.nspid {
		ids[i] = fmt.Sprint(id)
	}
	if p.egid == 0 {
		p.egid = uint32(os.Getgid())
	}
	if p.sigCgt == 0 {
		p.sigCgt = 0x5ccf
	}
	writeFile(h.t, filepath.Join(dir, "status"), fmt.Sprintf("Name:\tjava\nNSpid:\t%s\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\nSigCgt:\t%016x\n",
		strings.Join(ids, "\t"), p.euid, p.euid, p.euid, p.euid, p.egid, p.egid, p.egid, p.egid, p.sigCgt))
	if err := os.Symlink(p.ns, filepath.Join(dir, "ns", "pid")); err != nil {
		h.t.Fatal(err)
	}
	if p.root == "" {
		p.root = h.newRoot("root" + fmt.Sprint(p.pid))
	}
	if err := os.Symlink(p.root, filepath.Join(dir, "root")); err != nil {
		h.t.Fatal(err)
	}
	if p.cwd != "" {
		if err := os.Symlink(p.cwd, filepath.Join(dir, "cwd")); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *host) newRoot(name string) string {
	dir := filepath.Join(h.base, name)
	if err := os.MkdirAll(filepath.Join(dir, "tmp"), 0o755); err != nil {
		h.t.Fatal(err)
	}
	return dir
}

// jvm gives the process the perfdata file HotSpot would create for it.
func (h *host) jvm(pid int, data []byte) {
	h.t.Helper()
	dir := h.rootOf(pid)
	st, err := Proc{Root: h.proc}.Status(pid)
	if err != nil {
		h.t.Fatal(err)
	}
	writeFile(h.t, filepath.Join(dir, "tmp", "hsperfdata_app", fmt.Sprint(st.NSPid[len(st.NSPid)-1])), string(data))
}

func (h *host) rootOf(pid int) string {
	dir, err := os.Readlink(filepath.Join(h.proc, fmt.Sprint(pid), "root"))
	if err != nil {
		h.t.Fatal(err)
	}
	return dir
}

func (h *host) setStart(pid int, start uint64) {
	h.t.Helper()
	writeFile(h.t, filepath.Join(h.proc, fmt.Sprint(pid), "stat"), statLine(pid, "java", start))
}

func (h *host) resolver() *Resolver {
	return &Resolver{Proc: Proc{Root: h.proc}}
}

func systemd(r *Resolver, pid int) *Resolver {
	r.MainPID = func(context.Context, string) (int, error) { return pid, nil }
	return r
}

func containerInit(r *Resolver, pid int) *Resolver {
	r.ContainerPID = func(context.Context, string) (int, error) { return pid, nil }
	return r
}

func commandOf(t *testing.T, p *perfdata.PerfData) string {
	t.Helper()
	command, ok := p.Text("sun.rt.javaCommand")
	if !ok {
		t.Fatal("no sun.rt.javaCommand")
	}
	return command
}

func TestResolveSystemdUnit(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		h := newHost(t)
		h.addProcess(process{pid: 4242, start: 777})
		h.jvm(4242, jvmFile(t, sampleCommand))
		r := systemd(h.resolver(), 4242)
		j, err := r.Resolve(context.Background(), Target{Name: "api", SystemdUnit: "api.service"})
		if err != nil {
			t.Fatal(err)
		}
		if j.PID != 4242 || j.NSPid != 4242 || j.StartTime != 777 || j.EUID != uint32(os.Getuid()) {
			t.Errorf("jvm = %+v", j)
		}
		p, err := j.ReadPerfData(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got := perfdata.FirstWord(commandOf(t, p)); got != sampleClass {
			t.Errorf("main class = %q", got)
		}
	})
}

func TestResolveSystemdUnitReportsStoppedUnit(t *testing.T) {
	h := newHost(t)
	r := h.resolver()
	r.MainPID = func(context.Context, string) (int, error) { return 0, ErrNotRunning }
	if _, err := r.Resolve(context.Background(), Target{Name: "api", SystemdUnit: "api.service"}); !errors.Is(err, ErrNotRunning) {
		t.Errorf("err = %v; want ErrNotRunning", err)
	}
	// A pid that has no process by the time we look.
	if _, err := systemd(h.resolver(), 31337).Resolve(context.Background(), Target{Name: "api", SystemdUnit: "api.service"}); !errors.Is(err, ErrProcessChanged) {
		t.Errorf("err = %v; want ErrProcessChanged", err)
	}
}

func TestResolveRejectsInvalidTargetBeforeLookup(t *testing.T) {
	r := &Resolver{Proc: Proc{Root: t.TempDir()}}
	r.MainPID = func(context.Context, string) (int, error) { t.Fatal("lookup for an invalid target"); return 0, nil }
	r.ContainerPID = func(context.Context, string) (int, error) { t.Fatal("lookup for an invalid target"); return 0, nil }
	for _, target := range []Target{{Name: "x"}, {Name: "x", SystemdUnit: "--user.service"}, {Name: "x", Container: "a/b", MainClass: "M"}} {
		if _, err := r.Resolve(context.Background(), target); err == nil {
			t.Errorf("%+v accepted", target)
		}
	}
}

func TestResolveContainerPicksTheJVMWithTheMainClass(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		h := newHost(t)
		const ns = "pid:[4026532001]"
		// pid 100 is the container's init (pid 1 inside) and runs another JVM; 101 is the wanted one.
		h.addProcess(process{pid: 100, nspid: []int{100, 1}, ns: ns})
		h.jvm(100, jvmFile(t, "org.other.Main --x"))
		h.addProcess(process{pid: 101, nspid: []int{101, 7}, ns: ns})
		h.jvm(101, jvmFile(t, sampleCommand))
		// A shell in the container has no hsperfdata.
		h.addProcess(process{pid: 102, nspid: []int{102, 8}, ns: ns})
		// A JVM of the same class in another PID namespace must not be considered.
		h.addProcess(process{pid: 200, nspid: []int{200, 1}, ns: "pid:[4026532999]"})
		h.jvm(200, jvmFile(t, sampleCommand))
		// A JVM in a PID namespace nested below the container's has a different namespace too.
		h.addProcess(process{pid: 300, nspid: []int{300, 5, 1}, ns: "pid:[4026533111]"})
		h.jvm(300, jvmFile(t, sampleCommand))

		r := containerInit(h.resolver(), 100)
		j, err := r.Resolve(context.Background(), Target{Name: "web", Container: "web", MainClass: sampleClass})
		if err != nil {
			t.Fatal(err)
		}
		if j.PID != 101 || j.NSPid != 7 {
			t.Errorf("jvm = %+v; want pid 101, nspid 7", j)
		}
		if _, err := j.ReadPerfData(context.Background()); err != nil {
			t.Error(err)
		}
		j, err = r.Resolve(context.Background(), Target{Name: "web", Container: "web", MainClass: "org.other.Main"})
		if err != nil || j.PID != 100 || j.NSPid != 1 {
			t.Errorf("jvm = %+v, %v; want pid 100", j, err)
		}
	})
}

func TestResolveContainerErrors(t *testing.T) {
	h := newHost(t)
	const ns = "pid:[4026532001]"
	h.addProcess(process{pid: 100, nspid: []int{100, 1}, ns: ns})
	h.jvm(100, jvmFile(t, "org.a.Main --token=CANARY-one"))
	h.addProcess(process{pid: 101, nspid: []int{101, 7}, ns: ns})
	h.jvm(101, jvmFile(t, "org.a.Main --token=CANARY-two"))
	h.addProcess(process{pid: 102, nspid: []int{102, 8}, ns: ns})
	h.jvm(102, jvmFile(t, "org.b.Main --password=CANARY-three"))
	r := containerInit(h.resolver(), 100)
	_, err := r.Resolve(context.Background(), Target{Name: "web", Container: "web", MainClass: "org.a.Main"})
	if !errors.Is(err, ErrAmbiguous) {
		t.Errorf("two matches: err = %v; want ErrAmbiguous", err)
	}
	_, err = r.Resolve(context.Background(), Target{Name: "web", Container: "web", MainClass: "org.missing.Main"})
	if !errors.Is(err, ErrNoMatch) {
		t.Errorf("no match: err = %v; want ErrNoMatch", err)
	}
	for _, e := range []error{err} {
		if strings.Contains(e.Error(), "CANARY") || strings.Contains(e.Error(), "org.a.Main") {
			t.Errorf("error discloses other JVMs: %v", e)
		}
	}
	// A prefix of the main class is not the main class.
	if _, err := r.Resolve(context.Background(), Target{Name: "web", Container: "web", MainClass: "org.b"}); !errors.Is(err, ErrNoMatch) {
		t.Errorf("prefix: err = %v; want ErrNoMatch", err)
	}
	// A container whose processes publish no hsperfdata.
	empty := newHost(t)
	empty.addProcess(process{pid: 100, nspid: []int{100, 1}, ns: ns})
	_, err = containerInit(empty.resolver(), 100).Resolve(context.Background(), Target{Name: "web", Container: "web", MainClass: "org.a.Main"})
	if !errors.Is(err, ErrNoPerfData) || !strings.Contains(err.Error(), "UsePerfData") {
		t.Errorf("no hsperfdata: err = %v; want ErrNoPerfData naming the JVM options", err)
	}
	// The container's init process itself is gone.
	if _, err := containerInit(h.resolver(), 31337).Resolve(context.Background(), Target{Name: "web", Container: "web", MainClass: "org.a.Main"}); !errors.Is(err, ErrProcessChanged) {
		t.Errorf("missing init: err = %v; want ErrProcessChanged", err)
	}
}

func TestReadPerfDataWithoutHsperfdata(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		for name, prepare := range map[string]func(h *host, root string){
			"no tmp directory":  func(h *host, root string) { os.RemoveAll(filepath.Join(root, "tmp")) },
			"no hsperfdata dir": func(h *host, root string) {},
			// -XX:-UsePerfData and -XX:+PerfDisableSharedMem leave the directory without a file.
			"empty hsperfdata dir": func(h *host, root string) { os.MkdirAll(filepath.Join(root, "tmp", "hsperfdata_app"), 0o755) },
			"file of another pid": func(h *host, root string) {
				writeFile(h.t, filepath.Join(root, "tmp", "hsperfdata_app", "99"), string(jvmFile(h.t, sampleCommand)))
			},
			"file owned by another user": func(h *host, root string) {
				writeFile(h.t, filepath.Join(root, "tmp", "hsperfdata_app", "4242"), string(jvmFile(h.t, sampleCommand)))
			},
		} {
			t.Run(name, func(t *testing.T) {
				h := newHost(t)
				h.addProcess(process{pid: 4242})
				prepare(h, h.rootOf(4242))
				// Resolving a unit needs the process only; the file is needed when it is read.
				j := &JVM{PID: 4242, NSPid: 4242, StartTime: 1000 + 4242, EUID: uint32(os.Getuid()), resolver: h.resolver()}
				if name == "file owned by another user" {
					j.EUID++ // the file belongs to the test user, not to the JVM's effective user
				}
				_, err := j.ReadPerfData(context.Background())
				if !errors.Is(err, ErrNoPerfData) {
					t.Fatalf("err = %v; want ErrNoPerfData", err)
				}
				if !strings.Contains(err.Error(), "UsePerfData") {
					t.Errorf("err = %v; want it to name the JVM options", err)
				}
			})
		}
	})
}

// A container that makes /tmp a link to a host directory holding a forged hsperfdata file.
func TestReadPerfDataIgnoresSymlinkedTmp(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		h := newHost(t)
		h.addProcess(process{pid: 4242})
		root := h.rootOf(4242)
		forged := filepath.Join(h.base, "host-dir")
		writeFile(t, filepath.Join(forged, "hsperfdata_app", "4242"), string(jvmFile(t, "forged.Main")))
		if err := os.RemoveAll(filepath.Join(root, "tmp")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(forged, filepath.Join(root, "tmp")); err != nil {
			t.Fatal(err)
		}
		j := &JVM{PID: 4242, NSPid: 4242, StartTime: 1000 + 4242, EUID: uint32(os.Getuid()), resolver: h.resolver()}
		p, err := j.ReadPerfData(context.Background())
		if !errors.Is(err, ErrNoPerfData) {
			t.Fatalf("err = %v, parsed = %v; want ErrNoPerfData", err, p)
		}
	})
}

func TestReadPerfDataRejectsUnsafeFiles(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		for name, prepare := range map[string]func(t *testing.T, file, outside string){
			"symlink to a host file": func(t *testing.T, file, outside string) {
				writeFile(t, outside, string(jvmFile(t, "forged.Main")))
				if err := os.Symlink(outside, file); err != nil {
					t.Fatal(err)
				}
			},
			"symlink inside the container": func(t *testing.T, file, outside string) {
				writeFile(t, file+".real", string(jvmFile(t, sampleCommand)))
				if err := os.Symlink(filepath.Base(file)+".real", file); err != nil {
					t.Fatal(err)
				}
			},
			"fifo": func(t *testing.T, file, outside string) {
				if err := syscall.Mkfifo(file, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			"directory": func(t *testing.T, file, outside string) {
				if err := os.Mkdir(file, 0o755); err != nil {
					t.Fatal(err)
				}
			},
		} {
			t.Run(name, func(t *testing.T) {
				h := newHost(t)
				h.addProcess(process{pid: 4242})
				dir := filepath.Join(h.rootOf(4242), "tmp", "hsperfdata_app")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				prepare(t, filepath.Join(dir, "4242"), filepath.Join(h.base, "host-file"))
				j := &JVM{PID: 4242, NSPid: 4242, StartTime: 1000 + 4242, EUID: uint32(os.Getuid()), resolver: h.resolver()}
				done := make(chan error, 1)
				go func() {
					_, err := j.ReadPerfData(context.Background())
					done <- err
				}()
				select {
				case err := <-done:
					if !errors.Is(err, ErrNoPerfData) {
						t.Fatalf("err = %v; want ErrNoPerfData", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("reading blocked")
				}
			})
		}
	})
}

func TestReadPerfDataRejectsForgedContent(t *testing.T) {
	good := jvmFile(t, sampleCommand)
	for name, content := range map[string][]byte{
		"truncated":       good[:len(good)/4],
		"not perfdata":    []byte(strings.Repeat("root:x:0:0:root:/root:/bin/sh\n", 100)),
		"empty":           {},
		"bad length":      append(append([]byte(nil), good[:32]...), bytes.Repeat([]byte{0xff}, 4096)...),
		"oversized":       nil, // replaced below
		"zero filled big": make([]byte, 1<<20),
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t)
			h.addProcess(process{pid: 4242})
			file := filepath.Join(h.rootOf(4242), "tmp", "hsperfdata_app", "4242")
			if name == "oversized" {
				if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
					t.Fatal(err)
				}
				f, err := os.Create(file) // sparse: one byte over the limit
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate(perfdata.MaxFileSize + 1); err != nil {
					t.Fatal(err)
				}
				f.Close()
			} else {
				writeFile(t, file, string(content))
			}
			j := &JVM{PID: 4242, NSPid: 4242, StartTime: 1000 + 4242, EUID: uint32(os.Getuid()), resolver: h.resolver()}
			p, err := j.ReadPerfData(context.Background())
			if err == nil {
				t.Fatalf("parsed %v", p)
			}
			if errors.Is(err, ErrNoPerfData) || !(errors.Is(err, perfdata.ErrCorrupt) || errors.Is(err, perfdata.ErrNotPerfData)) {
				t.Errorf("err = %v; want a perfdata parse error", err)
			}
		})
	}
}

// The pid of a JVM that exited is reused for another process before or while we read.
func TestReadPerfDataDetectsPidReuse(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		newJVM := func() (*host, *JVM) {
			h := newHost(t)
			h.addProcess(process{pid: 4242, start: 500})
			h.jvm(4242, jvmFile(t, sampleCommand))
			j, err := systemd(h.resolver(), 4242).Resolve(context.Background(), Target{Name: "api", SystemdUnit: "api.service"})
			if err != nil {
				t.Fatal(err)
			}
			return h, j
		}
		// Before the read.
		h, j := newJVM()
		h.setStart(4242, 501)
		if _, err := j.ReadPerfData(context.Background()); !errors.Is(err, ErrProcessChanged) {
			t.Errorf("replaced before the read: err = %v; want ErrProcessChanged", err)
		}
		// While reading: the data was read, then the process was replaced.
		h, j = newJVM()
		j.resolver.afterRead = func() { h.setStart(4242, 502) }
		p, err := j.ReadPerfData(context.Background())
		if !errors.Is(err, ErrProcessChanged) || p != nil {
			t.Errorf("replaced during the read: err = %v, data = %v; want ErrProcessChanged and no data", err, p)
		}
		// The process exits.
		h, j = newJVM()
		if err := os.RemoveAll(filepath.Join(h.proc, "4242")); err != nil {
			t.Fatal(err)
		}
		if _, err := j.ReadPerfData(context.Background()); !errors.Is(err, ErrProcessChanged) {
			t.Errorf("exited: err = %v; want ErrProcessChanged", err)
		}
		// Unchanged processes read repeatedly.
		_, j = newJVM()
		for i := 0; i < 3; i++ {
			if _, err := j.ReadPerfData(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// Candidates of a container scan are checked for pid reuse too: a process that changes during the scan is not returned.
func TestResolveContainerDetectsPidReuseDuringScan(t *testing.T) {
	h := newHost(t)
	const ns = "pid:[4026532001]"
	h.addProcess(process{pid: 100, nspid: []int{100, 1}, ns: ns, start: 10})
	h.jvm(100, jvmFile(t, sampleCommand))
	r := containerInit(h.resolver(), 100)
	r.afterRead = func() { h.setStart(100, 11) }
	if j, err := r.Resolve(context.Background(), Target{Name: "web", Container: "web", MainClass: sampleClass}); err == nil {
		t.Errorf("resolved %+v although the process changed", j)
	}
}

func TestResolveHonoursContext(t *testing.T) {
	h := newHost(t)
	h.addProcess(process{pid: 4242})
	h.jvm(4242, jvmFile(t, sampleCommand))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := systemd(h.resolver(), 4242).Resolve(ctx, Target{Name: "api", SystemdUnit: "api.service"}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled", err)
	}
	j := &JVM{PID: 4242, NSPid: 4242, StartTime: 1000 + 4242, EUID: uint32(os.Getuid()), resolver: h.resolver()}
	if _, err := j.ReadPerfData(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("read: err = %v; want context.Canceled", err)
	}
}

// A busy /tmp with several hsperfdata_* directories: the file is found, and the directories are tried in name order.
func TestReadPerfDataInBusyTmp(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		h := newHost(t)
		h.addProcess(process{pid: 4242})
		tmp := filepath.Join(h.rootOf(4242), "tmp")
		for i := 0; i < 3000; i++ {
			writeFile(t, filepath.Join(tmp, fmt.Sprintf("noise-%d", i)), "x")
		}
		writeFile(t, filepath.Join(tmp, "hsperfdata_zz", "4242"), string(jvmFile(t, "last.Main")))
		writeFile(t, filepath.Join(tmp, "hsperfdata_aa", "4242"), string(jvmFile(t, sampleCommand)))
		writeFile(t, filepath.Join(tmp, "hsperfdata_mm", "1"), string(jvmFile(t, "other.Main")))
		j := &JVM{PID: 4242, NSPid: 4242, StartTime: 1000 + 4242, EUID: uint32(os.Getuid()), resolver: h.resolver()}
		p, err := j.ReadPerfData(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got := perfdata.FirstWord(commandOf(t, p)); got != sampleClass {
			t.Errorf("main class = %q; want the file of the first directory", got)
		}
	})
}

// A container started with --pid=host shares the host's PID namespace: scanning it would
// look at every host process, so the target is refused.
func TestResolveContainerRefusesHostPIDNamespace(t *testing.T) {
	h := newHost(t)
	h.addProcess(process{pid: 100, ns: "pid:[1]"}) // the same namespace as self
	h.jvm(100, jvmFile(t, sampleCommand))
	_, err := containerInit(h.resolver(), 100).Resolve(context.Background(), Target{Name: "web", Container: "web", MainClass: sampleClass})
	if err == nil || !strings.Contains(err.Error(), "host's PID namespace") {
		t.Fatalf("err = %v; want a refusal naming the host PID namespace", err)
	}
}

// On Linux before 4.1 (CentOS 7 has 3.10) /proc/<pid>/status has no NSpid line, so the
// name of the hsperfdata file of a process in a container is unknown. The error must say so
// instead of claiming that the JVM publishes no hsperfdata.
func TestResolveContainerOnKernelWithoutNSpid(t *testing.T) {
	h := newHost(t)
	h.addProcess(process{pid: 100, nspid: []int{100, 1}, ns: "pid:[4026532001]"})
	h.jvm(100, jvmFile(t, sampleCommand))
	writeFile(t, filepath.Join(h.proc, "100", "status"), fmt.Sprintf("Name:\tjava\nUid:\t%d\t%d\t%d\t%d\n", os.Getuid(), os.Getuid(), os.Getuid(), os.Getuid()))
	_, err := containerInit(h.resolver(), 100).Resolve(context.Background(), Target{Name: "web", Container: "web", MainClass: sampleClass})
	if err == nil || !strings.Contains(err.Error(), "NSpid") || errors.Is(err, ErrNoPerfData) {
		t.Fatalf("err = %v; want an error about NSpid that is not ErrNoPerfData", err)
	}
}

// A container whose /tmp is a link to a directory of its own: HotSpot creates the
// hsperfdata directory behind the link, and the reader finds it there.
func TestReadPerfDataThroughTmpSymlinkInsideRoot(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		h := newHost(t)
		h.addProcess(process{pid: 4242})
		h.jvm(4242, jvmFile(t, sampleCommand))
		root := h.rootOf(4242)
		moved := filepath.Join(root, "var", "tmp", "x")
		if err := os.MkdirAll(filepath.Dir(moved), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(root, "tmp"), moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/var/tmp/x", filepath.Join(root, "tmp")); err != nil {
			t.Fatal(err)
		}
		j := &JVM{PID: 4242, NSPid: 4242, StartTime: 1000 + 4242, EUID: uint32(os.Getuid()), resolver: h.resolver()}
		p, err := j.ReadPerfData(context.Background())
		if err != nil {
			t.Fatalf("ReadPerfData: %v", err)
		}
		if got := commandOf(t, p); got != sampleCommand {
			t.Errorf("command = %q", got)
		}
	})
}
