package jvmtarget

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// statLine builds a /proc/<pid>/stat line whose start time is field 22.
func statLine(pid int, comm string, start uint64) string {
	fields := []string{"S", "1", "1", "1", "0", "-1", "4194560", "10", "0", "0", "0", "1", "2", "0", "0", "20", "0", "5", "0"}
	line := strconv.Itoa(pid) + " (" + comm + ")"
	for _, f := range fields {
		line += " " + f
	}
	return line + " " + strconv.FormatUint(start, 10) + " 1000 2000 18446744073709551615 1 1 0 0 0\n"
}

func TestStartTime(t *testing.T) {
	root := t.TempDir()
	p := Proc{Root: root}
	// comm may contain spaces and parentheses; the last ')' ends it.
	for _, comm := range []string{"java", "my (weird) name", "a b)c (d"} {
		writeFile(t, filepath.Join(root, "42", "stat"), statLine(42, comm, 123456789))
		start, err := p.StartTime(42)
		if err != nil || start != 123456789 {
			t.Errorf("comm %q: start = %d, %v", comm, start, err)
		}
	}
	for name, content := range map[string]string{
		"empty":          "",
		"no parenthesis": "42 java S 1 1 1\n",
		"too few fields": "42 (java) S 1 1 1\n",
		"not a number":   "42 (java) S 1 1 1 0 -1 4194560 10 0 0 0 1 2 0 0 20 0 5 0 soon 1\n",
		"negative":       "42 (java) S 1 1 1 0 -1 4194560 10 0 0 0 1 2 0 0 20 0 5 0 -5 1\n",
	} {
		writeFile(t, filepath.Join(root, "42", "stat"), content)
		if start, err := p.StartTime(42); err == nil {
			t.Errorf("%s: parsed %d", name, start)
		}
	}
	if _, err := p.StartTime(43); err == nil {
		t.Error("a missing process has a start time")
	}
	if _, err := p.StartTime(0); err == nil {
		t.Error("pid 0 accepted")
	}
	if _, err := p.StartTime(-1); err == nil {
		t.Error("negative pid accepted")
	}
}

func TestStartTimeOfThisProcess(t *testing.T) {
	p := DefaultProc()
	first, err := p.StartTime(os.Getpid())
	if err != nil || first == 0 {
		t.Fatalf("start = %d, %v", first, err)
	}
	if second, _ := p.StartTime(os.Getpid()); second != first {
		t.Errorf("start time changed: %d then %d", first, second)
	}
}

func TestStatus(t *testing.T) {
	root := t.TempDir()
	p := Proc{Root: root}
	writeFile(t, filepath.Join(root, "42", "status"), "Name:\tjava\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t42\nNSpid:\t42\t17\t1\nUid:\t1000\t1001\t1002\t1003\nGid:\t1\t1\t1\t1\n")
	st, err := p.Status(42)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.NSPid) != 3 || st.NSPid[0] != 42 || st.NSPid[2] != 1 || st.UID != 1000 || st.EUID != 1001 {
		t.Errorf("status = %+v", st)
	}
	for name, content := range map[string]string{
		"no uid":         "NSpid:\t42\n",
		"bad uid":        "NSpid:\t42\nUid:\tx\ty\n",
		"short uid":      "NSpid:\t42\nUid:\t5\n",
		"bad nspid":      "NSpid:\t42\tx\nUid:\t1\t1\t1\t1\n",
		"zero nspid":     "NSpid:\t42\t0\nUid:\t1\t1\t1\t1\n",
		"negative uid":   "NSpid:\t42\nUid:\t-1\t-1\t-1\t-1\n",
		"empty nspid":    "NSpid:\nUid:\t1\t1\t1\t1\n",
		"huge nspid":     "NSpid:\t99999999999999999999\nUid:\t1\t1\t1\t1\n",
		"nspid mismatch": "NSpid:\t41\t1\nUid:\t1\t1\t1\t1\n",
	} {
		writeFile(t, filepath.Join(root, "42", "status"), content)
		if st, err := p.Status(42); err == nil {
			t.Errorf("%s: parsed %+v", name, st)
		}
	}
}

// Kernels before 4.1 (CentOS 7 has 3.10) print no NSpid line. A process in our own PID namespace
// then has the pid we see; a process in another namespace has no pid we can derive.
func TestStatusWithoutNSpid(t *testing.T) {
	root := t.TempDir()
	p := Proc{Root: root}
	writeFile(t, filepath.Join(root, "42", "status"), "Name:\tjava\nUid:\t7\t8\t9\t10\n")
	if err := os.MkdirAll(filepath.Join(root, "self", "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "42", "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := func(pid, target string) {
		path := filepath.Join(root, pid, "ns", "pid")
		_ = os.Remove(path)
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	link("self", "pid:[4026531836]")
	link("42", "pid:[4026531836]")
	st, err := p.Status(42)
	if err != nil || len(st.NSPid) != 1 || st.NSPid[0] != 42 || st.EUID != 8 {
		t.Fatalf("same namespace: %+v, %v", st, err)
	}
	link("42", "pid:[4026532555]")
	if st, err := p.Status(42); err == nil {
		t.Fatalf("another namespace without NSpid resolved to %+v", st)
	}
}

func TestPIDNamespaceAndPIDs(t *testing.T) {
	root := t.TempDir()
	p := Proc{Root: root}
	for _, pid := range []string{"1", "42", "1000"} {
		if err := os.MkdirAll(filepath.Join(root, pid, "ns"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"self", "sys", "007", "1x", "-5"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "uptime"), "1 1\n")
	if err := os.Symlink("pid:[4026531836]", filepath.Join(root, "42", "ns", "pid")); err != nil {
		t.Fatal(err)
	}
	ns, err := p.PIDNamespace(42)
	if err != nil || ns != "pid:[4026531836]" {
		t.Errorf("namespace = %q, %v", ns, err)
	}
	if _, err := p.PIDNamespace(1000); err == nil {
		t.Error("a process without ns/pid has a namespace")
	}
	pids, err := p.PIDs()
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]bool{1: true, 42: true, 1000: true}
	if len(pids) != len(want) {
		t.Fatalf("pids = %v", pids)
	}
	for _, pid := range pids {
		if !want[pid] {
			t.Errorf("unexpected pid %d in %v", pid, pids)
		}
	}
}

func TestStatusGroupsAndSignals(t *testing.T) {
	root := t.TempDir()
	p := Proc{Root: root}
	status := func(sigCgt string) string {
		return "Name:\tjava\nNSpid:\t42\t7\nUid:\t10001\t10001\t10001\t10001\nGid:\t10002\t10003\t10002\t10002\nSigIgn:\t0000000000000000\nSigCgt:\t" + sigCgt + "\n"
	}
	for sigCgt, wantQuit := range map[string]bool{
		"0000000000005ccf": true,  // a JVM: SIGQUIT (bit 2) is caught
		"0000000000001cc8": false, // -Xrs: the JVM leaves SIGQUIT alone
		"0000000000000004": true,
		"0000000000000000": false,
		"fffffffffffffffb": false,
		"ffffffffffffffff": true,
	} {
		writeFile(t, filepath.Join(root, "42", "status"), status(sigCgt))
		st, err := p.Status(42)
		if err != nil {
			t.Fatal(err)
		}
		if st.GID != 10002 || st.EGID != 10003 || st.UID != 10001 || st.EUID != 10001 {
			t.Errorf("ids = %d/%d %d/%d", st.UID, st.EUID, st.GID, st.EGID)
		}
		if st.CatchesSIGQUIT() != wantQuit {
			t.Errorf("SigCgt %s: CatchesSIGQUIT = %v", sigCgt, st.CatchesSIGQUIT())
		}
	}
	for name, content := range map[string]string{
		"short gid":  "NSpid:\t42\nUid:\t1\t1\t1\t1\nGid:\t5\n",
		"bad gid":    "NSpid:\t42\nUid:\t1\t1\t1\t1\nGid:\ta\tb\tc\td\n",
		"bad sigcgt": "NSpid:\t42\nUid:\t1\t1\t1\t1\nSigCgt:\tzz\n",
		"neg sigcgt": "NSpid:\t42\nUid:\t1\t1\t1\t1\nSigCgt:\t-4\n",
	} {
		writeFile(t, filepath.Join(root, "42", "status"), content)
		if st, err := p.Status(42); err == nil {
			t.Errorf("%s: parsed %+v", name, st)
		}
	}
	// The ids and the signal mask are optional: older tests and kernels print what they know.
	writeFile(t, filepath.Join(root, "42", "status"), "NSpid:\t42\nUid:\t1\t1\t1\t1\n")
	if st, err := p.Status(42); err != nil || st.SigCgt != 0 || st.CatchesSIGQUIT() {
		t.Errorf("status without Gid and SigCgt: %+v, %v", st, err)
	}
}

func TestNetNamespace(t *testing.T) {
	root := t.TempDir()
	p := Proc{Root: root}
	if err := os.MkdirAll(filepath.Join(root, "42", "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[4026532700]", filepath.Join(root, "42", "ns", "net")); err != nil {
		t.Fatal(err)
	}
	if ns, err := p.NetNamespace(42); err != nil || ns != "net:[4026532700]" {
		t.Errorf("namespace = %q, %v", ns, err)
	}
	if _, err := p.NetNamespace(43); err == nil {
		t.Error("a missing process has a network namespace")
	}
}

// fakeThreads gives the process one task directory per thread name.
func fakeThreads(t *testing.T, root string, pid int, names ...string) {
	t.Helper()
	if err := os.RemoveAll(filepath.Join(root, strconv.Itoa(pid), "task")); err != nil {
		t.Fatal(err)
	}
	for i, name := range names {
		writeFile(t, filepath.Join(root, strconv.Itoa(pid), "task", strconv.Itoa(pid+i), "comm"), name+"\n")
	}
	if len(names) == 0 {
		if err := os.MkdirAll(filepath.Join(root, strconv.Itoa(pid), "task"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestArthasThreads(t *testing.T) {
	root := t.TempDir()
	p := Proc{Root: root}
	fakeThreads(t, root, 42, "java", "GC Thread#0", "arthas-NettyWeb", "arthas-timer", "my-arthas-worker", "Arthas-x", "arthas", "arthas-")
	// "arthas-" followed by nothing is a prefix match too: only the exact prefix counts, case sensitive.
	if n, err := p.ArthasThreads(42); err != nil || n != 3 {
		t.Errorf("count = %d, %v; want 3 (arthas-NettyWeb, arthas-timer, arthas-)", n, err)
	}
	fakeThreads(t, root, 42, "java", "C2 CompilerThre")
	if n, err := p.ArthasThreads(42); err != nil || n != 0 {
		t.Errorf("count = %d, %v; want 0", n, err)
	}
	fakeThreads(t, root, 42)
	if n, err := p.ArthasThreads(42); err != nil || n != 0 {
		t.Errorf("no threads: count = %d, %v", n, err)
	}
	// A thread that ended while the directory was listed has no comm file.
	fakeThreads(t, root, 42, "arthas-a", "arthas-b")
	if err := os.Remove(filepath.Join(root, "42", "task", "43", "comm")); err != nil {
		t.Fatal(err)
	}
	if n, err := p.ArthasThreads(42); err != nil || n != 1 {
		t.Errorf("count = %d, %v; want 1", n, err)
	}
	if _, err := p.ArthasThreads(43); !errors.Is(err, ErrProcessChanged) {
		t.Errorf("missing process: %v; want ErrProcessChanged", err)
	}
	if _, err := p.ArthasThreads(0); err == nil {
		t.Error("pid 0 accepted")
	}
}

func TestArthasThreadsOfThisProcess(t *testing.T) {
	n, err := DefaultProc().ArthasThreads(os.Getpid())
	if err != nil || n != 0 {
		t.Errorf("count = %d, %v; the test process has no Arthas threads", n, err)
	}
}
