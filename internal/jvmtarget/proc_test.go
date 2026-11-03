package jvmtarget

import (
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
