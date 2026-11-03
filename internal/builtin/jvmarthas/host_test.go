package jvmarthas

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/liubing0806/allowops/internal/jvmtarget"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// hostTree is a fake procfs and cgroup mount.
type hostTree struct {
	t    *testing.T
	base string
}

func newHostTree(t *testing.T) (*hostTree, *procHost) {
	t.Helper()
	base := t.TempDir()
	h := &procHost{
		proc:       jvmtarget.Proc{Root: filepath.Join(base, "proc")},
		cgroupRoot: filepath.Join(base, "cgroup"),
		meminfo:    filepath.Join(base, "proc", "meminfo"),
		bootIDPath: filepath.Join(base, "proc", "boot_id"),
	}
	write(t, h.meminfo, "MemTotal:       16384000 kB\nMemFree:         1000000 kB\nMemAvailable:    8000000 kB\n")
	return &hostTree{t: t, base: base}, h
}

func (ht *hostTree) cgroupOf(pid int, content string) {
	write(ht.t, filepath.Join(ht.base, "proc", fmt.Sprint(pid), "cgroup"), content)
}

func (ht *hostTree) file(rel, content string) {
	write(ht.t, filepath.Join(ht.base, "cgroup", rel), content+"\n")
}

func TestMemoryHeadroomCgroupV2(t *testing.T) {
	ht, h := newHostTree(t)
	ht.file("cgroup.controllers", "cpuset cpu io memory pids")
	ht.cgroupOf(10, "0::/system.slice/docker-abc.scope\n")
	ht.file("system.slice/docker-abc.scope/memory.max", "1073741824")
	ht.file("system.slice/docker-abc.scope/memory.current", "300000000")
	ht.file("system.slice/memory.max", "max")
	ht.file("system.slice/memory.current", "5000000000")
	ht.file("memory.current", "9000000000")
	got, err := h.MemoryHeadroom(10)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(1073741824 - 300000000); got != want {
		t.Errorf("headroom = %d, want %d", got, want)
	}
}

func TestMemoryHeadroomUsesTheTightestAncestor(t *testing.T) {
	ht, h := newHostTree(t)
	ht.file("cgroup.controllers", "memory")
	ht.cgroupOf(10, "0::/a/b\n")
	ht.file("a/b/memory.max", "1000000000")
	ht.file("a/b/memory.current", "100000000")
	ht.file("a/memory.max", "500000000")
	ht.file("a/memory.current", "450000000")
	got, err := h.MemoryHeadroom(10)
	if err != nil {
		t.Fatal(err)
	}
	if got != 50000000 {
		t.Errorf("headroom = %d, want 50000000 (the parent is nearly full)", got)
	}
}

func TestMemoryHeadroomWithoutALimitIsTheAvailableMemory(t *testing.T) {
	ht, h := newHostTree(t)
	ht.file("cgroup.controllers", "memory")
	ht.cgroupOf(10, "0::/system.slice/api.service\n")
	ht.file("system.slice/api.service/memory.max", "max")
	ht.file("system.slice/api.service/memory.current", "1")
	ht.file("system.slice/memory.max", "max")
	got, err := h.MemoryHeadroom(10)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(8000000) * 1024; got != want {
		t.Errorf("headroom = %d, want MemAvailable %d", got, want)
	}
}

func TestMemoryHeadroomCgroupV1(t *testing.T) {
	ht, h := newHostTree(t)
	ht.cgroupOf(10, "12:cpu,cpuacct:/docker/abc\n4:memory:/docker/abc\n1:name=systemd:/docker/abc\n")
	ht.file("memory/docker/abc/memory.limit_in_bytes", "536870912")
	ht.file("memory/docker/abc/memory.usage_in_bytes", "100000000")
	ht.file("memory/docker/memory.limit_in_bytes", "9223372036854771712")
	ht.file("memory/docker/memory.usage_in_bytes", "123")
	got, err := h.MemoryHeadroom(10)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(536870912 - 100000000); got != want {
		t.Errorf("headroom = %d, want %d", got, want)
	}
}

func TestMemoryHeadroomCgroupV1Unlimited(t *testing.T) {
	ht, h := newHostTree(t)
	ht.cgroupOf(10, "4:memory:/system.slice/api.service\n")
	ht.file("memory/system.slice/api.service/memory.limit_in_bytes", "9223372036854771712")
	ht.file("memory/system.slice/api.service/memory.usage_in_bytes", "123")
	got, err := h.MemoryHeadroom(10)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(8000000) * 1024; got != want {
		t.Errorf("headroom = %d, want MemAvailable %d", got, want)
	}
}

func TestMemoryHeadroomErrors(t *testing.T) {
	ht, h := newHostTree(t)
	ht.file("cgroup.controllers", "memory")
	if _, err := h.MemoryHeadroom(10); err == nil {
		t.Error("a process without a cgroup file was accepted")
	}
	ht.cgroupOf(10, "0::/a/../../etc\n")
	if _, err := h.MemoryHeadroom(10); err == nil {
		t.Error("a cgroup path with .. was accepted")
	}
	ht.cgroupOf(10, "0::/a\n")
	ht.file("a/memory.max", "banana")
	ht.file("a/memory.current", "1")
	if _, err := h.MemoryHeadroom(10); err == nil {
		t.Error("a malformed memory.max was accepted")
	}
	ht.file("a/memory.max", "1000")
	ht.file("a/memory.current", "2000")
	got, err := h.MemoryHeadroom(10)
	if err != nil || got != 0 {
		t.Errorf("usage above the limit: headroom = %d, err = %v, want 0", got, err)
	}
}

func TestCPUTicksSumsUserAndSystemTime(t *testing.T) {
	ht, h := newHostTree(t)
	// Fields 14 and 15 are utime and stime. The name in field 2 holds a space and parentheses.
	write(t, filepath.Join(ht.base, "proc", "10", "stat"),
		"10 (java (x) y) S 1 10 10 0 -1 4194560 100 0 0 0 1500 250 0 0 20 0 30 0 5555 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n")
	got, err := h.CPUTicks(10)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1750 {
		t.Errorf("ticks = %d, want 1750", got)
	}
	write(t, filepath.Join(ht.base, "proc", "11", "stat"), "11 (java) S 1\n")
	if _, err := h.CPUTicks(11); err == nil {
		t.Error("a short stat line was accepted")
	}
	if _, err := h.CPUTicks(12); err == nil {
		t.Error("a missing process was accepted")
	}
}

func TestBootID(t *testing.T) {
	ht, h := newHostTree(t)
	write(t, filepath.Join(ht.base, "proc", "boot_id"), "0123ABCD-0000-4000-8000-123456789ABC\n")
	got, err := h.BootID()
	if err != nil || got != "0123abcd-0000-4000-8000-123456789abc" {
		t.Errorf("boot id = %q, %v", got, err)
	}
	write(t, filepath.Join(ht.base, "proc", "boot_id"), "../../x\n")
	if _, err := h.BootID(); err == nil {
		t.Error("a malformed boot id was accepted")
	}
}
