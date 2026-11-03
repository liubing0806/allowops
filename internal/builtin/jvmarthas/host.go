package jvmarthas

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/liubing0806/allowops/internal/jvmtarget"
)

// maxHostFile bounds what is read from a procfs or cgroup file.
const maxHostFile = 64 << 10

// unlimitedBytes is the value from which a cgroup v1 limit means no limit: the kernel
// reports an unset limit as the largest page-aligned number below 2^63.
const unlimitedBytes = int64(1) << 60

// procHost is the Host of this machine: procfs and the cgroup file system.
type procHost struct {
	proc jvmtarget.Proc
	// cgroupRoot is where the cgroup file system is mounted.
	cgroupRoot string
	// meminfo is the host's memory statistics, used when no cgroup limit applies.
	meminfo string
	// bootIDPath holds the identifier of the current boot.
	bootIDPath string
}

func newProcHost() *procHost {
	return &procHost{
		proc:       jvmtarget.DefaultProc(),
		cgroupRoot: "/sys/fs/cgroup",
		meminfo:    "/proc/meminfo",
		bootIDPath: "/proc/sys/kernel/random/boot_id",
	}
}

func (h *procHost) PickPort(pid, lo, hi int) (int, error)   { return h.proc.PickPort(pid, lo, hi) }
func (h *procHost) IsListening(pid, port int) (bool, error) { return h.proc.IsListening(pid, port) }
func (h *procHost) ArthasThreads(pid int) (int, error)      { return h.proc.ArthasThreads(pid) }
func (h *procHost) StartTime(pid int) (uint64, error)       { return h.proc.StartTime(pid) }

func (h *procHost) OpenRoot(pid int) (Files, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid pid %d", pid)
	}
	return jvmtarget.OpenRoot(filepath.Join(h.proc.Root, strconv.Itoa(pid), "root"))
}

func readSmallFile(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxHostFile+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxHostFile {
		return "", fmt.Errorf("%s is larger than %d bytes", name, maxHostFile)
	}
	return string(data), nil
}

// BootID returns the identifier of the current boot, in lower case.
func (h *procHost) BootID() (string, error) {
	data, err := readSmallFile(h.bootIDPath)
	if err != nil {
		return "", err
	}
	id := strings.ToLower(strings.TrimSpace(data))
	if !bootIDPattern.MatchString(id) {
		return "", fmt.Errorf("malformed boot id in %s", h.bootIDPath)
	}
	return id, nil
}

// CPUTicks returns utime plus stime, fields 14 and 15 of /proc/<pid>/stat.
func (h *procHost) CPUTicks(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	name := filepath.Join(h.proc.Root, strconv.Itoa(pid), "stat")
	data, err := readSmallFile(name)
	if err != nil {
		return 0, err
	}
	// The command name in field 2 may contain spaces and parentheses; the last ')' ends it.
	end := strings.LastIndexByte(data, ')')
	if end < 0 {
		return 0, fmt.Errorf("malformed %s", name)
	}
	// After ") " come the state (field 3) and the rest, so field 14 is the 12th of them.
	fields := strings.Fields(data[end+1:])
	if len(fields) < 13 {
		return 0, fmt.Errorf("malformed %s: %d fields after the command name", name, len(fields))
	}
	user, err1 := strconv.ParseUint(fields[11], 10, 64)
	system, err2 := strconv.ParseUint(fields[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("malformed %s: CPU time", name)
	}
	return user + system, nil
}

// MemoryHeadroom returns the smallest "limit minus usage" over the memory cgroup of the
// process and its parents. The usage includes page cache, so the value is on the low side.
func (h *procHost) MemoryHeadroom(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	data, err := readSmallFile(filepath.Join(h.proc.Root, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return 0, err
	}
	_, statErr := os.Stat(filepath.Join(h.cgroupRoot, "cgroup.controllers"))
	unified := statErr == nil
	var base, limitFile, usageFile, group string
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case unified && parts[0] == "0" && parts[1] == "":
			base, limitFile, usageFile, group = h.cgroupRoot, "memory.max", "memory.current", parts[2]
		case !unified && slices.Contains(strings.Split(parts[1], ","), "memory"):
			base, limitFile, usageFile, group = filepath.Join(h.cgroupRoot, "memory"), "memory.limit_in_bytes", "memory.usage_in_bytes", parts[2]
		}
	}
	if group == "" {
		return 0, errors.New("the process has no memory cgroup")
	}
	if !path.IsAbs(group) || path.Clean(group) != group {
		return 0, fmt.Errorf("unexpected cgroup path %q", group)
	}
	best := int64(-1)
	for dir := group; ; dir = path.Dir(dir) {
		left, limited, err := cgroupHeadroom(filepath.Join(base, filepath.FromSlash(dir)), limitFile, usageFile)
		if err != nil {
			return 0, err
		}
		if limited && (best < 0 || left < best) {
			best = left
		}
		if dir == "/" {
			break
		}
	}
	if best >= 0 {
		return best, nil
	}
	return h.availableMemory()
}

// cgroupHeadroom returns the limit minus the usage of one cgroup directory. A directory
// without the limit file, or with no limit set, has no limit of its own.
func cgroupHeadroom(dir, limitFile, usageFile string) (left int64, limited bool, err error) {
	text, err := readSmallFile(filepath.Join(dir, limitFile))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	text = strings.TrimSpace(text)
	if text == "max" {
		return 0, false, nil
	}
	limit, err := strconv.ParseInt(text, 10, 64)
	if err != nil || limit < 0 {
		return 0, false, fmt.Errorf("malformed %s in %s", limitFile, dir)
	}
	if limit >= unlimitedBytes {
		return 0, false, nil
	}
	text, err = readSmallFile(filepath.Join(dir, usageFile))
	if err != nil {
		return 0, false, err
	}
	usage, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	if err != nil || usage < 0 {
		return 0, false, fmt.Errorf("malformed %s in %s", usageFile, dir)
	}
	return max(limit-usage, 0), true, nil
}

// availableMemory returns MemAvailable of the host in bytes.
func (h *procHost) availableMemory() (int64, error) {
	data, err := readSmallFile(h.meminfo)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(data, "\n") {
		rest, ok := strings.CutPrefix(line, "MemAvailable:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) != 2 || fields[1] != "kB" {
			break
		}
		kb, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || kb < 0 {
			break
		}
		return kb * 1024, nil
	}
	return 0, fmt.Errorf("no MemAvailable in %s", h.meminfo)
}

// CPULimit returns the number of CPUs the process may use: the smallest quota of its cpu cgroup
// and the parents (cpu.max in cgroup v2, cpu.cfs_quota_us / cpu.cfs_period_us in v1), and at
// most the number of CPUs it may run on (Cpus_allowed_list of /proc/<pid>/status).
func (h *procHost) CPULimit(pid int) (float64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	status, err := readSmallFile(filepath.Join(h.proc.Root, strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	cpus, err := allowedCPUs(status)
	if err != nil {
		return 0, err
	}
	limit := float64(cpus)
	data, err := readSmallFile(filepath.Join(h.proc.Root, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return 0, err
	}
	_, statErr := os.Stat(filepath.Join(h.cgroupRoot, "cgroup.controllers"))
	unified := statErr == nil
	var base, group string
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case unified && parts[0] == "0" && parts[1] == "":
			base, group = h.cgroupRoot, parts[2]
		case !unified && slices.Contains(strings.Split(parts[1], ","), "cpu"):
			// The hierarchy is mounted under the list of its controllers, such as cpu,cpuacct.
			base, group = filepath.Join(h.cgroupRoot, parts[1]), parts[2]
		}
	}
	if group == "" {
		return limit, nil // no cpu controller: the affinity is the limit
	}
	if !path.IsAbs(group) || path.Clean(group) != group {
		return 0, fmt.Errorf("unexpected cgroup path %q", group)
	}
	for dir := group; ; dir = path.Dir(dir) {
		quota, limited, err := cgroupCPUQuota(filepath.Join(base, filepath.FromSlash(dir)), unified)
		if err != nil {
			return 0, err
		}
		if limited && quota < limit {
			limit = quota
		}
		if dir == "/" {
			break
		}
	}
	return limit, nil
}

// cgroupCPUQuota returns the CPUs that the quota of one cgroup directory allows. A directory
// without the quota file, or with no quota set, has no limit of its own.
func cgroupCPUQuota(dir string, unified bool) (cpus float64, limited bool, err error) {
	var quotaText, periodText string
	if unified {
		text, err := readSmallFile(filepath.Join(dir, "cpu.max"))
		if errors.Is(err, fs.ErrNotExist) {
			return 0, false, nil
		}
		if err != nil {
			return 0, false, err
		}
		fields := strings.Fields(text)
		if len(fields) != 2 {
			return 0, false, fmt.Errorf("malformed cpu.max in %s", dir)
		}
		quotaText, periodText = fields[0], fields[1]
		if quotaText == "max" {
			return 0, false, nil
		}
	} else {
		text, err := readSmallFile(filepath.Join(dir, "cpu.cfs_quota_us"))
		if errors.Is(err, fs.ErrNotExist) {
			return 0, false, nil
		}
		if err != nil {
			return 0, false, err
		}
		if quotaText = strings.TrimSpace(text); quotaText == "-1" {
			return 0, false, nil
		}
		if periodText, err = readSmallFile(filepath.Join(dir, "cpu.cfs_period_us")); err != nil {
			return 0, false, err
		}
	}
	quota, err1 := strconv.ParseInt(quotaText, 10, 64)
	period, err2 := strconv.ParseInt(strings.TrimSpace(periodText), 10, 64)
	if err1 != nil || err2 != nil || quota <= 0 || period <= 0 {
		return 0, false, fmt.Errorf("malformed CPU quota in %s", dir)
	}
	return float64(quota) / float64(period), true, nil
}

// maxCPUs bounds the CPU numbers read from an affinity list.
const maxCPUs = 1 << 16

// allowedCPUs counts the CPUs of the Cpus_allowed_list line of /proc/<pid>/status, such as
// "0-3,8,10-11".
func allowedCPUs(status string) (int, error) {
	for _, line := range strings.Split(status, "\n") {
		list, ok := strings.CutPrefix(line, "Cpus_allowed_list:")
		if !ok {
			continue
		}
		n := 0
		for _, part := range strings.Split(strings.TrimSpace(list), ",") {
			lo, hi, isRange := strings.Cut(part, "-")
			if !isRange {
				hi = lo
			}
			a, err1 := strconv.Atoi(lo)
			b, err2 := strconv.Atoi(hi)
			if err1 != nil || err2 != nil || a < 0 || b < a || b >= maxCPUs {
				return 0, fmt.Errorf("malformed Cpus_allowed_list %q", strings.TrimSpace(list))
			}
			n += b - a + 1
		}
		return n, nil
	}
	return 0, errors.New("no Cpus_allowed_list in the process status")
}
