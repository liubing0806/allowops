package jvmtarget

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Proc reads process metadata below a procfs mount. Root is /proc except in tests.
type Proc struct{ Root string }

// DefaultProc is the host's procfs.
func DefaultProc() Proc { return Proc{Root: "/proc"} }

// Status holds the fields of /proc/<pid>/status that target resolution needs.
type Status struct {
	// NSPid lists the pid in each PID namespace, outermost first. The last
	// element is the pid the process sees itself, and the name of its hsperfdata file.
	NSPid []int
	// UID and GID are the real ids, EUID and EGID the effective ids. HotSpot compares the
	// effective ones with the owner of the attach file and with the peer of the attach socket.
	UID, EUID uint32
	GID, EGID uint32
	// SigCgt is the set of signals the process catches: bit n-1 is signal n. It is zero when
	// the status has no SigCgt line.
	SigCgt uint64
}

// sigQuit is the signal that makes HotSpot start its attach listener.
const sigQuit = 3

// CatchesSIGQUIT reports whether the process installed a handler for SIGQUIT. Without one the
// signal ends the process (default action), or has no effect when ignored.
func (s Status) CatchesSIGQUIT() bool { return s.SigCgt&(1<<(sigQuit-1)) != 0 }

// maxProcFile bounds what is read from a procfs file; the kernel's output is far smaller.
const maxProcFile = 64 << 10

func (p Proc) path(pid int, name string) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid pid %d", pid)
	}
	return filepath.Join(p.Root, strconv.Itoa(pid), name), nil
}

func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxProcFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxProcFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxProcFile)
	}
	return data, nil
}

// StartTime returns field 22 of /proc/<pid>/stat: the start time in clock
// ticks since boot. It identifies the process, because a reused pid has a
// different start time.
func (p Proc) StartTime(pid int) (uint64, error) {
	path, err := p.path(pid, "stat")
	if err != nil {
		return 0, err
	}
	data, err := readSmall(path)
	if err != nil {
		return 0, err
	}
	// The command name in field 2 may contain spaces and parentheses; the last ')' ends it.
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return 0, fmt.Errorf("malformed %s", path)
	}
	// After ") " come state (field 3) and the rest; start time is field 22.
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 {
		return 0, fmt.Errorf("malformed %s: %d fields after the command name", path, len(fields))
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("malformed %s: start time: %w", path, err)
	}
	return start, nil
}

// Status parses /proc/<pid>/status. Kernels before 4.1 have no NSpid line (CentOS 7 has
// 3.10); a process in our own PID namespace then has the pid we see, and for a process in
// another namespace the pid inside it is unknown, which is an error.
func (p Proc) Status(pid int) (Status, error) {
	path, err := p.path(pid, "status")
	if err != nil {
		return Status{}, err
	}
	data, err := readSmall(path)
	if err != nil {
		return Status{}, err
	}
	var st Status
	haveUID := false
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "NSpid":
			for _, field := range strings.Fields(value) {
				id, err := strconv.Atoi(field)
				if err != nil || id <= 0 {
					return Status{}, fmt.Errorf("malformed NSpid in %s", path)
				}
				st.NSPid = append(st.NSPid, id)
			}
			if len(st.NSPid) == 0 || st.NSPid[0] != pid {
				return Status{}, fmt.Errorf("malformed NSpid in %s", path)
			}
		case "Uid":
			real, effective, ok := parseIDs(value)
			if !ok {
				return Status{}, fmt.Errorf("malformed Uid in %s", path)
			}
			st.UID, st.EUID, haveUID = real, effective, true
		case "Gid":
			real, effective, ok := parseIDs(value)
			if !ok {
				return Status{}, fmt.Errorf("malformed Gid in %s", path)
			}
			st.GID, st.EGID = real, effective
		case "SigCgt":
			mask, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
			if err != nil {
				return Status{}, fmt.Errorf("malformed SigCgt in %s", path)
			}
			st.SigCgt = mask
		}
	}
	if !haveUID {
		return Status{}, fmt.Errorf("no Uid in %s", path)
	}
	if st.NSPid == nil {
		own, err1 := os.Readlink(filepath.Join(p.Root, "self", "ns", "pid"))
		theirs, err2 := p.PIDNamespace(pid)
		if err1 != nil || err2 != nil || own != theirs {
			return Status{}, fmt.Errorf("process %d is in another PID namespace and this kernel does not report NSpid (needs Linux 4.1)", pid)
		}
		st.NSPid = []int{pid}
	}
	return st, nil
}

// parseIDs reads the four ids of a Uid or Gid line and returns the real and the effective one.
func parseIDs(value string) (real, effective uint32, ok bool) {
	fields := strings.Fields(value)
	if len(fields) != 4 {
		return 0, 0, false
	}
	r, err1 := strconv.ParseUint(fields[0], 10, 32)
	e, err2 := strconv.ParseUint(fields[1], 10, 32)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uint32(r), uint32(e), true
}

// PIDNamespace returns the identity of the PID namespace of a process.
func (p Proc) PIDNamespace(pid int) (string, error) {
	path, err := p.path(pid, "ns/pid")
	if err != nil {
		return "", err
	}
	return os.Readlink(path)
}

// NetNamespace returns the identity of the network namespace of a process.
func (p Proc) NetNamespace(pid int) (string, error) {
	path, err := p.path(pid, "ns/net")
	if err != nil {
		return "", err
	}
	return os.Readlink(path)
}

// PIDs lists the numeric entries of the procfs root.
func (p Proc) PIDs() ([]int, error) {
	dir, err := os.Open(p.Root)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	var pids []int
	for {
		names, err := dir.Readdirnames(1024)
		for _, name := range names {
			if pid, convErr := strconv.Atoi(name); convErr == nil && pid > 0 && strconv.Itoa(pid) == name {
				pids = append(pids, pid)
			}
		}
		if errors.Is(err, io.EOF) {
			return pids, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

const (
	// arthasThreadPrefix starts the name of every thread of an Arthas server (arthas-NettyWeb,
	// arthas-timer, arthas-command-execute, ...). Linux keeps 15 bytes of a thread name in comm.
	arthasThreadPrefix = "arthas-"
	// maxThreads bounds the threads examined per process; the kernel's default limit is 32768.
	maxThreads = 1 << 16
)

// ArthasThreads counts the threads of the process whose name starts with "arthas-". An
// Arthas server in the process has them, and none is left after it stopped. An application
// thread with such a name is counted too. The file descriptors and memory mappings of
// Arthas' jar files stay after a stop, so they say nothing about a running server.
func (p Proc) ArthasThreads(pid int) (int, error) {
	dirPath, err := p.path(pid, "task")
	if err != nil {
		return 0, err
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		return 0, vanished(pid, err)
	}
	defer dir.Close()
	count, seen := 0, 0
	for {
		names, err := dir.Readdirnames(256)
		for _, name := range names {
			if seen++; seen > maxThreads {
				return 0, fmt.Errorf("process %d has more than %d threads", pid, maxThreads)
			}
			comm, err := readComm(filepath.Join(dirPath, name, "comm"))
			if errors.Is(err, fs.ErrNotExist) {
				continue // the thread ended
			}
			if err != nil {
				return 0, err
			}
			if strings.HasPrefix(comm, arthasThreadPrefix) {
				count++
			}
		}
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			return 0, vanished(pid, err)
		}
	}
}

// readComm reads a thread name; the kernel writes at most 16 bytes.
func readComm(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, 64)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		if errors.Is(err, syscall.ESRCH) {
			return "", fs.ErrNotExist
		}
		return "", err
	}
	return strings.TrimRight(string(buf[:n]), "\n"), nil
}
