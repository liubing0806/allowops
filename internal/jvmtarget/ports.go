package jvmtarget

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	// ErrNoFreePort means every port of the requested range is in use.
	ErrNoFreePort = errors.New("no free port in the range")
	// ErrForeignListener means a socket that the process does not hold listens on the port.
	ErrForeignListener = errors.New("a socket of another process listens on the port")
	// ErrNotListening means no socket listens on the port.
	ErrNotListening = errors.New("no socket listens on the port")
)

// maxPortTable bounds the bytes read from /proc/<pid>/net/tcp or tcp6. The kernel lists the
// listening sockets first, so a table cut off here would only lack connections.
const maxPortTable = 64 << 20

// maxDescriptors bounds the descriptors of a process that are examined; it is the kernel's
// default limit on open files per process (nr_open).
const maxDescriptors = 1 << 20

// PortTable holds the local ports of the TCP sockets of a network namespace (IPv4 and IPv6).
type PortTable struct {
	listening map[int]bool
	used      map[int]bool
	// listeners holds the inodes of the listening sockets of each port; 0 when the line had none.
	listeners map[int][]uint64
}

// Ports reads /proc/<pid>/net/tcp and tcp6. That directory shows the network namespace of
// the process, so no setns is needed.
func (p Proc) Ports(pid int) (*PortTable, error) {
	t := &PortTable{listening: map[int]bool{}, used: map[int]bool{}, listeners: map[int][]uint64{}}
	haveV4 := false
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		path, err := p.path(pid, name)
		if err != nil {
			return nil, err
		}
		err = t.read(path)
		if errors.Is(err, fs.ErrNotExist) && name == "net/tcp6" && haveV4 {
			continue // a kernel or namespace without IPv6
		}
		if err != nil {
			return nil, vanished(pid, err)
		}
		haveV4 = true
	}
	return t, nil
}

func (t *PortTable) read(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	limited := &io.LimitedReader{R: f, N: maxPortTable + 1}
	sc := bufio.NewScanner(limited)
	if !sc.Scan() { // header
		return sc.Err()
	}
	for sc.Scan() {
		if limited.N <= 0 {
			return fmt.Errorf("%s is larger than %d bytes", path, maxPortTable)
		}
		// "  0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 ..."
		// local address, remote address, state, queues, timer, retransmits, uid, timeout, inode
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			return fmt.Errorf("malformed line in %s", path)
		}
		i := strings.LastIndexByte(fields[1], ':')
		port, err := strconv.ParseUint(fields[1][i+1:], 16, 16)
		if i < 0 || err != nil {
			return fmt.Errorf("malformed address %q in %s", fields[1], path)
		}
		t.used[int(port)] = true
		if fields[3] == "0A" { // TCP_LISTEN
			t.listening[int(port)] = true
			var inode uint64
			if len(fields) > 9 {
				inode, _ = strconv.ParseUint(fields[9], 10, 64)
			}
			t.listeners[int(port)] = append(t.listeners[int(port)], inode)
		}
	}
	return sc.Err()
}

// Listening reports whether a socket listens on the port, on any address.
func (t *PortTable) Listening(port int) bool { return t.listening[port] }

// Pick returns a port of lo..hi that no TCP socket of the namespace uses, as a listener or as
// the local end of a connection. The search starts at a random port of the range, so that
// concurrent callers do not pick the same one.
func (t *PortTable) Pick(lo, hi int) (int, error) {
	if lo < 1 || hi > 65535 || lo > hi {
		return 0, fmt.Errorf("invalid port range %d-%d", lo, hi)
	}
	n := hi - lo + 1
	start := rand.IntN(n)
	for i := 0; i < n; i++ {
		if port := lo + (start+i)%n; !t.used[port] {
			return port, nil
		}
	}
	return 0, fmt.Errorf("%w %d-%d", ErrNoFreePort, lo, hi)
}

// IsListening reports whether a socket in the network namespace of the process listens on the port.
func (p Proc) IsListening(pid, port int) (bool, error) {
	t, err := p.Ports(pid)
	if err != nil {
		return false, err
	}
	return t.Listening(port), nil
}

// PickPort returns a free port of lo..hi in the network namespace of the process. A JVM
// that binds the port between this call and the use of it is not detected here.
func (p Proc) PickPort(pid, lo, hi int) (int, error) {
	t, err := p.Ports(pid)
	if err != nil {
		return 0, err
	}
	return t.Pick(lo, hi)
}

// CheckListener tells whether the process itself listens on the port: at least one socket listens
// there, and the process has a descriptor of every one of them. It fails with ErrNotListening or
// ErrForeignListener otherwise. A socket that another process of the network namespace holds can
// be one that took the port before the process bound it.
func (p Proc) CheckListener(pid, port int) error {
	t, err := p.Ports(pid)
	if err != nil {
		return err
	}
	inodes := t.listeners[port]
	if len(inodes) == 0 {
		return fmt.Errorf("%w: port %d in the network namespace of process %d", ErrNotListening, port, pid)
	}
	held, err := p.socketInodes(pid)
	if err != nil {
		return err
	}
	for _, inode := range inodes {
		if inode == 0 || !held[inode] {
			return fmt.Errorf("%w: port %d, process %d", ErrForeignListener, port, pid)
		}
	}
	return nil
}

// socketInodes returns the inodes of the sockets the process has descriptors of. /proc/<pid>/fd
// shows a socket as a link to "socket:[<inode>]".
func (p Proc) socketInodes(pid int) (map[uint64]bool, error) {
	dirPath, err := p.path(pid, "fd")
	if err != nil {
		return nil, err
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		return nil, vanished(pid, err)
	}
	defer dir.Close()
	inodes := map[uint64]bool{}
	seen := 0
	for {
		names, err := dir.Readdirnames(1024)
		for _, name := range names {
			if seen++; seen > maxDescriptors {
				return nil, fmt.Errorf("process %d has more than %d descriptors", pid, maxDescriptors)
			}
			target, err := os.Readlink(filepath.Join(dirPath, name))
			if err != nil {
				continue // the descriptor was closed
			}
			if number, ok := strings.CutPrefix(target, "socket:["); ok {
				if inode, err := strconv.ParseUint(strings.TrimSuffix(number, "]"), 10, 64); err == nil {
					inodes[inode] = true
				}
			}
		}
		if errors.Is(err, io.EOF) {
			return inodes, nil
		}
		if err != nil {
			return nil, vanished(pid, err)
		}
	}
}
