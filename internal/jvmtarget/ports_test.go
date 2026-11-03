package jvmtarget

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

// tcpLine formats one row of /proc/net/tcp (IPv4) with the local address 127.0.0.1.
func tcpLine(n, port int, state string) string {
	return fmt.Sprintf("%4d: 0100007F:%04X 00000000:0000 %s 00000000:00000000 00:00000000 00000000 10001        0 %d 1 0000000000000000 100 0 0 10 0\n", n, port, state, 9000+n)
}

func tcp6Line(n, port int, state string) string {
	return fmt.Sprintf("%4d: 00000000000000000000000000000000:%04X 00000000000000000000000000000000:0000 %s 00000000:00000000 00:00000000 00000000 10001        0 %d 1 0000000000000000 100 0 0 10 0\n", n, port, state, 9500+n)
}

func writeTCP(t *testing.T, root string, pid int, v4, v6 string) {
	t.Helper()
	writeFile(t, filepath.Join(root, fmt.Sprint(pid), "net", "tcp"), tcpHeader+v4)
	if v6 != "-" {
		writeFile(t, filepath.Join(root, fmt.Sprint(pid), "net", "tcp6"), tcpHeader+v6)
	}
}

func TestPortsReadsListenersOfBothFamilies(t *testing.T) {
	root := t.TempDir()
	p := Proc{Root: root}
	writeTCP(t, root, 42,
		tcpLine(0, 8080, "0A")+tcpLine(1, 18563, "0A")+tcpLine(2, 40000, "01")+tcpLine(3, 40001, "06"),
		tcp6Line(0, 9090, "0A")+tcp6Line(1, 41000, "01"))
	table, err := p.Ports(42)
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{8080, 18563, 9090} {
		if !table.Listening(port) {
			t.Errorf("port %d is not listening", port)
		}
	}
	for _, port := range []int{40000, 40001, 41000, 8081, 1} {
		if table.Listening(port) {
			t.Errorf("port %d listens", port)
		}
	}
	if ok, err := p.IsListening(42, 9090); err != nil || !ok {
		t.Errorf("IsListening(9090) = %v, %v", ok, err)
	}
	if ok, err := p.IsListening(42, 40000); err != nil || ok {
		t.Errorf("IsListening(40000) = %v, %v; an established connection is not a listener", ok, err)
	}
}

func TestPortsWithoutIPv6(t *testing.T) {
	root := t.TempDir()
	p := Proc{Root: root}
	writeTCP(t, root, 42, tcpLine(0, 8080, "0A"), "-")
	if ok, err := p.IsListening(42, 8080); err != nil || !ok {
		t.Errorf("IsListening = %v, %v", ok, err)
	}
	// Without the IPv4 table the process is gone.
	if _, err := p.Ports(43); !errors.Is(err, ErrProcessChanged) {
		t.Errorf("missing process: %v; want ErrProcessChanged", err)
	}
}

func TestPortsRejectsMalformedTables(t *testing.T) {
	root := t.TempDir()
	p := Proc{Root: root}
	for name, v4 := range map[string]string{
		"short line":   "0: 0100007F:1F90\n",
		"no colon":     "0: 0100007F 00000000:0000 0A\n",
		"bad hex port": "0: 0100007F:ZZZZ 00000000:0000 0A\n",
		"port too big": "0: 0100007F:10000 00000000:0000 0A\n",
	} {
		writeTCP(t, root, 42, v4, "")
		if _, err := p.Ports(42); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPortsBoundsTheTable(t *testing.T) {
	root := t.TempDir()
	p := Proc{Root: root}
	var b strings.Builder
	b.WriteString(tcpHeader)
	line := tcpLine(0, 8080, "01")
	for b.Len() <= maxPortTable {
		b.WriteString(line)
	}
	writeFile(t, filepath.Join(root, "42", "net", "tcp"), b.String())
	writeFile(t, filepath.Join(root, "42", "net", "tcp6"), tcpHeader)
	if _, err := p.Ports(42); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v; want a size error", err)
	}
}

func TestPickPort(t *testing.T) {
	root := t.TempDir()
	p := Proc{Root: root}
	// 18560..18563 are taken: two listeners, an IPv6 listener and a connection that uses 18562 as its local port.
	writeTCP(t, root, 42, tcpLine(0, 18560, "0A")+tcpLine(1, 18561, "0A")+tcpLine(2, 18562, "01"), tcp6Line(0, 18563, "0A"))
	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		port, err := p.PickPort(42, 18560, 18570)
		if err != nil {
			t.Fatal(err)
		}
		if port < 18564 || port > 18570 {
			t.Fatalf("picked %d; 18560-18563 are in use", port)
		}
		seen[port] = true
	}
	if len(seen) < 3 {
		t.Errorf("200 picks gave only %v; the search should start at a random port", seen)
	}
	port, err := p.PickPort(42, 18563, 18564)
	if err != nil || port != 18564 {
		t.Errorf("last free port: %d, %v", port, err)
	}
	if port, err := p.PickPort(42, 18560, 18563); !errors.Is(err, ErrNoFreePort) {
		t.Errorf("full range: %d, %v; want ErrNoFreePort", port, err)
	}
	for _, r := range [][2]int{{0, 10}, {10, 9}, {1, 65536}, {-5, 5}} {
		if port, err := p.PickPort(42, r[0], r[1]); err == nil {
			t.Errorf("range %v accepted: %d", r, port)
		}
	}
	if port, err := p.PickPort(42, 65535, 65535); err != nil || port != 65535 {
		t.Errorf("single port range: %d, %v", port, err)
	}
}

// The tables of this very process, from the kernel: a listener the test opened is found and gone after it closed.
func TestPortsOfThisProcess(t *testing.T) {
	if _, err := os.Stat("/proc/self/net/tcp"); err != nil {
		t.Skip("no procfs")
	}
	p := DefaultProc()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if ok, err := p.IsListening(os.Getpid(), port); err != nil || !ok {
		t.Errorf("IsListening(%d) = %v, %v while listening", port, ok, err)
	}
	if picked, err := p.PickPort(os.Getpid(), port, port+1); err == nil && picked == port {
		t.Errorf("picked %d, the port the test listens on", picked)
	}
	l.Close()
	if ok, err := p.IsListening(os.Getpid(), port); err != nil || ok {
		t.Errorf("IsListening(%d) = %v, %v after close", port, ok, err)
	}
	l6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	defer l6.Close()
	port6 := l6.Addr().(*net.TCPAddr).Port
	if ok, err := p.IsListening(os.Getpid(), port6); err != nil || !ok {
		t.Errorf("IsListening(%d) = %v, %v for an IPv6 listener", port6, ok, err)
	}
}

// Every socket that listens on the port must be one of the process's: a socket of another process
// on [::]:<port> takes the connections to 127.0.0.1:<port> as well when it is dual-stack.
func TestCheckListener(t *testing.T) {
	root := t.TempDir()
	p := Proc{Root: root}
	writeTCP(t, root, 42, tcpLine(0, 18563, "0A")+tcpLine(1, 18564, "0A")+tcpLine(2, 40000, "01"),
		tcp6Line(0, 18564, "0A"))
	holdSocket(t, root, 42, 3, 9000) // 127.0.0.1:18563
	holdSocket(t, root, 42, 4, 9001) // 127.0.0.1:18564; [::]:18564 (inode 9500) is not the process's
	holdSocket(t, root, 42, 5, 9002) // the connection on port 40000 is not a listener
	if err := p.CheckListener(42, 18563); err != nil {
		t.Errorf("own listener: %v", err)
	}
	if err := p.CheckListener(42, 18564); !errors.Is(err, ErrForeignListener) {
		t.Errorf("a second listener of another process: %v; want ErrForeignListener", err)
	}
	if err := p.CheckListener(42, 40000); !errors.Is(err, ErrNotListening) {
		t.Errorf("an established connection: %v; want ErrNotListening", err)
	}
	// A line without the inode column cannot be matched with a descriptor.
	writeTCP(t, root, 43, "   0: 0100007F:4883 00000000:0000 0A 00000000:00000000\n", "-")
	holdSocket(t, root, 43, 3, 0)
	if err := p.CheckListener(43, 18563); !errors.Is(err, ErrForeignListener) {
		t.Errorf("listener without inode: %v; want ErrForeignListener", err)
	}
	// A process without the descriptor directory is gone.
	writeTCP(t, root, 44, tcpLine(0, 18563, "0A"), "-")
	if err := p.CheckListener(44, 18563); !errors.Is(err, ErrProcessChanged) {
		t.Errorf("no fd directory: %v; want ErrProcessChanged", err)
	}
}
