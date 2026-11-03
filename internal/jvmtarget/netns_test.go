package jvmtarget

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDialTCPRejectsBadPorts(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	for _, port := range []int{-1, 0, 65536, 1 << 20} {
		if conn, err := e.jvm.DialTCP(context.Background(), port); err == nil {
			conn.Close()
			t.Errorf("port %d accepted", port)
		}
	}
}

// The namespace is opened, then the process is compared with the one that was resolved. A
// reused pid never gets as far as setns.
func TestDialTCPChecksTheStartTime(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	writeFile(t, filepath.Join(e.h.proc, "4242", "ns", "net"), "not a namespace")
	e.h.setStart(testPID, e.jvm.StartTime+1)
	conn, err := e.jvm.DialTCP(context.Background(), 8080)
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, ErrProcessChanged) {
		t.Errorf("err = %v; want ErrProcessChanged", err)
	}
	// The same process: the namespace is entered, which a regular file is not.
	e.h.setStart(testPID, e.jvm.StartTime)
	_, err = e.jvm.DialTCP(context.Background(), 8080)
	if err == nil || !strings.Contains(err.Error(), "entering the network namespace") {
		t.Errorf("err = %v; want the setns error", err)
	}
	// A process that is gone.
	if err := os.RemoveAll(filepath.Join(e.h.proc, "4242", "ns")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.jvm.DialTCP(context.Background(), 8080); !errors.Is(err, ErrProcessChanged) {
		t.Errorf("no namespace: %v; want ErrProcessChanged", err)
	}
}

func TestDialTCPHonoursTheContext(t *testing.T) {
	e := newAttachEnv(t, attachOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.jvm.DialTCP(ctx, 8080); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled", err)
	}
}

// The test process stands in for a JVM that shares our network namespace: setns to it works for
// root and fails for everyone else, and leaves every thread of the process in its namespace.
func TestDialTCPOfThisProcess(t *testing.T) {
	r := &Resolver{Proc: DefaultProc()}
	start, err := r.Proc.StartTime(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	j := &JVM{PID: os.Getpid(), StartTime: start, resolver: r}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- c
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	conn, err := j.DialTCP(context.Background(), port)
	if os.Geteuid() != 0 {
		if conn != nil {
			conn.Close()
			t.Skip("setns is allowed without root here")
		}
		if !errors.Is(err, unix.EPERM) {
			t.Errorf("err = %v; want EPERM without root", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("the listener got no connection")
	}
	own, _ := os.Readlink("/proc/self/ns/net")
	deadline := time.Now().Add(5 * time.Second)
	for {
		var other []string
		tasks, _ := os.ReadDir("/proc/self/task")
		for _, task := range tasks {
			if ns, err := os.Readlink("/proc/self/task/" + task.Name() + "/ns/net"); err == nil && ns != own {
				other = append(other, task.Name()+" "+ns)
			}
		}
		if len(other) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("threads in another network namespace: %v", other)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
