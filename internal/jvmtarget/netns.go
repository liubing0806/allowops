package jvmtarget

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// DialTCP connects to 127.0.0.1:port in the network namespace of the JVM and returns the
// connection. A socket stays in the namespace it was made in, so the connection works after
// DialTCP returned. The namespace is entered on a thread that the call does not give
// back (see onLockedThread). The JVM must still be the process that was resolved when the
// namespace is opened, and again before it is entered.
//
// Only a listener of the JVM itself is connected to (see Proc.CheckListener): another process
// of the namespace can bind a port before the JVM does, and would then get what the caller
// sends and answer in the JVM's name. The JVM can still close its listener between that check
// and the connection, and another process bind the port in that moment.
func (j *JVM) DialTCP(ctx context.Context, port int) (net.Conn, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := j.resolver
	ns, err := os.Open(filepath.Join(r.Proc.Root, strconv.Itoa(j.PID), "ns", "net"))
	if err != nil {
		return nil, vanished(j.PID, err)
	}
	defer ns.Close()
	if err := r.Proc.CheckListener(j.PID, port); err != nil {
		return nil, err
	}
	// The descriptor refers to the namespace of the process that had the pid at the time of the
	// open, and the listener was looked up after that. If the start time is still the recorded
	// one, that process is the JVM.
	if err := r.check(j); err != nil {
		return nil, err
	}
	return onLockedThread(func() (net.Conn, error) {
		if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
			return nil, fmt.Errorf("entering the network namespace of process %d: %w", j.PID, err)
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	})
}
