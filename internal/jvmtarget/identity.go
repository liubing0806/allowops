package jvmtarget

import (
	"context"
	"fmt"
	"net"
	"runtime"

	"golang.org/x/sys/unix"
)

// onLockedThread runs f on a goroutine that has an OS thread of its own, which f may change:
// enter another namespace, give up root. The thread is never released. When the goroutine
// ends, the Go runtime ends the thread instead of returning it to the pool, so no other goroutine
// ever runs with the changed state. New threads that the runtime needs while f runs are
// started by a thread it keeps clean for that purpose.
//
// The runtime cannot end the main thread of the process: it parks the thread for good with
// whatever state f gave it, and ps and /proc/<pid> then report that state for the process. A
// goroutine that starts on the main thread therefore does not run f. It keeps the thread
// occupied, so that the next goroutine cannot start on it, until the call is done.
func onLockedThread[T any](f func() (T, error)) (T, error) {
	type result struct {
		value T
		err   error
		// release is set when the goroutine started on the main thread and did not run f.
		release chan struct{}
	}
	var occupied []chan struct{}
	defer func() {
		for _, release := range occupied {
			close(release)
		}
	}()
	for {
		done := make(chan result, 1)
		go func() {
			runtime.LockOSThread() // deliberately not undone, except on the main thread
			if unix.Gettid() == unix.Getpid() {
				release := make(chan struct{})
				done <- result{release: release}
				<-release
				runtime.UnlockOSThread()
				return
			}
			value, err := f()
			done <- result{value: value, err: err}
		}()
		r := <-done
		if r.release == nil {
			return r.value, r.err
		}
		occupied = append(occupied, r.release)
	}
}

// switchIdentity gives the calling thread, and only it, the user and group ids. The ids
// are set with the raw system calls: syscall.Setuid and its relatives change every thread of
// the process since Go 1.16. The supplementary groups are dropped first, the group before the
// user, because a thread that is no longer root cannot do either. The thread cannot become
// root again: all three ids are set.
func switchIdentity(uid, gid uint32) error {
	if unix.Geteuid() == 0 {
		if _, _, e := unix.RawSyscall(unix.SYS_SETGROUPS, 0, 0, 0); e != 0 {
			return fmt.Errorf("setgroups: %w", e)
		}
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETRESGID, uintptr(gid), uintptr(gid), uintptr(gid)); e != 0 {
		return fmt.Errorf("setresgid(%d): %w", gid, e)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, uintptr(uid), uintptr(uid), uintptr(uid)); e != 0 {
		return fmt.Errorf("setresuid(%d): %w", uid, e)
	}
	if uint32(unix.Geteuid()) != uid || uint32(unix.Getegid()) != gid {
		return fmt.Errorf("the thread has uid %d and gid %d after the switch to %d and %d", unix.Geteuid(), unix.Getegid(), uid, gid)
	}
	return nil
}

// dialUnixAs connects to the unix socket at path as the user uid and group gid. Linux
// records the credentials of the connecting thread as the peer credentials of the socket,
// which JDK 8 compares with its own. The path must not need the thread's former privileges
// to be reached; /proc/self/fd/<n> of a descriptor that was opened before is such a path.
func dialUnixAs(ctx context.Context, path string, uid, gid uint32) (net.Conn, error) {
	return onLockedThread(func() (net.Conn, error) {
		if err := switchIdentity(uid, gid); err != nil {
			return nil, err
		}
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	})
}
