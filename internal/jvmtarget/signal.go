package jvmtarget

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// The system calls that deliver a signal are variables so that tests can stand in for a kernel
// without pidfds and keep the signals away from the fake processes of their procfs.
var (
	pidfdOpen       = unix.PidfdOpen
	pidfdSendSignal = unix.PidfdSendSignal
	killProcess     = unix.Kill
)

// signalQuit sends SIGQUIT to the JVM, after checking that its pid still belongs to the
// process that was resolved. It returns how the signal was sent.
func (r *Resolver) signalQuit(j *JVM) (string, error) {
	return r.sendSignal(j, unix.SIGQUIT)
}

// sendSignal sends a signal to the process. With pidfd_open (Linux 5.3) the descriptor is
// opened first, then the start time is compared, then the signal goes to the descriptor. A
// descriptor refers to one process for its whole life, so a pid that is reused after the
// comparison cannot receive the signal.
//
// Kernels without pidfd (CentOS 7 has 3.10) get kill(2) after the same comparison. A window
// remains between the comparison and the system call, in which the process can exit and its
// pid be given to a new process. That needs a wrap of the pid space within a few
// microseconds. A new process would then get one SIGQUIT, which ends it unless it catches it.
func (r *Resolver) sendSignal(j *JVM, sig unix.Signal) (string, error) {
	fd, err := pidfdOpen(j.PID, 0)
	switch {
	case err == nil:
		defer unix.Close(fd)
		if err := r.check(j); err != nil {
			return "", err
		}
		err := pidfdSendSignal(fd, sig, nil, 0)
		switch {
		case err == nil:
			return "pidfd", nil
		case errors.Is(err, unix.ESRCH):
			return "", fmt.Errorf("process %d: %w", j.PID, ErrProcessChanged)
		case !pidfdUnavailable(err):
			return "", err
		}
	case errors.Is(err, unix.ESRCH):
		return "", fmt.Errorf("process %d: %w", j.PID, ErrProcessChanged)
	case !pidfdUnavailable(err):
		return "", err
	}
	if err := r.check(j); err != nil {
		return "", err
	}
	if err := killProcess(j.PID, syscall.Signal(sig)); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return "", fmt.Errorf("process %d: %w", j.PID, ErrProcessChanged)
		}
		return "", err
	}
	return "kill", nil
}

// pidfdUnavailable tells an error of a kernel without pidfds, or one that a seccomp filter
// answers, from an error of the process.
func pidfdUnavailable(err error) bool {
	return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM)
}
