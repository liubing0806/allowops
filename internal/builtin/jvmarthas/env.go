package jvmarthas

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/builtin/httpget"
	"github.com/liubing0806/allowops/internal/jvmtarget"
	"github.com/liubing0806/allowops/internal/jvmtarget/perfdata"
)

// JVMOps is what a call does to a JVM; *jvmtarget.JVM implements it.
type JVMOps interface {
	CheckAttach(ctx context.Context) (*jvmtarget.AttachCheck, error)
	Attach(ctx context.Context, req jvmtarget.AttachRequest) (*jvmtarget.AttachResult, error)
	// DialTCP connects to 127.0.0.1:port in the network namespace of the JVM, only when the JVM
	// itself holds the socket that listens there.
	DialTCP(ctx context.Context, port int) (net.Conn, error)
	ReadPerfData(ctx context.Context) (*perfdata.PerfData, error)
}

// Process is a resolved JVM.
type Process struct {
	// PID is the pid in the host's PID namespace, NSPid the one the JVM sees.
	PID, NSPid int
	StartTime  uint64
	EUID       uint32
	JVM        JVMOps
}

// Resolver finds a JVM.
type Resolver interface {
	Resolve(ctx context.Context, t jvmtarget.Target) (*Process, error)
	// Identify reaches a process by the pid and start time of a session record.
	Identify(pid int, startTime uint64) (*Process, error)
}

// Files reads files in the mount namespace of the JVM.
type Files interface {
	// OpenFile opens a regular file for reading; a symbolic link at the end is an error.
	OpenFile(path string) (*os.File, error)
	Close() error
}

// Host reads the procfs and cgroup data of the processes. All pids are host pids.
type Host interface {
	// PickPort returns a port of lo..hi that no TCP socket in the network namespace of the process uses.
	PickPort(pid, lo, hi int) (int, error)
	// IsListening reports whether a socket in the network namespace of the process listens on the port.
	IsListening(pid, port int) (bool, error)
	// ArthasThreads counts the threads named arthas-*.
	ArthasThreads(pid int) (int, error)
	// StartTime is the start time of the process in clock ticks since boot.
	StartTime(pid int) (uint64, error)
	// CPUTicks is the user and system CPU time of the process in clock ticks.
	CPUTicks(pid int) (uint64, error)
	// MemoryHeadroom is the number of bytes the process's cgroup can still allocate:
	// the smallest limit of the cgroup and its parents minus the usage there. Without a
	// limit it is the available memory of the host.
	MemoryHeadroom(pid int) (int64, error)
	// OpenRoot opens the root directory of the mount namespace of the process.
	OpenRoot(pid int) (Files, error)
	BootID() (string, error)
}

// Env is everything a call touches outside its own memory. NewEnv returns the
// one for this host; tests replace the parts.
type Env struct {
	Resolver Resolver
	Host     Host
	// StateDir and StateOwner locate the state directory and name the user that owns it.
	StateDir   string
	StateOwner uint32
	Now        func() time.Time
	// NewPassword returns a password for one Arthas server.
	NewPassword func() (string, error)
	// Cleanup bounds the clean-up sequence; its zero value selects the defaults of the arthas package.
	Cleanup arthas.CleanupOptions
	// StopWait is the time after stop in which the port must close and the arthas- threads must end.
	StopWait time.Duration
	// PollEvery is the interval of the polls that wait for a port or a thread count.
	PollEvery time.Duration
	// SampleEvery is the interval of the run-time guard.
	SampleEvery time.Duration
	// ListenWait bounds the wait for the Arthas port after the attach.
	ListenWait time.Duration
	// AttachSettle is how long a failed attach is watched for a server that started anyway.
	AttachSettle time.Duration
	// Arch is the architecture of this host as GOARCH names it; the architecture of the build when empty.
	Arch string
	// Probe sends the health request of the run-time guard and returns nil when the target answered well.
	Probe func(ctx context.Context, check HealthCheck) error
}

// hostResolver adapts the resolver of the jvmtarget package.
type hostResolver struct{ r *jvmtarget.Resolver }

func process(j *jvmtarget.JVM) *Process {
	return &Process{PID: j.PID, NSPid: j.NSPid, StartTime: j.StartTime, EUID: j.EUID, JVM: j}
}

func (h hostResolver) Resolve(ctx context.Context, t jvmtarget.Target) (*Process, error) {
	j, err := h.r.Resolve(ctx, t)
	if err != nil {
		return nil, err
	}
	return process(j), nil
}

func (h hostResolver) Identify(pid int, startTime uint64) (*Process, error) {
	j, err := h.r.Identify(pid, startTime)
	if err != nil {
		return nil, err
	}
	return process(j), nil
}

// maxProbeBody bounds what a health request reads.
const maxProbeBody = 64 << 10

// httpProbe sends the health request of the run-time guard. It counts a status outside 200 to 299, an
// error, and an answer slower than MaxLatency as a failure.
func httpProbe(ctx context.Context, h HealthCheck) error {
	start := time.Now()
	res, err := httpget.Run(ctx, httpget.Config{AllowedPrefixes: h.AllowedPrefixes, Timeout: h.Timeout, MaxResponseBytes: maxProbeBody}, httpget.Params{URL: h.URL})
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("HTTP status %d", res.StatusCode)
	}
	if elapsed := time.Since(start); h.MaxLatency > 0 && elapsed > h.MaxLatency {
		return fmt.Errorf("the answer took %s, the limit is %s", elapsed.Round(time.Millisecond), h.MaxLatency)
	}
	return nil
}

// NewEnv returns the environment of this host.
func NewEnv() Env {
	return Env{
		Resolver:    hostResolver{jvmtarget.NewResolver()},
		Host:        newProcHost(),
		StateDir:    StateDirectory,
		StateOwner:  0,
		Now:         time.Now,
		NewPassword: arthas.NewPassword,
		Probe:       httpProbe,
	}
}
