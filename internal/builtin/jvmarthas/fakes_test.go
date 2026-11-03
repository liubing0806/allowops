package jvmarthas

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/liubing0806/allowops/internal/jvmtarget"
	"github.com/liubing0806/allowops/internal/jvmtarget/perfdata"
)

// fakeHost is a Host whose answers the tests set.
type fakeHost struct {
	mu          sync.Mutex
	headroom    int64
	headroomErr error
	boot        string
	// startTimes holds the start time of every process that exists, by pid.
	startTimes map[int]uint64
	// listening is the set of ports with a listener, threads the number of arthas- threads.
	listening map[int]bool
	threads   int
	cpu       map[int]uint64
	cpuStep   uint64
	cpuErr    error
	pickErr   error
	nextPort  int
	root      Files
	rootErr   error
	// cpuLimit is the answer of CPULimit; zero reads as one CPU.
	cpuLimit    float64
	cpuLimitErr error
}

func (h *fakeHost) PickPort(pid, lo, hi int) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pickErr != nil {
		return 0, h.pickErr
	}
	if h.nextPort == 0 {
		h.nextPort = lo
	}
	return h.nextPort, nil
}

func (h *fakeHost) IsListening(pid, port int) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.startTimes[pid]; !ok && h.startTimes != nil {
		return false, errors.New("process exited or was replaced")
	}
	return h.listening[port], nil
}

func (h *fakeHost) ArthasThreads(pid int) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.threads, nil
}

func (h *fakeHost) StartTime(pid int) (uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	start, ok := h.startTimes[pid]
	if !ok {
		return 0, os.ErrNotExist
	}
	return start, nil
}

func (h *fakeHost) CPUTicks(pid int) (uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cpu != nil {
		h.cpu[pid] += h.cpuStep
	}
	return h.cpu[pid], h.cpuErr
}

func (h *fakeHost) CPULimit(pid int) (float64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cpuLimit == 0 && h.cpuLimitErr == nil {
		return 1, nil
	}
	return h.cpuLimit, h.cpuLimitErr
}

func (h *fakeHost) MemoryHeadroom(pid int) (int64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.headroom, h.headroomErr
}

func (h *fakeHost) OpenRoot(pid int) (Files, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.root, h.rootErr
}

func (h *fakeHost) BootID() (string, error) {
	if h.boot == "" {
		return testKey.BootID, nil
	}
	return h.boot, nil
}

// dropPrefix removes every counter whose name starts with prefix.
func dropPrefix(prefix string) func(map[string]perfdata.Entry) {
	return func(e map[string]perfdata.Entry) {
		for name := range e {
			if strings.HasPrefix(name, prefix) {
				delete(e, name)
			}
		}
	}
}

// fakeJVM is a JVMOps whose answers the tests set.
type fakeJVM struct {
	mu        sync.Mutex
	perf      *perfdata.PerfData
	perfErr   error
	perfReads int

	checkErr error
	// onAttach runs inside Attach, for example to start a fake Arthas server.
	onAttach  func(req jvmtarget.AttachRequest) error
	attachErr error
	attached  []jvmtarget.AttachRequest

	dial func(ctx context.Context, port int) (net.Conn, error)
}

func (j *fakeJVM) CheckAttach(ctx context.Context) (*jvmtarget.AttachCheck, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.checkErr != nil {
		return nil, j.checkErr
	}
	return &jvmtarget.AttachCheck{PerfData: j.perf, JavaHome: "/opt/java", EUID: 1000, EGID: 1000}, nil
}

func (j *fakeJVM) Attach(ctx context.Context, req jvmtarget.AttachRequest) (*jvmtarget.AttachResult, error) {
	j.mu.Lock()
	j.attached = append(j.attached, req)
	hook, err := j.onAttach, j.attachErr
	j.mu.Unlock()
	res := &jvmtarget.AttachResult{ReturnCode: 0}
	if hook != nil {
		if herr := hook(req); herr != nil {
			return res, herr
		}
	}
	if err != nil {
		res.ReturnCode = -1
	}
	return res, err
}

func (j *fakeJVM) DialTCP(ctx context.Context, port int) (net.Conn, error) {
	j.mu.Lock()
	dial := j.dial
	j.mu.Unlock()
	if dial == nil {
		return nil, errors.New("connection refused")
	}
	return dial(ctx, port)
}

func (j *fakeJVM) ReadPerfData(ctx context.Context) (*perfdata.PerfData, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.perfReads++
	if j.perfErr != nil {
		return nil, j.perfErr
	}
	return j.perf, nil
}

func (j *fakeJVM) attachCount() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.attached)
}

// fakeResolver is a Resolver for one process.
type fakeResolver struct {
	mu   sync.Mutex
	proc *Process
	err  error
	// known are the processes Identify finds, by pid.
	known map[int]*Process
}

func (r *fakeResolver) Resolve(ctx context.Context, t jvmtarget.Target) (*Process, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.proc, r.err
}

func (r *fakeResolver) Identify(pid int, startTime uint64) (*Process, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.known[pid]
	if !ok || p.StartTime != startTime {
		return nil, fmt.Errorf("process %d: %w", pid, jvmtarget.ErrProcessChanged)
	}
	return p, nil
}
