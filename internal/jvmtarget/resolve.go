package jvmtarget

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/liubing0806/allowops/internal/jvmtarget/perfdata"
)

var (
	// ErrNoPerfData means the process has no usable hsperfdata file: the JVM
	// runs with -XX:-UsePerfData or -XX:+PerfDisableSharedMem, runs as a user
	// without a passwd entry, or the file is not a regular file owned by the JVM's user.
	ErrNoPerfData = errors.New("no usable hsperfdata")
	// ErrProcessChanged means the process exited or its pid now belongs to another process.
	ErrProcessChanged = errors.New("process exited or was replaced")
	// ErrNoMatch means no JVM in the container has the configured main class.
	ErrNoMatch = errors.New("no JVM matches")
	// ErrAmbiguous means more than one JVM in the container has the configured main class.
	ErrAmbiguous = errors.New("more than one JVM matches")
	// ErrNotRunning means the unit or container has no running main process.
	ErrNotRunning = errors.New("not running")
)

const (
	// maxCandidates bounds the processes of one container that are examined.
	maxCandidates = 1024
	// maxPerfDirs bounds the hsperfdata_<user> directories tried for one process.
	maxPerfDirs   = 64
	perfDirPrefix = "hsperfdata_"
	perfHint      = "the JVM may run with -XX:-UsePerfData or -XX:+PerfDisableSharedMem, or as a user without a passwd entry"
)

// Resolver turns a Target into a running JVM.
type Resolver struct {
	Proc Proc
	// Systemctl and DockerSocket default to /usr/bin/systemctl and /var/run/docker.sock.
	Systemctl    string
	DockerSocket string
	// MainPID and ContainerPID replace the systemctl and Docker lookups in tests.
	MainPID      func(ctx context.Context, unit string) (int, error)
	ContainerPID func(ctx context.Context, container string) (int, error)

	// afterRead runs after hsperfdata was read and before the process is checked again (tests).
	afterRead func()
	// beforeConnect runs between opening the attach socket and connecting to it (tests).
	beforeConnect func()
}

// NewResolver returns a Resolver for the local host.
func NewResolver() *Resolver { return &Resolver{Proc: DefaultProc()} }

// JVM is a resolved process. PID and StartTime identify it; ReadPerfData checks them on every read.
type JVM struct {
	// PID is the pid in the host's PID namespace.
	PID int
	// NSPid is the pid in the JVM's own PID namespace; HotSpot names the hsperfdata file after it.
	NSPid int
	// StartTime is the process start time in clock ticks since boot.
	StartTime uint64
	// EUID owns the hsperfdata file.
	EUID uint32

	resolver *Resolver
}

// Resolve finds the JVM of the target.
func (r *Resolver) Resolve(ctx context.Context, t Target) (*JVM, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t.SystemdUnit != "" {
		pid, err := r.mainPID(ctx, t.SystemdUnit)
		if err != nil {
			return nil, err
		}
		return r.identify(pid)
	}
	return r.resolveContainer(ctx, t)
}

func (r *Resolver) mainPID(ctx context.Context, unit string) (int, error) {
	if r.MainPID != nil {
		return r.MainPID(ctx, unit)
	}
	systemctl := r.Systemctl
	if systemctl == "" {
		systemctl = "/usr/bin/systemctl"
	}
	return systemdMainPID(ctx, systemctl, unit)
}

func (r *Resolver) containerPID(ctx context.Context, name string) (int, error) {
	if r.ContainerPID != nil {
		return r.ContainerPID(ctx, name)
	}
	socket := r.DockerSocket
	if socket == "" {
		socket = "/var/run/docker.sock"
	}
	return dockerContainerPID(ctx, socket, name)
}

// vanished maps the error of reading a process that is gone.
func vanished(pid int, err error) error {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("process %d: %w", pid, ErrProcessChanged)
	}
	return err
}

// identify records the identity of a process. The start time is read on both
// sides of the status, so a pid reused in between is noticed.
func (r *Resolver) identify(pid int) (*JVM, error) {
	start, err := r.Proc.StartTime(pid)
	if err != nil {
		return nil, vanished(pid, err)
	}
	st, err := r.Proc.Status(pid)
	if err != nil {
		return nil, vanished(pid, err)
	}
	again, err := r.Proc.StartTime(pid)
	if err != nil {
		return nil, vanished(pid, err)
	}
	if again != start {
		return nil, fmt.Errorf("process %d: %w", pid, ErrProcessChanged)
	}
	return &JVM{PID: pid, NSPid: st.NSPid[len(st.NSPid)-1], StartTime: start, EUID: st.EUID, resolver: r}, nil
}

// resolveContainer finds the JVM whose main class is configured among the
// processes that share the PID namespace of the container's main process.
func (r *Resolver) resolveContainer(ctx context.Context, t Target) (*JVM, error) {
	initPID, err := r.containerPID(ctx, t.Container)
	if err != nil {
		return nil, err
	}
	ns, err := r.Proc.PIDNamespace(initPID)
	if err != nil {
		return nil, vanished(initPID, err)
	}
	if own, err := os.Readlink(filepath.Join(r.Proc.Root, "self", "ns", "pid")); err != nil || own == ns {
		return nil, fmt.Errorf("container %s shares the host's PID namespace, so its processes cannot be told from the host's", t.Container)
	}
	pids, err := r.Proc.PIDs()
	if err != nil {
		return nil, err
	}
	slices.Sort(pids)
	var matches []*JVM
	candidates, identified, withData := 0, 0, 0
	var identifyErr error
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if other, err := r.Proc.PIDNamespace(pid); err != nil || other != ns {
			continue
		}
		if candidates++; candidates > maxCandidates {
			break
		}
		j, err := r.identify(pid)
		if err != nil {
			if !errors.Is(err, ErrProcessChanged) {
				identifyErr = err
			}
			continue
		}
		identified++
		data, err := j.ReadPerfData(ctx)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			continue
		}
		withData++
		if command, ok := data.Text("sun.rt.javaCommand"); ok && perfdata.FirstWord(command) == t.MainClass {
			matches = append(matches, j)
		}
	}
	switch {
	case len(matches) == 1:
		return matches[0], nil
	case len(matches) > 1:
		return nil, fmt.Errorf("%w: %d JVMs in container %s have main class %s", ErrAmbiguous, len(matches), t.Container, t.MainClass)
	case identified == 0 && identifyErr != nil:
		// No process could be examined (for example the kernel reports no NSpid); that is not an absence of hsperfdata.
		return nil, fmt.Errorf("container %s: %w", t.Container, identifyErr)
	case withData == 0:
		return nil, fmt.Errorf("%w: none of the %d processes of container %s publishes hsperfdata; %s", ErrNoPerfData, candidates, t.Container, perfHint)
	default:
		return nil, fmt.Errorf("%w: none of the %d JVMs in container %s has main class %s", ErrNoMatch, withData, t.Container, t.MainClass)
	}
}

// ReadPerfData reads and parses the JVM's hsperfdata file through
// /proc/<pid>/root without following a symbolic link out of the JVM's root.
// It fails with ErrProcessChanged when the pid no longer belongs to the process
// that was resolved, before or while the file was read.
func (j *JVM) ReadPerfData(ctx context.Context) (*perfdata.PerfData, error) {
	r := j.resolver
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := r.check(j); err != nil {
		return nil, err
	}
	type result struct {
		data *perfdata.PerfData
		err  error
	}
	done := make(chan result, 1)
	// The read can block in the kernel (a hung network filesystem in the
	// container); the caller is released at the deadline and the goroutine ends later.
	go func() {
		data, err := r.readFile(ctx, j)
		done <- result{data, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-done:
		if res.err != nil {
			return nil, res.err
		}
		if r.afterRead != nil {
			r.afterRead()
		}
		if err := r.check(j); err != nil {
			return nil, err
		}
		return res.data, nil
	}
}

// check compares the process with the identity recorded at resolution.
func (r *Resolver) check(j *JVM) error {
	start, err := r.Proc.StartTime(j.PID)
	if err != nil {
		return vanished(j.PID, err)
	}
	if start != j.StartTime {
		return fmt.Errorf("process %d: %w", j.PID, ErrProcessChanged)
	}
	return nil
}

// readFile opens /tmp/hsperfdata_<user>/<nspid> in the root of the process. The
// user name is unknown (it comes from the container's passwd), so the
// hsperfdata_* directories are listed and the first file that is a regular
// file owned by the JVM's effective user is used.
func (r *Resolver) readFile(ctx context.Context, j *JVM) (*perfdata.PerfData, error) {
	root, err := OpenRoot(filepath.Join(r.Proc.Root, strconv.Itoa(j.PID), "root"))
	if err != nil {
		return nil, vanished(j.PID, err)
	}
	defer root.Close()
	dirs, err := perfDirs(ctx, root)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, noPerfData(j.PID, "cannot list /tmp ("+errText(err)+")")
	}
	var rejected []string
	for _, dir := range dirs {
		path := "/tmp/" + dir + "/" + strconv.Itoa(j.NSPid)
		f, err := root.OpenFile(path)
		switch {
		case err == nil:
		case errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR):
			continue
		default:
			rejected = append(rejected, path+": "+errText(err))
			continue
		}
		data, err := readPerfFile(f, j.EUID)
		f.Close()
		if err == errForeignOwner {
			rejected = append(rejected, path+": owned by another user than the JVM")
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("hsperfdata of pid %d: %w", j.PID, err)
		}
		return data, nil
	}
	reason := fmt.Sprintf("no file /tmp/%s*/%d", perfDirPrefix, j.NSPid)
	if len(rejected) > 0 {
		reason = strings.Join(rejected, "; ")
	}
	return nil, noPerfData(j.PID, reason)
}

func noPerfData(pid int, reason string) error {
	return fmt.Errorf("%w for pid %d: %s; %s", ErrNoPerfData, pid, reason, perfHint)
}

// errText drops the path an os.PathError carries; callers add their own.
func errText(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	return err.Error()
}

// perfDirs lists the hsperfdata_* directories of /tmp in name order.
func perfDirs(ctx context.Context, root *Root) ([]string, error) {
	dir, err := root.OpenDir("/tmp")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	var dirs []string
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		names, err := dir.Readdirnames(1024)
		for _, name := range names {
			if strings.HasPrefix(name, perfDirPrefix) && len(dirs) < maxPerfDirs {
				dirs = append(dirs, name)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	slices.Sort(dirs)
	return dirs, nil
}

var errForeignOwner = errors.New("file owned by another user")

// readPerfFile parses an opened regular file owned by euid.
func readPerfFile(f *os.File, euid uint32) (*perfdata.PerfData, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != euid {
		return nil, errForeignOwner
	}
	if info.Size() > perfdata.MaxFileSize {
		return nil, fmt.Errorf("%w: file is larger than %d bytes", perfdata.ErrCorrupt, perfdata.MaxFileSize)
	}
	// The file can grow, or be a file of a pseudo filesystem with a wrong size, so the read is bounded too.
	data, err := io.ReadAll(io.LimitReader(f, perfdata.MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	return perfdata.Parse(data)
}
