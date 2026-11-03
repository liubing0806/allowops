package jvmtarget

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/liubing0806/allowops/internal/jvmtarget/perfdata"
)

// This file implements the HotSpot attach mechanism from outside the target, without a JVM of
// our own. The mechanism, as HotSpot's attachListener_linux.cpp implements it:
//
//  1. A process that wants to attach creates the file .attach_pid<pid> in the working
//     directory of the target or in /tmp, owned by the target's effective user, and sends
//     SIGQUIT. <pid> is the pid the target sees itself, which differs from the host's pid in a container.
//  2. The target's signal handler finds the file and starts the attach listener, a unix
//     socket /tmp/.java_pid<pid>. Without the file a SIGQUIT makes the JVM print a thread dump
//     to its standard output, and a process that does not catch SIGQUIT dies of it.
//  3. The attaching process connects to the socket and sends "1\0load\0instrument\0false\0<arg>\0".
//     The target answers with a status line, "0" for success, and then text, which for the load
//     command is what the agent's initialisation returned: "return code: <n>" from JDK 9 on, "<n>" with JDK 8.
//
// JDK 8 accepts the connection only from the effective user of the target, and an attach file
// only when that user owns it. JDK 9 and later also accept root.

var (
	// ErrAttachDisabled means the JVM does not allow attach (-XX:+DisableAttachMechanism), or its
	// hsperfdata does not say that it does.
	ErrAttachDisabled = errors.New("the JVM does not allow attach")
	// ErrNoInstrument means the runtime of the JVM lacks the java.instrument module, so no agent can be loaded.
	ErrNoInstrument = errors.New("the runtime of the JVM has no java.instrument module")
	// ErrSigQuitNotCaught means the JVM does not handle SIGQUIT (it runs with -Xrs) and has no
	// attach socket. Sending the signal would end the process.
	ErrSigQuitNotCaught = errors.New("the JVM does not catch SIGQUIT and has no attach socket")
	// ErrNoAttachFile means the attach file cannot be created in the working directory of the
	// JVM nor in /tmp. Sending SIGQUIT then only makes the JVM print a thread dump.
	ErrNoAttachFile = errors.New("the attach file cannot be created")
	// ErrArthasRunning means threads of an Arthas server exist in the JVM. A second load is
	// ignored by Arthas and its new arguments do not take effect.
	ErrArthasRunning = errors.New("an Arthas server is running in the JVM")
	// ErrBadAttachSocket means the attach socket exists but is not a socket owned by the JVM's user.
	ErrBadAttachSocket = errors.New("the attach socket is not usable")
	// ErrAttachTimeout means the attach socket did not appear after the signal.
	ErrAttachTimeout = errors.New("the attach socket did not appear")
	// ErrAttachRefused means the JVM did not load the agent, or answered in an unknown way.
	ErrAttachRefused = errors.New("the JVM did not load the agent")
	// ErrLoadUnanswered means the load command was sent and the JVM did not answer it. The JVM
	// answers only after the agent's initialisation returned, so the agent may still start.
	ErrLoadUnanswered = errors.New("the JVM got the load command and may still load the agent")
	// ErrAgentArgument means the argument of the load command is not acceptable. Nothing was sent.
	ErrAgentArgument = errors.New("invalid agent argument")
)

const (
	// maxAgentArgument is HotSpot's limit for one argument of an attach command.
	maxAgentArgument = 1024
	// maxAttachReply bounds what is read from the attach socket.
	maxAttachReply = 64 << 10
	// maxJavaMessage bounds the text of the JVM that is kept in a result or an error.
	maxJavaMessage = 512
	// maxReleaseFile bounds the release file of the Java runtime.
	maxReleaseFile = 64 << 10

	defaultSocketWait = 10 * time.Second
	defaultReplyWait  = 30 * time.Second
	socketPollEvery   = 10 * time.Millisecond
)

// AttachCheck is what the checks before an attach found out.
type AttachCheck struct {
	// SocketExists means /tmp/.java_pid<pid> is a socket owned by the JVM's user. An attach then needs no signal.
	SocketExists bool
	// JavaHome is the java.home property of the JVM, a path inside the JVM's root.
	JavaHome string
	// EUID and EGID are the effective ids of the JVM at the time of the check.
	EUID, EGID uint32
	// PerfData is the hsperfdata that was read for the check.
	PerfData *perfdata.PerfData
}

// AttachRequest is one attach with the instrument library: it loads a Java agent.
type AttachRequest struct {
	// Agent is the argument of the load command: the absolute path of the agent jar as the JVM
	// sees it, then "=" and the options. At most 1024 bytes. The options may hold secrets;
	// they are not kept in errors or results.
	Agent string
	// SocketWait bounds the wait for the attach socket after the signal. Default 10 seconds.
	SocketWait time.Duration
	// ReplyWait bounds the connection to the socket and the JVM's answer. Default 30 seconds.
	ReplyWait time.Duration
}

// AttachResult describes what an Attach did, also when it failed.
type AttachResult struct {
	// Check is the result of the checks; nil when an argument or an early check failed.
	Check *AttachCheck
	// Signal tells how SIGQUIT was sent: "pidfd" or "kill", empty when no signal was needed or
	// none was sent.
	Signal string
	// AttachFiles lists the attach files that were created, as paths inside the JVM's root.
	AttachFiles []string
	// Leftover lists the attach files that could not be removed.
	Leftover []string
	// ReturnCode is the value the agent's initialisation returned; -1 when the JVM did not report one.
	ReturnCode int
	// Message is the text of the JVM after the status line, without control characters and
	// without the agent argument. It can still hold other output of the JVM; treat it as untrusted.
	Message string
}

// attachState is what a check collects and the steps after it use.
type attachState struct {
	AttachCheck
	status Status
	root   *Root
}

func (j *JVM) rootPath() string {
	return filepath.Join(j.resolver.Proc.Root, strconv.Itoa(j.PID), "root")
}

func (j *JVM) socketPath() string { return "/tmp/.java_pid" + strconv.Itoa(j.NSPid) }

// CheckAttach runs the checks that need neither an attach file nor a signal. It fails with
// one of ErrAttachDisabled, ErrSigQuitNotCaught, ErrBadAttachSocket, ErrNoInstrument and
// ErrArthasRunning, with ErrProcessChanged when the pid belongs to another process now, or with
// the error of reading the process. Whether an attach file can be created is not checked here:
// the only way to know is to create it, which Attach does before it sends the signal.
func (j *JVM) CheckAttach(ctx context.Context) (*AttachCheck, error) {
	st, err := j.prepare(ctx)
	if err != nil {
		return nil, err
	}
	defer st.root.Close()
	check := st.AttachCheck
	return &check, nil
}

func (j *JVM) prepare(ctx context.Context) (*attachState, error) {
	r := j.resolver
	data, err := j.ReadPerfData(ctx)
	if err != nil {
		return nil, err
	}
	// The counter is a string of flags; the first one is "attach is allowed". jps reads the same one.
	switch caps, ok := data.Text("sun.rt.jvmCapabilities"); {
	case !ok || caps == "":
		return nil, fmt.Errorf("%w: hsperfdata has no sun.rt.jvmCapabilities counter", ErrAttachDisabled)
	case caps[0] != '1':
		return nil, fmt.Errorf("%w: sun.rt.jvmCapabilities starts with %q (-XX:+DisableAttachMechanism)", ErrAttachDisabled, caps[0])
	}
	home, ok := data.Text("java.property.java.home")
	if !ok {
		return nil, fmt.Errorf("%w: hsperfdata has no java.home, so java.instrument cannot be looked for", ErrNoInstrument)
	}
	status, err := r.Proc.Status(j.PID)
	if err != nil {
		return nil, vanished(j.PID, err)
	}
	root, err := OpenRoot(j.rootPath())
	if err != nil {
		return nil, vanished(j.PID, err)
	}
	st := &attachState{
		AttachCheck: AttachCheck{JavaHome: home, EUID: status.EUID, EGID: status.EGID, PerfData: data},
		status:      status,
		root:        root,
	}
	if err := j.checkLocked(st); err != nil {
		root.Close()
		return nil, err
	}
	return st, nil
}

// checkLocked runs the checks after the hsperfdata one. The order puts the cheap ones first.
func (j *JVM) checkLocked(st *attachState) error {
	fd, err := st.root.OpenSocket(j.socketPath(), st.status.EUID)
	switch {
	case err == nil:
		unix.Close(fd)
		st.SocketExists = true
	case errors.Is(err, fs.ErrNotExist):
		// No socket yet. A missing /tmp is not distinguished: the attach file check finds that.
	default:
		// Something else is at the name of the socket. HotSpot would replace it after a signal,
		// but it is more likely planted than left over, so nothing is sent.
		return fmt.Errorf("%w: %s: %s", ErrBadAttachSocket, j.socketPath(), errText(err))
	}
	if !st.SocketExists && !st.status.CatchesSIGQUIT() {
		return fmt.Errorf("%w (process %d)", ErrSigQuitNotCaught, j.PID)
	}
	has, err := hasInstrument(st.root, st.JavaHome)
	if err != nil {
		return err
	}
	if !has {
		return fmt.Errorf("%w: no libinstrument.so below %s and no java.instrument in its release file", ErrNoInstrument, st.JavaHome)
	}
	n, err := j.resolver.Proc.ArthasThreads(j.PID)
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: %d threads named arthas-*", ErrArthasRunning, n)
	}
	return j.resolver.check(j)
}

// instrumentArchs are the directories of the platform below lib/ in a JDK 8 runtime.
var instrumentArchs = []string{"amd64", "aarch64", "i386", "arm", "ppc64le", "ppc64", "s390x"}

// hasInstrument tells whether the runtime below home has the java.instrument module: the
// native library is there (lib/ in JDK 9 and later, lib/<arch>/ in JDK 8), or the release file
// of a runtime image lists the module. The path is the JVM's own property, so it is resolved
// inside the JVM's root.
func hasInstrument(root *Root, home string) (bool, error) {
	if !strings.HasPrefix(home, "/") || len(home) > maxPath-64 || strings.ContainsRune(home, 0) {
		return false, fmt.Errorf("%w: java.home is not an absolute path", ErrNoInstrument)
	}
	home = strings.TrimRight(home, "/")
	candidates := []string{home + "/lib/libinstrument.so"}
	for _, arch := range instrumentArchs {
		candidates = append(candidates, home+"/lib/"+arch+"/libinstrument.so")
	}
	for _, path := range candidates {
		st, err := root.Stat(path, true)
		if err == nil && st.Mode&unix.S_IFMT == unix.S_IFREG {
			return true, nil
		}
	}
	f, err := root.OpenFile(home + "/release")
	if err != nil {
		return false, nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxReleaseFile))
	if err != nil {
		return false, nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "MODULES=")
		if !ok {
			continue
		}
		for _, module := range strings.Fields(strings.Trim(value, `"`)) {
			if module == "java.instrument" {
				return true, nil
			}
		}
	}
	return false, nil
}

// validateAgent checks the argument of the load command before anything is sent.
func validateAgent(arg string) error {
	jar, _, _ := strings.Cut(arg, "=")
	switch {
	case arg == "":
		return fmt.Errorf("%w: empty", ErrAgentArgument)
	case len(arg) > maxAgentArgument:
		return fmt.Errorf("%w: %d bytes, HotSpot accepts at most %d", ErrAgentArgument, len(arg), maxAgentArgument)
	case strings.ContainsRune(arg, 0):
		return fmt.Errorf("%w: contains a NUL byte", ErrAgentArgument)
	case !strings.HasPrefix(jar, "/"):
		return fmt.Errorf("%w: the agent jar must be an absolute path", ErrAgentArgument)
	}
	for i := 0; i < len(jar); i++ {
		if jar[i] < ' ' || jar[i] == 0x7f {
			return fmt.Errorf("%w: the agent jar path has a control character", ErrAgentArgument)
		}
	}
	return nil
}

// Attach loads a Java agent into the JVM through the attach mechanism. The checks of CheckAttach
// run first. Then the attach file is created, SIGQUIT is sent unless the attach socket already
// exists, and the agent is loaded over the socket. The attach files are removed on every
// path. The result is never nil; it reports what was done also when the error is not nil,
// for example whether a signal was sent.
//
// The caller must prevent a second Attach or Arthas session on the same JVM at the same time.
// Creating a file in the file systems of the JVM, and connecting, cannot be interrupted: a
// hung network file system in the JVM's container delays the return beyond ctx.
func (j *JVM) Attach(ctx context.Context, req AttachRequest) (*AttachResult, error) {
	res := &AttachResult{ReturnCode: -1}
	if err := validateAgent(req.Agent); err != nil {
		return res, err
	}
	st, err := j.prepare(ctx)
	if err != nil {
		return res, err
	}
	defer st.root.Close()
	check := st.AttachCheck
	res.Check = &check
	return res, j.attach(ctx, st, res, req, st.status.EUID, st.status.EGID)
}

// attach is Attach after the checks. The identity is the one the connection uses.
func (j *JVM) attach(ctx context.Context, st *attachState, res *AttachResult, req AttachRequest, uid, gid uint32) (err error) {
	var created []*CreatedFile
	cleanup := func() error {
		var errs []error
		for _, f := range created {
			if err := f.Remove(); err != nil {
				res.Leftover = append(res.Leftover, f.Path)
				errs = append(errs, err)
			}
		}
		created = nil
		return errors.Join(errs...)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("removing the attach file: %w", cerr))
		}
	}()

	if !st.SocketExists {
		created, err = j.createAttachFiles(st)
		for _, f := range created {
			res.AttachFiles = append(res.AttachFiles, f.Path)
		}
		if err != nil {
			return err
		}
		method, err := j.resolver.signalQuit(j)
		if err != nil {
			return fmt.Errorf("sending SIGQUIT to process %d: %w", j.PID, err)
		}
		res.Signal = method
		wait := req.SocketWait
		if wait <= 0 {
			wait = defaultSocketWait
		}
		if err := j.waitForSocket(ctx, st, wait); err != nil {
			return err
		}
		// The JVM needs the file only to start the listener.
		if err := cleanup(); err != nil {
			return fmt.Errorf("removing the attach file: %w", err)
		}
	}
	reply := req.ReplyWait
	if reply <= 0 {
		reply = defaultReplyWait
	}
	raw, err := j.exchange(ctx, st, uid, gid, req.Agent, reply)
	if err != nil {
		return err
	}
	return parseLoadReply(raw, req.Agent, res)
}

// createAttachFiles makes the attach file where HotSpot looks for it: the working directory
// of the target, then /tmp. One of them is enough. /tmp is tried first, because it is scratch
// space and a working directory can be a volume the application watches, and because the name
// of /tmp does not depend on where the working directory link leads. The working directory is
// used when /tmp refuses the file. The file is made by creating it, because that is the only
// check that is not racy: a read-only file system, a full one or a missing permission all show.
//
// The file is made with the ids of the JVM's user (see createAs), so only where HotSpot's own
// attach client, which runs as that user, could make it. The user can take the name in /tmp
// first and so choose the working directory; as root the file would land there in any case.
func (j *JVM) createAttachFiles(st *attachState) ([]*CreatedFile, error) {
	name := ".attach_pid" + strconv.Itoa(j.NSPid)
	var reasons []string
	try := func(dir string) *CreatedFile {
		f, err := createAs(st.root, dir, name, st.status.EUID, st.status.EGID)
		if err != nil {
			reasons = append(reasons, dir+": "+errText(err))
			return nil
		}
		return f
	}
	if f := try("/tmp"); f != nil {
		return []*CreatedFile{f}, nil
	}
	// readlink gives the directory as the target sees it, but a path that was replaced by a
	// link in the meantime is resolved inside the root like any other.
	cwd, err := os.Readlink(filepath.Join(j.resolver.Proc.Root, strconv.Itoa(j.PID), "cwd"))
	switch {
	case err != nil:
		reasons = append(reasons, "working directory: "+errText(err))
	case !strings.HasPrefix(cwd, "/") || strings.HasSuffix(cwd, " (deleted)"):
		reasons = append(reasons, "working directory: not available")
	default:
		if f := try(cwd); f != nil {
			return []*CreatedFile{f}, nil
		}
	}
	return nil, fmt.Errorf("%w in process %d (%s); SIGQUIT would only make it print a thread dump", ErrNoAttachFile, j.PID, strings.Join(reasons, "; "))
}

// waitForSocket waits for the attach socket to appear.
func (j *JVM) waitForSocket(ctx context.Context, st *attachState, wait time.Duration) error {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	tick := time.NewTicker(socketPollEvery)
	defer tick.Stop()
	for {
		fd, err := st.root.OpenSocket(j.socketPath(), st.status.EUID)
		switch {
		case err == nil:
			unix.Close(fd)
			return nil
		case errors.Is(err, fs.ErrNotExist):
		default:
			return fmt.Errorf("%w: %s: %s", ErrBadAttachSocket, j.socketPath(), errText(err))
		}
		if err := j.resolver.check(j); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("%w within %v (process %d got SIGQUIT; the JVM may have printed a thread dump)", ErrAttachTimeout, wait, j.PID)
		case <-tick.C:
		}
	}
}

// exchange connects to the attach socket as uid and gid, sends the load command and returns
// the JVM's answer.
func (j *JVM) exchange(ctx context.Context, st *attachState, uid, gid uint32, arg string, wait time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	// The descriptor is made as root, before the identity changes; the connection goes to the
	// inode that was checked.
	fd, err := st.root.OpenSocket(j.socketPath(), st.status.EUID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %s", ErrBadAttachSocket, j.socketPath(), errText(err))
	}
	defer unix.Close(fd)
	if j.resolver.beforeConnect != nil {
		j.resolver.beforeConnect()
	}
	if err := j.resolver.check(j); err != nil {
		return nil, err
	}
	conn, err := dialUnixAs(ctx, "/proc/self/fd/"+strconv.Itoa(fd), uid, gid)
	if err != nil {
		return nil, fmt.Errorf("connecting to the attach socket of process %d: %w", j.PID, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	// Version 1 of the protocol: the version, the command and three arguments, each ended by NUL.
	request := "1\x00load\x00instrument\x00false\x00" + arg + "\x00"
	if _, err := io.WriteString(conn, request); err != nil {
		return nil, j.exchangeError("sending the load command", err, ctx)
	}
	raw, err := io.ReadAll(io.LimitReader(conn, maxAttachReply))
	if err != nil {
		return nil, j.exchangeError("reading the answer", err, ctx)
	}
	return raw, nil
}

func (j *JVM) exchangeError(what string, err error, ctx context.Context) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%s: %w", what, ctx.Err())
	}
	if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		// JDK 8 closes the connection of a peer that is not its own user.
		return fmt.Errorf("%w: the JVM closed the connection while %s (it accepts only its own user, or root with JDK 9 and later)", ErrAttachRefused, what)
	}
	return fmt.Errorf("%s: %w", what, err)
}

// parseLoadReply reads the JVM's answer to the load command. The first line is the status of
// the command, 0 for success. The load command then reports what the agent's initialisation
// returned: "return code: <n>" from JDK 9 on, a bare "<n>" as the first line with JDK 8. Any
// other text is an error message. The argument and its options are removed from the text,
// because a JVM can quote them.
func parseLoadReply(raw []byte, arg string, res *AttachResult) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("%w: the JVM closed the connection without an answer (the argument may be too long or the agent unreadable)", ErrAttachRefused)
	}
	first, rest, _ := strings.Cut(string(raw), "\n")
	status, err := strconv.Atoi(strings.TrimSpace(first))
	if err != nil {
		return fmt.Errorf("%w: unexpected answer %q", ErrAttachRefused, javaText(first, arg))
	}
	res.Message = javaText(rest, arg)
	if status != 0 {
		return fmt.Errorf("%w: status %d: %s", ErrAttachRefused, status, res.Message)
	}
	bare := true // JDK 8 style is accepted only as the first line of text
	for _, line := range strings.Split(rest, "\n") {
		line = strings.TrimSpace(line)
		value, ok := strings.CutPrefix(line, "return code: ")
		if !ok && bare && line != "" {
			if _, err := strconv.Atoi(line); err == nil {
				value, ok = line, true
			}
		}
		if line != "" {
			bare = false
		}
		if ok {
			code, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("%w: unexpected return code %q", ErrAttachRefused, javaText(value, arg))
			}
			res.ReturnCode = code
			if code != 0 {
				return fmt.Errorf("%w: the agent's initialisation returned %d", ErrAttachRefused, code)
			}
			return nil
		}
	}
	if strings.TrimSpace(rest) != "" {
		// Status 0 with an unknown text: the JVM did not say that the agent was initialised.
		return fmt.Errorf("%w: unexpected answer: %s", ErrAttachRefused, res.Message)
	}
	return nil
}

// javaText makes text from the JVM safe to show: the agent argument and its options are
// replaced, control characters and invalid UTF-8 are dropped, and the length is bounded.
func javaText(text, arg string) string {
	if arg != "" {
		text = strings.ReplaceAll(text, arg, "<agent>")
		if _, options, ok := strings.Cut(arg, "="); ok && options != "" {
			text = strings.ReplaceAll(text, options, "<options>")
		}
	}
	var b strings.Builder
	for _, r := range strings.TrimSpace(text) {
		switch {
		case r == utf8.RuneError, r < ' ' && r != '\n' && r != '\t', r == 0x7f:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
		if b.Len() >= maxJavaMessage {
			b.WriteString("...")
			break
		}
	}
	return b.String()
}
