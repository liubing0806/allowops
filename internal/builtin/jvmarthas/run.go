package jvmarthas

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/jvmtarget"
)

// Words of the status row in the call section of the output.
const (
	StatusOK          = "ok"
	StatusRefused     = "refused"
	StatusUnsupported = "unsupported"
	StatusBusy        = "busy"
	StatusFailed      = "failed"
	StatusTimeout     = "timeout"
	StatusCancelled   = "cancelled"
	StatusAborted     = "aborted_by_guard"
)

// noBlockingThread is the message of Arthas when thread -b finds no thread that blocks another.
const noBlockingThread = "No most blocking thread found!"

// CheckPreviousSession is the check that refuses a call while an earlier session of the same JVM cannot be ended.
const CheckPreviousSession = "previous_session"

const (
	// sessionSlack is added to the execution time of the command for the idle timeout of the session.
	sessionSlack = 30 * time.Second
	// recordLifetime is added to the execution time for the deadline of a session record. The deadline
	// only informs the reader of the record; a record is recovered as soon as its call has ended.
	recordLifetime = 2 * time.Minute
	// initAttempts is the number of tries of init_session: the HTTP server may need a moment after it listens.
	initAttempts = 3
	// maxReason bounds the characters of a reason in the output.
	maxReason = 400
)

// Defaults of Env.
const (
	defaultStopWait     = 10 * time.Second
	defaultPollEvery    = 100 * time.Millisecond
	defaultSampleEvery  = time.Second
	defaultListenWait   = 10 * time.Second
	defaultAttachSettle = 3 * time.Second
	defaultCPUWindow    = 5 * time.Second
	// defaultJobGrace covers the end of a job after its enhancement: Arthas ends the job when
	// --timeout expires, and the last results still have to be read.
	defaultJobGrace = 10 * time.Second
)

func (e Env) withDefaults() Env {
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.NewPassword == nil {
		e.NewPassword = arthas.NewPassword
	}
	if e.StopWait <= 0 {
		e.StopWait = defaultStopWait
	}
	if e.PollEvery <= 0 {
		e.PollEvery = defaultPollEvery
	}
	if e.SampleEvery <= 0 {
		e.SampleEvery = defaultSampleEvery
	}
	if e.ListenWait <= 0 {
		e.ListenWait = defaultListenWait
	}
	if e.AttachSettle <= 0 {
		e.AttachSettle = defaultAttachSettle
	}
	if e.CPUWindow <= 0 {
		e.CPUWindow = defaultCPUWindow
	}
	if e.JobGrace <= 0 {
		e.JobGrace = defaultJobGrace
	}
	if e.Arch == "" {
		e.Arch = runtime.GOARCH
	}
	return e
}

// Params are the caller's inputs.
type Params struct {
	Target string
	// Request holds the arguments of the command. Its Kind is ignored: the configuration fixes the command.
	Request arthas.Request
}

// Result is the handler output.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Run executes one call on this host.
func Run(ctx context.Context, cfg Config, p Params, mask func(string) string) (Result, error) {
	return RunWith(ctx, NewEnv(), cfg, p, mask)
}

// RunWith is Run with the given environment. Only a cancelled or expired context is returned as an
// error, after the Arthas server was shut down; everything else is in the Result. mask is applied to
// the output line by line.
func RunWith(ctx context.Context, env Env, cfg Config, p Params, mask func(string) string) (Result, error) {
	if err := cfg.Validate(); err != nil {
		return Result{ExitCode: builtin.ExitFailure}, err
	}
	env = env.withDefaults()
	eff := cfg.Effective()
	req := p.Request
	req.Kind = eff.Command
	cmd, err := arthas.Build(req, arthas.Policy{
		SyspropKeys: eff.SyspropKeys, ExecTimeout: eff.ExecTimeout, ClassPrefixes: eff.ClassPrefixes,
		Enhance: eff.EnhanceDuration, MaxMethods: eff.MaxMethods, ObjectSizeLimit: eff.ObjectSizeLimit,
	})
	if err != nil {
		return failure(mask, "%v", err), nil
	}
	target, ok := eff.Targets[p.Target]
	if !ok {
		return failure(mask, "unknown target %q; allowed: %s", p.Target, strings.Join(eff.TargetNames(), ", ")), nil
	}
	c := &call{env: env, cfg: eff, cmd: cmd, target: target, rep: report{command: string(cmd.Kind), target: target.Name}}
	err = c.run(ctx)
	return c.rep.result(mask), err
}

func failure(mask func(string) string, format string, args ...any) Result {
	return Result{Stderr: maskText(mask, "jvm_arthas: "+oneLine(fmt.Sprintf(format, args...))+"\n"), ExitCode: builtin.ExitFailure}
}

// report collects what the output tells about the call.
type report struct {
	command, target string
	pid             int
	status          string
	check, reason   string
	attach          string
	earlier         string
	cleanup         string
	cleanupFailed   bool
	body            string
	// cpuBefore, affect and enhanced are the rows of the L2 commands: the CPU use before the
	// attach, the enhancer result, and the classes left enhanced after the clean-up.
	cpuBefore string
	affect    string
	enhanced  string
}

func (r *report) result(mask func(string) string) Result {
	var b strings.Builder
	b.WriteString("# call\n")
	row := func(key, value string) {
		if value != "" {
			b.WriteString(key + "\t" + oneLine(value) + "\n")
		}
	}
	row("command", r.command)
	row("target", r.target)
	if r.pid > 0 {
		row("pid", strconv.Itoa(r.pid))
	}
	row("status", r.status)
	row("check", r.check)
	row("reason", r.reason)
	row("cpu_before", r.cpuBefore)
	row("attach", r.attach)
	row("affect", r.affect)
	row("earlier_sessions", r.earlier)
	row("enhanced_classes", r.enhanced)
	row("cleanup", r.cleanup)
	if r.body != "" {
		b.WriteString("\n" + r.body)
	}
	res := Result{Stdout: maskText(mask, b.String())}
	if r.status != StatusOK {
		line := "jvm_arthas: " + r.status
		if r.check != "" {
			line += " (" + r.check + ")"
		}
		if r.reason != "" {
			line += ": " + oneLine(r.reason)
		}
		res.Stderr = line + "\n"
	}
	if r.cleanupFailed {
		res.Stderr += "jvm_arthas: cleanup failed, the Arthas server may still run; " + oneLine(r.cleanup) + "\n"
	}
	res.Stderr = maskText(mask, res.Stderr)
	res.ExitCode = builtin.ExitSuccess
	if r.status != StatusOK || r.cleanupFailed {
		res.ExitCode = builtin.ExitFailure
	}
	return res
}

// oneLine makes text from other programs fit a row: control characters and runs of white space become one space.
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if runes := []rune(s); len(runes) > maxReason {
		s = string(runes[:maxReason]) + "..."
	}
	return s
}

// maskText applies mask to every line of text.
func maskText(mask func(string) string, text string) string {
	if mask == nil || text == "" {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = mask(line)
	}
	return strings.Join(lines, "\n")
}

// call is the state of one run.
type call struct {
	env    Env
	cfg    Config
	cmd    arthas.Command
	target jvmtarget.Target
	rep    report
}

func (c *call) fail(format string, args ...any) {
	c.rep.status, c.rep.reason = StatusFailed, fmt.Sprintf(format, args...)
}

func (c *call) refuse(status, check, format string, args ...any) {
	c.rep.status, c.rep.check, c.rep.reason = status, check, fmt.Sprintf(format, args...)
}

// interrupted records that the context of the call ended and returns its error.
func (c *call) interrupted(ctx context.Context) error {
	err := ctxErr(ctx)
	c.rep.status, c.rep.reason = ctxStatus(err), err.Error()
	return err
}

// ctxErr is the error of the context, and context.DeadlineExceeded as soon as its deadline has
// passed. The Arthas client and the attach set that deadline on their connections, and it can
// fire before the timer of the context: a read fails on the deadline while ctx.Err() is still nil.
func ctxErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func ctxStatus(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return StatusTimeout
	}
	return StatusCancelled
}

func (c *call) run(ctx context.Context) error {
	if ctxErr(ctx) != nil {
		return c.interrupted(ctx)
	}
	state, err := OpenState(c.env.StateDir, c.env.StateOwner)
	if err != nil {
		c.fail("state directory: %v", err)
		return nil
	}
	defer state.Close()
	boot, err := c.env.Host.BootID()
	if err != nil {
		c.fail("boot id: %v", err)
		return nil
	}
	// The lock is keyed by the process, so the target is resolved first. Resolving only reads.
	proc, err := c.env.Resolver.Resolve(ctx, c.target)
	if err != nil {
		if ctxErr(ctx) != nil {
			return c.interrupted(ctx)
		}
		c.fail("target %q: %v", c.target.Name, err)
		return nil
	}
	c.rep.pid = proc.PID
	key := Key{BootID: boot, PID: proc.PID, StartTime: proc.StartTime}
	lock, err := state.TryLock(key)
	switch {
	case errors.Is(err, ErrBusy):
		c.rep.status, c.rep.reason = StatusBusy, err.Error()
		return nil
	case err != nil:
		c.fail("lock: %v", err)
		return nil
	}
	defer lock.Unlock()

	if c.recoverEarlier(ctx, state, boot, key) {
		c.prepare(ctx, state, proc, key)
	}
	return c.endedBy(ctx)
}

// endedBy returns the error of the context when it ended the call without a result.
func (c *call) endedBy(ctx context.Context) error {
	if c.rep.status == StatusCancelled || c.rep.status == StatusTimeout {
		return ctxErr(ctx)
	}
	return nil
}

// recoverEarlier ends what earlier calls left behind: first the session of this JVM, which the
// call cannot go on without, then those of other JVMs, which are best effort. It reports
// whether the call may go on.
func (c *call) recoverEarlier(ctx context.Context, state *State, boot string, key Key) bool {
	var rec Recovery
	own, err := recoverKey(ctx, c.env, state, boot, key)
	switch {
	case err != nil:
		rec.Failed = append(rec.Failed, err.Error())
	case own == recovered:
		rec.Cleaned++
	case own == stale:
		rec.Stale++
	}
	if err == nil {
		rec.add(recoverAll(ctx, c.env, state, boot, &key))
	}
	c.rep.earlier = rec.String()
	if err != nil {
		if ctxErr(ctx) != nil {
			c.interrupted(ctx)
			return false
		}
		c.refuse(StatusRefused, CheckPreviousSession, "an earlier session of this JVM could not be ended: %v", err)
		return false
	}
	return true
}

// prepare runs the checks, then attaches, runs the command and shuts the server down.
func (c *call) prepare(ctx context.Context, state *State, proc *Process, key Key) {
	check, err := proc.JVM.CheckAttach(ctx)
	if err != nil {
		if ctxErr(ctx) != nil {
			c.interrupted(ctx)
			return
		}
		status := StatusRefused
		if errors.Is(err, jvmtarget.ErrAttachDisabled) || errors.Is(err, jvmtarget.ErrNoInstrument) || errors.Is(err, jvmtarget.ErrSigQuitNotCaught) {
			status = StatusUnsupported
		}
		c.refuse(status, CheckAttachState, "%v", err)
		return
	}
	if check.PerfData == nil {
		c.fail("the JVM published no hsperfdata")
		return
	}
	counter, err := state.Counter(key)
	if err != nil {
		c.fail("attach counter: %v", err)
		return
	}
	if r := runChecks(checkInput{
		Config: c.cfg, Command: c.cmd, PID: proc.PID, Perf: check.PerfData, Counter: counter,
		Now: c.env.Now(), Host: c.env.Host, Arch: c.env.Arch,
	}); r != nil {
		status := StatusRefused
		if r.Check == CheckJVMVersion || r.Check == CheckArchitecture {
			status = StatusUnsupported
		}
		c.refuse(status, r.Check, "%s", r.Reason)
		return
	}
	root, err := c.env.Host.OpenRoot(proc.PID)
	if err != nil {
		c.refuse(StatusRefused, CheckArthasFiles, "the file system of the process cannot be opened: %v", err)
		return
	}
	err = verifyFiles(root, c.cfg.ArthasDir, c.cfg.SHA256)
	root.Close()
	if err != nil {
		c.refuse(StatusRefused, CheckArthasFiles, "%v", err)
		return
	}
	port, err := c.env.Host.PickPort(proc.PID, c.cfg.HTTPPortMin, c.cfg.HTTPPortMax)
	if err != nil {
		c.refuse(StatusRefused, CheckPortRange, "%v", err)
		return
	}
	// The CPU check comes last: it takes a few seconds, which should end right before the attach.
	if slices.Contains(c.cmd.PreChecks, arthas.PreCheckCPU) {
		row, r, err := checkCPU(ctx, c.env, c.cfg, proc.PID)
		c.rep.cpuBefore = row
		if err != nil {
			c.interrupted(ctx)
			return
		}
		if r != nil {
			c.refuse(StatusRefused, r.Check, "%s", r.Reason)
			return
		}
	}
	password, err := c.env.NewPassword()
	if err != nil {
		c.fail("password: %v", err)
		return
	}
	agent := arthas.AgentConfig{
		AgentJar: path.Join(c.cfg.ArthasDir, "arthas-agent.jar"), CoreJar: path.Join(c.cfg.ArthasDir, "arthas-core.jar"),
		HTTPPort: port, Password: password, Enabled: c.cmd.Enabled(), SessionTimeout: c.cmd.ExecTimeout + c.cmd.Enhance + sessionSlack,
	}
	arg, err := agent.Argument()
	if err != nil {
		c.fail("agent argument: %v", err)
		return
	}

	// The record goes to disk before the attach, so that a call that dies after it can be recovered.
	now := c.env.Now()
	rec := Record{
		Version: recordVersion, BootID: key.BootID, PID: key.PID, StartTime: key.StartTime, Target: c.target.Name,
		Command: string(c.cmd.Kind), Port: port, Password: password, Created: now, Deadline: now.Add(c.cmd.ExecTimeout + c.cmd.Enhance + recordLifetime),
	}
	if err := state.WriteRecord(rec); err != nil {
		c.fail("session record: %v", err)
		return
	}
	counter, err = state.AddAttach(key, now, gcCount(check.PerfData))
	if err != nil {
		state.RemoveRecord(key)
		c.fail("attach counter: %v", err)
		return
	}
	c.rep.attach = fmt.Sprintf("%d of %d", counter.Attaches, c.cfg.Checks.MaxAttaches)
	c.serve(ctx, state, proc, rec, arg)
}

// outcome is what the attach and the command produced.
type outcome struct {
	status, check, reason string
	body                  string
	// session is the Arthas session, empty until init_session worked.
	session string
	// mayExist tells that an Arthas server may be running and has to be shut down.
	mayExist bool
}

// serve attaches, runs the command and shuts the server down.
func (c *call) serve(ctx context.Context, state *State, proc *Process, rec Record, arg string) {
	client := newClient(proc, rec.Port, rec.Password)
	out := c.attachAndRun(ctx, state, proc, client, &rec, arg)
	if err := ctxErr(ctx); out.status != StatusOK && err != nil {
		out.status, out.reason = ctxStatus(err), err.Error()
	}
	c.rep.status, c.rep.check, c.rep.reason, c.rep.body = out.status, out.check, out.reason, out.body
	key := rec.Key()
	if !out.mayExist {
		state.RemoveRecord(key)
		return
	}
	sd := shutdown(ctx, c.env, proc, rec.Port, client, out.session, c.cmd.Level == 2)
	if c.cmd.Level == 2 {
		c.confirmReset(sd)
	}
	switch {
	case !sd.stopped:
		// The record stays: the next call, or the start of the agent, ends the server.
		c.rep.cleanup, c.rep.cleanupFailed = "failed: "+sd.problem(), true
	case sd.steps != nil:
		state.RemoveRecord(key)
		c.rep.cleanup = "stopped, with errors: " + sd.steps.Error()
	default:
		state.RemoveRecord(key)
		c.rep.cleanup = "ok"
	}
}

func newClient(proc *Process, port int, password string) *arthas.Client {
	// The password is never empty, so NewClient cannot fail.
	client, _ := arthas.NewClient(arthas.Config{
		Dial:     func(ctx context.Context) (net.Conn, error) { return proc.JVM.DialTCP(ctx, port) },
		Password: password,
	})
	return client
}

func (c *call) attachAndRun(ctx context.Context, state *State, proc *Process, client *arthas.Client, rec *Record, arg string) outcome {
	// Looking for a server uses a context that cannot be cancelled: after a cancelled attach
	// the server may still come up, and it has to be found to be shut down.
	bg := context.WithoutCancel(ctx)
	if _, err := proc.JVM.Attach(ctx, jvmtarget.AttachRequest{Agent: arg}); err != nil {
		// The load can have worked although the reply did not arrive.
		present := waitPresent(bg, c.env, proc, rec.Port, c.env.AttachSettle)
		return outcome{status: StatusFailed, reason: "attach: " + err.Error(), mayExist: present}
	}
	if err := waitListening(ctx, c.env, proc, rec.Port); err != nil {
		return outcome{status: StatusFailed, reason: err.Error(), mayExist: serverPresent(c.env, proc, rec.Port)}
	}
	session, err := initSession(ctx, c.env, client)
	if err != nil {
		return outcome{status: StatusFailed, reason: err.Error(), mayExist: true}
	}
	rec.SessionID = session.ID
	if err := state.WriteRecord(*rec); err != nil {
		return outcome{status: StatusFailed, reason: "session record: " + err.Error(), session: session.ID, mayExist: true}
	}
	if c.cmd.Enhance > 0 {
		return c.job(ctx, proc, client, session)
	}
	return c.command(ctx, proc, client, session.ID)
}

// guardConfig returns the thresholds of the guard. For an L2 command the settle time is at least
// DefaultSettle: the first seconds of an enhancement raise the CPU use of the JVM (plan 3.3).
func (c *call) guardConfig() Guard {
	g := c.cfg.Guard
	if c.cmd.Level == 2 && g.Settle < DefaultSettle {
		g.Settle = DefaultSettle
	}
	return g
}

// command runs the command while the guard watches the process. When the guard trips, the
// command is cancelled and the call reports the abort whatever the command returned.
func (c *call) command(ctx context.Context, proc *Process, client *arthas.Client, session string) outcome {
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	aborted := make(chan *Abort, 1)
	go func() {
		abort := watch(execCtx, c.env, c.guardConfig(), proc, c.env.Now())
		if abort != nil {
			cancel()
		}
		aborted <- abort
	}()
	resp, execErr := client.Exec(execCtx, session, c.cmd)
	cancel()
	abort := <-aborted
	out := outcome{session: session, mayExist: true}
	var stateErr *arthas.StateError
	switch {
	case abort != nil:
		out.status, out.check, out.reason = StatusAborted, abort.Check, abort.Detail
	case errors.Is(execErr, arthas.ErrInterrupted):
		out.status = StatusTimeout
		out.reason = fmt.Sprintf("the command did not finish within %s", c.cmd.ExecTimeout)
		if errors.As(execErr, &stateErr) && stateErr.Response != nil {
			// What the interrupted job produced is still worth showing.
			if text, err := arthas.Render(c.cmd.Kind, stateErr.Response); err == nil {
				out.body = text
			}
		}
	case execErr != nil:
		out.status, out.reason = StatusFailed, execErr.Error()
	default:
		text, err := arthas.Render(c.cmd.Kind, resp)
		var failed *arthas.CommandError
		switch {
		case errors.As(err, &failed) && c.cmd.Kind == arthas.KindThreadBlocking && failed.Message == noBlockingThread:
			// thread -b reports "nothing found" as a failure; the answer is that no thread blocks another.
			out.status, out.body = StatusOK, "# blocking lock\nnone\n"
		case err != nil:
			out.status, out.reason = StatusFailed, err.Error()
		default:
			out.status, out.body = StatusOK, text
		}
	}
	return out
}

// job runs an enhancing command: its setup commands, then the command as a background job, while
// the guard watches the process from the start of the enhancement. RunJob returns as soon as the
// enhancer result is outside the limits of the command; the clean-up then interrupts the job and
// resets the class.
func (c *call) job(ctx context.Context, proc *Process, client *arthas.Client, s arthas.Session) outcome {
	out := outcome{session: s.ID, mayExist: true}
	if err := client.Setup(ctx, s.ID, c.cmd); err != nil {
		out.status, out.reason = StatusFailed, "setup: "+err.Error()
		return out
	}
	jobCtx, cancel := context.WithTimeout(ctx, c.cmd.Enhance+c.env.JobGrace)
	defer cancel()
	aborted := make(chan *Abort, 1)
	go func() {
		abort := watch(jobCtx, c.env, c.guardConfig(), proc, c.env.Now())
		if abort != nil {
			cancel()
		}
		aborted <- abort
	}()
	job, err := client.RunJob(jobCtx, s, c.cmd)
	timedOut := err != nil && errors.Is(ctxErr(jobCtx), context.DeadlineExceeded)
	cancel()
	abort := <-aborted
	if job != nil && job.Affect != nil {
		c.rep.affect = job.Affect.String()
	}
	var affect *arthas.AffectError
	switch {
	case abort != nil:
		out.status, out.check, out.reason = StatusAborted, abort.Check, abort.Detail
		out.body = c.partial(job)
	case errors.As(err, &affect):
		out.status, out.check, out.reason = StatusFailed, CheckAffect, affect.Reason
	case timedOut:
		out.status = StatusTimeout
		out.reason = fmt.Sprintf("the job did not end within %s of the start of the enhancement", c.cmd.Enhance+c.env.JobGrace)
		out.body = c.partial(job)
	case err != nil:
		out.status, out.reason = StatusFailed, err.Error()
	default:
		if job.Affect == nil {
			// The n-th result ended the job before Arthas added the enhancer result, which Arthas
			// then drops (EnhancerCommand.enhance, ProcessImpl.appendResult). The reset count of
			// the clean-up still tells how many classes were enhanced.
			c.rep.affect = "not reported: the job ended before Arthas reported the enhancement"
		}
		text, err := arthas.Render(c.cmd.Kind, job.Response())
		if err != nil {
			out.status, out.reason = StatusFailed, err.Error()
		} else {
			out.status, out.body = StatusOK, text
		}
	}
	return out
}

// partial renders the results a job produced before it was stopped.
func (c *call) partial(job *arthas.Job) string {
	if job == nil || len(job.Results) == 0 {
		return ""
	}
	partial := *job
	partial.Ended = false
	text, err := arthas.Render(c.cmd.Kind, partial.Response())
	if err != nil {
		return ""
	}
	return text
}

// confirmReset writes the enhanced_classes row of an L2 command. A call that would be ok fails
// when the clean-up cannot confirm that no class stays enhanced, or when an enhancing command
// enhanced more than one class.
func (c *call) confirmReset(sd shutdownResult) {
	restored := "an unknown number of classes"
	if sd.restored >= 0 {
		restored = strconv.Itoa(sd.restored)
	}
	switch {
	case sd.left < 0:
		reason := "no confirming reset"
		if sd.leftErr != nil {
			reason = sd.leftErr.Error()
		}
		c.rep.enhanced = "unconfirmed: " + reason
		c.failIfOK(CheckEnhancedClasses, "the clean-up could not confirm that no class stays enhanced: %s", reason)
	case sd.left > 0:
		c.rep.enhanced = fmt.Sprintf("unconfirmed: a second reset still restored %d classes (reset restored %s)", sd.left, restored)
		c.failIfOK(CheckEnhancedClasses, "a second reset still restored %d classes", sd.left)
	default:
		c.rep.enhanced = "0 (reset restored " + restored + ")"
		if c.cmd.Enhance > 0 && sd.restored > 1 {
			c.failIfOK(CheckAffect, "the reset restored %d classes, the limit is 1", sd.restored)
		}
	}
}

// failIfOK marks a call that is ok so far as failed.
func (c *call) failIfOK(check, format string, args ...any) {
	if c.rep.status == StatusOK {
		c.refuse(StatusFailed, check, format, args...)
	}
}

// sleep waits for d or until ctx ends.
func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// waitListening waits for the Arthas port to open after the attach.
func waitListening(ctx context.Context, env Env, proc *Process, port int) error {
	deadline := time.Now().Add(env.ListenWait)
	for {
		listening, err := env.Host.IsListening(proc.PID, port)
		if err != nil {
			return fmt.Errorf("port %d: %w", port, err)
		}
		if listening {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the Arthas server did not open port %d within %s", port, env.ListenWait)
		}
		sleep(ctx, env.PollEvery)
	}
}

// initSession creates the Arthas session. The HTTP server can need a moment after the port opened.
func initSession(ctx context.Context, env Env, client *arthas.Client) (arthas.Session, error) {
	var err error
	for attempt := 0; attempt < initAttempts; attempt++ {
		var session arthas.Session
		if session, err = client.OpenSession(ctx); err == nil {
			return session, nil
		}
		if ctx.Err() != nil || errors.Is(err, arthas.ErrUnauthorized) {
			break
		}
		sleep(ctx, env.PollEvery)
	}
	return arthas.Session{}, fmt.Errorf("init_session: %w", err)
}

// stopSent reports whether the stop request of a clean-up reached the server.
func stopSent(r arthas.CleanupResult) bool {
	for _, step := range r.Steps {
		if step.Name == arthas.StepStop {
			return step.Sent
		}
	}
	return false
}

// serverPresent reports whether an Arthas server may be running: its port is open, or the
// JVM has arthas- threads.
func serverPresent(env Env, proc *Process, port int) bool {
	state := inspect(env, proc, port)
	return state.listening || state.threads > 0 || state.err != nil && !state.gone
}

// waitPresent waits up to wait for a server to show.
func waitPresent(ctx context.Context, env Env, proc *Process, port int, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		if serverPresent(env, proc, port) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		sleep(ctx, env.PollEvery)
	}
}

// serverState is what the host knows about the Arthas server of a JVM.
type serverState struct {
	listening bool
	threads   int
	// gone is true when the process itself is gone, so that nothing of the server is left.
	gone bool
	err  error
}

func (s serverState) stopped() bool { return s.gone || s.err == nil && !s.listening && s.threads == 0 }

func inspect(env Env, proc *Process, port int) serverState {
	var s serverState
	var err1, err2 error
	s.listening, err1 = env.Host.IsListening(proc.PID, port)
	s.threads, err2 = env.Host.ArthasThreads(proc.PID)
	if s.err = errors.Join(err1, err2); s.err != nil {
		start, err := env.Host.StartTime(proc.PID)
		// A process that is gone reads as ENOENT or ESRCH, depending on the file.
		s.gone = errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) || err == nil && start != proc.StartTime
	}
	return s
}

// shutdownResult is how a shutdown ended.
type shutdownResult struct {
	// stopped means the port is closed and no arthas- thread is left, or the JVM is gone.
	stopped bool
	// steps holds the errors of the steps of the clean-up sequence.
	steps error
	// verify says why the server was still there after the wait.
	verify error
	// restored is the number of classes the reset steps restored, and -1 when Arthas reported
	// none. left is what the confirming reset of the last clean-up restored, and -1 with leftErr
	// when it is unknown or no confirming reset ran.
	restored int
	left     int
	leftErr  error
}

func (r shutdownResult) problem() string {
	return oneLine(errors.Join(r.steps, r.verify).Error())
}

// shutdown runs the clean-up sequence, with a time budget of its own, and then waits for the port to close
// and the threads to end. Whether the sequence worked is decided by the state of the JVM, not by the
// answers of Arthas: stop is answered with a closed connection.
//
// The sequence is repeated while stop did not reach the server and the server may still be starting:
// its threads exist before its HTTP port is bound, and a server that nobody stops runs on.
//
// confirm adds a confirming reset to the sequence, for a call that may have enhanced classes.
func shutdown(ctx context.Context, env Env, proc *Process, port int, client *arthas.Client, session string, confirm bool) shutdownResult {
	bg := context.WithoutCancel(ctx)
	startBy := time.Now().Add(env.ListenWait)
	opts := env.Cleanup
	opts.ConfirmReset = confirm
	restored := -1
	run := func() arthas.CleanupResult {
		r := client.Cleanup(bg, session, opts)
		if n, _, _ := r.Enhanced(); n >= 0 {
			restored = max(restored, 0) + n
		}
		return r
	}
	cleanup := run()
	for !stopSent(cleanup) && time.Now().Before(startBy) && !inspect(env, proc, port).stopped() {
		sleep(bg, env.PollEvery)
		cleanup = run()
	}
	res := shutdownResult{steps: cleanup.Err(), restored: restored, left: -1}
	if confirm {
		_, res.left, res.leftErr = cleanup.Enhanced()
	}
	deadline := time.Now().Add(env.StopWait)
	for {
		state := inspect(env, proc, port)
		if state.stopped() {
			res.stopped, res.verify = true, nil
			return res
		}
		res.verify = state.err
		if res.verify == nil {
			res.verify = fmt.Errorf("port %d listening: %v, arthas- threads: %d", port, state.listening, state.threads)
		}
		if time.Now().After(deadline) {
			res.verify = fmt.Errorf("the Arthas server did not stop within %s: %w", env.StopWait, res.verify)
			return res
		}
		sleep(bg, env.PollEvery)
	}
}
