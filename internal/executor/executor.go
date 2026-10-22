package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/liubing0806/allowops/internal/redact"
	"golang.org/x/sys/unix"
)

const DefaultMaxScan int64 = 256 * 1024 * 1024

// pipeDrainDelay bounds how long Wait reads output after the process exits.
// At exit at most one pipe buffer is unread; a longer wait means a descendant
// that left the process group still holds the pipes.
const pipeDrainDelay = 5 * time.Second

var errScanLimit = errors.New("stdout scan limit reached")

type Result struct {
	ExitCode             int          `json:"exit_code"`
	DurationMS           int64        `json:"duration_ms"`
	Stdout               string       `json:"stdout"`
	Stderr               string       `json:"stderr"`
	Truncated            bool         `json:"truncated"`
	ScanLimitReached     bool         `json:"scan_limit_reached"`
	StatusCode           int          `json:"status_code,omitempty"`
	ResourceLimitReached bool         `json:"resource_limit_reached,omitempty"`
	Steps                []StepResult `json:"steps,omitempty"`
}
type StepResult struct {
	Index            int    `json:"index"`
	Name             string `json:"name"`
	Skipped          bool   `json:"skipped,omitempty"`
	ExitCode         *int   `json:"exit_code,omitempty"`
	DurationMS       int64  `json:"duration_ms"`
	Stdout           string `json:"stdout"`
	Stderr           string `json:"stderr"`
	Truncated        bool   `json:"truncated"`
	ScanLimitReached bool   `json:"scan_limit_reached"`
}

// Callbacks run synchronously. A callback error stops execution. Started is
// invoked once after the first successful process start, or before a builtin
// handler runs. StepCompleted receives already redacted, bounded output.
type Callbacks struct {
	Started       func() error
	StepCompleted func(StepResult, error) error
}

// A13: steps share stdout+stderr budget and use the first failed exit code.
// Non-step actions preserve P1's independent stdout/stderr budgets.
func stepBudget(limit int64) *outputBudget { return &outputBudget{remaining: limit} }

type outputBudget struct {
	mu        sync.Mutex
	remaining int64
}
type limitedOutput struct {
	buffer    bytes.Buffer
	limit     int64
	budget    *outputBudget
	truncated bool
}

func (w *limitedOutput) Write(p []byte) (int, error) {
	remaining := w.limit - int64(w.buffer.Len())
	if w.budget != nil {
		w.budget.mu.Lock()
		defer w.budget.mu.Unlock()
		remaining = w.budget.remaining
	}
	n := min(int64(len(p)), remaining)
	if n > 0 {
		_, _ = w.buffer.Write(p[:n])
		if w.budget != nil {
			w.budget.remaining -= n
		}
	}
	if n < int64(len(p)) {
		w.truncated = true
	}
	return len(p), nil
}

// room reports how many more bytes the output accepts before truncating.
func (w *limitedOutput) room() int64 {
	if w.budget != nil {
		w.budget.mu.Lock()
		defer w.budget.mu.Unlock()
		return w.budget.remaining
	}
	return w.limit - int64(w.buffer.Len())
}

type scanReader struct {
	reader    io.Reader
	remaining int64
}

func (r *scanReader) Read(p []byte) (int, error) {
	if r.remaining > 0 {
		n, err := r.reader.Read(p[:min(int64(len(p)), r.remaining)])
		r.remaining -= int64(n)
		return n, err
	}
	var probe [1]byte
	n, err := r.reader.Read(probe[:])
	if n > 0 {
		return 0, errScanLimit
	}
	return 0, err
}

func splitInput(a catalog.Action, input map[string]any) (map[string]any, map[string]any, error) {
	defs, err := catalog.ParameterDefinitions(a)
	if err != nil {
		return nil, nil, err
	}
	values := map[string]any{}
	filters := map[string]any{}

	for key, value := range input {
		if _, declared := defs[key]; !declared && slices.Contains(a.Filters, key) {
			filters[key] = value
		} else {
			values[key] = value
		}
	}

	return values, filters, nil
}

// Run is the single-map compatibility entry point. Declared action/handler
// parameters take precedence over same-named filters.
func Run(parent context.Context, a catalog.Action, input map[string]any, globalRedact *redact.Config) (Result, error) {
	values, filters, err := splitInput(a, input)
	if err != nil {
		return Result{ExitCode: -1}, err
	}
	return RunWithFilters(parent, a, values, filters, globalRedact)
}

// RunWithFilters executes as the current user with independent parameter maps.
// Privileged callers select run_as before invoking the executor.
func RunWithFilters(parent context.Context, a catalog.Action, actionInput, filterInput map[string]any, globalRedact *redact.Config) (result Result, runErr error) {
	return RunWithCallbacks(parent, a, actionInput, filterInput, globalRedact, Callbacks{})
}

func RunWithCallbacks(parent context.Context, a catalog.Action, actionInput, filterInput map[string]any, globalRedact *redact.Config, callbacks Callbacks) (result Result, runErr error) {
	result.ExitCode = -1
	start := time.Now()
	defer func() { result.DurationMS = time.Since(start).Milliseconds() }()
	support := catalog.CheckHost(a)
	if !support.Supported {
		return result, fmt.Errorf("unsupported: %s", support.Reason)
	}
	for _, warning := range support.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	filters, err := ParseFilters(a.Filters, filterInput)
	if err != nil {
		return result, err
	}
	defs, err := catalog.ParameterDefinitions(a)
	if err != nil {
		return result, err
	}
	values, err := params.Parse(defs, actionInput)
	if err != nil {
		return result, err
	}
	if a.Builtin != "" && len(a.Params) > 0 {
		if _, err := params.Parse(a.Params, subset(actionInput, a.Params)); err != nil {
			return result, err
		}
	}
	config := a.Redact
	if config == nil {
		config = globalRedact
	}
	redactor, err := redact.New(config)
	if err != nil {
		return result, err
	}
	timeout, _ := time.ParseDuration(a.Timeout)
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	scan := int64(a.MaxScan)
	if scan == 0 {
		scan = DefaultMaxScan
	}
	limit := int64(a.MaxOutput)
	started := false
	onStart := func() error {
		if started {
			return nil
		}
		started = true
		if callbacks.Started != nil {
			err := callbacks.Started()
			if err != nil {
				cancel()
			}
			return err
		}
		return nil
	}
	if a.Builtin != "" {
		if err := onStart(); err != nil {
			return result, err
		}
		handler := catalog.Builtins[a.Builtin]
		var raw catalog.BuiltinResult
		var runErr error
		stdoutRedactor := redactor
		if structured, ok := handler.(catalog.RedactingBuiltinHandler); ok {
			raw, runErr = structured.RunRedacted(ctx, a.BuiltinConfig, values, redactor.Line)
			// Original values have already been redacted. Reapplying a custom
			// rule to JSON/TSV could match encoding characters or replacement text.
			stdoutRedactor = &redact.Redactor{}
		} else {
			raw, runErr = handler.Run(ctx, a.BuiltinConfig, values)
		}
		out, outputErr := processOutput(strings.NewReader(raw.Stdout), strings.NewReader(raw.Stderr), stdoutRedactor, redactor, filters, limit, scan, nil)
		out.ExitCode = raw.ExitCode
		out.StatusCode = raw.StatusCode
		out.ResourceLimitReached = raw.ResourceLimited
		out.Truncated = out.Truncated || raw.ResourceLimited
		return out, errors.Join(runErr, outputErr)

	}
	if a.Script != nil {
		args, err := params.Render(a.Args, defs, values)
		if err != nil {
			return result, err
		}
		argv, cleanup, err := prepareScript(*a.Script, args)
		if err != nil {
			return result, err
		}
		defer cleanup()
		return runCommand(ctx, argv, redactor, filters, limit, scan, nil, onStart)
	}
	if a.Steps == nil {
		argv, err := renderCommand(a.Exec, a.ExecFallbacks, a.AllowInterpreter, defs, values)
		if err != nil {
			return result, err
		}
		return runCommand(ctx, argv, redactor, filters, limit, scan, nil, onStart)
	}
	budget := stepBudget(limit)
	result.ExitCode = 0
	stopped := false
	for index, step := range a.Steps {
		if stopped {
			sr := StepResult{Index: index, Name: step.Name, Skipped: true}
			result.Steps = append(result.Steps, sr)
			if callbacks.StepCompleted != nil {
				if err := callbacks.StepCompleted(sr, nil); err != nil {
					return result, errors.Join(runErr, err)
				}
			}
			continue
		}
		argv, err := renderCommand(step.Exec, nil, a.AllowInterpreter, defs, values)
		r := Result{ExitCode: -1}
		if err == nil {
			r, err = runCommand(ctx, argv, redactor, filters, limit, scan, budget, onStart)
		}
		sr := StepResult{Index: index, Name: step.Name, DurationMS: r.DurationMS, Stdout: r.Stdout, Stderr: r.Stderr, Truncated: r.Truncated, ScanLimitReached: r.ScanLimitReached}
		if r.ExitCode >= 0 {
			code := r.ExitCode
			sr.ExitCode = &code
		}
		result.Steps = append(result.Steps, sr)
		result.Truncated = result.Truncated || r.Truncated
		result.ScanLimitReached = result.ScanLimitReached || r.ScanLimitReached
		if result.ExitCode == 0 && (r.ExitCode != 0 || err != nil) {
			result.ExitCode = r.ExitCode
		}
		if err != nil {
			runErr = errors.Join(runErr, err)
		}
		if callbacks.StepCompleted != nil {
			if callbackErr := callbacks.StepCompleted(sr, err); callbackErr != nil {
				return result, errors.Join(runErr, callbackErr)
			}
		}
		stopped = ctx.Err() != nil || (a.OnError == "stop" && (err != nil || r.ExitCode != 0))
	}
	return result, runErr
}

func subset(input map[string]any, defs map[string]params.Definition) map[string]any {
	out := map[string]any{}
	for name := range defs {
		if value, ok := input[name]; ok {
			out[name] = value
		}
	}
	return out
}
func renderCommand(template []any, fallbacks []string, allow bool, defs map[string]params.Definition, values map[string]any) ([]string, error) {
	program, err := catalog.ResolveExecutable(template, fallbacks, allow)
	if err != nil {
		return nil, err
	}
	argv, err := params.Render(template, defs, values)
	if err != nil {
		return nil, err
	}
	argv[0] = program
	if err := catalog.CheckCommand(argv, allow); err != nil {
		return nil, err
	}
	return argv, nil
}

func streamStdout(input io.Reader, output *limitedOutput, r *redact.Redactor, filters FilterOptions, scan int64) error {
	writer := newFilterWriter(output, filters)
	err := r.Stream(&scanReader{reader: input, remaining: scan}, writer, redact.DefaultMaxLine)
	if err == nil || errors.Is(err, errScanLimit) {
		err = errors.Join(err, writer.finish())
	}
	return err
}
func processOutput(stdout, stderr io.Reader, stdoutRedactor, stderrRedactor *redact.Redactor, filters FilterOptions, limit, scan int64, budget *outputBudget) (Result, error) {
	out := &limitedOutput{limit: limit, budget: budget}
	diagnostic := &limitedOutput{limit: limit, budget: budget}
	stdoutErr := streamStdout(stdout, out, stdoutRedactor, filters, scan)
	stderrErr := stderrRedactor.Stream(stderr, diagnostic, redact.DefaultMaxLine)
	result := Result{Stdout: out.buffer.String(), Stderr: diagnostic.buffer.String(), Truncated: out.truncated || diagnostic.truncated, ScanLimitReached: errors.Is(stdoutErr, errScanLimit)}
	if errors.Is(stdoutErr, errScanLimit) {
		stdoutErr = nil
	}
	return result, errors.Join(stdoutErr, stderrErr)
}

func runCommand(parent context.Context, argv []string, r *redact.Redactor, filters FilterOptions, limit, scan int64, budget *outputBudget, onStart func() error) (Result, error) {
	result := Result{ExitCode: -1}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	command := exec.Command(argv[0], argv[1:]...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "PAGER=cat", "SYSTEMD_PAGER="}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = pipeDrainDelay
	stdoutReader, stdoutWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()
	defer stdoutReader.Close()
	defer stderrReader.Close()
	command.Stdout = stdoutWriter
	command.Stderr = stderrWriter
	stdout := &limitedOutput{limit: limit, budget: budget}
	stderr := &limitedOutput{limit: limit, budget: budget}
	stdoutDone := make(chan error, 1)
	stderrDone := make(chan error, 1)
	var scanCancelled atomic.Bool
	readStream := func(reader *io.PipeReader, done chan<- error, read func() error) {
		err := read()
		if err != nil {
			if errors.Is(err, errScanLimit) {
				scanCancelled.Store(true)
			}
			cancel()
			_, _ = io.Copy(io.Discard, reader)
		}
		done <- err
	}
	start := time.Now()
	if err := command.Start(); err != nil {
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
		return result, err
	}
	go readStream(stdoutReader, stdoutDone, func() error { return streamStdout(stdoutReader, stdout, r, filters, scan) })
	go readStream(stderrReader, stderrDone, func() error { return r.Stream(stderrReader, stderr, redact.DefaultMaxLine) })
	processDone := make(chan struct{})
	watcherDone := make(chan struct{})
	killedForScan := false
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			runningBeforeKill := false
			if scanCancelled.Load() {
				// Do not reinterpret an already-exited process's SIGKILL as
				// our scan cleanup merely because descendants still hold pipes.
				// WNOWAIT leaves command.Wait as the sole status consumer.
				var info unix.Siginfo
				runningBeforeKill = unix.Waitid(unix.P_PID, command.Process.Pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil) == nil && info.Signo == 0
			}
			if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err == nil {
				killedForScan = runningBeforeKill
			}
		case <-processDone:
		}
	}()
	startErr := onStart()
	if startErr != nil {
		cancel()
	}
	waitErr := command.Wait()
	close(processDone)
	<-watcherDone
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	stdoutErr, stderrErr := <-stdoutDone, <-stderrDone
	result.DurationMS = time.Since(start).Milliseconds()
	result.Stdout = stdout.buffer.String()
	result.Stderr = stderr.buffer.String()
	result.Truncated = stdout.truncated || stderr.truncated
	result.ScanLimitReached = errors.Is(stdoutErr, errScanLimit)
	if startErr != nil {
		return result, startErr
	}
	if result.ScanLimitReached {
		stdoutErr = nil
	}
	if stdoutErr != nil || stderrErr != nil {
		result.Truncated = true
		return result, errors.Join(stdoutErr, stderrErr)
	}
	if parent.Err() != nil {
		return result, parent.Err()
	}
	if waitErr == nil {
		result.ExitCode = 0
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		// A50: only the scan cleanup signal is a nominal success. Preserve
		// an observed natural nonzero exit, other signals and wait failures.
		if result.ScanLimitReached && killedForScan {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() && status.Signal() == syscall.SIGKILL {
				result.ExitCode = 0
			}
		}
		return result, nil
	}
	return result, waitErr
}
