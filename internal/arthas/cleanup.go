package arthas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"syscall"
	"time"
)

// Clean-up step names, in the order they run.
const (
	StepInterruptJob = "interrupt_job"
	StepCloseSession = "close_session"
	StepReset        = "reset"
	// StepConfirmReset runs only with CleanupOptions.ConfirmReset: a second reset, whose count
	// of restored classes must be zero.
	StepConfirmReset = "confirm_reset"
	StepStop         = "stop"
)

// Defaults of CleanupOptions.
const (
	DefaultCleanupBudget      = 20 * time.Second
	DefaultCleanupStepTimeout = 5 * time.Second
)

// CleanupOptions sets the time budget of Cleanup.
type CleanupOptions struct {
	// Budget bounds the whole sequence; DefaultCleanupBudget when zero.
	Budget time.Duration
	// StepTimeout bounds one step; DefaultCleanupStepTimeout when zero.
	StepTimeout time.Duration
	// ConfirmReset adds StepConfirmReset after the reset, for calls that enhanced classes.
	ConfirmReset bool
}

// CleanupStep is the outcome of one step.
type CleanupStep struct {
	Name string
	// Sent is true when Arthas received the request. For stop it includes the
	// normal case where the server closes the connection without a response.
	Sent bool
	// Err is nil when the step worked or had nothing to do.
	Err     error
	Note    string
	Elapsed time.Duration
	// Restored is the number of classes a reset step restored, and -1 when Arthas did not
	// report it or the step is not a reset.
	Restored int
}

// CleanupResult lists the steps in order.
type CleanupResult struct {
	Steps []CleanupStep
}

// Enhanced reads the reset steps: restored is the number of classes the reset step restored, and
// left the number the confirming reset still restored, which is 0 when nothing stayed enhanced.
// err says why left is unknown; it is also an error when no confirming reset ran.
func (r CleanupResult) Enhanced() (restored, left int, err error) {
	restored, left = -1, -1
	for _, s := range r.Steps {
		switch s.Name {
		case StepReset:
			restored = s.Restored
		case StepConfirmReset:
			switch {
			case s.Err != nil:
				return restored, -1, s.Err
			case s.Restored < 0:
				return restored, -1, errors.New("the confirming reset reported no class count")
			}
			return restored, s.Restored, nil
		}
	}
	return restored, -1, errors.New("no confirming reset ran")
}

// Err joins the errors of the steps, each prefixed with the step name.
func (r CleanupResult) Err() error {
	var errs []error
	for _, s := range r.Steps {
		if s.Err != nil {
			errs = append(errs, fmt.Errorf("cleanup %s: %w", s.Name, s.Err))
		}
	}
	return errors.Join(errs...)
}

// Cleanup ends a call: interrupt_job, close_session, reset and stop, in this
// order, with a confirming second reset before stop when opts.ConfirmReset is set. Interrupting first matters: a reset while a job still runs leaves the
// enhanced classes enhanced and makes Arthas forget them.
//
// The sequence runs even when ctx is cancelled or past its deadline: it keeps
// the values of ctx and takes its time from opts. Every step runs whatever the
// earlier steps returned, because a server left running is worse than a reset
// that failed. Whether the port is closed and the arthas- threads are gone is
// for the caller to check after stop.
//
// With an empty sessionID the two session steps are skipped.
func (c *Client) Cleanup(ctx context.Context, sessionID string, opts CleanupOptions) CleanupResult {
	if opts.Budget <= 0 {
		opts.Budget = DefaultCleanupBudget
	}
	if opts.StepTimeout <= 0 {
		opts.StepTimeout = DefaultCleanupStepTimeout
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opts.Budget)
	defer cancel()

	steps := []struct {
		name string
		run  func(ctx context.Context) CleanupStep
	}{
		{StepInterruptJob, func(ctx context.Context) CleanupStep {
			if sessionID == "" {
				return CleanupStep{Note: "no session"}
			}
			err := c.InterruptJob(ctx, sessionID)
			switch {
			case err == nil:
				return CleanupStep{Sent: true, Note: "job interrupted"}
			case errors.Is(err, ErrNoForegroundJob):
				return CleanupStep{Sent: true, Note: "no foreground job"}
			case errors.Is(err, ErrSessionNotFound):
				return CleanupStep{Sent: true, Note: "session not found"}
			}
			return CleanupStep{Sent: received(err), Err: err}
		}},
		{StepCloseSession, func(ctx context.Context) CleanupStep {
			if sessionID == "" {
				return CleanupStep{Note: "no session"}
			}
			err := c.CloseSession(ctx, sessionID)
			switch {
			case err == nil:
				return CleanupStep{Sent: true, Note: "session closed"}
			case errors.Is(err, ErrSessionNotFound):
				return CleanupStep{Sent: true, Note: "session not found"}
			}
			return CleanupStep{Sent: received(err), Err: err}
		}},
		{StepReset, func(ctx context.Context) CleanupStep { return c.reset(ctx, opts.StepTimeout) }},
		{StepConfirmReset, func(ctx context.Context) CleanupStep { return c.reset(ctx, opts.StepTimeout) }},
		{StepStop, func(ctx context.Context) CleanupStep {
			_, err := c.exec(ctx, "", "stop", opts.StepTimeout)
			switch {
			case err == nil:
				return CleanupStep{Sent: true}
			case connectionClosedAfterRequest(err):
				// Arthas closes the connection while it shuts down.
				var re *RequestError
				errors.As(err, &re)
				return CleanupStep{Sent: true, Note: "connection closed by the server (" + re.Err.Error() + ")"}
			}
			return CleanupStep{Sent: received(err), Err: err}
		}},
	}
	var res CleanupResult
	for _, s := range steps {
		if s.name == StepConfirmReset && !opts.ConfirmReset {
			continue
		}
		stepCtx, stop := context.WithTimeout(ctx, opts.StepTimeout)
		start := time.Now()
		step := s.run(stepCtx)
		if s.name != StepReset && s.name != StepConfirmReset {
			step.Restored = -1
		}
		stop()
		step.Name, step.Elapsed = s.name, time.Since(start)
		res.Steps = append(res.Steps, step)
	}
	return res
}

// received reports whether Arthas got the request: it answered, or the whole
// request was written.
func received(err error) bool {
	var se *StateError
	if errors.As(err, &se) {
		return true
	}
	var re *RequestError
	return errors.As(err, &re) && re.Written
}

// connectionClosedAfterRequest recognises the end of an exchange in which the
// request was written and the server then closed the connection: no bytes of a
// response (EOF), a response cut short (unexpected EOF) or a reset.
func connectionClosedAfterRequest(err error) bool {
	var re *RequestError
	if !errors.As(err, &re) || !re.Written {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// reset runs reset outside any session and reads the number of restored classes.
func (c *Client) reset(ctx context.Context, timeout time.Duration) CleanupStep {
	resp, err := c.exec(ctx, "", "reset", timeout)
	if err != nil {
		return CleanupStep{Sent: received(err), Err: err, Restored: -1}
	}
	if code, msg, found := resp.Status(); found && code != 0 {
		return CleanupStep{Sent: true, Err: fmt.Errorf("status %d: %s", code, msg), Restored: -1}
	}
	n, ok := restoredClasses(resp)
	if !ok {
		return CleanupStep{Sent: true, Restored: -1}
	}
	return CleanupStep{Sent: true, Note: fmt.Sprintf("classes restored: %d", n), Restored: n}
}

// restoredClasses reads the number of restored classes from the reset result.
func restoredClasses(resp *ExecResponse) (int, bool) {
	for _, r := range resp.Results {
		if r.Type != "reset" {
			continue
		}
		var m struct {
			Affect *struct {
				ClassCount *int `json:"classCount"`
			} `json:"affect"`
		}
		if json.Unmarshal(r.Raw, &m) == nil && m.Affect != nil && m.Affect.ClassCount != nil && *m.Affect.ClassCount >= 0 {
			return *m.Affect.ClassCount, true
		}
	}
	return 0, false
}
