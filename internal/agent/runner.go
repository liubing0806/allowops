package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"syscall"
	"time"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
	"github.com/liubing0806/allowops/internal/executor"
)

// Runner is the P12 integration boundary;
// unsupported signed features must never be ignored by an adapter.
type Runner interface {
	Run(context.Context, catalog.Action, map[string]any, map[string]any, string, int64, executor.Callbacks) (executor.Result, error)
}

type LocalRunner struct{}

func (LocalRunner) Run(ctx context.Context, action catalog.Action, input, filters map[string]any, catalogID string, version int64, callbacks executor.Callbacks) (executor.Result, error) {
	if !action.RequiresExec() {
		return executor.RunWithCallbacks(ctx, action, input, filters, nil, callbacks)
	}
	data, err := json.Marshal(execd.Request{CatalogID: catalogID, CatalogVersion: version, Action: action.Name, Params: input, Filters: filters})
	if err != nil {
		return executor.Result{ExitCode: -1}, errors.New("INVALID_PARAMETERS")
	}
	command := exec.Command("/usr/bin/sudo", "-n", "/usr/libexec/allowops/allowops-exec")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "PAGER=cat", "SYSTEMD_PAGER="}
	command.Stdin = bytes.NewReader(data)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return executor.Result{ExitCode: -1}, errors.New("HELPER_START_FAILED")
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return executor.Result{ExitCode: -1}, errors.New("HELPER_START_FAILED")
	}
	done, watched := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watched)
		select {
		case <-ctx.Done():
			// sudo forwards TERM to the helper, whose signal context terminates
			// the P1 executor's separate process group with its target identity.
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		case <-done:
		}
	}()
	// Bound the whole event stream before decoding. Steps appear both in their
	// completion event and final result; metadata is bounded by signed step count.
	metadata := int64(len(action.Steps))*2048 + 65536
	limit := int64(action.MaxOutput)
	if limit > (1<<63-1-metadata)/12 {
		limit = (1<<63 - 1 - metadata) / 12
	}
	bounded := &io.LimitedReader{R: stdout, N: limit*12 + metadata + 1}
	response, readErr := readHelperEvents(bounded, action, callbacks)
	if bounded.N == 0 {
		readErr = errors.New("HELPER_PROTOCOL_ERROR")
	}
	if readErr != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		_ = stdout.Close()
	}
	waitErr := command.Wait()
	close(done)
	<-watched
	if ctx.Err() != nil {
		return response.Result, ctx.Err()
	}
	if readErr != nil {
		return response.Result, readErr
	}
	if response.Reason != "" {
		return response.Result, helperReason(response.Reason)
	}
	if waitErr != nil {
		return response.Result, errors.New("HELPER_FAILED")
	}
	return response.Result, nil
}

func readHelperEvents(input io.Reader, action catalog.Action, callbacks executor.Callbacks) (execd.Response, error) {
	decoder := json.NewDecoder(input)
	response := execd.Response{Result: executor.Result{ExitCode: -1}}
	started, completed := false, false
	steps := 0
	protocolError := errors.New("HELPER_PROTOCOL_ERROR")
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF && completed {
				return response, nil
			}
			return response, protocolError
		}
		var event execd.Event
		if completed || execd.DecodeJSON(raw, &event) != nil {
			return response, protocolError
		}
		switch event.Type {
		case "started":
			if started || event.Response != nil {
				return response, protocolError
			}
			started = true
			if callbacks.Started != nil {
				if err := callbacks.Started(); err != nil {
					return response, err
				}
			}
		case "step_completed":
			if event.Response == nil || len(event.Response.Result.Steps) != 1 || steps >= len(action.Steps) {
				return response, protocolError
			}
			step := event.Response.Result.Steps[0]
			if step.Index != steps || step.Name != action.Steps[steps].Name || (!started && step.ExitCode != nil) || (step.Skipped && (step.ExitCode != nil || step.Stdout != "" || step.Stderr != "")) {
				return response, protocolError
			}
			steps++
			if callbacks.StepCompleted != nil {
				if err := callbacks.StepCompleted(step, helperReason(event.Response.Reason)); err != nil {
					return response, err
				}
			}
		case "completed":
			if event.Response == nil || len(event.Response.Result.Steps) != steps || (!started && event.Response.Result.ExitCode >= 0) {
				return response, protocolError
			}
			response, completed = *event.Response, true
		default:
			return response, protocolError
		}
	}
}

func helperReason(reason string) error {
	switch reason {
	case "":
		return nil
	case "CANCELLED":
		return context.Canceled
	case "TIMEOUT":
		return context.DeadlineExceeded
	default:
		return errors.New("EXECUTION_FAILED")
	}
}

func boundedTimeout(action catalog.Action, requested time.Duration) (time.Duration, error) {
	signed, err := time.ParseDuration(action.Timeout)
	if err != nil || requested <= 0 || requested > signed {
		return 0, errors.New("INVALID_TIMEOUT")
	}
	return requested, nil
}
