package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"syscall"

	"github.com/liubing0806/allowops/internal/execd"
	"github.com/liubing0806/allowops/internal/executor"
)

func main() {
	os.Clearenv()
	syscall.Umask(0077)
	if len(os.Args) != 1 {
		_, _ = os.Stderr.WriteString("ARGUMENTS_FORBIDDEN\n")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = os.Stdin.Close()
		case <-done:
		}
	}()
	encoder := json.NewEncoder(os.Stdout)
	response := execd.ExecuteWithCallbacks(ctx, os.Stdin, executor.Callbacks{
		Started: func() error { return encoder.Encode(execd.Event{Type: "started"}) },
		StepCompleted: func(step executor.StepResult, err error) error {
			return encoder.Encode(execd.Event{Type: "step_completed", Response: &execd.Response{Result: executor.Result{Steps: []executor.StepResult{step}}, Reason: execd.ExecutionReason(err)}})
		},
	})
	if err := encoder.Encode(execd.Event{Type: "completed", Response: &response}); err != nil {
		os.Exit(1)
	}
	if response.Reason != "" {
		os.Exit(1)
	}
}
