package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
	"github.com/liubing0806/allowops/internal/executor"
)

func TestHelperEventOrderingAndBytes(t *testing.T) {
	step := executor.StepResult{Index: 0, Name: "one", Stdout: string([]byte{0xff, 0xfe})}
	code := 0
	step.ExitCode = &code
	events := []execd.Event{{Type: "started"}, {Type: "step_completed", Response: &execd.Response{Result: executor.Result{Steps: []executor.StepResult{step}}}}, {Type: "completed", Response: &execd.Response{Result: executor.Result{Steps: []executor.StepResult{step}}}}}
	encode := func(items []execd.Event) string {
		var data strings.Builder
		for _, item := range items {
			if err := json.NewEncoder(&data).Encode(item); err != nil {
				t.Fatal(err)
			}
		}
		return data.String()
	}
	a := catalog.Action{Steps: []catalog.Step{{Name: "one"}}}
	started, steps := 0, 0
	response, err := readHelperEvents(strings.NewReader(encode(events)), a, executor.Callbacks{
		Started: func() error { started++; return nil },
		StepCompleted: func(s executor.StepResult, err error) error {
			if started != 1 || s.Stdout != step.Stdout {
				t.Fatalf("callback bytes/order=%+v", s)
			}
			steps++
			return err
		},
	})
	if err != nil || steps != 1 || response.Result.Steps[0].Stdout != step.Stdout {
		t.Fatalf("steps=%d response=%+v err=%v", steps, response, err)
	}
	for name, items := range map[string][]execd.Event{
		"duplicate-start":   {events[0], events[0]},
		"step-before-start": {events[1], events[2]},
		"no-final":          {events[0], events[1]},
		"after-final":       {events[0], events[1], events[2], events[0]},
		"missing-step":      {events[0], events[2]},
		"unknown-event":     {{Type: "unknown"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readHelperEvents(strings.NewReader(encode(items)), a, executor.Callbacks{}); err == nil {
				t.Fatal("invalid event stream accepted")
			}
		})
	}
}

func TestHelperCallbackFailure(t *testing.T) {
	_, err := readHelperEvents(strings.NewReader(`{"type":"started"}`), catalog.Action{}, executor.Callbacks{Started: func() error { return context.Canceled }})
	if err != context.Canceled {
		t.Fatalf("callback error=%v", err)
	}
}

// A builtin failure reaches the agent as reason EXECUTION_FAILED plus the
// redacted error text in stderr; the agent must keep both.
func TestHelperFailureKeepsStderr(t *testing.T) {
	started := execd.Event{Type: "started"}
	completed := execd.Event{Type: "completed", Response: &execd.Response{Result: executor.Result{ExitCode: 1, Stderr: "sqlguard: statement not allowed\n"}, Reason: "EXECUTION_FAILED"}}
	var data strings.Builder
	for _, event := range []execd.Event{started, completed} {
		if err := json.NewEncoder(&data).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	response, err := readHelperEvents(strings.NewReader(data.String()), catalog.Action{}, executor.Callbacks{})
	if err != nil || response.Reason != "EXECUTION_FAILED" || response.Result.Stderr != "sqlguard: statement not allowed\n" || response.Result.ExitCode != 1 {
		t.Fatalf("response=%+v err=%v", response, err)
	}
}
