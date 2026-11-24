package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
	"github.com/liubing0806/allowops/internal/executor"
	"github.com/liubing0806/allowops/internal/params"
)

func TestStepDataflowAgentLoadsAndRunsSignedActions(t *testing.T) {
	g, _, cfg := startGateway(t, false)
	a, _ := startAgent(t, cfg)
	c := connection(t, g)
	for _, feature := range []string{"step_extract", "step_when"} {
		if features := c.hello.GetCapabilities().GetFeatures(); !slices.Contains(features, feature) {
			t.Fatalf("features=%v, want %q", features, feature)
		}
	}

	parse := func(raw string) catalog.Action {
		t.Helper()
		action, err := catalog.ParseAction([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return action
	}
	success := parse(`
name: extract_id
description: Extract an ID and conditionally use it
risk: read
timeout: 5s
max_output: 1KB
steps:
  - name: producer
    exec: [/usr/bin/printf, 'id=42\n']
    extract:
      id:
        regex: '^id=(.*)$'
        as: {type: int, min: 0, max: 100}
  - name: conditional
    exec: [/usr/bin/false]
    when: {ref: steps.producer.id, gt: 42}
  - name: consumer
    exec: [/usr/bin/printf, 'selected:%s\n', '{steps.producer.id}']
    when: {ref: prev.skipped, eq: true}
`)
	failure := parse(`
name: extract_invalid_id
description: Stop when the extracted ID has the wrong type
risk: read
timeout: 5s
max_output: 1KB
on_error: stop
steps:
  - name: producer
    exec: [/usr/bin/printf, 'id=invalid\n']
    extract:
      id:
        regex: '^id=(.*)$'
        as: {type: int, min: 0, max: 100}
  - name: following
    exec: [/usr/bin/false]
    when: {ref: prev.exit_code, exists: false}
`)
	legacy := parse(`
name: legacy
description: Run an action with the original schema
risk: read
timeout: 5s
max_output: 1KB
exec: [/usr/bin/true]
`)
	p, notice := publish(t, g, a, []catalog.Action{success, failure, legacy}, time.Now(), time.Hour)
	c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}})
	report := c.next(t, func(m *v1.ConnectRequest) bool { return m.GetCatalogLoad() != nil }).GetCatalogLoad()
	if !report.Loaded || len(report.UnsupportedActions) != 0 {
		t.Fatalf("catalog did not load: %v", report)
	}
	for _, tc := range []struct {
		action       catalog.Action
		skipReason   string
		taskReason   string
		wantExitZero bool
		wantStdout   string
	}{
		{action: success, skipReason: executor.ReasonSkipConditionFalse, wantExitZero: true, wantStdout: "selected:42\n"},
		{action: failure, skipReason: executor.ReasonSkipStopped, taskReason: executor.ReasonExtractTypeInvalid},
		{action: legacy, wantExitZero: true},
	} {
		t.Run(tc.action.Name, func(t *testing.T) {
			sendTask(t, c, task(p, tc.action.Name, tc.action.Name))
			messages := collectTask(t, c, tc.action.Name)
			var steps []*v1.StepCompleted
			var stdout bytes.Buffer
			for _, msg := range messages {
				if step := msg.GetStepCompleted(); step != nil {
					steps = append(steps, step)
				}
				if chunk := msg.GetOutput(); chunk != nil && chunk.GetStepIndex() == 2 && chunk.Stream == v1.OutputStream_OUTPUT_STREAM_STDOUT {
					stdout.Write(chunk.Data)
				}
			}
			completed := messages[len(messages)-1].GetTaskCompleted()
			if messages[0].GetTaskStarted() == nil || len(steps) != len(tc.action.Steps) ||
				int(completed.CompletedSteps) != len(steps) || completed.Result.Reason != tc.taskReason {
				t.Fatalf("messages=%v", messages)
			}
			if tc.wantExitZero {
				if result := completed.Result; result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED || result.ExitCode == nil || *result.ExitCode != 0 {
					t.Fatalf("expected successful exit, got %v", result)
				}
			} else if completed.Result.Status != v1.TaskStatus_TASK_STATUS_FAILED || completed.Result.ExitCode != nil ||
				steps[0].Result.Reason != tc.taskReason || steps[0].Result.Status != v1.TaskStatus_TASK_STATUS_FAILED {
				t.Fatalf("expected extraction failure, steps=%v, completed=%v", steps, completed)
			}
			if tc.skipReason != "" {
				if skipped := steps[1].Result; skipped.Status != v1.TaskStatus_TASK_STATUS_SKIPPED || skipped.Reason != tc.skipReason ||
					skipped.ExitCode != nil || skipped.Stdout != nil || skipped.Stderr != nil {
					t.Fatalf("unexpected skipped result: %v", skipped)
				}
			}
			if stdout.String() != tc.wantStdout {
				t.Fatalf("consumer stdout=%q, want %q", stdout.String(), tc.wantStdout)
			}
		})
	}
}

func TestStepDataflowHelperEventsPreserveReasons(t *testing.T) {
	action := catalog.Action{Steps: []catalog.Step{{Name: "first"}, {Name: "second"}}}
	for code, sentinel := range map[string]error{
		"EXTRACT_FAILED":       executor.ErrExtractFailed,
		"EXTRACT_TYPE_INVALID": executor.ErrExtractTypeInvalid,
		"EXTRACT_MISSING":      executor.ErrExtractMissing,
		"PATH_NOT_TRUSTED":     params.ErrPathNotTrusted,
	} {
		t.Run(code, func(t *testing.T) {
			localErr := fmt.Errorf("step first variable id: %w", sentinel)
			skip := executor.ReasonSkipStopped
			first := executor.StepResult{Name: "first"}
			second := executor.StepResult{Name: "second", Index: 1, Skipped: true, SkipReason: skip}
			var wire bytes.Buffer
			encoder := json.NewEncoder(&wire)
			for _, event := range []execd.Event{
				{Type: "started"},
				{Type: "step_completed", Response: &execd.Response{Reason: execd.ExecutionReason(localErr), Result: executor.Result{Steps: []executor.StepResult{first}}}},
				{Type: "step_completed", Response: &execd.Response{Result: executor.Result{Steps: []executor.StepResult{second}}}},
				{Type: "completed", Response: &execd.Response{Reason: execd.ExecutionReason(localErr), Result: executor.Result{ExitCode: -1, Steps: []executor.StepResult{first, second}}}},
			} {
				if err := encoder.Encode(event); err != nil {
					t.Fatal(err)
				}
			}
			if wire.String() == "" || bytes.Contains(wire.Bytes(), []byte(localErr.Error())) {
				t.Fatal("helper wire must carry only the reason code")
			}
			check := func(err error) {
				t.Helper()
				if status, reason := taskStatus(-1, err); status != v1.TaskStatus_TASK_STATUS_FAILED || reason != code || !errors.Is(err, sentinel) {
					t.Fatalf("status=%s, reason=%q, err=%v, want %s", status, reason, err, code)
				}
			}
			check(localErr)
			seen := 0
			response, err := readHelperEvents(&wire, action, executor.Callbacks{StepCompleted: func(step executor.StepResult, err error) error {
				seen++
				if step.Index == 0 {
					check(err)
				} else if step != second || err != nil {
					t.Fatalf("skipped step=%+v, err=%v, want %+v", step, err, second)
				}
				return nil
			}})
			if err != nil || seen != 2 || len(response.Result.Steps) != 2 || response.Result.Steps[1] != second {
				t.Fatalf("response=%+v, steps seen=%d, error=%v", response, seen, err)
			}
			check(helperReason(response.Reason))
		})
	}
}
