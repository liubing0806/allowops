package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
)

func TestCallbacksReportRedactedStepsBeforeNextProcess(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "next-step")
	a := catalog.Action{Name: "events", Description: "events", Risk: "read", Timeout: "5s", MaxOutput: 1024,
		Steps: []catalog.Step{{Name: "first", Exec: []any{"/usr/bin/printf", "password=secret\\n"}}, {Name: "next", Exec: []any{"/usr/bin/touch", marker}}, {Name: "fail", Exec: []any{"/usr/bin/false"}}, {Name: "skip", Exec: []any{"/usr/bin/touch", marker + ".skip"}}}, OnError: "stop"}
	starts, steps := 0, 0
	r, err := RunWithCallbacks(context.Background(), a, nil, nil, nil, Callbacks{
		Started: func() error { starts++; return nil },
		StepCompleted: func(s StepResult, err error) error {
			if s.Index != steps || starts != 1 {
				t.Fatalf("callback order: starts=%d step=%+v", starts, s)
			}
			steps++
			if s.Index == 0 {
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("next process started before completion callback")
				}
				if s.Stdout != "[REDACTED:credential]\n" {
					t.Fatalf("callback leaked raw output: %q", s.Stdout)
				}
			}
			if s.Index == 3 && (!s.Skipped || s.ExitCode != nil || s.Stdout != "") {
				t.Fatalf("skipped=%+v", s)
			}
			return err
		},
	})
	if err != nil || starts != 1 || steps != 4 || len(r.Steps) != 4 || r.ExitCode != 1 {
		t.Fatalf("starts=%d steps=%d result=%+v err=%v", starts, steps, r, err)
	}
	if _, err := os.Stat(marker + ".skip"); !os.IsNotExist(err) {
		t.Fatal("skipped process executed")
	}
}

func TestCallbacksDoNotConfirmFailedStart(t *testing.T) {
	program := filepath.Join(t.TempDir(), "invalid-binary")
	if err := os.WriteFile(program, []byte("invalid executable format"), 0700); err != nil {
		t.Fatal(err)
	}
	a := catalog.Action{Name: "invalid", Description: "invalid", Risk: "read", Exec: []any{program}, Timeout: "1s", MaxOutput: 1024}
	started := false
	_, err := RunWithCallbacks(context.Background(), a, nil, nil, nil, Callbacks{Started: func() error { started = true; return nil }})
	if err == nil || started {
		t.Fatalf("started=%v err=%v", started, err)
	}
}

func TestCallbackFailureTerminatesStartedProcess(t *testing.T) {
	want := errors.New("transport unavailable")
	_, err := RunWithCallbacks(context.Background(), helperAction("parent"), nil, nil, nil, Callbacks{Started: func() error { return want }})
	if !errors.Is(err, want) {
		t.Fatalf("callback error=%v", err)
	}
}

func TestStartCallbackFailureStopsContinuingSteps(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "must-not-run")
	want := errors.New("start notification failed")
	a := catalog.Action{Name: "events", Description: "events", Risk: "read", Timeout: "5s", MaxOutput: 1024, OnError: "continue",
		Steps: []catalog.Step{{Name: "first", Exec: []any{"/usr/bin/sleep", "3"}}, {Name: "next", Exec: []any{"/usr/bin/touch", marker}}}}
	r, err := RunWithCallbacks(context.Background(), a, nil, nil, nil, Callbacks{Started: func() error { return want }})
	if !errors.Is(err, want) {
		t.Fatalf("callback error=%v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("next step executed after start callback failed")
	}
	if len(r.Steps) != 2 || !r.Steps[1].Skipped {
		t.Fatalf("steps=%+v", r.Steps)
	}
}
