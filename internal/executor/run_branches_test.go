package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/redact"
)

func TestRunWithCallbacksRejectsInvalidSetup(t *testing.T) {
	a := catalog.Action{Name: "setup", Description: "setup", Risk: "read", Exec: []any{"/usr/bin/printf", "x"}, Timeout: "2s", MaxOutput: 1024, Filters: []string{"match"}}
	started := false
	callbacks := Callbacks{Started: func() error { started = true; return nil }}
	r, err := RunWithCallbacks(context.Background(), a, nil, map[string]any{"tail": 1}, nil, callbacks)
	if err == nil || !strings.Contains(err.Error(), "filter tail is not allowed") || r.ExitCode != -1 || started {
		t.Fatalf("disallowed filter: %+v %v started=%v", r, err, started)
	}
	a.Redact = &redact.Config{Builtin: []string{"unknown"}}
	r, err = RunWithCallbacks(context.Background(), a, nil, nil, nil, callbacks)
	if err == nil || !strings.Contains(err.Error(), "unknown redaction builtin") || r.ExitCode != -1 || started {
		t.Fatalf("redact config: %+v %v started=%v", r, err, started)
	}
	a.Redact = nil
	a.Exec = []any{"/nonexistent/program"}
	r, err = RunWithCallbacks(context.Background(), a, nil, nil, nil, callbacks)
	if err == nil || r.ExitCode != -1 || started {
		t.Fatalf("host does not support the executable: %+v %v started=%v", r, err, started)
	}
}

func TestRunWithCallbacksScriptAction(t *testing.T) {
	content := []byte("echo script-ran\nexit 3\n")
	sum := sha256.Sum256(content)
	a := catalog.Action{Name: "script", Description: "script", Risk: "read", Script: &catalog.Script{File: "s.sh", Interpreter: "/bin/sh", Content: content, SHA256: hex.EncodeToString(sum[:])}, Timeout: "5s", MaxOutput: 1024}
	starts := 0
	r, err := RunWithCallbacks(context.Background(), a, nil, nil, nil, Callbacks{Started: func() error { starts++; return nil }})
	if err != nil || r.ExitCode != 3 || r.Stdout != "script-ran\n" || starts != 1 {
		t.Fatalf("script: %+v %v starts=%d", r, err, starts)
	}
	want := errors.New("start refused")
	_, err = RunWithCallbacks(context.Background(), a, nil, nil, nil, Callbacks{Started: func() error { return want }})
	if !errors.Is(err, want) {
		t.Fatalf("script start callback: %v", err)
	}
}

func TestStepCallbackErrorsStopRemainingSteps(t *testing.T) {
	dir := t.TempDir()
	want := errors.New("event delivery failed")
	steps := func(onError string) catalog.Action {
		return catalog.Action{Name: "steps", Description: "steps", Risk: "read", Timeout: "5s", MaxOutput: 1024, OnError: onError,
			Steps: []catalog.Step{{Name: "first", Exec: []any{"/usr/bin/false"}}, {Name: "second", Exec: []any{"/usr/bin/touch", filepath.Join(dir, "second")}}, {Name: "third", Exec: []any{"/usr/bin/touch", filepath.Join(dir, "third")}}}}
	}
	// A callback error for an executed step ends the run before the next process.
	var seen []int
	r, err := RunWithCallbacks(context.Background(), steps("continue"), nil, nil, nil, Callbacks{StepCompleted: func(s StepResult, _ error) error {
		seen = append(seen, s.Index)
		return want
	}})
	if !errors.Is(err, want) || len(r.Steps) != 1 || len(seen) != 1 || r.ExitCode != 1 {
		t.Fatalf("executed step: %+v %v seen=%v", r, err, seen)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "second")); !os.IsNotExist(statErr) {
		t.Fatal("second step ran after callback error")
	}
	// A callback error for a skipped step ends the run with the steps so far.
	seen = nil
	r, err = RunWithCallbacks(context.Background(), steps("stop"), nil, nil, nil, Callbacks{StepCompleted: func(s StepResult, _ error) error {
		seen = append(seen, s.Index)
		if s.Skipped {
			return want
		}
		return nil
	}})
	if !errors.Is(err, want) || len(r.Steps) != 2 || !r.Steps[1].Skipped || len(seen) != 2 || r.ExitCode != 1 {
		t.Fatalf("skipped step: %+v %v seen=%v", r, err, seen)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "third")); !os.IsNotExist(statErr) {
		t.Fatal("third step ran")
	}
}
