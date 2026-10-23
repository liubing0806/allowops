package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
	"github.com/liubing0806/allowops/internal/executor"
)

func TestTaskStatusForwardsBuiltinReasons(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status v1.TaskStatus
		reason string
	}{
		{builtin.NewError(builtin.ReasonPathOutsideRoots, "path_glob is outside allowed_roots"), v1.TaskStatus_TASK_STATUS_FAILED, "PATH_OUTSIDE_ROOTS"},
		{errors.Join(builtin.NewError(builtin.ReasonSourceUnsupported, ""), errors.New("output")), v1.TaskStatus_TASK_STATUS_FAILED, "SOURCE_UNSUPPORTED"},
		{errors.New("PATH_OUTSIDE_ROOTS"), v1.TaskStatus_TASK_STATUS_FAILED, "EXECUTION_FAILED"},
		{context.Canceled, v1.TaskStatus_TASK_STATUS_CANCELLED, "CANCELLED"},
	} {
		if status, reason := taskStatus(1, tc.err); status != tc.status || reason != tc.reason {
			t.Errorf("taskStatus(%v)=%v,%q want %v,%q", tc.err, status, reason, tc.status, tc.reason)
		}
	}
}

// The root helper sends only the code; the agent must rebuild an error that
// taskStatus forwards, and still collapse helper-internal codes.
func TestHelperReasonRoundTrip(t *testing.T) {
	for reason, want := range map[string]string{
		"":                   "",
		"PATH_OUTSIDE_ROOTS": "PATH_OUTSIDE_ROOTS",
		"CURSOR_INVALID":     "CURSOR_INVALID",
		"CANCELLED":          "CANCELLED",
		"TIMEOUT":            "TIMEOUT",
		"EXECUTION_FAILED":   "EXECUTION_FAILED",
		"ROOT_REQUIRED":      "EXECUTION_FAILED",
	} {
		_, got := taskStatus(0, helperReason(reason))
		if got != want {
			t.Errorf("helperReason(%q) -> %q want %q", reason, got, want)
		}
	}
	err := builtin.NewError(builtin.ReasonSourceNoFiles, "no files")
	events := `{"type":"started"}` + "\n" + `{"type":"completed","response":{"result":{"exit_code":1,"stdout":"","stderr":""},"reason":"` + execd.ExecutionReason(err) + `"}}` + "\n"
	response, readErr := readHelperEvents(strings.NewReader(events), catalog.Action{}, executor.Callbacks{})
	if readErr != nil {
		t.Fatal(readErr)
	}
	if _, got := taskStatus(1, helperReason(response.Reason)); got != "SOURCE_NO_FILES" {
		t.Fatalf("helper completed reason=%q got %q", response.Reason, got)
	}
}

// Local (non-root) builtins reach taskStatus through the executor unchanged.
func TestLocalRunnerForwardsLogSearchReason(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "app.log"), []byte("hit\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a := catalog.Action{Name: "log_search", Description: "log_search", Risk: "read", Builtin: "log_search", BuiltinConfig: map[string]any{"allowed_roots": []string{dir}}, Timeout: "2s", MaxOutput: 1024}
	r, err := LocalRunner{}.Run(context.Background(), a, map[string]any{"path_glob": filepath.Join(outside, "app.log"), "pattern": "hit", "fixed": true}, nil, "", 0, executor.Callbacks{})
	if status, reason := taskStatus(r.ExitCode, err); status != v1.TaskStatus_TASK_STATUS_FAILED || reason != "PATH_OUTSIDE_ROOTS" {
		t.Fatalf("status=%v reason=%q err=%v", status, reason, err)
	}
}
