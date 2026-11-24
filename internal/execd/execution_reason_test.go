package execd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/executor"
	"github.com/liubing0806/allowops/internal/params"
)

func TestExecutionReasonReportsUntrustedPath(t *testing.T) {
	for err, want := range map[error]string{
		nil: "", context.Canceled: "CANCELLED", context.DeadlineExceeded: "TIMEOUT",
		fmt.Errorf("parameter file: %w", params.ErrPathNotTrusted): "PATH_NOT_TRUSTED",
		errors.New("other"): "EXECUTION_FAILED",
	} {
		if got := ExecutionReason(err); got != want {
			t.Errorf("ExecutionReason(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestExecutionReasonForwardsStepDataflowFailures(t *testing.T) {
	for err, want := range map[error]string{
		executor.ErrExtractFailed:      "EXTRACT_FAILED",
		executor.ErrExtractTypeInvalid: "EXTRACT_TYPE_INVALID",
		executor.ErrExtractMissing:     "EXTRACT_MISSING",
	} {
		wrapped := errors.Join(errors.New("prior step error"), fmt.Errorf("step producer variable id: %w", err))
		if got := ExecutionReason(wrapped); got != want {
			t.Errorf("ExecutionReason(%v) = %q, want %q", wrapped, got, want)
		}
		if !errors.Is(executor.NewReasonError(want, ""), err) {
			t.Errorf("reconstructed reason %q does not match %v", want, err)
		}
	}
}

func TestWirePreservesSkipReason(t *testing.T) {
	result := Response{Result: executor.Result{ExitCode: 0, Steps: []executor.StepResult{
		{Index: 0, Name: "first", ExitCode: new(0), Stdout: "ok\n"},
		{Index: 1, Name: "conditional", Skipped: true, SkipReason: executor.ReasonSkipConditionFalse},
		{Index: 2, Name: "stopped", Skipped: true, SkipReason: executor.ReasonSkipStopped},
		{Index: 3, Name: "legacy", Skipped: true},
	}}}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), `"skip_reason"`) != 2 {
		t.Fatalf("skip_reason encoding=%s", data)
	}
	var decoded Response
	if err := json.Unmarshal(data, &decoded); err != nil || !reflect.DeepEqual(decoded, result) {
		t.Fatalf("decoded=%+v, err=%v, want %+v", decoded, err, result)
	}
}
