package execd

import (
	"context"
	"errors"
	"fmt"
	"testing"

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
