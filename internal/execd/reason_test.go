package execd

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/liubing0806/allowops/internal/builtin"
)

func TestExecutionReasonForwardsBuiltinReasons(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, ""},
		{context.Canceled, "CANCELLED"},
		{fmt.Errorf("run: %w", context.DeadlineExceeded), "TIMEOUT"},
		{errors.New("path_glob is outside allowed_roots"), "EXECUTION_FAILED"},
		{builtin.NewError(builtin.ReasonPathOutsideRoots, "path_glob is outside allowed_roots"), "PATH_OUTSIDE_ROOTS"},
		{errors.Join(builtin.NewError(builtin.ReasonCursorExpired, ""), errors.New("output")), "CURSOR_EXPIRED"},
		{builtin.NewError("ROOT_REQUIRED", ""), "EXECUTION_FAILED"},
	} {
		if got := ExecutionReason(tc.err); got != tc.want {
			t.Errorf("ExecutionReason(%v)=%q want %q", tc.err, got, tc.want)
		}
	}
}
