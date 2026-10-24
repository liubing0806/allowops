package builtin

import (
	"errors"
	"fmt"
	"testing"
)

type customReason string

func (c customReason) Error() string  { return string(c) }
func (c customReason) Reason() string { return string(c) }

func TestReasonOf(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, ""},
		{errors.New("PATH_OUTSIDE_ROOTS"), ""},
		{NewError(ReasonPathOutsideRoots, "path_glob is outside allowed_roots"), ReasonPathOutsideRoots},
		{fmt.Errorf("wrapped: %w", NewError(ReasonCursorExpired, "")), ReasonCursorExpired},
		{errors.Join(errors.New("output"), customReason(ReasonSourceUnsupported)), ReasonSourceUnsupported},
		{customReason("LEVEL_UNSUPPORTED"), "LEVEL_UNSUPPORTED"},
		{customReason("EXECUTION_FAILED"), ""},
		{customReason("ROOT_REQUIRED"), ""},
	} {
		if got := ReasonOf(tc.err); got != tc.want {
			t.Errorf("ReasonOf(%v)=%q want %q", tc.err, got, tc.want)
		}
	}
}
