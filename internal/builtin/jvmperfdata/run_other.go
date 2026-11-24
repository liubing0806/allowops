//go:build !linux

package jvmperfdata

import (
	"context"
	"errors"

	"github.com/liubing0806/allowops/internal/builtin"
)

// Run is only supported on Linux hosts.
func Run(context.Context, Config, Params) (Result, error) {
	return Result{ExitCode: builtin.ExitFailure}, errors.New("jvm_perfdata is supported on Linux hosts only")
}
