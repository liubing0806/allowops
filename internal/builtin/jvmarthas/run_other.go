//go:build !linux

package jvmarthas

import (
	"context"
	"errors"

	"github.com/liubing0806/allowops/internal/builtin"
)

var errLinuxOnly = errors.New("jvm_arthas is supported on Linux hosts only")

// CheckInstalled reports whether the Arthas package is installed on this host.
func CheckInstalled(string) error {
	return errLinuxOnly
}

// Run is only supported on Linux hosts.
func Run(context.Context, Config, Params, func(string) string) (Result, error) {
	return Result{ExitCode: builtin.ExitFailure}, errLinuxOnly
}
