//go:build linux

package jvmperfdata

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/jvmtarget"
	"github.com/liubing0806/allowops/internal/jvmtarget/perfdata"
)

// output is the JSON the handler prints. perfdata.Summary holds no JVM
// arguments, command line or system property values.
type output struct {
	Target string `json:"target"`
	// PID is the pid in the host's PID namespace.
	PID int `json:"pid"`
	perfdata.Summary
}

// Run resolves the target on this host and prints the summary.
func Run(ctx context.Context, cfg Config, p Params) (Result, error) {
	return RunWith(ctx, jvmtarget.NewResolver(), cfg, p)
}

// RunWith is Run with a given resolver. Only a cancelled or expired context is
// returned as an error.
func RunWith(ctx context.Context, resolver *jvmtarget.Resolver, cfg Config, p Params) (Result, error) {
	if err := cfg.Validate(); err != nil {
		return Result{ExitCode: builtin.ExitFailure}, err
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = builtin.DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Result{ExitCode: builtin.ExitFailure}, err
	}
	target, ok := cfg.Targets[p.Target]
	if !ok {
		return failure("unknown target %q; allowed: %s", p.Target, strings.Join(cfg.TargetNames(), ", ")), nil
	}
	summary, pid, err := read(ctx, resolver, target)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Result{ExitCode: builtin.ExitFailure}, ctxErr
		}
		return failure("target %q: %v", target.Name, err), nil
	}
	data, err := json.MarshalIndent(output{Target: target.Name, PID: pid, Summary: summary}, "", "  ")
	if err != nil {
		return Result{ExitCode: builtin.ExitFailure}, err
	}
	return Result{Stdout: string(data) + "\n", ExitCode: builtin.ExitSuccess}, nil
}

func read(ctx context.Context, resolver *jvmtarget.Resolver, target jvmtarget.Target) (perfdata.Summary, int, error) {
	jvm, err := resolver.Resolve(ctx, target)
	if err != nil {
		return perfdata.Summary{}, 0, err
	}
	data, err := jvm.ReadPerfData(ctx)
	if err != nil {
		return perfdata.Summary{}, 0, err
	}
	summary, err := data.Summary()
	if err != nil {
		return perfdata.Summary{}, 0, err
	}
	return summary, jvm.PID, nil
}

func failure(format string, args ...any) Result {
	return Result{Stderr: "jvm_perfdata: " + fmt.Sprintf(format, args...) + "\n", ExitCode: builtin.ExitFailure}
}
