// Package jvmperfdata implements the jvm_perfdata builtin: it reads the
// hsperfdata of an allowlisted JVM and prints heap, GC, class and thread
// figures. It does not attach to the JVM, signal it or write to its files.
package jvmperfdata

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/jvmtarget"
	"github.com/liubing0806/allowops/internal/jvmtarget/perfdata"
)

// MaxTargets bounds the allowlist of one action.
const MaxTargets = 64

// Config is trusted catalog configuration. Targets maps the name a caller
// selects to the unit or container; the caller never supplies a pid or a path.
// Zero Timeout selects the builtin default.
type Config struct {
	Targets map[string]jvmtarget.Target
	Timeout time.Duration
}

// Params are the caller's inputs.
type Params struct {
	Target string
}

// Result is the handler output. Failures the operator can act on (no hsperfdata,
// service stopped, ...) are reported on Stderr with ExitCode 1 and no error.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Validate checks the configuration.
func (c Config) Validate() error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("jvm_perfdata requires at least one target")
	}
	if len(c.Targets) > MaxTargets {
		return fmt.Errorf("jvm_perfdata allows at most %d targets", MaxTargets)
	}
	if c.Timeout < 0 || c.Timeout > builtin.DefaultTimeout {
		return fmt.Errorf("jvm_perfdata timeout must be between 0s and %s", builtin.DefaultTimeout)
	}
	for _, name := range c.TargetNames() {
		t := c.Targets[name]
		if t.Name != name {
			return fmt.Errorf("target %q: name field %q differs", name, t.Name)
		}
		if err := t.Validate(); err != nil {
			return fmt.Errorf("target %q: %w", name, err)
		}
	}
	return nil
}

// TargetNames returns the selectable names in order.
func (c Config) TargetNames() []string {
	names := make([]string, 0, len(c.Targets))
	for name := range c.Targets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

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
