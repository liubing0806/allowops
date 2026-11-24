// Package jvmperfdata implements the jvm_perfdata builtin: it reads the
// hsperfdata of an allowlisted JVM and prints heap, GC, class and thread
// figures. It does not attach to the JVM, signal it or write to its files.
package jvmperfdata

import (
	"fmt"
	"sort"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/jvmtarget"
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
