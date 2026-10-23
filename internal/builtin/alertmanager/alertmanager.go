// Package alertmanager implements the read-only alertmanager_alerts builtin.
// It only issues GET /api/v2/alerts through the shared API client.
package alertmanager

import (
	"context"
	"errors"
	"time"
)

// Limits. Configuration may only tighten them; zero selects the default.
const (
	DefaultTimeout                = 10 * time.Second
	MaxTimeout                    = 30 * time.Second
	DefaultMaxAlerts              = 100
	MaxAlerts                     = 1000
	DefaultMaxResponseBytes int64 = 4 << 20
	MaxResponseBytes        int64 = 16 << 20
)

// Config is trusted catalog configuration.
type Config struct {
	Address          string
	Credential       string
	CAFile           string
	Timeout          time.Duration
	MaxAlerts        int
	MaxResponseBytes int64
}

// Params are the caller-supplied query options. A false value excludes the
// corresponding alert state; the catalog adapter supplies the defaults.
type Params struct {
	Filter                      []string
	Active, Silenced, Inhibited bool
}

// Result is raw handler output. Truncated reports a max_alerts cut.
type Result struct {
	Stdout, Stderr string
	ExitCode       int
	Truncated      bool
}

func (c Config) Validate() error { return errors.New("not implemented") }

// UsesCredential reports whether the action reads a credential file.
func (c Config) UsesCredential() bool { return false }

// Run queries Alertmanager and renders the alerts as TSV. mask redacts original
// field text before TSV escaping; nil leaves text unchanged.
func Run(ctx context.Context, cfg Config, p Params, mask func(string) string) (Result, error) {
	return Result{}, errors.New("not implemented")
}
