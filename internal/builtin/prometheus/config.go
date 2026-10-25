// Package prometheus implements the read-only prometheus_query builtin for the
// Prometheus HTTP API v1.
package prometheus

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/liubing0806/allowops/internal/builtin/apiclient"
)

// Defaults and upper limits of builtin_config. Configuration can only tighten
// the limits; MinStep can only be raised.
const (
	DefaultTimeout          = 10 * time.Second
	MaxTimeout              = 30 * time.Second
	DefaultMaxRange         = 24 * time.Hour
	MaxRange                = 7 * 24 * time.Hour
	DefaultMinStep          = 15 * time.Second
	DefaultMaxPoints        = 300
	MaxPoints               = 11000 // Prometheus rejects query_range above this.
	DefaultMaxSeries        = 50
	MaxSeries               = 1000
	DefaultMaxResponseBytes = 4 << 20
	MaxResponseBytes        = 16 << 20
)

// The supported API names. Each fixes one request path.
const (
	APIQuery       = "query"
	APIQueryRange  = "query_range"
	APISeries      = "series"
	APILabels      = "labels"
	APILabelValues = "label_values"
	APIAlerts      = "alerts"
	APIRules       = "rules"
	APITargets     = "targets"
)

// APIs lists every supported api value.
var APIs = []string{APIQuery, APIQueryRange, APISeries, APILabels, APILabelValues, APIAlerts, APIRules, APITargets}

// Config is trusted catalog configuration. Zero limits select the defaults.
// The embedded apiclient.Config carries address, credential, ca_file, timeout
// and max_response_bytes.
type Config struct {
	API string
	apiclient.Config
	MaxRange  time.Duration
	MinStep   time.Duration
	MaxPoints int
	MaxSeries int
}

// Validate checks the configuration without touching the file system.
func (c Config) Validate() error {
	_, err := c.resolve()
	return err
}

// resolve returns a copy with defaults applied.
func (c Config) resolve() (Config, error) {
	if !slices.Contains(APIs, c.API) {
		return c, fmt.Errorf("api must be one of %v", APIs)
	}
	if err := c.Config.Validate(); err != nil {
		return c, err
	}
	var err error
	if c.Timeout, err = apiclient.Tighten("timeout", c.Timeout, DefaultTimeout, MaxTimeout); err != nil {
		return c, err
	}
	if c.MaxResponseBytes, err = apiclient.Tighten("max_response_bytes", c.MaxResponseBytes, DefaultMaxResponseBytes, MaxResponseBytes); err != nil {
		return c, err
	}
	if c.MaxRange, err = apiclient.Tighten("max_range", c.MaxRange, DefaultMaxRange, MaxRange); err != nil {
		return c, err
	}
	if c.MaxPoints, err = apiclient.Tighten("max_points", c.MaxPoints, DefaultMaxPoints, MaxPoints); err != nil {
		return c, err
	}
	if c.MaxPoints < 2 {
		return c, errors.New("max_points must be at least 2")
	}
	if c.MaxSeries, err = apiclient.Tighten("max_series", c.MaxSeries, DefaultMaxSeries, MaxSeries); err != nil {
		return c, err
	}
	if c.MinStep == 0 {
		c.MinStep = DefaultMinStep
	}
	if c.MinStep < DefaultMinStep {
		return c, fmt.Errorf("min_step must be at least %s", DefaultMinStep)
	}
	return c, nil
}
