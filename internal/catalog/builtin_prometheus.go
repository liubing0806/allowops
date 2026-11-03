package catalog

import (
	"context"
	"fmt"
	"time"

	"github.com/liubing0806/allowops/internal/builtin/apiclient"
	prombuiltin "github.com/liubing0806/allowops/internal/builtin/prometheus"
	"github.com/liubing0806/allowops/internal/params"
)

type prometheusHandler struct{}

func builtinDuration(name, text string) (time.Duration, error) {
	if text == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("builtin_config.%s requires a Go duration", name)
	}
	return d, nil
}

// prometheusConfig decodes builtin_config. Zero limits stay zero here; the
// handler package applies the defaults and the upper limits.
func prometheusConfig(input map[string]any) (prombuiltin.Config, error) {
	var fields struct {
		API              string `json:"api"`
		Address          string `json:"address"`
		Credential       string `json:"credential"`
		CAFile           string `json:"ca_file"`
		Timeout          string `json:"timeout"`
		MaxRange         string `json:"max_range"`
		MinStep          string `json:"min_step"`
		MaxPoints        int    `json:"max_points"`
		MaxSeries        int    `json:"max_series"`
		MaxResponseBytes Size   `json:"max_response_bytes"`
	}
	if err := decodeBuiltinConfig(input, &fields); err != nil {
		return prombuiltin.Config{}, err
	}
	cfg := prombuiltin.Config{
		API: fields.API,
		Config: apiclient.Config{
			Address: fields.Address, Credential: fields.Credential, CAFile: fields.CAFile,
			MaxResponseBytes: int64(fields.MaxResponseBytes),
		},
		MaxPoints: fields.MaxPoints, MaxSeries: fields.MaxSeries,
	}
	var err error
	if cfg.Timeout, err = builtinDuration("timeout", fields.Timeout); err != nil {
		return cfg, err
	}
	if cfg.MaxRange, err = builtinDuration("max_range", fields.MaxRange); err != nil {
		return cfg, err
	}
	if cfg.MinStep, err = builtinDuration("min_step", fields.MinStep); err != nil {
		return cfg, err
	}
	return cfg, cfg.Validate()
}

func (prometheusHandler) ValidateConfig(input map[string]any) error {
	_, err := prometheusConfig(input)
	return err
}

// ValidateActionFields requires run_as: root for a credential. The credential
// file is readable by root only, so allowops-exec must run the action as root.
func (prometheusHandler) ValidateActionFields(a Action) error {
	if cred, _ := a.BuiltinConfig["credential"].(string); cred != "" && a.RunAs != "root" {
		return fmt.Errorf("prometheus_query with a credential requires run_as: root")
	}
	return nil
}

func (prometheusHandler) Parameters(input map[string]any) (map[string]params.Definition, error) {
	cfg, err := prometheusConfig(input)
	if err != nil {
		return nil, err
	}
	return prombuiltin.Definitions(cfg.API)
}

func (prometheusHandler) Run(ctx context.Context, input, values map[string]any) (BuiltinResult, error) {
	return (prometheusHandler{}).RunRedacted(ctx, input, values, nil)
}

func (prometheusHandler) RunRedacted(ctx context.Context, input, values map[string]any, mask func(string) string) (BuiltinResult, error) {
	cfg, err := prometheusConfig(input)
	if err != nil {
		return BuiltinResult{ExitCode: 1}, err
	}
	text := func(name string) string { s, _ := values[name].(string); return s }
	p := prombuiltin.Params{Query: text("query"), Time: text("time"), Start: text("start"), End: text("end"), Label: text("label"), RuleType: text("rule_type")}
	p.Step, p.HasStep = values["step"].(time.Duration)
	p.Match, _ = values["match"].([]string)
	p.Summary, _ = values["summary"].(bool)
	r, err := prombuiltin.RunRedacted(ctx, cfg, p, mask)
	return BuiltinResult{Stdout: r.Stdout, Stderr: r.Stderr, ExitCode: r.ExitCode, ResourceLimited: r.Truncated, StatusCode: r.StatusCode}, err
}
