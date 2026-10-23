package catalog

import (
	"context"
	"fmt"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/builtin/alertmanager"
	"github.com/liubing0806/allowops/internal/params"
)

// credentialedBuiltin is implemented by handlers that read a root-owned
// credential file. Such an action must run through allowops-exec as root.
type credentialedBuiltin interface {
	UsesCredential(map[string]any) bool
}

// validateBuiltinRunAs rejects a configuration whose credential the agent user
// could not read, so the failure surfaces at catalog validation.
func validateBuiltinRunAs(a Action) error {
	handler, ok := Builtins[a.Builtin].(credentialedBuiltin)
	if ok && handler.UsesCredential(a.BuiltinConfig) && a.RunAs != "root" {
		return fmt.Errorf("builtin_config.credential requires run_as: root")
	}
	return nil
}

type alertmanagerHandler struct{}

func alertmanagerConfig(input map[string]any) (alertmanager.Config, error) {
	var fields struct {
		Address          string `json:"address"`
		Credential       string `json:"credential"`
		CAFile           string `json:"ca_file"`
		Timeout          string `json:"timeout"`
		MaxAlerts        int    `json:"max_alerts"`
		MaxResponseBytes Size   `json:"max_response_bytes"`
	}
	if err := decodeBuiltinConfig(input, &fields); err != nil {
		return alertmanager.Config{}, err
	}
	var timeout time.Duration
	if fields.Timeout != "" {
		d, err := time.ParseDuration(fields.Timeout)
		if err != nil {
			return alertmanager.Config{}, fmt.Errorf("builtin_config.timeout requires a duration: %w", err)
		}
		timeout = d
	}
	cfg := alertmanager.Config{Address: fields.Address, Credential: fields.Credential, CAFile: fields.CAFile, Timeout: timeout, MaxAlerts: fields.MaxAlerts, MaxResponseBytes: int64(fields.MaxResponseBytes)}
	return cfg, cfg.Validate()
}

func (alertmanagerHandler) ValidateConfig(input map[string]any) error {
	_, err := alertmanagerConfig(input)
	return err
}

func (alertmanagerHandler) UsesCredential(input map[string]any) bool {
	cfg, err := alertmanagerConfig(input)
	return err == nil && cfg.UsesCredential()
}

func (alertmanagerHandler) Parameters(input map[string]any) (map[string]params.Definition, error) {
	if _, err := alertmanagerConfig(input); err != nil {
		return nil, err
	}
	return map[string]params.Definition{
		"filter":    {Type: params.StringArray, Description: `Alertmanager matchers, for example alertname="HighLatency"`, MaxLen: 256, MaxItems: 10, Optional: true},
		"active":    {Type: params.Bool, Description: "Include active alerts", Default: true},
		"silenced":  {Type: params.Bool, Description: "Include silenced alerts", Default: false},
		"inhibited": {Type: params.Bool, Description: "Include inhibited alerts", Default: false},
	}, nil
}

func (alertmanagerHandler) Run(ctx context.Context, input, values map[string]any) (BuiltinResult, error) {
	return (alertmanagerHandler{}).RunRedacted(ctx, input, values, nil)
}

func (alertmanagerHandler) RunRedacted(ctx context.Context, input, values map[string]any, mask func(string) string) (BuiltinResult, error) {
	cfg, err := alertmanagerConfig(input)
	if err != nil {
		return BuiltinResult{ExitCode: builtin.ExitFailure}, err
	}
	filter, _ := values["filter"].([]string)
	p := alertmanager.Params{Filter: filter, Active: values["active"].(bool), Silenced: values["silenced"].(bool), Inhibited: values["inhibited"].(bool)}
	r, err := alertmanager.Run(ctx, cfg, p, mask)
	return BuiltinResult{Stdout: r.Stdout, Stderr: r.Stderr, ExitCode: r.ExitCode, ResourceLimited: r.Truncated}, err
}
