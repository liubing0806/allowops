package catalog

import (
	"context"
	"fmt"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/builtin/jvmperfdata"
	"github.com/liubing0806/allowops/internal/jvmtarget"
	"github.com/liubing0806/allowops/internal/params"
)

type jvmPerfdataHandler struct{}

func jvmPerfdataConfig(input map[string]any) (jvmperfdata.Config, error) {
	var fields struct {
		Targets map[string]jvmtarget.Target `json:"targets"`
		Timeout string                      `json:"timeout"`
	}
	if err := decodeBuiltinConfig(input, &fields); err != nil {
		return jvmperfdata.Config{}, err
	}
	timeout, err := builtinTimeout(fields.Timeout)
	if err != nil {
		return jvmperfdata.Config{}, err
	}
	for name, target := range fields.Targets {
		target.Name = name
		fields.Targets[name] = target
	}
	cfg := jvmperfdata.Config{Targets: fields.Targets, Timeout: timeout}
	return cfg, cfg.Validate()
}

func (jvmPerfdataHandler) ValidateConfig(input map[string]any) error {
	_, err := jvmPerfdataConfig(input)
	return err
}

func (jvmPerfdataHandler) Parameters(input map[string]any) (map[string]params.Definition, error) {
	cfg, err := jvmPerfdataConfig(input)
	if err != nil {
		return nil, err
	}
	return map[string]params.Definition{
		"target": {Type: params.Enum, Description: "JVM target from the action's allowlist", Values: cfg.TargetNames()},
	}, nil
}

func (jvmPerfdataHandler) Run(ctx context.Context, input, values map[string]any) (BuiltinResult, error) {
	cfg, err := jvmPerfdataConfig(input)
	if err != nil {
		return BuiltinResult{ExitCode: builtin.ExitFailure}, err
	}
	target, ok := values["target"].(string)
	if !ok {
		return BuiltinResult{ExitCode: builtin.ExitFailure}, fmt.Errorf("jvm_perfdata requires parameter target")
	}
	r, err := jvmperfdata.Run(ctx, cfg, jvmperfdata.Params{Target: target})
	return BuiltinResult{Stdout: r.Stdout, Stderr: r.Stderr, ExitCode: r.ExitCode}, err
}
