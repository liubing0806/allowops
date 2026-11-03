package catalog

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/builtin/jvmarthas"
	"github.com/liubing0806/allowops/internal/jvmtarget"
	"github.com/liubing0806/allowops/internal/params"
)

type jvmArthasHandler struct{}

// jvmArthasRun and jvmArthasInstalled are replaced in tests.
var (
	jvmArthasRun = func(ctx context.Context, cfg jvmarthas.Config, p jvmarthas.Params, mask func(string) string) (jvmarthas.Result, error) {
		return jvmarthas.Run(ctx, cfg, p, mask)
	}
	jvmArthasInstalled = func() error { return jvmarthas.CheckInstalled(jvmarthas.DefaultDir) }
)

const (
	// classNamePattern is the rule of arthas.Build for the class of sc and sm, applied to the parameter as well.
	classNamePattern  = `^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$`
	identifierPattern = `^[A-Za-z_$][A-Za-z0-9_$]*$`
	maxJavaName       = 255
)

// durationField is a duration of builtin_config in its text form and the place it goes to.
type durationField struct {
	name string
	text string
	to   *time.Duration
}

// jvmArthasConfig decodes builtin_config. Thresholds that are not set stay zero; the handler
// package applies the defaults and rejects a threshold that is looser than its default.
func jvmArthasConfig(input map[string]any) (jvmarthas.Config, error) {
	var fields struct {
		Command     string                      `json:"command"`
		Targets     map[string]jvmtarget.Target `json:"targets"`
		ArthasDir   string                      `json:"arthas_dir"`
		SHA256      map[string]string           `json:"sha256"`
		HTTPPortMin int                         `json:"http_port_min"`
		HTTPPortMax int                         `json:"http_port_max"`
		ExecTimeout string                      `json:"exec_timeout"`
		SyspropKeys []string                    `json:"sysprop_keys"`
		Checks      struct {
			MinMemoryHeadroom    Size   `json:"min_memory_headroom"`
			MinMetaspaceHeadroom Size   `json:"min_metaspace_headroom"`
			MaxAttaches          int    `json:"max_attaches"`
			MinAttachInterval    string `json:"min_attach_interval"`
			MaxBlockingThreads   int    `json:"max_blocking_threads"`
			MaxOldGenPercent     int    `json:"max_old_gen_percent"`
			NoFullGCWithin       string `json:"no_full_gc_within"`
		} `json:"checks"`
		Guard struct {
			MaxCPUPercent    int    `json:"max_cpu_percent"`
			MaxGCTimePercent int    `json:"max_gc_time_percent"`
			MaxGCPerSecond   int    `json:"max_gc_per_second"`
			Settle           string `json:"settle"`
			HealthCheck      *struct {
				URL             string   `json:"url"`
				AllowedPrefixes []string `json:"allowed_prefixes"`
				Timeout         string   `json:"timeout"`
				MaxFailures     int      `json:"max_failures"`
				MaxLatency      string   `json:"max_latency"`
			} `json:"health_check"`
		} `json:"guard"`
	}
	if err := decodeBuiltinConfig(input, &fields); err != nil {
		return jvmarthas.Config{}, err
	}
	for name, target := range fields.Targets {
		target.Name = name
		fields.Targets[name] = target
	}
	cfg := jvmarthas.Config{
		Command: arthas.Kind(fields.Command), Targets: fields.Targets, ArthasDir: fields.ArthasDir, SHA256: fields.SHA256,
		HTTPPortMin: fields.HTTPPortMin, HTTPPortMax: fields.HTTPPortMax, SyspropKeys: fields.SyspropKeys,
		Checks: jvmarthas.Checks{
			MinMemoryHeadroom: int64(fields.Checks.MinMemoryHeadroom), MinMetaspaceHeadroom: int64(fields.Checks.MinMetaspaceHeadroom),
			MaxAttaches: fields.Checks.MaxAttaches, MaxBlockingThreads: fields.Checks.MaxBlockingThreads, MaxOldGenPercent: fields.Checks.MaxOldGenPercent,
		},
		Guard: jvmarthas.Guard{
			MaxCPUPercent: fields.Guard.MaxCPUPercent, MaxGCTimePercent: fields.Guard.MaxGCTimePercent, MaxGCPerSecond: fields.Guard.MaxGCPerSecond,
		},
	}
	durations := []durationField{
		{"exec_timeout", fields.ExecTimeout, &cfg.ExecTimeout},
		{"checks.min_attach_interval", fields.Checks.MinAttachInterval, &cfg.Checks.MinAttachInterval},
		{"checks.no_full_gc_within", fields.Checks.NoFullGCWithin, &cfg.Checks.NoFullGCWithin},
		{"guard.settle", fields.Guard.Settle, &cfg.Guard.Settle},
	}
	if h := fields.Guard.HealthCheck; h != nil {
		cfg.Guard.Health = &jvmarthas.HealthCheck{URL: h.URL, AllowedPrefixes: h.AllowedPrefixes, MaxFailures: h.MaxFailures}
		durations = append(durations,
			durationField{"guard.health_check.timeout", h.Timeout, &cfg.Guard.Health.Timeout},
			durationField{"guard.health_check.max_latency", h.MaxLatency, &cfg.Guard.Health.MaxLatency},
		)
	}
	for _, d := range durations {
		var err error
		if *d.to, err = builtinDuration(d.name, d.text); err != nil {
			return jvmarthas.Config{}, err
		}
	}
	return cfg, cfg.Validate()
}

func (jvmArthasHandler) ValidateConfig(input map[string]any) error {
	_, err := jvmArthasConfig(input)
	return err
}

// ValidateActionFields fixes the fields that keep a call to one JVM, one at a time: risk write
// (the attach loads code into the JVM), run_as root (allowops-exec needs it to attach and to
// enter the namespaces of the target), and no repetition or fan-out.
func (jvmArthasHandler) ValidateActionFields(a Action) error {
	switch {
	case a.RunAs != "root":
		return fmt.Errorf("jvm_arthas requires run_as: root")
	case a.Risk != "write":
		return fmt.Errorf("jvm_arthas requires risk: write")
	case a.Idempotent == nil || *a.Idempotent:
		return fmt.Errorf("jvm_arthas requires idempotent: false")
	case a.BatchSize != 1:
		return fmt.Errorf("jvm_arthas requires batch_size: 1")
	case a.MaxFailures == nil || *a.MaxFailures != 1:
		return fmt.Errorf("jvm_arthas requires max_failures: 1")
	case a.MaxTargets == nil || *a.MaxTargets != 1:
		return fmt.Errorf("jvm_arthas requires max_targets: 1")
	}
	return nil
}

// Parameters lists target and the arguments of the configured command. The command itself is
// fixed by the configuration, so a caller can never name one.
func (jvmArthasHandler) Parameters(input map[string]any) (map[string]params.Definition, error) {
	cfg, err := jvmArthasConfig(input)
	if err != nil {
		return nil, err
	}
	one := int64(1)
	defs := map[string]params.Definition{
		"target": {Type: params.Enum, Description: "JVM target from the action's allowlist", Values: cfg.TargetNames()},
	}
	class := params.Definition{Type: params.String, Description: "Binary name of the class, without wildcards", Regex: classNamePattern, MaxLen: maxJavaName}
	switch cfg.Command {
	case arthas.KindThreadTop:
		defs["top"] = params.Definition{Type: params.Int, Description: "Number of busiest threads to show", Min: &one, Max: int64(arthas.MaxTop)}
	case arthas.KindThreadInfo:
		defs["thread_id"] = params.Definition{Type: params.Int, Description: "ID of the thread", Min: &one}
	case arthas.KindClassInfo:
		defs["class"] = class
	case arthas.KindMethodInfo:
		defs["class"] = class
		defs["method"] = params.Definition{Type: params.String, Description: "Name of the method; all methods when omitted", Regex: identifierPattern, MaxLen: maxJavaName, Optional: true}
	case arthas.KindSysprop:
		keys := slices.Clone(cfg.SyspropKeys)
		slices.Sort(keys)
		defs["key"] = params.Definition{Type: params.Enum, Description: "System property from the action's allowlist", Values: keys}
	}
	return defs, nil
}

func (h jvmArthasHandler) Run(ctx context.Context, input, values map[string]any) (BuiltinResult, error) {
	return h.RunRedacted(ctx, input, values, nil)
}

func (jvmArthasHandler) RunRedacted(ctx context.Context, input, values map[string]any, mask func(string) string) (BuiltinResult, error) {
	cfg, err := jvmArthasConfig(input)
	if err != nil {
		return BuiltinResult{ExitCode: builtin.ExitFailure}, err
	}
	target, ok := values["target"].(string)
	if !ok {
		return BuiltinResult{ExitCode: builtin.ExitFailure}, fmt.Errorf("jvm_arthas requires parameter target")
	}
	req := arthas.Request{Kind: cfg.Command}
	if n, ok := values["top"].(int64); ok {
		req.Top = int(n)
	}
	req.ThreadID, _ = values["thread_id"].(int64)
	req.Class, _ = values["class"].(string)
	req.Method, _ = values["method"].(string)
	req.Key, _ = values["key"].(string)
	r, err := jvmArthasRun(ctx, cfg, jvmarthas.Params{Target: target, Request: req}, mask)
	return BuiltinResult{Stdout: r.Stdout, Stderr: r.Stderr, ExitCode: r.ExitCode}, err
}
