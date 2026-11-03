package catalog

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
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
		// The settings of the L2 commands.
		ClassPrefixes   []string `json:"class_prefixes"`
		EnhanceDuration string   `json:"enhance_duration"`
		MaxMethods      int      `json:"max_methods"`
		ObjectSizeLimit Size     `json:"object_size_limit"`
		Checks          struct {
			MinMemoryHeadroom    Size   `json:"min_memory_headroom"`
			MinMetaspaceHeadroom Size   `json:"min_metaspace_headroom"`
			MaxAttaches          int    `json:"max_attaches"`
			MinAttachInterval    string `json:"min_attach_interval"`
			MaxBlockingThreads   int    `json:"max_blocking_threads"`
			MaxOldGenPercent     int    `json:"max_old_gen_percent"`
			NoFullGCWithin       string `json:"no_full_gc_within"`
			MaxCPUPercent        int    `json:"max_cpu_percent"`
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
		ClassPrefixes: fields.ClassPrefixes, MaxMethods: fields.MaxMethods,
		Checks: jvmarthas.Checks{
			MinMemoryHeadroom: int64(fields.Checks.MinMemoryHeadroom), MinMetaspaceHeadroom: int64(fields.Checks.MinMetaspaceHeadroom),
			MaxAttaches: fields.Checks.MaxAttaches, MaxBlockingThreads: fields.Checks.MaxBlockingThreads, MaxOldGenPercent: fields.Checks.MaxOldGenPercent,
			MaxCPUPercent: fields.Checks.MaxCPUPercent,
		},
		Guard: jvmarthas.Guard{
			MaxCPUPercent: fields.Guard.MaxCPUPercent, MaxGCTimePercent: fields.Guard.MaxGCTimePercent, MaxGCPerSecond: fields.Guard.MaxGCPerSecond,
		},
	}
	// A size beyond the range of int is out of the range of object_size_limit as well.
	if fields.ObjectSizeLimit > Size(arthas.MaxObjectSizeLimit) {
		return jvmarthas.Config{}, fmt.Errorf("object_size_limit must be between %d and %d bytes", arthas.MinObjectSizeLimit, arthas.MaxObjectSizeLimit)
	}
	cfg.ObjectSizeLimit = int(fields.ObjectSizeLimit)
	durations := []durationField{
		{"exec_timeout", fields.ExecTimeout, &cfg.ExecTimeout},
		{"enhance_duration", fields.EnhanceDuration, &cfg.EnhanceDuration},
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

// l2Overhead is the part of the timeout of an L2 action beyond its enhancement, or beyond the
// command timeout of jad: the CPU check (5s), the attach, the setup commands, the end of the job
// and the clean-up with its confirming reset.
const l2Overhead = 60 * time.Second

// ValidateActionFields fixes the fields that keep a call to one JVM, one at a time: risk write
// (the attach loads code into the JVM), run_as root (allowops-exec needs it to attach and to
// enter the namespaces of the target), and no repetition or fan-out. An L2 action also needs the
// secrets and pii redaction, since its output holds application data, and a timeout that covers
// the enhancement.
func (jvmArthasHandler) ValidateActionFields(a Action) error {
	if err := validateArthasCommonFields(a); err != nil {
		return err
	}
	cfg, err := jvmArthasConfig(a.BuiltinConfig)
	if err != nil {
		return err
	}
	if cfg.Command.Level() != 2 {
		return nil
	}
	if a.Redact == nil || !slices.Contains(a.Redact.Builtin, "secrets") || !slices.Contains(a.Redact.Builtin, "pii") {
		return fmt.Errorf("jvm_arthas %s requires redact.builtin with secrets and pii", cfg.Command)
	}
	eff := cfg.Effective()
	least := eff.ExecTimeout + l2Overhead
	if cfg.Command.Enhances() {
		least = eff.EnhanceDuration + l2Overhead
	}
	if timeout, err := time.ParseDuration(a.Timeout); err != nil || timeout < least {
		return fmt.Errorf("jvm_arthas %s requires a timeout of at least %s", cfg.Command, least)
	}
	return nil
}

func validateArthasCommonFields(a Action) error {
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
	if cfg.Command.Level() == 2 {
		class.Description = "Binary name of the class, without wildcards; it must start with " + strings.Join(cfg.ClassPrefixes, ", ")
		defs["class"] = class
		method := params.Definition{Type: params.String, Description: "Name of the method, without wildcards", Regex: identifierPattern, MaxLen: maxJavaName}
		if cfg.Command == arthas.KindJad {
			method.Description, method.Optional = "Name of the method to decompile; the whole class when omitted", true
		}
		defs["method"] = method
	}
	if cfg.Command.Enhances() {
		maxCost := int64(arthas.MaxMinCost)
		defs["count"] = params.Definition{Type: params.Int, Description: "Number of results after which the enhancement ends", Min: &one, Max: int64(arthas.MaxCount), Default: int64(1)}
		defs["min_cost_ms"] = params.Definition{Type: params.Int, Description: "Only calls that take longer than this many milliseconds", Min: &one, Max: maxCost, Optional: true}
	}
	switch cfg.Command {
	case arthas.KindWatch:
		defs["express"] = params.Definition{Type: params.Enum, Description: "What to show of each call: arguments, return value, exception", Values: arthas.WatchExpressions(), Default: "params,returnObj"}
		defs["expand"] = params.Definition{Type: params.Int, Description: "Depth to which objects are expanded", Min: &one, Max: int64(arthas.MaxExpand), Default: int64(1)}
	case arthas.KindMonitor:
		// count × cycle must also stay below the enhancement time; arthas.Build checks that.
		seconds := int64(cfg.Effective().EnhanceDuration / time.Second)
		defs["cycle"] = params.Definition{Type: params.Int, Description: "Seconds of one statistics period; count × cycle must be less than " + strconv.FormatInt(seconds, 10), Min: &one, Max: seconds - 1}
	}
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
	req.Express, _ = values["express"].(string)
	if n, ok := values["expand"].(int64); ok {
		req.Expand = int(n)
	}
	if n, ok := values["count"].(int64); ok {
		req.Count = int(n)
	}
	req.MinCost, _ = values["min_cost_ms"].(int64)
	if n, ok := values["cycle"].(int64); ok {
		req.Cycle = int(n)
	}
	r, err := jvmArthasRun(ctx, cfg, jvmarthas.Params{Target: target, Request: req}, mask)
	return BuiltinResult{Stdout: r.Stdout, Stderr: r.Stderr, ExitCode: r.ExitCode}, err
}
