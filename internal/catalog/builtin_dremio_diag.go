package catalog

import (
	"context"
	"fmt"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/builtin/dremio"
	"github.com/liubing0806/allowops/internal/params"
)

type dremioDiagHandler struct{}

func dremioDiagConfig(input map[string]any) (dremio.DiagConfig, error) {
	var fields struct {
		Credential      string   `json:"credential"`
		URL             string   `json:"url"`
		MaxRows         int      `json:"max_rows"`
		MaxBytes        Size     `json:"max_bytes"`
		Timeout         string   `json:"timeout"`
		MaxProfileBytes Size     `json:"max_profile_bytes"`
		Ops             []string `json:"ops"`
	}
	if err := decodeBuiltinConfig(input, &fields); err != nil {
		return dremio.DiagConfig{}, err
	}
	if _, present := input["ops"]; present && fields.Ops == nil {
		return dremio.DiagConfig{}, fmt.Errorf("builtin_config.ops requires a nonempty list of strings")
	}
	timeout, err := builtinTimeout(fields.Timeout)
	if err != nil {
		return dremio.DiagConfig{}, err
	}
	cfg := dremio.DiagConfig{Ops: fields.Ops,
		Credential: fields.Credential, URL: fields.URL, MaxRows: fields.MaxRows, MaxBytes: int64(fields.MaxBytes), Timeout: timeout,
		MaxProfileBytes: int64(fields.MaxProfileBytes),
	}
	return cfg, cfg.Validate()
}

func (dremioDiagHandler) ValidateConfig(input map[string]any) error {
	_, err := dremioDiagConfig(input)
	return err
}

// Parameters lists the parameters of all ops. Which of them an op accepts is
// checked by the handler, because a tool schema with cross-field rules at its
// root is skipped by some MCP clients. Optional parameters have no default
// here: the handler applies the defaults of the op.
func (dremioDiagHandler) Parameters(input map[string]any) (map[string]params.Definition, error) {
	cfg, err := dremioDiagConfig(input)
	if err != nil {
		return nil, err
	}
	maxRows := positiveBound(cfg.MaxRows, builtin.DefaultDremioMaxRows)
	one, window := int64(1), dremio.MaxSince.String()
	op := params.Definition{Type: params.Enum, Description: "nodes: cluster nodes and memory; jobs: recent jobs; job: status of one job; job_profile: summary of the profile of one job; reflections: reflection status", Values: dremio.Ops}
	if cfg.Ops != nil {
		op.Values = cfg.Ops
		// A single op is the default, so that the caller can leave it out.
		if len(cfg.Ops) == 1 {
			op.Default = cfg.Ops[0]
		}
	}
	return map[string]params.Definition{
		"op":           op,
		"job_id":       {Type: params.String, Description: "Job id (job, job_profile)", Regex: `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`, MaxLen: 36, Optional: true},
		"since":        {Type: params.Duration, Description: "Time window of the job list, default 1h (jobs)", Max: window, Optional: true},
		"min_duration": {Type: params.Duration, Description: "Only jobs that ran at least this long (jobs)", Max: window, Optional: true},
		"state":        {Type: params.Enum, Description: "Only jobs in this state (jobs)", Values: dremio.JobStates, Optional: true},
		"user":         {Type: params.String, Description: "Only jobs of this user (jobs)", Regex: `^[A-Za-z0-9._@][A-Za-z0-9._@-]{0,127}$`, MaxLen: 128, Optional: true},
		"limit":        {Type: params.Int, Description: "Number of jobs, default 20 (jobs)", Min: &one, Max: maxRows, Optional: true},
		"top_n":        {Type: params.Int, Description: "Number of operators in the summary, default 10 (job_profile)", Min: &one, Max: 50, Optional: true},
	}, nil
}

func (h dremioDiagHandler) Run(ctx context.Context, input, values map[string]any) (BuiltinResult, error) {
	return h.RunRedacted(ctx, input, values, nil)
}

func diagDuration(values map[string]any, name string) *time.Duration {
	if d, ok := values[name].(time.Duration); ok {
		return &d
	}
	return nil
}

func diagInt(values map[string]any, name string) *int {
	if n, ok := values[name].(int64); ok {
		v := int(n)
		return &v
	}
	return nil
}

func (dremioDiagHandler) RunRedacted(ctx context.Context, input, values map[string]any, mask func(string) string) (BuiltinResult, error) {
	cfg, err := dremioDiagConfig(input)
	if err != nil {
		return BuiltinResult{ExitCode: builtin.ExitFailure}, err
	}
	text := func(name string) string { s, _ := values[name].(string); return s }
	r, err := dremio.RunDiagRedacted(ctx, cfg, dremio.DiagParams{
		Op: text("op"), JobID: text("job_id"), State: text("state"), User: text("user"),
		Since: diagDuration(values, "since"), MinDuration: diagDuration(values, "min_duration"),
		Limit: diagInt(values, "limit"), TopN: diagInt(values, "top_n"),
	}, mask)
	if err != nil {
		return BuiltinResult{ExitCode: builtin.ExitFailure}, err
	}
	return BuiltinResult{Stdout: r.Output, ResourceLimited: r.Truncated}, nil
}
