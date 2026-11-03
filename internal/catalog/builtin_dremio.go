package catalog

import (
	"context"
	"fmt"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/builtin/dremio"
	"github.com/liubing0806/allowops/internal/params"
)

type dremioHandler struct{}

func dremioConfig(input map[string]any) (dremio.Config, error) {
	var fields struct {
		Credential     string   `json:"credential"`
		URL            string   `json:"url"`
		MaxRows        int      `json:"max_rows"`
		MaxBytes       Size     `json:"max_bytes"`
		Timeout        string   `json:"timeout"`
		StatementTypes []string `json:"statement_types"`
		ShowTypes      []string `json:"show_types"`
	}
	if err := decodeBuiltinConfig(input, &fields); err != nil {
		return dremio.Config{}, err
	}
	for _, list := range []struct {
		name   string
		values []string
	}{{"statement_types", fields.StatementTypes}, {"show_types", fields.ShowTypes}} {
		if _, present := input[list.name]; present && list.values == nil {
			return dremio.Config{}, fmt.Errorf("builtin_config.%s requires a nonempty list of strings", list.name)
		}
	}
	timeout, err := builtinTimeout(fields.Timeout)
	if err != nil {
		return dremio.Config{}, err
	}
	cfg := dremio.Config{
		Credential: fields.Credential, URL: fields.URL, MaxRows: fields.MaxRows, MaxBytes: int64(fields.MaxBytes), Timeout: timeout,
		StatementTypes: fields.StatementTypes, ShowTypes: fields.ShowTypes,
	}
	return cfg, cfg.Validate()
}

func (dremioHandler) ValidateConfig(input map[string]any) error {
	_, err := dremioConfig(input)
	return err
}

// Parameters has the SQL only: names in it are complete paths, and there is no
// context parameter that could select a data source.
func (dremioHandler) Parameters(map[string]any) (map[string]params.Definition, error) {
	return map[string]params.Definition{
		"sql": {Type: params.String, Description: "Read-only Dremio SQL: one SELECT, SHOW, DESCRIBE or EXPLAIN statement with complete object paths", MaxLen: 4000},
	}, nil
}

func (h dremioHandler) Run(ctx context.Context, input, values map[string]any) (BuiltinResult, error) {
	return h.RunRedacted(ctx, input, values, nil)
}

func (dremioHandler) RunRedacted(ctx context.Context, input, values map[string]any, mask func(string) string) (BuiltinResult, error) {
	cfg, err := dremioConfig(input)
	if err != nil {
		return BuiltinResult{ExitCode: builtin.ExitFailure}, err
	}
	sql, _ := values["sql"].(string)
	r, err := dremio.RunRedacted(ctx, cfg, dremio.Params{SQL: sql}, mask)
	if err != nil {
		return BuiltinResult{ExitCode: builtin.ExitFailure}, err
	}
	return BuiltinResult{Stdout: r.Output, ResourceLimited: r.Truncated}, nil
}
