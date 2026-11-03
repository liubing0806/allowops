package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
)

type filterParameterBuiltin struct{}

func (filterParameterBuiltin) Parameters(map[string]any) (map[string]params.Definition, error) {
	return map[string]params.Definition{"exclude": {Type: params.String, Description: "Handler exclude", MaxLen: 64}}, nil
}

func (filterParameterBuiltin) ValidateConfig(map[string]any) error { return nil }

func (filterParameterBuiltin) Run(_ context.Context, _ map[string]any, values map[string]any) (catalog.BuiltinResult, error) {
	return catalog.BuiltinResult{Stdout: values["exclude"].(string) + "\nkeep\npassword=secret\n"}, nil
}

func filterParameterAction(t *testing.T) catalog.Action {
	t.Helper()
	const name = "filter_parameter_fixture"
	catalog.Builtins[name] = filterParameterBuiltin{}
	t.Cleanup(func() { delete(catalog.Builtins, name) })
	return catalog.Action{Name: "builtin_filters", Description: "builtin filters", Risk: "read", Builtin: name, Timeout: "1s", MaxOutput: 1024, Filters: []string{"exclude", "head", "match", "count"}}
}

func TestRunPrioritizesHandlerParameters(t *testing.T) {
	a := filterParameterAction(t)
	r, err := Run(context.Background(), a, map[string]any{"exclude": "handler_value", "head": 1}, nil)
	if err != nil || r.Stdout != "handler_value\n" {
		t.Fatalf("got %+v err=%v; want handler parameter preserved and head filter applied", r, err)
	}
}

func TestRunWithFiltersSeparatesHandlerAndFilterInputs(t *testing.T) {
	a := filterParameterAction(t)
	input := map[string]any{"exclude": "handler_value"}
	filters := map[string]any{"exclude": "^handler", "head": 1}
	r, err := RunWithFilters(context.Background(), a, input, filters, nil)
	if err != nil || r.Stdout != "keep\n" {
		t.Fatalf("got %+v err=%v; want independent exclude filter", r, err)
	}
	if input["exclude"] != "handler_value" || filters["exclude"] != "^handler" {
		t.Fatal("mutated caller maps")
	}
	r, err = RunWithFilters(context.Background(), a, input, map[string]any{"match": "secret", "count": true}, nil)
	if err != nil || r.Stdout != "0\n" {
		t.Fatalf("filter must run after redaction: %+v %v", r, err)
	}
	for _, invalid := range []map[string]any{{"tail": 1}, {"match": strings.Repeat("x", 201)}, {"head": 1, "count": false}, {"unknown": true}} {
		r, err = RunWithFilters(context.Background(), a, input, invalid, nil)
		if err == nil || r.Stdout != "" {
			t.Fatalf("accepted invalid filters %v: %+v %v", invalid, r, err)
		}
	}
	if _, err := RunWithFilters(context.Background(), a, map[string]any{"exclude": "handler_value", "head": 1}, nil, nil); err == nil {
		t.Fatal("interpreted explicit action input as filter")
	}
}

type resourceLimitedBuiltin struct{ filterParameterBuiltin }

func (resourceLimitedBuiltin) Run(ctx context.Context, config map[string]any, values map[string]any) (catalog.BuiltinResult, error) {
	r, err := filterParameterBuiltin{}.Run(ctx, config, values)
	r.ResourceLimited = true
	return r, err
}

func TestBuiltinResourceLimitReportsTruncated(t *testing.T) {
	a := filterParameterAction(t)
	catalog.Builtins[a.Builtin] = resourceLimitedBuiltin{}
	r, err := RunWithFilters(context.Background(), a, map[string]any{"exclude": "handler_value"}, map[string]any{"head": 1}, nil)
	if err != nil || r.ExitCode != 0 || !r.Truncated || !r.ResourceLimitReached || r.Stdout != "handler_value\n" {
		t.Fatalf("got %+v err=%v; want exit 0 and truncated on handler resource limit", r, err)
	}
}
