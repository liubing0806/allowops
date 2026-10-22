package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
)

func testAction() catalog.Action {
	min := int64(1)
	idempotent := true
	return catalog.Action{Name: "logs_read", Description: "Read application logs", Risk: "read", Idempotent: &idempotent, Timeout: "1s", MaxOutput: 8192, Exec: []any{"/usr/bin/true"}, Filters: []string{"match", "exclude", "tail", "head", "count"}, Params: map[string]params.Definition{
		"mode":   {Type: params.Enum, Description: "Log mode", Values: []string{"recent", "all"}},
		"lines":  {Type: params.Int, Description: "Line count", Min: &min, Max: 100, Default: 10},
		"reason": {Type: params.String, Description: "Log key", Regex: "^[a-z]+$", Default: "app"},
	}}
}

func TestActionSchemaAndAnnotations(t *testing.T) {
	tool, err := actionTool(testAction())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(tool.InputSchema)
	var schema map[string]any
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	props := schema["properties"].(map[string]any)
	actionProps := props["params"].(map[string]any)["properties"].(map[string]any)
	if actionProps["mode"].(map[string]any)["description"] != "Log mode" {
		t.Fatalf("schema=%s", b)
	}
	if actionProps["lines"].(map[string]any)["minimum"] != float64(1) || actionProps["lines"].(map[string]any)["maximum"] != float64(100) {
		t.Fatalf("bounds=%s", b)
	}
	if actionProps["reason"].(map[string]any)["pattern"] != "^[a-z]+$" {
		t.Fatalf("regex=%s", b)
	}
	if props["wait_seconds"].(map[string]any)["default"] != float64(30) || props["wait_seconds"].(map[string]any)["maximum"] != float64(120) {
		t.Fatalf("wait=%s", b)
	}
	if !tool.Annotations.ReadOnlyHint || !tool.Annotations.IdempotentHint {
		t.Fatalf("annotations=%+v", tool.Annotations)
	}
	if !strings.Contains(tool.Description, "untrusted") || !strings.Contains(tool.Description, "tools/list") {
		t.Fatalf("description=%q", tool.Description)
	}
}

func TestActionValidation(t *testing.T) {
	valid := `{"targets":{"selector":"env=test"},"expected_count":1,"params":{"mode":"recent"},"reason":"diagnosis","wait_seconds":0}`
	for _, tc := range []struct{ name, input, want string }{
		{"valid", valid, ""},
		{"expected count required", strings.Replace(valid, `"expected_count":1,`, "", 1), "expected_count"},
		{"enum", strings.Replace(valid, `"recent"`, `"unknown"`, 1), "recent"},
		{"wait range", strings.Replace(valid, `"wait_seconds":0`, `"wait_seconds":121`, 1), "120"},
		{"batch cannot relax", strings.Replace(valid, `"wait_seconds":0`, `"batch_size":21`, 1), "20"},
		{"failures cannot relax", strings.Replace(valid, `"wait_seconds":0`, `"max_failures":6`, 1), "5"},
		{"tail head", strings.Replace(valid, `"wait_seconds":0`, `"tail":1,"head":1`, 1), "mutually exclusive"},
		{"count false presence", strings.Replace(valid, `"wait_seconds":0`, `"tail":1,"count":false`, 1), "mutually exclusive"},
		{"two targets", strings.Replace(valid, `"selector":"env=test"`, `"selector":"env=test","hosts":["web-01"]`, 1), "hosts or selector"},
		{"unknown argument", strings.Replace(valid, `"wait_seconds":0`, `"extra":1`, 1), "allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := actionRequest(testAction(), json.RawMessage(tc.input))
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("error=%v; want %q", err, tc.want)
			}
		})
	}
}

func TestFixedToolSchemas(t *testing.T) {
	tools := fixedTools()
	if len(tools) != 4 {
		t.Fatalf("tools=%d want=4", len(tools))
	}
	seen := map[string]bool{}
	for _, tool := range tools {
		if seen[tool.Name] {
			t.Fatalf("duplicate fixed tool %s", tool.Name)
		}
		seen[tool.Name] = true
		if tool.InputSchema["type"] != "object" || tool.InputSchema["additionalProperties"] != false {
			t.Fatalf("schema=%v", tool.InputSchema)
		}
		if tool.Name != "jobs_cancel" && !tool.Annotations.ReadOnlyHint {
			t.Fatalf("read hint omitted for %s", tool.Name)
		}
		if !strings.Contains(tool.Description, "untrusted") {
			t.Fatalf("description=%s", tool.Description)
		}
	}
	for _, name := range []string{"hosts_search", "jobs_get", "jobs_list", "jobs_cancel"} {
		if !seen[name] {
			t.Fatalf("missing %s", name)
		}
	}
}

func TestGeneratedSchemaValidatesInputs(t *testing.T) {
	tool, err := actionTool(testAction())
	if err != nil {
		t.Fatal(err)
	}
	tools := append(fixedTools(), *tool)
	for _, tool := range tools {
		data := mustJSON(t, tool.InputSchema)
		var schema jsonschema.Schema
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatalf("%s schema: %v", tool.Name, err)
		}
		resolved, err := schema.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
		if err != nil {
			t.Fatalf("%s resolve: %v", tool.Name, err)
		}
		if tool.Name == "logs_read" {
			for _, tc := range []struct {
				input string
				valid bool
			}{
				{`{"targets":{"hosts":["web-01"]},"params":{"mode":"recent"},"reason":"inspect"}`, true},
				{`{"targets":{"selector":"env=test"},"params":{"mode":"recent"},"reason":"inspect"}`, false},
				{`{"targets":{"hosts":["web-01"]},"reason":"inspect"}`, false},
				{`{"targets":{"hosts":["web-01"]},"params":{"mode":"recent"},"reason":"inspect","count":false,"tail":1}`, false},
			} {
				var input any
				if err := json.Unmarshal([]byte(tc.input), &input); err != nil {
					t.Fatal(err)
				}
				if err := resolved.Validate(input); (err == nil) != tc.valid {
					t.Fatalf("valid=%v error=%v input=%s", tc.valid, err, tc.input)
				}
			}
		}
	}
}
