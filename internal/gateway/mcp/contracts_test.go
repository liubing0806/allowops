package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/params"
)

func starRocksAction() catalog.Action {
	a := testAction()
	a.Exec = nil
	a.Builtin = "starrocks_query"
	a.BuiltinConfig = map[string]any{"credential": "/etc/allowops/credentials/starrocks.json", "address": "tcp://127.0.0.1:9030"}
	a.Params = map[string]params.Definition{"database": {Type: params.String, Description: "Application database", Regex: "^demo$"}}
	return a
}

func TestStarRocksQueryToolSchemaAndRequest(t *testing.T) {
	a := starRocksAction()
	tool, err := actionTool(a, job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(tool.InputSchema)
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	paramsSchema := schema["properties"].(map[string]any)["params"].(map[string]any)
	properties := paramsSchema["properties"].(map[string]any)
	if len(properties) != 2 || properties["sql"].(map[string]any)["maxLength"] != float64(4000) {
		t.Fatalf("params schema: %s", data)
	}
	if required := paramsSchema["required"].([]any); len(required) != 1 || required[0] != "sql" {
		t.Fatalf("only sql is required: %v", required)
	}
	if !strings.Contains(string(data), "^demo$") || !strings.Contains(string(data), "^[a-zA-Z0-9_]{1,64}$") {
		t.Fatalf("database must keep the handler regex and add the signed one: %s", data)
	}
	if !tool.Annotations.ReadOnlyHint {
		t.Fatal("starrocks_query must be a read action")
	}
	long, _ := json.Marshal(strings.Repeat("x", 4001))
	for input, valid := range map[string]bool{
		`{"targets":{"hosts":["web-01"]},"params":{"sql":"SELECT 1"},"reason":"inspect"}`:                       true,
		`{"targets":{"hosts":["web-01"]},"params":{"sql":"SELECT 1","database":"demo"},"reason":"inspect"}`:     true,
		`{"targets":{"hosts":["web-01"]},"params":{"database":"demo"},"reason":"inspect"}`:                      false,
		`{"targets":{"hosts":["web-01"]},"reason":"inspect"}`:                                                   false,
		`{"targets":{"hosts":["web-01"]},"params":{"sql":"SELECT 1","database":"other"},"reason":"inspect"}`:    false,
		`{"targets":{"hosts":["web-01"]},"params":{"sql":"SELECT 1","database":"bad-name"},"reason":"inspect"}`: false,
		`{"targets":{"hosts":["web-01"]},"params":{"sql":"SELECT 1","extra":1},"reason":"inspect"}`:             false,
		`{"targets":{"hosts":["web-01"]},"params":{"sql":"SELECT 1\nSELECT 2"},"reason":"inspect"}`:             false,
		`{"targets":{"hosts":["web-01"]},"params":{"sql":` + string(long) + `},"reason":"inspect"}`:             false,
	} {
		_, _, err := actionRequest(a, json.RawMessage(input), job.DefaultConfig())
		if (err == nil) != valid {
			t.Errorf("%.100s: error=%v want valid=%v", input, err, valid)
		}
	}
}

func dremioAction() catalog.Action {
	a := testAction()
	a.Exec = nil
	a.Params = nil
	a.Builtin = "dremio_query"
	a.BuiltinConfig = map[string]any{"credential": "/etc/allowops/credentials/dremio.json", "url": "http://127.0.0.1:9047"}
	return a
}

func TestDremioQueryToolSchemaAndRequest(t *testing.T) {
	a := dremioAction()
	tool, err := actionTool(a, job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(tool.InputSchema)
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	paramsSchema := schema["properties"].(map[string]any)["params"].(map[string]any)
	properties := paramsSchema["properties"].(map[string]any)
	if len(properties) != 1 || properties["sql"].(map[string]any)["maxLength"] != float64(4000) {
		t.Fatalf("params schema: %s", data)
	}
	if required := paramsSchema["required"].([]any); len(required) != 1 || required[0] != "sql" {
		t.Fatalf("sql is required: %v", required)
	}
	if !tool.Annotations.ReadOnlyHint {
		t.Fatal("dremio_query must be a read action")
	}
	long, _ := json.Marshal(strings.Repeat("x", 4001))
	for input, valid := range map[string]bool{
		`{"targets":{"hosts":["web-01"]},"params":{"sql":"SELECT 1"},"reason":"inspect"}`:                   true,
		`{"targets":{"hosts":["web-01"]},"params":{"sql":"SELECT 1","context":"src"},"reason":"inspect"}`:   false,
		`{"targets":{"hosts":["web-01"]},"params":{"sql":"SELECT 1","database":"demo"},"reason":"inspect"}`: false,
		`{"targets":{"hosts":["web-01"]},"params":{},"reason":"inspect"}`:                                   false,
		`{"targets":{"hosts":["web-01"]},"reason":"inspect"}`:                                               false,
		`{"targets":{"hosts":["web-01"]},"params":{"sql":"SELECT 1\nSELECT 2"},"reason":"inspect"}`:         false,
		`{"targets":{"hosts":["web-01"]},"params":{"sql":` + string(long) + `},"reason":"inspect"}`:         false,
	} {
		_, _, err := actionRequest(a, json.RawMessage(input), job.DefaultConfig())
		if (err == nil) != valid {
			t.Errorf("%.100s: error=%v want valid=%v", input, err, valid)
		}
	}
}

func starRocksDiagAction(allowRun bool) catalog.Action {
	a := testAction()
	a.Exec = nil
	a.Builtin = "starrocks_diag"
	a.BuiltinConfig = map[string]any{"credential": "/etc/allowops/credentials/starrocks-diag.json", "address": "tcp://127.0.0.1:9030"}
	if allowRun {
		a.BuiltinConfig["allow_profile_run"] = true
	}
	a.Params = nil
	return a
}

func TestStarRocksDiagToolSchemaAndRequest(t *testing.T) {
	a := starRocksDiagAction(false)
	tool, err := actionTool(a, job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(tool.InputSchema)
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	paramsSchema := schema["properties"].(map[string]any)["params"].(map[string]any)
	for _, root := range []string{"oneOf", "anyOf", "allOf", "not", "if", "dependentRequired"} {
		if _, present := paramsSchema[root]; present {
			t.Errorf("root combinator %s in the params schema: %s", root, data)
		}
	}
	if required := paramsSchema["required"].([]any); len(required) != 1 || required[0] != "op" {
		t.Fatalf("only op is required: %v", required)
	}
	if strings.Contains(string(data), "profile_run") || strings.Contains(string(data), `"sql"`) {
		t.Fatalf("profile_run must not be exposed by default: %s", data)
	}
	if !tool.Annotations.ReadOnlyHint {
		t.Fatal("starrocks_diag must be a read action")
	}
	for input, valid := range map[string]bool{
		`{"targets":{"hosts":["web-01"]},"params":{"op":"cluster"},"reason":"inspect"}`:                                                                  true,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"running"},"reason":"inspect"}`:                                                                  true,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"slow_queries","since_minutes":30,"min_duration_ms":2000,"state":"ERR","limit":5},"reason":"x"}`: true,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"profile_summary","query_id":"b6e3e384-ced5-11f1-b155-5ee444682bc1"},"reason":"x"}`:              true,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"profile_summary","query_id":"x"},"reason":"x"}`:                                                 false,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"profile_run","sql":"SELECT 1"},"reason":"x"}`:                                                   false,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"drop"},"reason":"x"}`:                                                                           false,
		`{"targets":{"hosts":["web-01"]},"params":{},"reason":"x"}`:                                                                                      false,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"cluster","extra":1},"reason":"x"}`:                                                              false,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"slow_queries","limit":501},"reason":"x"}`:                                                       false,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"profile_summary","query_id":"b6e3e384-ced5-11f1-b155-5ee444682bc1","top_n":51},"reason":"x"}`:   false,
	} {
		_, _, err := actionRequest(a, json.RawMessage(input), job.DefaultConfig())
		if (err == nil) != valid {
			t.Errorf("%.120s: error=%v want valid=%v", input, err, valid)
		}
	}
	enabled := starRocksDiagAction(true)
	if _, _, err := actionRequest(enabled, json.RawMessage(`{"targets":{"hosts":["web-01"]},"params":{"op":"profile_run","sql":"SELECT 1"},"reason":"x"}`), job.DefaultConfig()); err != nil {
		t.Errorf("profile_run with allow_profile_run: %v", err)
	}
}

func TestActionDefaultsAndNamespace(t *testing.T) {
	r, format, err := actionRequest(testAction(), json.RawMessage(`{"targets":{"hosts":["web-01"]},"params":{"mode":"recent","reason":"app"},"reason":"investigation"}`), job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	// The job layer applies the gateway defaults to options the caller omitted.
	if r.WaitSeconds != nil || r.BatchSize != nil || r.MaxFailures != nil || format != "concise" || r.Reason != "investigation" {
		t.Fatalf("request=%+v format=%s", r, format)
	}
	var values map[string]any
	if err := json.Unmarshal(r.Params.Json, &values); err != nil {
		t.Fatal(err)
	}
	if values["reason"] != "app" || values["lines"] != float64(10) {
		t.Fatalf("params=%v", values)
	}
}

func TestNullDuplicateAndFilterValidation(t *testing.T) {
	for _, input := range []string{
		`null`, `{"targets":null,"reason":"x"}`, `{"targets":{"hosts":[]},"reason":"x"}`,
		`{"targets":{"hosts":["web-01"]},"reason":"x","reason":"y"}`,
		`{"targets":{"hosts":["web-01"]},"params":{"mode":"all","mode":"recent"},"reason":"x"}`,
		`{"targets":{"hosts":["web-01"]},"params":{"mode":"all"},"reason":"x","wait_seconds":null}`,
		`{"targets":{"selector":"env=test,env=prod"},"expected_count":1,"params":{"mode":"all"},"reason":"x"}`,
		`{"targets":{"hosts":["web-01"]},"params":{"mode":"all"},"reason":"x","tail":0}`,
		`{"targets":{"hosts":["web-01"]},"params":{"mode":"all"},"reason":"x","match":"["}`,
	} {
		if _, _, err := actionRequest(testAction(), json.RawMessage(input), job.DefaultConfig()); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	a := testAction()
	a.Filters = nil
	if _, _, err := actionRequest(a, json.RawMessage(`{"targets":{"hosts":["web-01"]},"params":{"mode":"all"},"reason":"x","tail":1}`), job.DefaultConfig()); err == nil {
		t.Fatal("accepted undeclared filter")
	}
}

func TestGatewayPathValidationDoesNotUseLocalFilesystem(t *testing.T) {
	a := testAction()
	a.Params = map[string]params.Definition{"path": {Type: params.Path, Description: "Host path", AllowedRoots: []string{"/var/log"}}}
	for _, tc := range []struct {
		path  string
		valid bool
	}{{"/var/log/nonexistent", true}, {"/var/log-other/file", false}, {"/var/log/../../etc/passwd", false}, {"relative", false}} {
		data, _ := json.Marshal(map[string]any{"targets": map[string]any{"hosts": []string{"web-01"}}, "params": map[string]any{"path": tc.path}, "reason": "inspect"})
		_, _, err := actionRequest(a, data, job.DefaultConfig())
		if (err == nil) != tc.valid {
			t.Fatalf("path=%s error=%v want valid=%v", tc.path, err, tc.valid)
		}
	}
}

func TestBuiltinRegexIsAddedToSchemaAndValidated(t *testing.T) {
	a := testAction()
	a.Exec = nil
	a.Builtin = "mysql_query"
	a.Params = map[string]params.Definition{"database": {Type: params.String, Description: "Application database", Regex: "^app$"}}
	tool, err := actionTool(a, job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(tool.InputSchema)
	if !strings.Contains(string(b), "^app$") {
		t.Fatalf("missing signed override: %s", b)
	}
	_, _, err = actionRequest(a, json.RawMessage(`{"targets":{"hosts":["web-01"]},"params":{"database":"other","sql":"SELECT 1"},"reason":"inspect"}`), job.DefaultConfig())
	if err == nil {
		t.Fatal("accepted value outside signed regex")
	}
}

func TestBuiltinArrayRegexAndBatchOverflow(t *testing.T) {
	a := testAction()
	a.Exec = nil
	a.Builtin = "redis_command"
	a.BuiltinConfig = map[string]any{"credential": "/etc/allowops/redis", "address": "127.0.0.1:6379"}
	a.Params = map[string]params.Definition{"args": {Type: params.StringArray, Description: "Allowed arguments", Regex: "^app$"}}
	tool, err := actionTool(a, job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(tool.InputSchema)
	if !strings.Contains(string(data), "^app$") {
		t.Fatal("array item regex missing")
	}
	_, _, err = actionRequest(a, json.RawMessage(`{"targets":{"hosts":["web-01"]},"params":{"command":"GET","args":["other"]},"reason":"inspect"}`), job.DefaultConfig())
	if err == nil {
		t.Fatal("accepted array outside signed override regex")
	}
	a = testAction()
	a.BatchSize = int(uint64(1) << 32)
	if _, err := actionTool(a, job.DefaultConfig()); err == nil {
		t.Fatal("accepted batch_size overflowing protobuf uint32")
	}
}

func TestHostSearchSelectionA27(t *testing.T) {
	if err := validateHostSearchSelection("", ""); err != nil {
		t.Fatalf("A27 empty condition rejected: %v", err)
	}
	if err := validateHostSearchSelection("web-01", ""); err != nil {
		t.Fatal(err)
	}
	if err := validateHostSearchSelection("", "env=test"); err != nil {
		t.Fatal(err)
	}
	if err := validateHostSearchSelection("web-01", "env=test"); err == nil {
		t.Fatal("accepted both query conditions")
	}
}

func dremioDiagAction() catalog.Action {
	a := dremioAction()
	a.Builtin = "dremio_diag"
	return a
}

// The cross-field rules of dremio_diag (which parameter belongs to which op)
// are not in the tool schema: a root allOf makes some MCP clients skip the tool.
func TestDremioDiagToolSchemaAndRequest(t *testing.T) {
	a := dremioDiagAction()
	tool, err := actionTool(a, job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(tool.InputSchema)
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"allOf", "anyOf", "oneOf", "not", "if"} {
		if _, ok := schema[key]; ok {
			t.Errorf("root %s in %s", key, data)
		}
	}
	paramsSchema := schema["properties"].(map[string]any)["params"].(map[string]any)
	properties := paramsSchema["properties"].(map[string]any)
	if len(properties) != 8 {
		t.Fatalf("params schema: %s", data)
	}
	if enum := properties["op"].(map[string]any)["enum"].([]any); len(enum) != 5 {
		t.Errorf("op enum: %v", enum)
	}
	if required := paramsSchema["required"].([]any); len(required) != 1 || required[0] != "op" {
		t.Errorf("only op is required: %v", required)
	}
	if !tool.Annotations.ReadOnlyHint {
		t.Fatal("dremio_diag must be a read action")
	}
	for input, valid := range map[string]bool{
		`{"targets":{"hosts":["web-01"]},"params":{"op":"nodes"},"reason":"inspect"}`:                                                                 true,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"jobs","since":"2h","state":"FAILED","limit":5},"reason":"inspect"}`:                          true,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"job","job_id":"152329ab-6312-f9a2-7240-1e8469e7bd00"},"reason":"inspect"}`:                   true,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"job_profile","job_id":"152329ab-6312-f9a2-7240-1e8469e7bd00","top_n":5},"reason":"inspect"}`: true,
		`{"targets":{"hosts":["web-01"]},"params":{},"reason":"inspect"}`:                                                                             false,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"kill"},"reason":"inspect"}`:                                                                  false,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"job","job_id":"../x"},"reason":"inspect"}`:                                                   false,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"jobs","state":"QUEUED"},"reason":"inspect"}`:                                                 false,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"jobs","since":"169h"},"reason":"inspect"}`:                                                   false,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"jobs","limit":501},"reason":"inspect"}`:                                                      false,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"jobs","user":"a\" or 1=1"},"reason":"inspect"}`:                                              false,
		`{"targets":{"hosts":["web-01"]},"params":{"op":"nodes","sql":"SELECT 1"},"reason":"inspect"}`:                                                false,
	} {
		_, _, err := actionRequest(a, json.RawMessage(input), job.DefaultConfig())
		if (err == nil) != valid {
			t.Errorf("%.120s: error=%v want valid=%v", input, err, valid)
		}
	}
}
