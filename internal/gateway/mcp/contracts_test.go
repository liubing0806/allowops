package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/params"
)

func TestActionDefaultsAndNamespace(t *testing.T) {
	r, format, err := actionRequest(testAction(), json.RawMessage(`{"targets":{"hosts":["web-01"]},"params":{"mode":"recent","reason":"app"},"reason":"investigation"}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.GetWaitSeconds() != 30 || r.GetBatchSize() != 20 || r.GetMaxFailures() != 5 || format != "concise" || r.Reason != "investigation" {
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
		if _, _, err := actionRequest(testAction(), json.RawMessage(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	a := testAction()
	a.Filters = nil
	if _, _, err := actionRequest(a, json.RawMessage(`{"targets":{"hosts":["web-01"]},"params":{"mode":"all"},"reason":"x","tail":1}`)); err == nil {
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
		_, _, err := actionRequest(a, data)
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
	tool, err := actionTool(a)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(tool.InputSchema)
	if !strings.Contains(string(b), "^app$") {
		t.Fatalf("missing signed override: %s", b)
	}
	_, _, err = actionRequest(a, json.RawMessage(`{"targets":{"hosts":["web-01"]},"params":{"database":"other","sql":"SELECT 1"},"reason":"inspect"}`))
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
	tool, err := actionTool(a)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(tool.InputSchema)
	if !strings.Contains(string(data), "^app$") {
		t.Fatal("array item regex missing")
	}
	_, _, err = actionRequest(a, json.RawMessage(`{"targets":{"hosts":["web-01"]},"params":{"command":"GET","args":["other"]},"reason":"inspect"}`))
	if err == nil {
		t.Fatal("accepted array outside signed override regex")
	}
	a = testAction()
	a.BatchSize = int(uint64(1) << 32)
	if _, err := actionTool(a); err == nil {
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
