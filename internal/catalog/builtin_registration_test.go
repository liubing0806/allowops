package catalog

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/params"
)

func registeredBuiltinAction(name string) Action {
	configs := map[string]map[string]any{
		"log_search": {"allowed_roots": []string{"/nonexistent/catalog-root"}},
		"log_query": {"mode": "search", "allowed_roots": []string{"/nonexistent/catalog-root"}, "sources": map[string]any{
			"app": map[string]any{"type": "file", "paths": []string{"/nonexistent/catalog-root/app/*.log*"}, "timestamp": map[string]any{"layouts": []string{"2006-01-02 15:04:05.000"}, "timezone": "Asia/Shanghai"}},
		}},
		"http_get":      {"allowed_prefixes": []string{"http://127.0.0.1:12001/api"}},
		"redis_command": {"address": "127.0.0.1:6379", "credential": "/etc/allowops/credentials/redis.json"},
		"mysql_query":   {"address": "tcp://127.0.0.1:3306", "credential": "/etc/allowops/credentials/mysql.json"},
	}
	return Action{Name: name, Description: name, Risk: "read", Builtin: name, BuiltinConfig: configs[name], Timeout: "1s", MaxOutput: 1024}
}

func TestBuiltinCatalogSchemas(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "actions"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte("schema_version: 1\ncatalog_id: four_builtins\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"log_search", "log_query", "http_get", "redis_command", "mysql_query"} {
		a := registeredBuiltinAction(name)
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "actions", name+".yaml"), data, 0600); err != nil {
			t.Fatal(err)
		}
		defs, err := ParameterDefinitions(a)
		if err != nil {
			t.Errorf("%s definitions: %v", name, err)
			continue
		}
		schema, err := params.JSONSchema(defs)
		if err != nil {
			t.Errorf("%s schema: %v", name, err)
			continue
		}
		properties := schema["properties"].(map[string]any)
		switch name {
		case "log_search":
			if properties["fixed"].(map[string]any)["type"] != "boolean" {
				t.Error("fixed must be boolean")
			}
		case "log_query":
			if fmt.Sprint(properties["source"].(map[string]any)["enum"]) != "[app]" || properties["limit"].(map[string]any)["maximum"] != 200 {
				t.Errorf("log_query schema: %v", properties)
			}
		case "redis_command":
			if properties["args"].(map[string]any)["type"] != "array" {
				t.Error("args must be array")
			}
		case "http_get":
			if properties["url"].(map[string]any)["format"] != "uri" {
				t.Error("url must retain URL schema")
			}
		}
	}
	loaded, err := Load(dir)
	if err != nil || len(loaded.Actions) != 5 {
		t.Fatalf("five builtin catalog: %#v %v", loaded, err)
	}
}

func TestBuiltinConfigOnlyTightensDefaults(t *testing.T) {
	cases := []struct {
		name, key    string
		narrow, wide any
	}{
		{"log_search", "max_files", 1, builtin.DefaultLogMaxFiles + 1},
		{"log_search", "max_scan", "1KB", fmt.Sprint(builtin.DefaultLogMaxScan + 1)},
		{"log_search", "max_matches", 1, builtin.DefaultLogMaxMatches + 1},
		{"log_search", "max_context", 1, builtin.DefaultLogMaxContext + 1},
		{"log_query", "max_files", 1, builtin.DefaultLogMaxFiles + 1},
		{"log_query", "max_scan", "1KB", fmt.Sprint(builtin.DefaultLogMaxScan + 1)},
		{"log_query", "max_window", "1h", "25h"},
		{"log_query", "max_page_records", 10, 201},
		{"log_query", "max_record_bytes", "1KB", "65537"},
		{"log_query", "mode", "sources", "stats"},
		{"http_get", "max_response_bytes", "1KB", fmt.Sprint(builtin.DefaultHTTPMaxResponseBytes + 1)},
		{"redis_command", "max_response_bytes", Size(1024), fmt.Sprint(builtin.DefaultRedisMaxResponseBytes + 1)},
		{"redis_command", "max_scan_count", 1, builtin.DefaultRedisMaxScanCount + 1},
		{"mysql_query", "max_rows", 1, 501},
		{"mysql_query", "max_response_bytes", Size(1024), fmt.Sprint(builtin.DefaultMySQLMaxResponseBytes + 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/"+tc.key, func(t *testing.T) {
			a := registeredBuiltinAction(tc.name)
			a.BuiltinConfig = maps.Clone(a.BuiltinConfig)
			a.BuiltinConfig[tc.key] = tc.narrow
			if _, err := ValidateAction(a); err != nil {
				t.Fatalf("narrow config: %v", err)
			}
			a.BuiltinConfig[tc.key] = tc.wide
			if _, err := ValidateAction(a); err == nil {
				t.Fatalf("accepted widened %s=%v", tc.key, tc.wide)
			}
		})
	}
	for _, name := range []string{"log_search", "log_query", "http_get", "redis_command", "mysql_query"} {
		a := registeredBuiltinAction(name)
		a.BuiltinConfig["timeout"] = "20ms"
		if _, err := ValidateAction(a); err != nil {
			t.Errorf("%s narrow timeout: %v", name, err)
		}
		a.BuiltinConfig["timeout"] = "11s"
		if _, err := ValidateAction(a); err == nil {
			t.Errorf("%s widened timeout accepted", name)
		}
		a = registeredBuiltinAction(name)
		a.BuiltinConfig["unknown_field"] = true
		if _, err := ValidateAction(a); err == nil {
			t.Errorf("%s unknown config field accepted", name)
		}
		a = registeredBuiltinAction(name)
		a.Params = map[string]params.Definition{"unknown": {Type: params.String, Description: "unknown"}}
		if _, err := ValidateAction(a); err == nil {
			t.Errorf("%s unknown parameter accepted", name)
		}
	}
}

func TestBuiltinExecutionPlacement(t *testing.T) {
	for _, name := range []string{"log_search", "log_query", "http_get", "redis_command", "mysql_query"} {
		for _, runAs := range []string{"", "root"} {
			a := registeredBuiltinAction(name)
			a.RunAs = runAs
			data, err := json.Marshal(CheckHost(a))
			if err != nil {
				t.Fatal(err)
			}
			var metadata map[string]any
			if err := json.Unmarshal(data, &metadata); err != nil {
				t.Fatal(err)
			}
			want := runAs != "" || name == "redis_command" || name == "mysql_query"
			if metadata["requires_exec"] != want {
				t.Errorf("%s run_as=%q metadata=%s; want requires_exec=%v", name, runAs, data, want)
			}
		}
	}
}

// mysql_query max_response_bytes follows redis_command: byte-size syntax, tighten-only.
func TestMySQLMaxResponseBytesRejectsInvalidValues(t *testing.T) {
	for _, value := range []any{-1, "-1", "abc", "1TB", true, nil, []any{1}, 1.5, fmt.Sprint(builtin.DefaultMySQLMaxResponseBytes + 1), "17MB"} {
		a := registeredBuiltinAction("mysql_query")
		a.BuiltinConfig = maps.Clone(a.BuiltinConfig)
		a.BuiltinConfig["max_response_bytes"] = value
		if _, err := ValidateAction(a); err == nil {
			t.Errorf("accepted max_response_bytes=%#v", value)
		}
	}
	for _, value := range []any{0, 1, "1KB", Size(64 << 10), fmt.Sprint(builtin.DefaultMySQLMaxResponseBytes)} {
		a := registeredBuiltinAction("mysql_query")
		a.BuiltinConfig = maps.Clone(a.BuiltinConfig)
		a.BuiltinConfig["max_response_bytes"] = value
		if _, err := ValidateAction(a); err != nil {
			t.Errorf("max_response_bytes=%#v: %v", value, err)
		}
	}
}
