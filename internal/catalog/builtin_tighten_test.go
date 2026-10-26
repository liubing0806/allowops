package catalog

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestBuiltinConfigRestrictionLists(t *testing.T) {
	for _, tc := range []struct {
		builtin, field   string
		allowed, invalid any
		legal            string
	}{
		{"redis_command", "commands", []string{"GET", "SCAN", "INFO"}, []string{"GET", "KEYS"}, "MGET"},
		{"redis_command", "key_prefixes", []string{"tenant:"}, []string{""}, "nonempty"},
		{"redis_command", "info_sections", []string{"server", "memory"}, []string{"all"}, "server"},
		{"redis_command", "config_params", []string{"maxmemory", "maxmemory-policy"}, []string{"requirepass"}, "requirepass"},
		{"mysql_query", "databases", []string{"fixture"}, []string{"invalid-name"}, "a-zA-Z0-9_"},
		{"mysql_query", "statement_types", []string{"SELECT", "SHOW", "DESCRIBE", "EXPLAIN"}, []string{"DELETE"}, "SELECT"},
		{"mysql_query", "show_types", []string{"TABLES", "DATABASES", "PROCESSLIST", "VARIABLES", "STATUS", "CREATE TABLE", "COLUMNS"}, []string{"SELECT"}, "TABLES"},
		{"starrocks_query", "statement_types", []string{"SELECT", "SHOW", "DESCRIBE", "EXPLAIN"}, []string{"DELETE"}, "SELECT"},
		{"starrocks_query", "show_types", []string{"TABLES", "DATABASES", "CREATE TABLE", "COLUMNS", "PARTITIONS"}, []string{"SELECT"}, "TABLES"},
		// SHOW PROFILELIST belongs to a different handler and cannot be enabled.
		{"starrocks_query", "show_types", []string{"TABLES"}, []string{"PROFILELIST"}, "PROFILELIST"},
	} {
		t.Run(tc.builtin+"/"+tc.field, func(t *testing.T) {
			a := registeredBuiltinAction(tc.builtin)
			a.BuiltinConfig[tc.field] = tc.allowed
			if _, err := ValidateAction(a); err != nil {
				t.Errorf("allowed restriction: %v", err)
			}
			a.BuiltinConfig[tc.field] = tc.invalid
			if _, err := ValidateAction(a); err == nil || !strings.Contains(err.Error(), tc.legal) {
				t.Errorf("invalid restriction must name legal values (%s): %v", tc.legal, err)
			}
			for _, value := range []any{nil, []string(nil), []string{}, "not-a-list", []any{1}} {
				a.BuiltinConfig[tc.field] = value
				if _, err := ValidateAction(a); err == nil {
					t.Errorf("accepted invalid list %v", value)
				}
			}
		})
	}
}

func TestRedisCommandsSchemaRestriction(t *testing.T) {
	a := registeredBuiltinAction("redis_command")
	a.BuiltinConfig["commands"] = []string{"get", "INFO"}
	defs, err := ParameterDefinitions(a)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(defs["command"].Values, []string{"GET", "INFO"}) {
		t.Fatalf("command schema values=%v; want [GET INFO]", defs["command"].Values)
	}
	delete(a.BuiltinConfig, "commands")
	defs, err = ParameterDefinitions(a)
	if err != nil || len(defs["command"].Values) != 13 {
		t.Fatalf("default command schema: %v, %v", defs, err)
	}
}

func TestRedisConfigAndSlowlogSchema(t *testing.T) {
	a := registeredBuiltinAction("redis_command")
	a.BuiltinConfig["commands"] = []string{"config", "SlowLog"}
	a.BuiltinConfig["config_params"] = []string{"maxmemory"}
	defs, err := ParameterDefinitions(a)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(defs["command"].Values, []string{"CONFIG", "SLOWLOG"}) {
		t.Fatalf("command schema values=%v; want [CONFIG SLOWLOG]", defs["command"].Values)
	}
	result, err := Builtins["redis_command"].Run(context.Background(), a.BuiltinConfig, map[string]any{"command": "CONFIG", "args": []string{"GET", "requirepass"}})
	if err == nil || !strings.Contains(err.Error(), "sensitive") || result.ExitCode != 1 {
		t.Fatalf("sensitive CONFIG GET: %+v, %v", result, err)
	}
	result, err = Builtins["redis_command"].Run(context.Background(), a.BuiltinConfig, map[string]any{"command": "CONFIG", "args": []string{"GET", "other"}})
	if err == nil || !strings.Contains(err.Error(), "config_params") || result.ExitCode != 1 {
		t.Fatalf("unlisted CONFIG GET: %+v, %v", result, err)
	}
	result, err = Builtins["redis_command"].Run(context.Background(), a.BuiltinConfig, map[string]any{"command": "SLOWLOG", "args": []string{"RESET"}})
	if err == nil || result.ExitCode != 1 {
		t.Fatalf("SLOWLOG RESET: %+v, %v", result, err)
	}
}

func TestBuiltinRunAppliesRestrictions(t *testing.T) {
	for _, tc := range []struct {
		builtin, field string
		allowed        any
		values         map[string]any
	}{
		{"redis_command", "commands", []string{"GET"}, map[string]any{"command": "INFO"}},
		{"redis_command", "key_prefixes", []string{"tenant:"}, map[string]any{"command": "GET", "args": []string{"other:key"}}},
		{"redis_command", "info_sections", []string{"memory"}, map[string]any{"command": "INFO", "args": []string{"server"}}},
		{"mysql_query", "databases", []string{"fixture"}, map[string]any{"database": "other", "sql": "SELECT 1"}},
		{"mysql_query", "databases", []string{"fixture"}, map[string]any{"database": "fixture", "sql": "EXPLAIN SELECT * FROM private.items"}},
		{"mysql_query", "databases", []string{"fixture"}, map[string]any{"database": "fixture", "sql": "SHOW COLUMNS FROM items IN private"}},
		{"mysql_query", "statement_types", []string{"SHOW"}, map[string]any{"database": "fixture", "sql": "SELECT 1"}},
		{"mysql_query", "show_types", []string{"TABLES"}, map[string]any{"database": "fixture", "sql": "SHOW DATABASES"}},
		{"starrocks_query", "statement_types", []string{"SHOW"}, map[string]any{"database": "fixture", "sql": "SELECT 1"}},
		{"starrocks_query", "statement_types", []string{"EXPLAIN"}, map[string]any{"sql": "EXPLAIN SELECT 1"}},
		{"starrocks_query", "show_types", []string{"TABLES"}, map[string]any{"database": "fixture", "sql": "SHOW DATABASES"}},
	} {
		t.Run(tc.builtin+"/"+tc.field, func(t *testing.T) {
			a := registeredBuiltinAction(tc.builtin)
			a.BuiltinConfig[tc.field] = tc.allowed
			result, err := Builtins[tc.builtin].Run(context.Background(), a.BuiltinConfig, tc.values)
			if err == nil || !strings.Contains(err.Error(), tc.field) || result.ExitCode != 1 {
				t.Fatalf("want %s restriction failure: %+v, %v", tc.field, result, err)
			}
		})
	}
}

// The configuration tightens the handler; it never turns on what the guard or
// the handler refuses, and the SQL is checked before the credential is read.
func TestStarRocksQueryRunChecksSQLBeforeCredential(t *testing.T) {
	a := registeredBuiltinAction("starrocks_query")
	for _, tc := range []struct {
		name   string
		config map[string]any
		sql    string
		reject string // empty: reaches the credential file
	}{
		{"select", nil, "SELECT 1", ""},
		{"write", nil, "INSERT INTO t VALUES (1)", "sqlguard"},
		{"multiple statements", nil, "SELECT 1; SELECT 2", "sqlguard"},
		{"hash comment", nil, "SELECT 1 # ; DROP TABLE t", "sqlguard"},
		{"outfile", nil, "SELECT 1 INTO OUTFILE 'file:///tmp/x'", "sqlguard"},
		{"profile list", nil, "SHOW PROFILELIST", "profile"},
		{"profile list with explicit show types", map[string]any{"show_types": []string{"TABLES", "DATABASES"}}, "SHOW PROFILELIST", "profile"},
		{"analyze profile", nil, "ANALYZE PROFILE FROM 'a'", "profile"},
		{"explain analyze default", nil, "EXPLAIN ANALYZE SELECT 1", "sqlguard"},
		{"explain analyze enabled", map[string]any{"allow_explain_analyze": true}, "EXPLAIN ANALYZE SELECT 1", ""},
		{"explain analyze enabled, insert target", map[string]any{"allow_explain_analyze": true}, "EXPLAIN ANALYZE INSERT INTO t SELECT 1", "sqlguard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]any{}
			for k, v := range a.BuiltinConfig {
				config[k] = v
			}
			for k, v := range tc.config {
				config[k] = v
			}
			result, err := Builtins["starrocks_query"].Run(context.Background(), config, map[string]any{"sql": tc.sql})
			if result.ExitCode != 1 || err == nil {
				t.Fatalf("%+v, %v", result, err)
			}
			if tc.reject == "" && !strings.Contains(err.Error(), "cannot open credential file") || tc.reject != "" && !strings.Contains(err.Error(), tc.reject) {
				t.Fatalf("got %v; want %q", err, tc.reject)
			}
		})
	}
}

func TestStarRocksQueryConfigFields(t *testing.T) {
	for _, tc := range []struct {
		field string
		value any
		valid bool
	}{
		{"allow_explain_analyze", true, true}, {"allow_explain_analyze", false, true}, {"allow_explain_analyze", "yes", false},
		{"max_rows", 500, true}, {"max_rows", "many", false}, {"max_rows", -1, false},
		{"max_bytes", "512KB", true}, {"max_bytes", 1048576, true}, {"max_bytes", "2MB", false}, {"max_bytes", "x", false},
		{"timeout", "5s", true}, {"timeout", "11s", false}, {"timeout", 5, false},
		{"credential", "relative", false}, {"address", "unix:///var/run/starrocks.sock", false}, {"address", "127.0.0.1:9030", false},
		// The database range comes from the account's grants; there is no setting for it.
		{"databases", []string{"demo"}, false}, {"catalogs", []string{"default_catalog"}, false},
	} {
		a := registeredBuiltinAction("starrocks_query")
		a.BuiltinConfig[tc.field] = tc.value
		_, err := ValidateAction(a)
		if tc.valid && err != nil || !tc.valid && err == nil {
			t.Errorf("%s=%v: %v", tc.field, tc.value, err)
		}
	}
}
