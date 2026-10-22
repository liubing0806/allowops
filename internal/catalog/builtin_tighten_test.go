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
		{"mysql_query", "databases", []string{"fixture"}, []string{"invalid-name"}, "a-zA-Z0-9_"},
		{"mysql_query", "statement_types", []string{"SELECT", "SHOW", "DESCRIBE", "EXPLAIN"}, []string{"DELETE"}, "SELECT"},
		{"mysql_query", "show_types", []string{"TABLES", "DATABASES", "PROCESSLIST", "VARIABLES", "STATUS", "CREATE TABLE", "COLUMNS"}, []string{"SELECT"}, "TABLES"},
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
