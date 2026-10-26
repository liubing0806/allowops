package catalog

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/params"
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
		{"dremio_query", "statement_types", []string{"SELECT", "SHOW", "DESCRIBE", "EXPLAIN"}, []string{"DELETE"}, "SELECT"},
		{"dremio_query", "show_types", []string{"SCHEMAS", "TABLES", "VIEWS", "PARTITIONS", "FILES", "CREATE TABLE", "FUNCTIONS"}, []string{"DATABASES"}, "SCHEMAS"},
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
		{"dremio_query", "statement_types", []string{"SHOW"}, map[string]any{"sql": "SELECT 1"}},
		{"dremio_query", "statement_types", []string{"EXPLAIN"}, map[string]any{"sql": "EXPLAIN PLAN FOR SELECT 1"}},
		{"dremio_query", "show_types", []string{"TABLES"}, map[string]any{"sql": "SHOW SCHEMAS"}},
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

// The configuration tightens the handler; it never turns on what the guard
// refuses, and the SQL is checked before the credential is read. Nothing here
// reaches the network: the credential file does not exist.
func TestDremioQueryRunChecksSQLBeforeCredential(t *testing.T) {
	a := registeredBuiltinAction("dremio_query")
	for _, tc := range []struct {
		name   string
		sql    string
		reject string // empty: reaches the credential file
	}{
		{"select", `SELECT 1`, ""},
		{"explain plan", `EXPLAIN PLAN FOR SELECT 1`, ""},
		{"show", `SHOW SCHEMAS`, ""},
		{"external_query", `SELECT * FROM TABLE(src.external_query('SELECT 1'))`, "sqlguard"},
		{"external_query in explain", `EXPLAIN PLAN FOR SELECT * FROM TABLE(src.external_query('INSERT INTO t VALUES (1)'))`, "sqlguard"},
		{"create view", `CREATE VIEW v AS SELECT 1`, "sqlguard"},
		{"truncate", `TRUNCATE TABLE t`, "sqlguard"},
		{"alter system", `ALTER SYSTEM SET "planner.slice_target" = 1`, "sqlguard"},
		{"multiple statements", `SELECT 1; SELECT 2`, "sqlguard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Builtins["dremio_query"].Run(context.Background(), a.BuiltinConfig, map[string]any{"sql": tc.sql})
			if result.ExitCode != 1 || err == nil {
				t.Fatalf("%+v, %v", result, err)
			}
			if tc.reject == "" && !strings.Contains(err.Error(), "cannot open credential file") || tc.reject != "" && !strings.Contains(err.Error(), tc.reject) {
				t.Fatalf("got %v; want %q", err, tc.reject)
			}
		})
	}
}

func TestDremioQueryConfigFields(t *testing.T) {
	for _, tc := range []struct {
		field string
		value any
		valid bool
	}{
		{"max_rows", 500, true}, {"max_rows", "many", false}, {"max_rows", -1, false}, {"max_rows", 501, false},
		{"max_bytes", "512KB", true}, {"max_bytes", 1048576, true}, {"max_bytes", "2MB", false}, {"max_bytes", "x", false},
		{"timeout", "5s", true}, {"timeout", "11s", false}, {"timeout", 5, false},
		{"credential", "relative", false},
		{"url", "https://dremio.example.com:9047", true}, {"url", "http://127.0.0.1", false}, {"url", "http://127.0.0.1:9047/api", false},
		{"url", "127.0.0.1:9047", false}, {"url", "tcp://127.0.0.1:9047", false}, {"url", "http://user:pw@127.0.0.1:9047", false},
		// The address key of the database handlers is not accepted, and neither are per-source ranges.
		{"address", "tcp://127.0.0.1:9047", false}, {"databases", []string{"demo"}, false}, {"context", []string{"src"}, false},
		{"ca_file", "/etc/ssl/ca.pem", false}, {"insecure_skip_verify", true, false},
	} {
		a := registeredBuiltinAction("dremio_query")
		a.BuiltinConfig[tc.field] = tc.value
		_, err := ValidateAction(a)
		if tc.valid && err != nil || !tc.valid && err == nil {
			t.Errorf("%s=%v: %v", tc.field, tc.value, err)
		}
	}
}

// The diag handler runs fixed statements; the configuration cannot widen them,
// and the parameters are checked before the credential is read.
func TestStarRocksDiagRunChecksParametersBeforeCredential(t *testing.T) {
	a := registeredBuiltinAction("starrocks_diag")
	const id = "b6e3e384-ced5-11f1-b155-5ee444682bc1"
	for _, tc := range []struct {
		name   string
		config map[string]any
		values map[string]any
		reject string // empty: reaches the credential file
	}{
		{"cluster", nil, map[string]any{"op": "cluster"}, ""},
		{"summary", nil, map[string]any{"op": "profile_summary", "query_id": id}, ""},
		{"summary without id", nil, map[string]any{"op": "profile_summary"}, "query_id"},
		{"analyze with a bad id", nil, map[string]any{"op": "profile_analyze", "query_id": "x' OR '1'='1"}, "query_id"},
		{"unknown op", nil, map[string]any{"op": "kill"}, "op"},
		{"id on cluster", nil, map[string]any{"op": "cluster", "query_id": id}, "query_id"},
		{"profile_run default", nil, map[string]any{"op": "profile_run", "sql": "SELECT 1"}, "allow_profile_run"},
		{"profile_run enabled", map[string]any{"allow_profile_run": true}, map[string]any{"op": "profile_run", "sql": "SELECT 1"}, ""},
		{"profile_run enabled, write", map[string]any{"allow_profile_run": true}, map[string]any{"op": "profile_run", "sql": "INSERT INTO t VALUES (1)"}, "sqlguard"},
		{"profile_run enabled, two statements", map[string]any{"allow_profile_run": true}, map[string]any{"op": "profile_run", "sql": "SELECT 1; SELECT 2"}, "sqlguard"},
		{"profile_run enabled, profile function", map[string]any{"allow_profile_run": true}, map[string]any{"op": "profile_run", "sql": "SELECT get_query_profile('" + id + "')"}, "sqlguard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]any{}
			for k, v := range a.BuiltinConfig {
				config[k] = v
			}
			for k, v := range tc.config {
				config[k] = v
			}
			result, err := Builtins["starrocks_diag"].Run(context.Background(), config, tc.values)
			if result.ExitCode != 1 || err == nil {
				t.Fatalf("%+v, %v", result, err)
			}
			if tc.reject == "" && !strings.Contains(err.Error(), "cannot open credential file") || tc.reject != "" && !strings.Contains(err.Error(), tc.reject) {
				t.Fatalf("got %v; want %q", err, tc.reject)
			}
		})
	}
}

func TestStarRocksDiagConfigFields(t *testing.T) {
	for _, tc := range []struct {
		field string
		value any
		valid bool
	}{
		{"allow_profile_run", true, true}, {"allow_profile_run", false, true}, {"allow_profile_run", "yes", false},
		{"audit_table", "starrocks_audit_db__.starrocks_audit_tbl__", true}, {"audit_table", "audit_tbl", true},
		{"audit_table", "a.b.c", false}, {"audit_table", "x; DROP TABLE y", false}, {"audit_table", "`a`", false}, {"audit_table", 7, false},
		{"audit_columns", map[string]any{"query_time": "latency_ms"}, true}, {"audit_columns", map[string]any{"query_time": "a b"}, false},
		{"audit_columns", map[string]any{"nope": "x"}, false}, {"audit_columns", "queryTime", false},
		{"max_rows", 500, true}, {"max_rows", 501, false}, {"max_bytes", "512KB", true}, {"max_bytes", "2MB", false},
		{"max_profile_bytes", "8MB", true}, {"max_profile_bytes", "17MB", false},
		{"timeout", "5s", true}, {"timeout", "11s", false},
		{"credential", "relative", false}, {"address", "127.0.0.1:9030", false},
		// The diag handler takes no SQL restrictions; its statements are fixed.
		{"statement_types", []string{"SELECT"}, false}, {"show_types", []string{"TABLES"}, false}, {"allow_explain_analyze", true, false},
	} {
		a := registeredBuiltinAction("starrocks_diag")
		a.BuiltinConfig[tc.field] = tc.value
		_, err := ValidateAction(a)
		if tc.valid && err != nil || !tc.valid && err == nil {
			t.Errorf("%s=%v: %v", tc.field, tc.value, err)
		}
	}
}

func TestDremioDiagParametersAndConfigFields(t *testing.T) {
	for _, tc := range []struct {
		field string
		value any
		valid bool
	}{
		{"max_rows", 500, true}, {"max_rows", 501, false}, {"max_rows", -1, false},
		{"max_bytes", "512KB", true}, {"max_bytes", "2MB", false},
		{"ops", []string{"nodes", "jobs"}, true}, {"ops", []string{"kill"}, false}, {"ops", []string{}, false}, {"ops", "nodes", false},
		{"max_profile_bytes", "8MB", true}, {"max_profile_bytes", "33MB", false}, {"max_profile_bytes", "x", false},
		{"timeout", "5s", true}, {"timeout", "11s", false},
		{"url", "http://127.0.0.1:9047/api", false}, {"credential", "relative", false},
		// The fields of dremio_query that select SQL do not exist here.
		{"statement_types", []string{"SELECT"}, false}, {"show_types", []string{"SCHEMAS"}, false}, {"context", []string{"src"}, false},
	} {
		a := registeredBuiltinAction("dremio_diag")
		a.BuiltinConfig[tc.field] = tc.value
		_, err := ValidateAction(a)
		if tc.valid && err != nil || !tc.valid && err == nil {
			t.Errorf("%s=%v: %v", tc.field, tc.value, err)
		}
	}
	a := registeredBuiltinAction("dremio_diag")
	a.BuiltinConfig["max_rows"] = 50
	defs, err := ParameterDefinitions(a)
	if err != nil {
		t.Fatal(err)
	}
	if got := defs["limit"].Max; got != 50 {
		t.Errorf("limit follows max_rows: %v", got)
	}
	for name, d := range defs {
		if name != "op" && !d.Optional {
			t.Errorf("%s must be optional: the required parameters depend on the op", name)
		}
		if d.Default != nil {
			t.Errorf("%s has a default %v: the handler applies it, so that a parameter of another op is noticed", name, d.Default)
		}
	}
	if !slices.Equal(defs["op"].Values, []string{"nodes", "jobs", "job", "job_profile", "reflections"}) {
		t.Errorf("op values: %v", defs["op"].Values)
	}
	// ops narrows the enum; a single op becomes the default, so the caller can omit it.
	a.BuiltinConfig["ops"] = []string{"jobs", "job"}
	defs, err = ParameterDefinitions(a)
	if err != nil || !slices.Equal(defs["op"].Values, []string{"jobs", "job"}) || defs["op"].Default != nil || defs["op"].Optional {
		t.Errorf("two ops: %+v %v", defs["op"], err)
	}
	a.BuiltinConfig["ops"] = []string{"nodes"}
	defs, err = ParameterDefinitions(a)
	if err != nil || !slices.Equal(defs["op"].Values, []string{"nodes"}) || defs["op"].Default != "nodes" {
		t.Errorf("one op: %+v %v", defs["op"], err)
	}
	// With the default, a call without op reaches the handler as op=nodes.
	parsed, err := params.Parse(defs, map[string]any{})
	if err != nil || parsed["op"] != "nodes" {
		t.Errorf("parse without op: %v %v", parsed, err)
	}
}

// The parameters of the op are checked before the credential file is read.
func TestDremioDiagRunChecksParametersBeforeCredential(t *testing.T) {
	a := registeredBuiltinAction("dremio_diag")
	a.BuiltinConfig["ops"] = []string{"nodes", "jobs", "job"}
	for _, tc := range []struct {
		name   string
		values map[string]any
		reject string // empty: reaches the credential file
	}{
		{"nodes", map[string]any{"op": "nodes"}, ""},
		{"job", map[string]any{"op": "job", "job_id": "152329ab-6312-f9a2-7240-1e8469e7bd00"}, ""},
		{"jobs filters", map[string]any{"op": "jobs", "since": 2 * time.Hour, "state": "FAILED", "limit": int64(5)}, ""},
		{"job without id", map[string]any{"op": "job"}, "job_id"},
		{"nodes with job_id", map[string]any{"op": "nodes", "job_id": "152329ab-6312-f9a2-7240-1e8469e7bd00"}, "does not take"},
		{"unknown op", map[string]any{"op": "kill"}, "op must be"},
		{"op outside ops", map[string]any{"op": "reflections"}, "ops allows only"},
		{"jobs with top_n", map[string]any{"op": "jobs", "top_n": int64(3)}, "does not take"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Builtins["dremio_diag"].Run(context.Background(), a.BuiltinConfig, tc.values)
			if result.ExitCode != 1 || err == nil {
				t.Fatalf("%+v, %v", result, err)
			}
			if tc.reject == "" && !strings.Contains(err.Error(), "cannot open credential file") || tc.reject != "" && !strings.Contains(err.Error(), tc.reject) {
				t.Fatalf("got %v; want %q", err, tc.reject)
			}
		})
	}
}

// Each dremio_diag example fixes its op, so the caller supplies only the
// parameters of that op, and no SQL.
func TestDremioDiagExamplesFixTheirOp(t *testing.T) {
	c := loadExamples(t)
	for name, tc := range map[string]struct{ op string }{
		"dremio_nodes": {"nodes"}, "dremio_jobs_recent": {"jobs"}, "dremio_job_profile": {"job_profile"},
	} {
		a, ok := c.Actions[name]
		if !ok {
			t.Errorf("example %s is missing", name)
			continue
		}
		if a.Builtin != "dremio_diag" || a.Risk != "read" || a.RunAs != "root" || !CheckHost(a).RequiresExec {
			t.Errorf("%s: %+v", name, a)
		}
		defs, err := ParameterDefinitions(a)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !slices.Equal(defs["op"].Values, []string{tc.op}) || defs["op"].Default != tc.op {
			t.Errorf("%s: op %+v", name, defs["op"])
		}
		parsed, err := params.Parse(defs, map[string]any{})
		if err != nil || parsed["op"] != tc.op {
			t.Errorf("%s: %v %v", name, parsed, err)
		}
		if _, ok := defs["sql"]; ok {
			t.Errorf("%s accepts SQL", name)
		}
	}
}
