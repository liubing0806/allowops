package starrocksdiag

import (
	"context"
	sqldriver "database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
)

func TestConfigValidate(t *testing.T) {
	base := baseConfig()
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{Credential: base.Credential, Address: base.Address, MaxRows: 500, MaxBytes: 1 << 20, Timeout: 10 * time.Second, MaxProfileBytes: 16 << 20},
		{Credential: base.Credential, Address: base.Address, MaxRows: 1, MaxBytes: 1, Timeout: time.Millisecond, MaxProfileBytes: 1},
		{Credential: base.Credential, Address: base.Address, AuditTable: "audit_tbl"},
		{Credential: base.Credential, Address: base.Address, AuditTable: "audit_db.audit_tbl", AuditColumns: map[string]string{"query_time": "latency_ms", "stmt": "sql_text"}},
		{Credential: base.Credential, Address: base.Address, AllowProfileRun: true},
	} {
		if err := c.Validate(); err != nil {
			t.Errorf("rejected %+v: %v", c, err)
		}
	}
	for _, c := range []Config{
		{Credential: "relative", Address: base.Address},
		{Credential: base.Credential, Address: "127.0.0.1:9030"},
		{Credential: base.Credential, Address: "tcp://user:pass@host:9030"},
		{Credential: base.Credential, Address: base.Address, MaxRows: -1},
		{Credential: base.Credential, Address: base.Address, MaxRows: 501},
		{Credential: base.Credential, Address: base.Address, MaxBytes: 1<<20 + 1},
		{Credential: base.Credential, Address: base.Address, Timeout: 11 * time.Second},
		{Credential: base.Credential, Address: base.Address, MaxProfileBytes: -1},
		{Credential: base.Credential, Address: base.Address, MaxProfileBytes: 16<<20 + 1},
	} {
		if c.Validate() == nil {
			t.Errorf("accepted invalid config %+v", c)
		}
	}
}

func TestConfigAuditIdentifiers(t *testing.T) {
	base := baseConfig()
	for _, table := range []string{"a.b.c", "a b", "a;DROP TABLE x", "`a`", "a.", ".a", "a-b", "1a", "a\nb", "é", strings.Repeat("a", 65), "a.b'", `a"b`, "a/**/b", "a.b;"} {
		c := base
		c.AuditTable = table
		if c.Validate() == nil {
			t.Errorf("accepted audit_table %q", table)
		}
	}
	for _, column := range []string{"", "a b", "a;b", "`a`", "a.b", "1a", strings.Repeat("a", 65), "a'", "a-b"} {
		c := base
		c.AuditColumns = map[string]string{"stmt": column}
		if c.Validate() == nil {
			t.Errorf("accepted audit column %q", column)
		}
	}
	c := base
	c.AuditColumns = map[string]string{"no_such_column": "x"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "no_such_column") {
		t.Errorf("unknown audit column key: %v", err)
	}
}

func TestConfigDefaults(t *testing.T) {
	got := baseConfig().normalized()
	if got.MaxRows != 500 || got.MaxBytes != 1<<20 || got.Timeout != 10*time.Second || got.MaxProfileBytes != 16<<20 {
		t.Errorf("limits: %+v", got)
	}
	if got.AuditTable != "starrocks_audit_db__.starrocks_audit_tbl__" {
		t.Errorf("audit table: %q", got.AuditTable)
	}
	want := map[string]string{
		"query_id": "queryId", "timestamp": "timestamp", "user": "user", "db": "db", "state": "state", "query_time": "queryTime",
		"scan_bytes": "scanBytes", "scan_rows": "scanRows", "return_rows": "returnRows", "cpu_cost_ns": "cpuCostNs", "mem_cost_bytes": "memCostBytes", "stmt": "stmt",
	}
	if len(got.AuditColumns) != len(want) {
		t.Errorf("audit columns: %v", got.AuditColumns)
	}
	for k, v := range want {
		if got.AuditColumns[k] != v {
			t.Errorf("audit column %s = %q, want %q", k, got.AuditColumns[k], v)
		}
	}
	c := baseConfig()
	c.AuditColumns = map[string]string{"stmt": "sql_text"}
	if n := c.normalized(); n.AuditColumns["stmt"] != "sql_text" || n.AuditColumns["user"] != "user" {
		t.Errorf("partial rename: %v", n.AuditColumns)
	}
	if c.AuditColumns["user"] != "" {
		t.Error("normalized modified the caller's map")
	}
}

func TestOps(t *testing.T) {
	c := baseConfig()
	want := []string{"cluster", "running", "slow_queries", "profile_list", "profile_analyze", "profile_summary"}
	if got := Ops(c); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("ops = %v, want %v", got, want)
	}
	c.AllowProfileRun = true
	if got := Ops(c); got[len(got)-1] != "profile_run" || len(got) != 7 {
		t.Errorf("ops with profile_run = %v", got)
	}
}

func TestQuoteLiteral(t *testing.T) {
	for in, want := range map[string]string{
		"abc": `'abc'`, "a'b": `'a''b'`, `a\b`: `'a\\b'`, `\'`: `'\\'''`, "": `''`, "a\x00b": `'a\0b'`, "a\nb": `'a\nb'`,
	} {
		if got := quoteLiteral(in); got != want {
			t.Errorf("quoteLiteral(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestParamValidation(t *testing.T) {
	enabled := baseConfig()
	enabled.AllowProfileRun = true
	tight := baseConfig()
	tight.MaxRows = 10
	for _, tc := range []struct {
		name string
		cfg  Config
		p    Params
		want string // empty: accepted; otherwise a substring of the error
	}{
		{"cluster", baseConfig(), Params{Op: "cluster"}, ""},
		{"cluster component", baseConfig(), Params{Op: "cluster", Component: "backends"}, ""},
		{"cluster bad component", baseConfig(), Params{Op: "cluster", Component: "all; DROP"}, "component"},
		{"running", baseConfig(), Params{Op: "running"}, ""},
		{"no op", baseConfig(), Params{}, "op"},
		{"unknown op", baseConfig(), Params{Op: "kill"}, "op"},
		{"slow defaults", baseConfig(), Params{Op: "slow_queries"}, ""},
		{"slow full", baseConfig(), Params{Op: "slow_queries", SinceMinutes: 10080, MinDurationMs: 86400000, State: "ERR", Limit: 500}, ""},
		{"slow since", baseConfig(), Params{Op: "slow_queries", SinceMinutes: 10081}, "since_minutes"},
		{"slow negative since", baseConfig(), Params{Op: "slow_queries", SinceMinutes: -1}, "since_minutes"},
		{"slow min duration", baseConfig(), Params{Op: "slow_queries", MinDurationMs: -1}, "min_duration_ms"},
		{"slow min duration high", baseConfig(), Params{Op: "slow_queries", MinDurationMs: 86400001}, "min_duration_ms"},
		{"slow state", baseConfig(), Params{Op: "slow_queries", State: "ERR' OR '1'='1"}, "state"},
		{"slow limit over config", tight, Params{Op: "slow_queries", Limit: 11}, "limit"},
		{"slow limit", tight, Params{Op: "slow_queries", Limit: 10}, ""},
		{"slow limit negative", baseConfig(), Params{Op: "slow_queries", Limit: -1}, "limit"},
		{"list", baseConfig(), Params{Op: "profile_list", Limit: 100}, ""},
		{"list over", baseConfig(), Params{Op: "profile_list", Limit: 501}, "limit"},
		{"analyze", baseConfig(), Params{Op: "profile_analyze", QueryID: testQueryID}, ""},
		{"analyze upper case", baseConfig(), Params{Op: "profile_analyze", QueryID: strings.ToUpper(testQueryID)}, ""},
		{"analyze missing id", baseConfig(), Params{Op: "profile_analyze"}, "query_id"},
		{"summary", baseConfig(), Params{Op: "profile_summary", QueryID: testQueryID, TopN: 50}, ""},
		{"summary top_n", baseConfig(), Params{Op: "profile_summary", QueryID: testQueryID, TopN: 51}, "top_n"},
		{"summary negative top_n", baseConfig(), Params{Op: "profile_summary", QueryID: testQueryID, TopN: -1}, "top_n"},
		{"id on cluster", baseConfig(), Params{Op: "cluster", QueryID: testQueryID}, "query_id"},
		{"sql on summary", baseConfig(), Params{Op: "profile_summary", QueryID: testQueryID, SQL: "SELECT 1"}, "sql"},
		{"database on summary", baseConfig(), Params{Op: "profile_summary", QueryID: testQueryID, Database: "demo"}, "database"},
		{"run disabled", baseConfig(), Params{Op: "profile_run", SQL: "SELECT 1"}, "allow_profile_run"},
		{"run", enabled, Params{Op: "profile_run", SQL: "SELECT 1"}, ""},
		{"run database", enabled, Params{Op: "profile_run", SQL: "SELECT count(*) FROM t", Database: "demo_dw"}, ""},
		{"run bad database", enabled, Params{Op: "profile_run", SQL: "SELECT 1", Database: "a;b"}, "database"},
		{"run without sql", enabled, Params{Op: "profile_run"}, "sql"},
		{"run with id", enabled, Params{Op: "profile_run", SQL: "SELECT 1", QueryID: testQueryID}, "query_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateParams(tc.cfg.normalized(), tc.p)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("rejected: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestQueryIDAcceptsOnlyUUIDs(t *testing.T) {
	cfg := baseConfig().normalized()
	for _, id := range []string{
		"", "x", "b6e3e384ced511f1b1555ee444682bc1", testQueryID + " ", " " + testQueryID, testQueryID + "'", testQueryID + "\n",
		"b6e3e384-ced5-11f1-b155-5ee444682bc", "b6e3e384-ced5-11f1-b155-5ee444682bcg", "'; DROP TABLE x; --", `\`, "b6e3e384-ced5-11f1-b155-5ee444682bc1-1",
		"{b6e3e384-ced5-11f1-b155-5ee444682bc1}", "b6e3e384-ced5-11f1-b155-5ee444682bc1\x00", "b6e3e384-ced5-11f1-b155-5ee444682bcé",
	} {
		for _, op := range []string{"profile_analyze", "profile_summary"} {
			if validateParams(cfg, Params{Op: op, QueryID: id}) == nil {
				t.Errorf("%s accepted query_id %q", op, id)
			}
		}
	}
}

func TestProfileRunSQLIsGuarded(t *testing.T) {
	cfg := baseConfig()
	cfg.AllowProfileRun = true
	cfg = cfg.normalized()
	for _, sql := range []string{
		"INSERT INTO t VALUES (1)", "DELETE FROM t", "SHOW TABLES", "DESC t", "EXPLAIN SELECT 1", "EXPLAIN ANALYZE SELECT 1",
		"SELECT 1; SELECT 2", "SELECT 1; INSERT INTO t VALUES (1)", "SELECT 1 # ; INSERT INTO t VALUES (1)",
		"SELECT get_query_profile('" + testQueryID + "')", "SELECT * FROM FILES('path'='file:///etc/passwd','format'='csv')",
		"SELECT 1 INTO OUTFILE 'file:///tmp/x'", "SELECT sleep(100)", "SELECT /*+ SET_VAR(query_timeout=3600) */ 1",
		"SET enable_profile = false", "ANALYZE PROFILE FROM '" + testQueryID + "'", "SHOW PROFILELIST", "", "   ", strings.Repeat("a", 4001),
	} {
		if err := validateParams(cfg, Params{Op: "profile_run", SQL: sql}); err == nil {
			t.Errorf("accepted %q", sql)
		}
	}
	for _, sql := range []string{
		"SELECT 1", "SELECT store_id, sum(amount) FROM demo_dw.fact_orders GROUP BY store_id",
		"WITH c AS (SELECT 1 AS n) SELECT * FROM c", "(SELECT 1) UNION ALL (SELECT 2);",
	} {
		if err := validateParams(cfg, Params{Op: "profile_run", SQL: sql}); err != nil {
			t.Errorf("rejected %q: %v", sql, err)
		}
	}
}

func TestRejectedParamsReachNeitherCredentialNorConnection(t *testing.T) {
	cfg := missingCredential()
	cfg.AllowProfileRun = true
	for _, p := range []Params{
		{Op: "profile_analyze", QueryID: "bad"}, {Op: "profile_summary"}, {Op: "profile_run", SQL: "INSERT INTO t VALUES (1)"},
		{Op: "nope"}, {Op: "slow_queries", SinceMinutes: -5},
	} {
		_, err := Run(context.Background(), cfg, p)
		if err == nil || strings.Contains(err.Error(), "credential") {
			t.Errorf("%+v: %v", p, err)
		}
	}
	// A valid request gets as far as the credential file.
	if _, err := Run(context.Background(), cfg, Params{Op: "cluster"}); err == nil || !strings.Contains(err.Error(), "credential") {
		t.Errorf("valid request: %v", err)
	}
	if _, err := Run(context.Background(), Config{Credential: "relative", Address: "tcp://h:1"}, Params{Op: "cluster"}); err == nil {
		t.Error("invalid config accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, cfg, Params{Op: "cluster"}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context: %v", err)
	}
}

func TestSlowQuerySQL(t *testing.T) {
	cfg := baseConfig().normalized()
	got := slowQuerySQL(cfg, Params{Op: "slow_queries", SinceMinutes: 60, MinDurationMs: 1000, State: "any", Limit: 20})
	want := "SELECT `queryId` AS `query_id`, `timestamp` AS `timestamp`, `user` AS `user`, `db` AS `db`, `state` AS `state`, `queryTime` AS `query_time`, " +
		"`scanBytes` AS `scan_bytes`, `scanRows` AS `scan_rows`, `returnRows` AS `return_rows`, `cpuCostNs` AS `cpu_cost_ns`, `memCostBytes` AS `mem_cost_bytes`, " +
		"LEFT(`stmt`, 1000) AS `stmt` FROM `starrocks_audit_db__`.`starrocks_audit_tbl__` " +
		"WHERE `timestamp` >= DATE_SUB(NOW(), INTERVAL 3600 SECOND) AND `queryTime` >= 1000 ORDER BY `queryTime` DESC LIMIT 20"
	if got != want {
		t.Errorf("sql:\n got %s\nwant %s", got, want)
	}
	got = slowQuerySQL(cfg, Params{Op: "slow_queries", SinceMinutes: 5, MinDurationMs: 0, State: "ERR", Limit: 3})
	if !strings.Contains(got, "INTERVAL 300 SECOND") || !strings.Contains(got, "`queryTime` >= 0") || !strings.Contains(got, "AND `state` = 'ERR'") || !strings.HasSuffix(got, "LIMIT 3") {
		t.Errorf("sql: %s", got)
	}
	renamed := baseConfig()
	renamed.AuditTable = "ops.slow_log"
	renamed.AuditColumns = map[string]string{"query_time": "latency_ms", "stmt": "sql_text", "timestamp": "ts"}
	got = slowQuerySQL(renamed.normalized(), Params{Op: "slow_queries", SinceMinutes: 1, MinDurationMs: 7, State: "OK", Limit: 1})
	for _, part := range []string{"FROM `ops`.`slow_log`", "`latency_ms` AS `query_time`", "LEFT(`sql_text`, 1000) AS `stmt`", "`ts` AS `timestamp`", "WHERE `ts` >= DATE_SUB", "`latency_ms` >= 7", "ORDER BY `latency_ms` DESC", "`state` = 'OK'"} {
		if !strings.Contains(got, part) {
			t.Errorf("renamed sql lacks %q: %s", part, got)
		}
	}
	single := baseConfig()
	single.AuditTable = "audit_tbl"
	if got := slowQuerySQL(single.normalized(), Params{Op: "slow_queries", SinceMinutes: 1, State: "any", Limit: 1}); !strings.Contains(got, "FROM `audit_tbl` WHERE") {
		t.Errorf("table without database: %s", got)
	}
}

func run(t *testing.T, f *fixture, cfg Config, p Params, mask func(string) string) (Result, error) {
	t.Helper()
	return runOp(context.Background(), f, cfg.normalized(), p, mask)
}

func TestSessionTimeoutPrecedesTheStatement(t *testing.T) {
	f := &fixture{handle: func(string) reply { return reply{columns: []string{"v"}} }}
	cfg := limits(10, 1<<20)
	cfg.Timeout = 1500 * time.Millisecond
	if _, err := run(t, f, cfg, Params{Op: "running"}, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.log) != 2 || f.log[0] != "exec: SET query_timeout = 2" || f.log[1] != "query: SHOW PROC '/current_queries'" {
		t.Errorf("statements: %q", f.log)
	}
	f = &fixture{handle: func(s string) reply {
		if strings.HasPrefix(s, "SET") {
			return reply{err: &mysqldriver.MySQLError{Number: 1064, Message: "secret"}}
		}
		return reply{}
	}}
	_, err := run(t, f, limits(10, 1<<20), Params{Op: "running"}, nil)
	if err == nil || err.Error() != "starrocks initialize session failed (code 1064)" || len(f.queried()) != 0 {
		t.Errorf("err = %v, queried %q", err, f.queried())
	}
}

func TestFixedStatementsPerOp(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    Params
		want []string
	}{
		{"cluster", Params{Op: "cluster"}, []string{"SHOW FRONTENDS", "SHOW BACKENDS", "SHOW COMPUTE NODES"}},
		{"frontends", Params{Op: "cluster", Component: "frontends"}, []string{"SHOW FRONTENDS"}},
		{"backends", Params{Op: "cluster", Component: "backends"}, []string{"SHOW BACKENDS"}},
		{"compute nodes", Params{Op: "cluster", Component: "compute_nodes"}, []string{"SHOW COMPUTE NODES"}},
		{"running", Params{Op: "running"}, []string{"SHOW PROC '/current_queries'"}},
		{"profile list default", Params{Op: "profile_list"}, []string{"SHOW PROFILELIST LIMIT 20"}},
		{"profile list", Params{Op: "profile_list", Limit: 7}, []string{"SHOW PROFILELIST LIMIT 7"}},
		{"analyze", Params{Op: "profile_analyze", QueryID: strings.ToUpper(testQueryID)}, []string{"ANALYZE PROFILE FROM '" + strings.ToUpper(testQueryID) + "'"}},
		{"summary", Params{Op: "profile_summary", QueryID: testQueryID}, []string{"SELECT get_query_profile('" + testQueryID + "')"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fixture{handle: func(s string) reply {
				if strings.HasPrefix(s, "SELECT get_query_profile") {
					return reply{columns: []string{"p"}, rows: [][]sqldriver.Value{{profileSample(t, "scan_agg")}}}
				}
				return reply{columns: []string{"value"}, rows: [][]sqldriver.Value{{"x"}}}
			}}
			if _, err := run(t, f, limits(10, 1<<20), tc.p, nil); err != nil {
				t.Fatal(err)
			}
			if got := f.queried(); strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("queried %q, want %q", got, tc.want)
			}
			for _, s := range f.log {
				if strings.HasPrefix(s, "exec: ") && s != "exec: SET query_timeout = 2" {
					t.Errorf("unexpected statement %q", s)
				}
			}
		})
	}
}

func TestClusterSections(t *testing.T) {
	f := &fixture{handle: func(s string) reply {
		switch s {
		case "SHOW FRONTENDS":
			return reply{columns: []string{"Name", "Alive"}, rows: [][]sqldriver.Value{{"fe1", "true"}}}
		case "SHOW BACKENDS":
			return reply{columns: []string{"BackendId", "Alive"}, rows: [][]sqldriver.Value{{"1001", "true"}, {"1002", "false"}}}
		}
		return reply{columns: []string{"IP"}}
	}}
	got, err := run(t, f, limits(10, 1<<20), Params{Op: "cluster"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "# frontends\nName\tAlive\nfe1\ttrue\n# backends\nBackendId\tAlive\n1001\ttrue\n1002\tfalse\n# compute_nodes\nIP\n"
	if got.Output != want || got.Rows != 3 || got.Truncated {
		t.Errorf("got %+v\nwant output %q", got, want)
	}
	// The row limit is shared by the sections.
	got, err = run(t, f, limits(2, 1<<20), Params{Op: "cluster"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || got.Rows != 2 || strings.Contains(got.Output, "1002") {
		t.Errorf("row limit: %+v", got)
	}
	// The byte limit is shared too.
	got, err = run(t, f, limits(10, int64(len("# frontends\nName\tAlive\nfe1\ttrue\n"))), Params{Op: "cluster"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || strings.Contains(got.Output, "backends") {
		t.Errorf("byte limit: %+v", got)
	}
}

func TestMaskAppliesToHeadersAndCells(t *testing.T) {
	f := &fixture{handle: func(string) reply {
		return reply{columns: []string{"User", "Info"}, rows: [][]sqldriver.Value{{"root", "password=hunter2"}}}
	}}
	mask := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, "hunter2", "[REDACTED]"), "User", "Account")
	}
	got, err := run(t, f, limits(10, 1<<20), Params{Op: "running"}, mask)
	if err != nil {
		t.Fatal(err)
	}
	if got.Output != "Account\tInfo\nroot\tpassword=[REDACTED]\n" {
		t.Errorf("output %q", got.Output)
	}
}

func TestAnalyzeStripsTerminalEscapes(t *testing.T) {
	f := &fixture{handle: func(string) reply {
		return reply{columns: []string{"Explain String"}, rows: [][]sqldriver.Value{{"\x1b[0mSummary\x1b[0m"}, {"\x1b[1;31m    1. OLAP_SCAN (id=0)\x1b[0m : 5ms"}}}
	}}
	got, err := run(t, f, limits(10, 1<<20), Params{Op: "profile_analyze", QueryID: testQueryID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Output != "Explain String\nSummary\n    1. OLAP_SCAN (id=0) : 5ms\n" {
		t.Errorf("output %q", got.Output)
	}
}

func TestSlowQueriesRows(t *testing.T) {
	f := &fixture{handle: func(string) reply {
		return reply{columns: []string{"query_id", "query_time", "stmt"}, rows: [][]sqldriver.Value{{testQueryID, int64(2500), "SELECT 'secret'"}}}
	}}
	mask := func(s string) string { return strings.ReplaceAll(s, "secret", "[REDACTED]") }
	got, err := run(t, f, limits(10, 1<<20), Params{Op: "slow_queries", SinceMinutes: 60, MinDurationMs: 1000, State: "any", Limit: 5}, mask)
	if err != nil {
		t.Fatal(err)
	}
	if got.Output != "query_id\tquery_time\tstmt\n"+testQueryID+"\t2500\tSELECT '[REDACTED]'\n" || got.Rows != 1 {
		t.Errorf("got %+v", got)
	}
	if q := f.queried(); len(q) != 1 || !strings.Contains(q[0], "FROM `starrocks_audit_db__`.`starrocks_audit_tbl__`") {
		t.Errorf("queried %q", q)
	}
}

func TestServerErrorsExposeOnlyTheCode(t *testing.T) {
	f := &fixture{handle: func(s string) reply {
		if strings.HasPrefix(s, "SHOW") {
			return reply{err: &mysqldriver.MySQLError{Number: 5203, Message: "Access denied for user 'diag' password hunter2"}}
		}
		return reply{}
	}}
	_, err := run(t, f, limits(10, 1<<20), Params{Op: "cluster"}, nil)
	if err == nil || err.Error() != "starrocks query failed (code 5203)" {
		t.Errorf("err = %v", err)
	}
}

func TestProfileSummary(t *testing.T) {
	text := profileSample(t, "nestloop_join")
	f := &fixture{handle: func(string) reply {
		return reply{columns: []string{"get_query_profile"}, rows: [][]sqldriver.Value{{text}}}
	}}
	got, err := run(t, f, limits(10, 1<<20), Params{Op: "profile_summary", QueryID: testQueryID, TopN: 3}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Query struct {
			State string `json:"state"`
		} `json:"query"`
		TopOperators []struct {
			Operator string `json:"operator"`
		} `json:"top_operators"`
		Findings []struct {
			Rule string `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(got.Output), &out); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, got.Output)
	}
	if out.Query.State != "Finished" || len(out.TopOperators) != 3 || out.TopOperators[0].Operator != "NESTLOOP_JOIN_PROBE" {
		t.Errorf("summary: %+v", out)
	}
	found := false
	for _, finding := range out.Findings {
		found = found || finding.Rule == "SR-JOIN-1"
	}
	if !found || got.Truncated || got.Rows != 1 {
		t.Errorf("findings %+v, result %+v", out.Findings, got)
	}
	if strings.Contains(got.Output, "SELECT") || strings.Contains(got.Output, "demo_dw") {
		t.Errorf("the summary contains SQL text: %s", got.Output)
	}
}

func TestProfileSummaryMasksStrings(t *testing.T) {
	f := &fixture{handle: func(string) reply {
		return reply{columns: []string{"p"}, rows: [][]sqldriver.Value{{profileSample(t, "nestloop_join")}}}
	}}
	got, err := run(t, f, limits(10, 1<<20), Params{Op: "profile_summary", QueryID: testQueryID}, func(s string) string { return strings.ReplaceAll(s, "NESTLOOP", "MASKED") })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.Output, "NESTLOOP") || !strings.Contains(got.Output, "MASKED_JOIN_PROBE") {
		t.Errorf("not masked: %s", got.Output)
	}
}

func TestProfileSummaryErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows [][]sqldriver.Value
		cfg  Config
		want string
	}{
		{"no row", nil, limits(10, 1<<20), "not found"},
		{"empty text", [][]sqldriver.Value{{""}}, limits(10, 1<<20), "not found"},
		{"null", [][]sqldriver.Value{{nil}}, limits(10, 1<<20), "not found"},
		{"not a profile", [][]sqldriver.Value{{"hello"}}, limits(10, 1<<20), "cannot be parsed"},
		{"too large", [][]sqldriver.Value{{profileSample(t, "scan_agg")}}, func() Config { c := limits(10, 1<<20); c.MaxProfileBytes = 1000; return c }(), "larger than"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fixture{handle: func(string) reply { return reply{columns: []string{"p"}, rows: tc.rows} }}
			_, err := run(t, f, tc.cfg, Params{Op: "profile_summary", QueryID: testQueryID}, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestProfileSummaryFitsMaxBytes(t *testing.T) {
	f := &fixture{handle: func(string) reply {
		return reply{columns: []string{"p"}, rows: [][]sqldriver.Value{{profileSample(t, "hash_join")}}}
	}}
	full, err := run(t, f, limits(10, 1<<20), Params{Op: "profile_summary", QueryID: testQueryID, TopN: 50}, nil)
	if err != nil || full.Truncated {
		t.Fatalf("full: %+v, %v", full, err)
	}
	small, err := run(t, f, limits(10, int64(len(full.Output)/2)), Params{Op: "profile_summary", QueryID: testQueryID, TopN: 50}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !small.Truncated || len(small.Output) > len(full.Output)/2 || !json.Valid([]byte(small.Output)) {
		t.Errorf("truncated output: truncated=%v len=%d/%d valid=%v", small.Truncated, len(small.Output), len(full.Output)/2, json.Valid([]byte(small.Output)))
	}
	if _, err := run(t, f, limits(10, 20), Params{Op: "profile_summary", QueryID: testQueryID}, nil); err == nil {
		t.Error("a 20-byte limit cannot hold a summary")
	}
}

// profileRunFixture serves a profile run: the caller's SELECT, last_query_id()
// and get_query_profile(), whose answer is empty for the first `empty` polls.
func profileRunFixture(t *testing.T, empty int) *fixture {
	polls := 0
	return &fixture{handle: func(s string) reply {
		switch {
		case s == "SELECT last_query_id()":
			return reply{columns: []string{"last_query_id()"}, rows: [][]sqldriver.Value{{testQueryID}}}
		case strings.HasPrefix(s, "SELECT get_query_profile("):
			polls++
			if polls <= empty {
				return reply{columns: []string{"p"}, rows: [][]sqldriver.Value{{""}}}
			}
			return reply{columns: []string{"p"}, rows: [][]sqldriver.Value{{profileSample(t, "scan_agg")}}}
		case strings.HasPrefix(s, "SELECT secret"):
			return reply{columns: []string{"secret_column"}, rows: [][]sqldriver.Value{{"secret-1"}, {"secret-2"}, {"secret-3"}}}
		}
		return reply{}
	}}
}

func TestProfileRun(t *testing.T) {
	defer func(old time.Duration) { pollInterval = old }(pollInterval)
	pollInterval = time.Millisecond
	cfg := limits(10, 1<<20)
	cfg.AllowProfileRun = true
	f := profileRunFixture(t, 2)
	got, err := run(t, f, cfg, Params{Op: "profile_run", SQL: "SELECT secret FROM t", Database: "demo_dw", TopN: 4}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"exec: SET query_timeout = 2", "exec: SET enable_profile = true", "query: SELECT secret FROM t", "query: SELECT last_query_id()",
		"query: SELECT get_query_profile('" + testQueryID + "')", "query: SELECT get_query_profile('" + testQueryID + "')", "query: SELECT get_query_profile('" + testQueryID + "')",
	}
	if strings.Join(f.log, "\n") != strings.Join(want, "\n") {
		t.Errorf("statements:\n%s\nwant:\n%s", strings.Join(f.log, "\n"), strings.Join(want, "\n"))
	}
	var out struct {
		ResultRows   int `json:"result_rows"`
		TopOperators []struct {
			Operator string `json:"operator"`
		} `json:"top_operators"`
	}
	if err := json.Unmarshal([]byte(got.Output), &out); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, got.Output)
	}
	if out.ResultRows != 3 || len(out.TopOperators) != 4 {
		t.Errorf("output: %s", got.Output)
	}
	if strings.Contains(got.Output, "secret") {
		t.Errorf("result rows leaked: %s", got.Output)
	}
}

func TestProfileRunNeverPollsForever(t *testing.T) {
	defer func(old time.Duration) { pollInterval = old }(pollInterval)
	pollInterval = time.Millisecond
	cfg := limits(10, 1<<20)
	cfg.AllowProfileRun = true
	cfg.Timeout = 50 * time.Millisecond
	f := profileRunFixture(t, 1<<30)
	start := time.Now()
	_, err := run(t, f, cfg, Params{Op: "profile_run", SQL: "SELECT 1"}, nil)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Errorf("err = %v after %v", err, time.Since(start))
	}
}

func TestProfileRunErrors(t *testing.T) {
	cfg := limits(10, 1<<20)
	cfg.AllowProfileRun = true
	f := &fixture{handle: func(s string) reply {
		if s == "SELECT 1 FROM missing" {
			return reply{err: &mysqldriver.MySQLError{Number: 5502, Message: "Unknown table 'secret_table'"}}
		}
		return reply{}
	}}
	_, err := run(t, f, cfg, Params{Op: "profile_run", SQL: "SELECT 1 FROM missing"}, nil)
	if err == nil || err.Error() != "starrocks query failed (code 5502)" {
		t.Errorf("err = %v", err)
	}
	f = &fixture{handle: func(s string) reply {
		if s == "SELECT last_query_id()" {
			return reply{columns: []string{"id"}, rows: [][]sqldriver.Value{{"not-a-uuid'; DROP TABLE x"}}}
		}
		return reply{}
	}}
	_, err = run(t, f, cfg, Params{Op: "profile_run", SQL: "SELECT 1"}, nil)
	if err == nil {
		t.Fatal("accepted a malformed last_query_id()")
	}
	for _, q := range f.queried() {
		if strings.Contains(q, "DROP") {
			t.Errorf("malformed id reached SQL: %q", q)
		}
	}
	// A disabled op is refused even when the validation was skipped.
	if _, err := run(t, &fixture{}, limits(10, 1<<20), Params{Op: "profile_run", SQL: "SELECT 1"}, nil); err == nil {
		t.Error("profile_run ran while disabled")
	}
}

func TestRunHonoursContext(t *testing.T) {
	f := &fixture{handle: func(string) reply { return reply{columns: []string{"v"}} }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runOp(ctx, f, baseConfig().normalized(), Params{Op: "running"}, nil); !errors.Is(err, context.Canceled) || len(f.log) != 0 {
		t.Errorf("err = %v, log %q", err, f.log)
	}
}
