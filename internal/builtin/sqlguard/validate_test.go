package sqlguard

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

var dialects = []Dialect{StarRocks, Dremio}

func rejectedCorpora() map[Dialect][]map[string][]string {
	return map[Dialect][]map[string][]string{
		StarRocks: {attacksCommon, attacksMeasuredCommon, attacksStarRocks, attacksMeasuredStarRocks},
		Dremio:    {attacksCommon, attacksMeasuredCommon, attacksDremio, attacksMeasuredDremio},
	}
}

var sel = Statement{Kind: KindSelect}

func show(showType string) Statement { return Statement{Kind: KindShow, ShowType: showType} }

func explain(variant string, target Statement) Statement {
	return Statement{Kind: KindExplain, Variant: variant, Target: &target}
}

type allowCase struct {
	sql  string
	want Statement
}

var allowCommon = []allowCase{
	{"SELECT 1", sel},
	{"select 1;", sel},
	{"SELECT 1 /* a */ ; /* b */", sel},
	{"SELECT /* ordinary */ 1; -- trailing\n", sel},
	{"SELECT 1 -- comment\n", sel},
	{"SELECT 1 -- ", sel},
	{"SELECT 1 -- 中文注释", sel},
	{"SELECT 1--\nFROM t", sel},
	{"SELECT 1 - -1, 2 - 1, -x FROM t", sel},
	{"SELECT * FROM catalog.db.table WHERE id = 1", sel},
	{"SELECT t.a, catalog.db.t.b FROM catalog.db.t", sel},
	{"SELECT COUNT(*), SUM(x), AVG(x), MIN(x), MAX(x) FROM t GROUP BY y HAVING COUNT(*) > 1 ORDER BY 1 DESC LIMIT 10 OFFSET 5", sel},
	{"WITH c AS (SELECT 1 AS x) SELECT * FROM c", sel},
	{"WITH a AS (SELECT 1 AS x), b AS (SELECT 2 AS y) SELECT * FROM a, b", sel},
	{"SELECT 1 UNION ALL SELECT 2", sel},
	{"SELECT 1 UNION SELECT 2 EXCEPT SELECT 3 INTERSECT SELECT 4", sel},
	{"(SELECT 1) UNION (SELECT 2)", sel},
	{"SELECT a, row_number() OVER (PARTITION BY b ORDER BY c DESC) AS rn, sum(x) OVER (ORDER BY c ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t", sel},
	{"SELECT CAST(a AS BIGINT), a != b, a % 2, a | b, a & b, a ^ b, ~a, a >= b, a <> b FROM t", sel},
	{"SELECT CASE WHEN a > 1 THEN 'x' ELSE 'y' END, COALESCE(a, 0), a BETWEEN 1 AND 2, a LIKE '%x%', a IN (1, 2, 3) FROM t", sel},
	{"SELECT * FROM t1 JOIN t2 ON t1.id = t2.id LEFT JOIN t3 USING (id) WHERE t1.x IN (SELECT y FROM t4)", sel},
	{"SELECT * FROM t WHERE name = '张三' AND note LIKE '%中文%'", sel},
	{"SELECT 'it''s', 'a--b#c/*d*/;e', '', '\t'", sel},
	{"SELECT 'files', 'sleep', 'external_query(1)', 'INTO OUTFILE', 'DROP TABLE t'", sel},
	{"SELECT files, sleep, external_query FROM t", sel},
	{"SELECT truncate(1.234, 2), TRUNCATE (x, 1), trunc(x) FROM t", sel},
	{"SELECT updated_at, deleted, settings, inserted, loaded_rows, created_by, dropped, use_count, admin_flag, killed, into_x FROM t", sel},
	{"SELECT x FROM t WHERE a = 1.5e3 AND b = 0x1F AND c = .5 AND d = 1e-3", sel},
	{"SELECT * FROM t WHERE ts >= '2026-01-01 00:00:00' AND ts < '2026-01-02'", sel},
	{"SHOW TABLES", show("TABLES")},
	{"show tables like 'x%'", show("TABLES")},
	{"SHOW CREATE TABLE catalog.db.t", show("CREATE TABLE")},
	{"show create table t;", show("CREATE TABLE")},
	{"SHOW  /* c */\n CREATE\tTABLE t", show("CREATE TABLE")},
	{"SHOW FUNCTIONS", show("FUNCTIONS")},
	{"SHOW PARTITIONS FROM t", show("PARTITIONS")},
	{"DESC t", Statement{Kind: KindDescribe}},
	{"describe catalog.db.t", Statement{Kind: KindDescribe}},
	{"DESCRIBE t;", Statement{Kind: KindDescribe}},
}

var allowStarRocks = []allowCase{
	{"SELECT `a`, `b c`, `d``e`, `delete` FROM `my-catalog`.`my-db`.`tbl`", sel},
	{"SELECT * FROM default_catalog.`my-db`.tbl", sel},
	{"SELECT `delete`, `set`, `into`, `insert`, `files`, `sleep` FROM t", sel},
	{"SELECT '; DROP TABLE t' AS `delete`", sel},
	{"SELECT `a\\` FROM t", sel},
	{"SELECT array_map(x -> x + 1, arr) FROM t", sel},
	{"SELECT array_map((x, y) -> x + y, a, b), array_filter(arr, x -> x > 1), arr[1], [1, 2, 3], array_length(arr) FROM t", sel},
	{"SELECT map{'a': 1, 'b': 2}, ARRAY<INT>[1, 2] FROM t", sel},
	{"SELECT col->'$.a', json_query(col, '$.b') FROM t", sel},
	{`SELECT 'it\'s', "say \"hi\"", 'a\\', "李四", 'a''b'`, sel},
	{`SELECT 'a\'; DROP TABLE t; --'`, sel},
	{`SELECT "a\"; DROP TABLE t; --"`, sel},
	{`SELECT "a""; DROP TABLE t; --"`, sel},
	{"SELECT '#' , 1, \"#a\", '`#`'", sel},
	{"SELECT `#`, `a#b` FROM `t#1`", sel},
	{"SELECT 1 /* # */ -- # x\n", sel},
	{"SELECT @@version, @@session.query_timeout, @x", sel},
	{"SELECT * FROM t1 JOIN [broadcast] t2 ON t1.id = t2.id", sel},
	{"SELECT * FROM t PARTITION (p1)", sel},
	{"SHOW DATABASES", show("DATABASES")},
	{"SHOW SCHEMAS", show("DATABASES")},
	{"SHOW CATALOGS", show("CATALOGS")},
	{"SHOW FULL TABLES FROM db LIKE 'x%'", show("TABLES")},
	{"show tables from catalog.db", show("TABLES")},
	{"SHOW TABLE STATUS FROM db", show("TABLE STATUS")},
	{"SHOW COLUMNS FROM t FROM db", show("COLUMNS")},
	{"SHOW FULL COLUMNS FROM t", show("COLUMNS")},
	{"SHOW FIELDS FROM t", show("COLUMNS")},
	{"SHOW CREATE MATERIALIZED VIEW mv", show("CREATE MATERIALIZED VIEW")},
	{"SHOW CREATE DATABASE d", show("CREATE DATABASE")},
	{"SHOW CREATE SCHEMA d", show("CREATE DATABASE")},
	{"SHOW TABLET FROM t", show("TABLET")},
	{"SHOW MATERIALIZED VIEWS", show("MATERIALIZED VIEWS")},
	{"SHOW VARIABLES LIKE 'query%'", show("VARIABLES")},
	{"SHOW GLOBAL VARIABLES", show("VARIABLES")},
	{"SHOW SESSION STATUS", show("STATUS")},
	{"SHOW STATUS", show("STATUS")},
	{"SHOW PROCESSLIST", show("PROCESSLIST")},
	{"SHOW FULL PROCESSLIST", show("PROCESSLIST")},
	{"SHOW PROFILELIST LIMIT 10", show("PROFILELIST")},
	{"SHOW FRONTENDS", show("FRONTENDS")},
	{"SHOW BACKENDS", show("BACKENDS")},
	{"SHOW COMPUTE NODES", show("COMPUTE NODES")},
	{"DESC db.t ALL", Statement{Kind: KindDescribe}},
	{"DESCRIBE `t`", Statement{Kind: KindDescribe}},
	{"EXPLAIN SELECT * FROM t", explain("", sel)},
	{"explain\nselect 1", explain("", sel)},
	{"EXPLAIN LOGICAL SELECT 1", explain("LOGICAL", sel)},
	{"EXPLAIN VERBOSE SELECT * FROM t WHERE id = 1", explain("VERBOSE", sel)},
	{"EXPLAIN COSTS SELECT 1", explain("COSTS", sel)},
	{"EXPLAIN COSTS WITH c AS (SELECT 1) SELECT * FROM c;", explain("COSTS", sel)},
	{"EXPLAIN (SELECT 1) UNION (SELECT 2)", explain("", sel)},
	{"ANALYZE PROFILE FROM '0b1c4f9c-3a8e-11ef-9c1f-0242ac120002'", Statement{Kind: KindAnalyzeProfile}},
	{"analyze profile from '0b1c4f9c-3a8e-11ef-9c1f-0242ac120002' , 1, 2", Statement{Kind: KindAnalyzeProfile}},
	{"ANALYZE /* c */ PROFILE FROM \"0b1c4f9c\" ,0 ,12;", Statement{Kind: KindAnalyzeProfile}},
	{"ANALYZE PROFILE FROM 'a' -- c\n", Statement{Kind: KindAnalyzeProfile}},
}

var allowDremio = []allowCase{
	{`SELECT * FROM "my-source"."db"."table" WHERE "id" = 1`, sel},
	{`SELECT * FROM src.db.tbl`, sel},
	{`SELECT "col" AS "alias", "a""b" FROM "src"."a b"."t"`, sel},
	{`SELECT "delete", "set", "into", "external_query" FROM t`, sel},
	{`SELECT '张三', "订单" FROM "订单库"."表"`, sel},
	{`SELECT 'a\' AS x`, sel},
	{`SELECT "a\" FROM t`, sel},
	{`SELECT 'a#b', '` + "`" + `', '"' FROM t WHERE x = '#'`, sel},
	{`VALUES (1, 'a'), (2, 'b')`, sel},
	{`values (1)`, sel},
	{`SELECT * FROM (VALUES (1), (2)) AS v(x)`, sel},
	{`SELECT * FROM t AT SNAPSHOT '123'`, sel},
	{`SELECT a[1], ARRAY[1, 2], a || b FROM t`, sel},
	{`SELECT * FROM TABLE(table_history('src.db.t'))`, sel},
	{`SELECT * FROM TABLE(table_snapshot('src.db.t'))`, sel},
	{`SELECT * FROM TABLE(table_manifests('src.db.t'))`, sel},
	{`SELECT * FROM TABLE(table_files('src.db.t'))`, sel},
	{`select * from table ( TABLE_FILES ( 'x' ) ) where 1 = 1`, sel},
	{`SELECT * FROM TABLE("table_history"('x'))`, sel},
	{`SELECT * FROM TABLE(/* c */ table_history -- c` + "\n" + `('x'))`, sel},
	{`SELECT 'table(', 'external_query(' FROM t`, sel},
	{`SHOW SCHEMAS`, show("SCHEMAS")},
	{`SHOW DATABASES`, show("SCHEMAS")},
	{`SHOW TABLES IN src.db`, show("TABLES")},
	{`SHOW TABLES LIKE '%x%'`, show("TABLES")},
	{`SHOW VIEWS`, show("VIEWS")},
	{`SHOW PARTITIONS`, show("PARTITIONS")},
	{`SHOW FILES IN src.db.t`, show("FILES")},
	{`SHOW CREATE TABLE src.db.t`, show("CREATE TABLE")},
	{`DESCRIBE src.db.t`, Statement{Kind: KindDescribe}},
	{`DESC "src"."db"."t"`, Statement{Kind: KindDescribe}},
	{`EXPLAIN PLAN FOR SELECT 1`, explain("PLAN FOR", sel)},
	{`explain plan for select * from "src"."t"`, explain("PLAN FOR", sel)},
	{`EXPLAIN PLAN WITH IMPLEMENTATION FOR WITH c AS (SELECT 1) SELECT * FROM c`, explain("PLAN WITH IMPLEMENTATION FOR", sel)},
	{`EXPLAIN PLAN FOR VALUES (1)`, explain("PLAN FOR", sel)},
	{`EXPLAIN PLAN FOR SELECT 1;`, explain("PLAN FOR", sel)},
}

func TestRejectSQL(t *testing.T) {
	for d, sets := range rejectedCorpora() {
		for _, set := range sets {
			for family, cases := range set {
				t.Run(d.String()+"/"+family, func(t *testing.T) {
					for _, sql := range cases {
						for _, opts := range []Options{{}, {AllowExplainAnalyze: true}} {
							if family == "explain_analyze_default" && opts.AllowExplainAnalyze {
								continue
							}
							st, err := Validate(d, sql, opts)
							if err == nil {
								t.Errorf("%s accepted forbidden SQL %q (opts %+v): %+v", d, sql, opts, st)
								continue
							}
							if !errors.Is(err, ErrRejected) {
								t.Errorf("%s error for %q does not match ErrRejected: %v", d, sql, err)
							}
							if !reflect.DeepEqual(st, Statement{}) {
								t.Errorf("%s returned statement %+v with error for %q", d, st, sql)
							}
						}
					}
				})
			}
		}
	}
}

func TestAllowSQL(t *testing.T) {
	sets := map[Dialect][]allowCase{
		StarRocks: slices.Concat(allowCommon, allowMeasuredCommon, allowStarRocks, allowMeasuredStarRocks),
		Dremio:    slices.Concat(allowCommon, allowMeasuredCommon, allowDremio, allowMeasuredDremio),
	}
	for d, cases := range sets {
		t.Run(d.String(), func(t *testing.T) {
			for _, c := range cases {
				got, err := Validate(d, c.sql, Options{})
				if err != nil {
					t.Errorf("rejected %q: %v", c.sql, err)
					continue
				}
				if !reflect.DeepEqual(got, c.want) {
					t.Errorf("%q: got %+v (target %+v), want %+v (target %+v)", c.sql, got, got.Target, c.want, c.want.Target)
				}
				if got.Kind == KindShow && !slices.Contains(ShowTypes(d), got.ShowType) {
					t.Errorf("%q: show type %q is not listed by ShowTypes(%s)", c.sql, got.ShowType, d)
				}
			}
		})
	}
}

func TestExplainAnalyzeOption(t *testing.T) {
	if (Options{}).AllowExplainAnalyze {
		t.Fatal("EXPLAIN ANALYZE must be disabled by default")
	}
	allowed := map[string]Statement{
		"EXPLAIN ANALYZE SELECT 1":                                      explain("ANALYZE", sel),
		"explain analyze select * from t where id = 1;":                 explain("ANALYZE", sel),
		"EXPLAIN /* c */ ANALYZE\nWITH c AS (SELECT 1) SELECT * FROM c": explain("ANALYZE", sel),
	}
	for sql, want := range allowed {
		if _, err := Validate(StarRocks, sql, Options{}); err == nil {
			t.Errorf("default options accepted %q", sql)
		}
		got, err := Validate(StarRocks, sql, Options{AllowExplainAnalyze: true})
		if err != nil {
			t.Errorf("AllowExplainAnalyze rejected %q: %v", sql, err)
		} else if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %+v, want %+v", sql, got, want)
		}
		if _, err := Validate(Dremio, sql, Options{AllowExplainAnalyze: true}); err == nil {
			t.Errorf("Dremio accepted %q", sql)
		}
	}
	for _, sql := range []string{
		"EXPLAIN ANALYZE INSERT INTO t SELECT 1", "explain analyze insert into t values (1)", "EXPLAIN ANALYZE DELETE FROM t",
		"EXPLAIN ANALYZE UPDATE t SET x = 1", "EXPLAIN ANALYZE SHOW TABLES", "EXPLAIN ANALYZE DESC t", "EXPLAIN ANALYZE (SELECT 1)",
		"EXPLAIN ANALYZE", "EXPLAIN ANALYZE EXPLAIN ANALYZE SELECT 1", "EXPLAIN ANALYZE EXPLAIN SELECT 1",
		"EXPLAIN ANALYZE SELECT 1; DROP TABLE t", "EXPLAIN ANALYZE SELECT sleep(1)", "EXPLAIN ANALYZE SELECT 1 INTO OUTFILE '/tmp/x'",
		"EXPLAIN ANALYZE WITH c AS (SELECT 1) INSERT INTO t SELECT * FROM c", "EXPLAIN ANALYZE ANALYZE PROFILE FROM 'x'",
		"EXPLAIN ANALYZE INSERT INTO FILES('path'='s3://b/x') SELECT 1", "EXPLAIN ANALYZE CREATE TABLE t AS SELECT 1",
		"EXPLAIN ANALYZE /*+ SET_VAR(query_timeout=1) */ SELECT 1", "EXPLAIN ANALYZE VALUES (1)",
	} {
		for _, d := range dialects {
			if _, err := Validate(d, sql, Options{AllowExplainAnalyze: true}); err == nil {
				t.Errorf("%s accepted %q with AllowExplainAnalyze", d, sql)
			}
		}
	}
}

func TestDialectEscapes(t *testing.T) {
	cases := []struct {
		sql               string
		starrocks, dremio bool
	}{
		// A backslash escapes the quote in StarRocks and is an ordinary character in Dremio.
		{`SELECT 'a\'; DROP TABLE t; --'`, true, false},
		{`SELECT "a\"; DROP TABLE t; --"`, true, false},
		{`SELECT 'a\'`, false, true},
		{`SELECT "a\"`, false, true},
		{`SELECT 'a\\'`, true, true},
		{`SELECT 'a\\'; DROP TABLE t; --'`, false, false},
		// Doubled quotes are an escape in both dialects.
		{`SELECT 'a''; DROP TABLE t; --'`, true, true},
		{`SELECT "a""; DROP TABLE t; --"`, true, true},
		// Backquotes are identifiers only in StarRocks, with no backslash escape.
		{"SELECT `a\\`", true, false},
		{"SELECT `a``; DROP TABLE t; --`", true, false},
		{"SELECT `a`; DROP TABLE t; --`", false, false},
		// `#` is rejected in both dialects (StarRocks drops it and parses the rest); `@` and braces exist only in StarRocks.
		{"SELECT 1 # c", false, false},
		{"SELECT '#'", true, true},
		{"SELECT @@version", true, false},
		{"SELECT map{'a': 1}", true, false},
	}
	for _, c := range cases {
		for d, want := range map[Dialect]bool{StarRocks: c.starrocks, Dremio: c.dremio} {
			_, err := Validate(d, c.sql, Options{})
			if (err == nil) != want {
				t.Errorf("%s %q: accepted=%v, want %v (err %v)", d, c.sql, err == nil, want, err)
			}
		}
	}
}

func TestKeywordBoundary(t *testing.T) {
	for _, want := range []string{
		"INSERT", "UPDATE", "DELETE", "MERGE", "CREATE", "DROP", "ALTER", "TRUNCATE", "GRANT", "REVOKE", "SET", "RESET", "KILL",
		"ADMIN", "INSTALL", "UNINSTALL", "LOAD", "EXPORT", "SUBMIT", "CANCEL", "REFRESH", "OPTIMIZE", "VACUUM", "ROLLBACK",
		"COMMIT", "USE", "CALL", "INTO",
	} {
		if !slices.Contains(deniedKeywords, want) {
			t.Errorf("deniedKeywords does not contain %s", want)
		}
	}
	for _, kw := range deniedKeywords {
		for _, d := range dialects {
			quote := "\""
			if d == StarRocks {
				quote = "`"
			}
			for _, sql := range []string{
				"SELECT 1 FROM t WHERE x = 1 " + kw,
				"SELECT 1 FROM t WHERE x = 1 " + strings.ToLower(kw),
				"SELECT 1 FROM t WHERE x = 1 " + strings.ToUpper(kw[:1]) + strings.ToLower(kw[1:]) + " x",
				"SELECT 1 /**/" + kw + "/**/ x",
				"WITH c AS (SELECT 1) " + kw + " x",
				"SELECT 1 FROM t." + kw,
				"SELECT 1;" + kw,
			} {
				if _, err := Validate(d, sql, Options{}); err == nil {
					t.Errorf("%s accepted %q", d, sql)
				}
			}
			for _, sql := range []string{
				"SELECT 1 AS " + quote + kw + quote,
				"SELECT " + quote + strings.ToLower(kw) + quote + " FROM t",
				"SELECT '" + kw + "' FROM t",
				"SELECT " + strings.ToLower(kw) + "_flag, flag_" + kw + ", x" + kw + "y, " + kw + "1 FROM t",
				"SELECT 1 /* " + kw + " */ -- " + kw + "\n",
			} {
				if _, err := Validate(d, sql, Options{}); err != nil {
					t.Errorf("%s rejected %q: %v", d, sql, err)
				}
			}
		}
	}
}

func TestDeniedFunctions(t *testing.T) {
	for _, name := range []string{"files", "sleep", "get_query_profile"} {
		if !slices.Contains(starrocksDeniedFunctions, name) {
			t.Errorf("starrocksDeniedFunctions does not contain %s", name)
		}
	}
	if !slices.Contains(dremioDeniedFunctions, "external_query") {
		t.Error("dremioDeniedFunctions does not contain external_query")
	}
	want := []string{"table_history", "table_snapshot", "table_manifests", "table_files"}
	if !slices.Equal(slices.Sorted(slices.Values(dremioTableFunctions)), slices.Sorted(slices.Values(want))) {
		t.Errorf("dremioTableFunctions = %v, want %v", dremioTableFunctions, want)
	}
	for _, name := range starrocksDeniedFunctions {
		for _, sql := range []string{
			"SELECT " + name + "(1)", "SELECT " + strings.ToUpper(name) + " (1)", "SELECT " + name + "/**/(1)",
			"SELECT `" + name + "`(1)", "SELECT db." + name + "(1)", "SELECT * FROM " + name + "('path'='x')",
		} {
			if _, err := Validate(StarRocks, sql, Options{}); err == nil {
				t.Errorf("StarRocks accepted %q", sql)
			}
		}
		if _, err := Validate(StarRocks, "SELECT "+name+" FROM t", Options{}); err != nil {
			t.Errorf("StarRocks rejected %s used as a column: %v", name, err)
		}
	}
	for _, name := range dremioDeniedFunctions {
		for _, sql := range []string{
			"SELECT " + name + "(1)", "SELECT " + strings.ToUpper(name) + " (1)", "SELECT \"" + name + "\"(1)",
			"SELECT * FROM TABLE(src." + name + "('x'))", "SELECT * FROM TABLE(" + name + "('x'))",
		} {
			if _, err := Validate(Dremio, sql, Options{}); err == nil {
				t.Errorf("Dremio accepted %q", sql)
			}
		}
	}
	for _, name := range dremioTableFunctions {
		if _, err := Validate(Dremio, "SELECT * FROM TABLE("+name+"('x'))", Options{}); err != nil {
			t.Errorf("Dremio rejected TABLE(%s): %v", name, err)
		}
		for _, sql := range []string{
			"SELECT * FROM TABLE(src." + name + "('x'))", "SELECT * FROM TABLE(" + name + ")", "SELECT * FROM TABLE((" + name + "('x')))",
			"SELECT * FROM TABLE(\"" + name + " \"('x'))", "SELECT * FROM TABLE('" + name + "'('x'))",
		} {
			if _, err := Validate(Dremio, sql, Options{}); err == nil {
				t.Errorf("Dremio accepted %q", sql)
			}
		}
	}
}

func TestSQLLength(t *testing.T) {
	if MaxLength != 4000 {
		t.Fatalf("MaxLength = %d, want 4000", MaxLength)
	}
	for _, d := range dialects {
		// The limit counts characters, not bytes.
		for _, fill := range []string{"a", "中", "😀"} {
			prefix, suffix := "SELECT '", "'"
			n := MaxLength - utf8.RuneCountInString(prefix+suffix)
			if _, err := Validate(d, prefix+strings.Repeat(fill, n)+suffix, Options{}); err != nil {
				t.Errorf("%s rejected %d characters of %q: %v", d, MaxLength, fill, err)
			}
			if _, err := Validate(d, prefix+strings.Repeat(fill, n+1)+suffix, Options{}); err == nil {
				t.Errorf("%s accepted %d characters of %q", d, MaxLength+1, fill)
			}
		}
		if _, err := Validate(d, "SELECT 1 -- "+strings.Repeat("x", MaxLength), Options{}); err == nil {
			t.Errorf("%s accepted an oversized comment", d)
		}
		if _, err := Validate(d, "SELECT 1"+strings.Repeat(" ", MaxLength), Options{}); err == nil {
			t.Errorf("%s accepted oversized whitespace", d)
		}
	}
}

func TestErrorShape(t *testing.T) {
	const secret = "s3cr3t-literal"
	for _, d := range dialects {
		for _, sql := range []string{
			"SELECT '" + secret + "'; DROP TABLE t", "SELECT '" + secret + "' INTO OUTFILE '/tmp/x'", "INSERT INTO t VALUES ('" + secret + "')",
			"SELECT '" + secret + "' /*+ x */", "SELECT '" + secret + "\xff'", "SHOW " + secret, "SELECT 1 /* set_var " + secret + " */",
			"SELECT '" + secret, "SELECT 订单 AS " + secret,
		} {
			_, err := Validate(d, sql, Options{})
			if err == nil {
				t.Errorf("%s accepted %q", d, sql)
				continue
			}
			if !errors.Is(err, ErrRejected) {
				t.Errorf("error for %q does not match ErrRejected: %v", sql, err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error echoes input for %q: %v", sql, err)
			}
			var re *RejectError
			if !errors.As(err, &re) || re.Reason == "" {
				t.Errorf("error for %q is not a *RejectError with a reason: %v", sql, err)
			}
		}
	}
	if _, err := Validate(Dialect(0), "SELECT 1", Options{}); err == nil {
		t.Error("unknown dialect accepted")
	}
	if _, err := Validate(Dialect(99), "SELECT 1", Options{}); err == nil {
		t.Error("unknown dialect accepted")
	}
}

func TestShowTypes(t *testing.T) {
	for d, want := range map[Dialect][]string{
		StarRocks: {"TABLES", "DATABASES", "CATALOGS", "COLUMNS", "CREATE TABLE", "PARTITIONS", "TABLET"},
		Dremio:    {"SCHEMAS", "TABLES", "VIEWS", "PARTITIONS", "FILES", "CREATE TABLE", "FUNCTIONS"},
	} {
		got := ShowTypes(d)
		for _, w := range want {
			if !slices.Contains(got, w) {
				t.Errorf("ShowTypes(%s) = %v, missing %s", d, got, w)
			}
		}
		if len(got) == 0 {
			t.Fatalf("ShowTypes(%s) is empty", d)
		}
		if d == Dremio && slices.Contains(got, "CREATE VIEW") {
			t.Errorf("ShowTypes(Dremio) lists CREATE VIEW, which Dremio 24.1 does not support")
		}
		got[0] = "MUTATED"
		if ShowTypes(d)[0] == "MUTATED" {
			t.Errorf("ShowTypes(%s) returns shared storage", d)
		}
	}
	if ShowTypes(Dialect(0)) != nil {
		t.Error("ShowTypes of an unknown dialect is not nil")
	}
}

func TestLexTokens(t *testing.T) {
	toks, err := lex(Dremio, "SELECT 'a''b' /* c */ \"d\"\"e\" -- f\n.")
	if err != nil {
		t.Fatal(err)
	}
	want := []token{{tWord, "SELECT"}, {tString, "a''b"}, {tQuoted, `d"e`}, {tPunct, "."}}
	if !reflect.DeepEqual(toks, want) {
		t.Errorf("tokens = %+v, want %+v", toks, want)
	}
	toks, err = lex(StarRocks, "select `a``b`, 'x\\'y' -- c\n1")
	if err != nil {
		t.Fatal(err)
	}
	want = []token{{tWord, "SELECT"}, {tQuoted, "a`b"}, {tPunct, ","}, {tString, `x\'y`}, {tNumber, "1"}}
	if !reflect.DeepEqual(toks, want) {
		t.Errorf("tokens = %+v, want %+v", toks, want)
	}
}

func fuzzSeeds(f *testing.F) {
	for _, sets := range rejectedCorpora() {
		for _, set := range sets {
			for _, cases := range set {
				for _, sql := range cases {
					f.Add(sql)
				}
			}
		}
	}
	for _, cases := range [][]allowCase{allowCommon, allowMeasuredCommon, allowStarRocks, allowMeasuredStarRocks, allowDremio, allowMeasuredDremio} {
		for _, c := range cases {
			f.Add(c.sql)
		}
	}
	for _, sql := range []string{
		"EXPLAIN ANALYZE SELECT 1", "SELECT 'a\\'", "SELECT 1 --\n", "SELECT 1 #", "SELECT 1 # ; INSERT INTO t VALUES (1)", "SELECT 1 # + 1",
		"SELECT # 1", "SELECT '#', `#`, \"#\"", "SELECT 1 /* # */ -- #\n", "SELECT `a``b`", "SELECT /*/ 1 */",
	} {
		f.Add(sql)
	}
}

func containsExplainAnalyze(s Statement) bool {
	return s.Kind == KindExplain && (s.Variant == "ANALYZE" || (s.Target != nil && containsExplainAnalyze(*s.Target)))
}

func FuzzValidate(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, sql string) {
		for _, d := range dialects {
			var accepted [2]bool
			var statements [2]Statement
			for i, opts := range []Options{{}, {AllowExplainAnalyze: true}} {
				st, err := Validate(d, sql, opts)
				if err != nil {
					if !errors.Is(err, ErrRejected) {
						t.Fatalf("%s: error does not match ErrRejected: %v", d, err)
					}
					continue
				}
				accepted[i], statements[i] = true, st
				if again, err := Validate(d, sql, opts); err != nil || !reflect.DeepEqual(st, again) {
					t.Fatalf("%s: validation is not deterministic", d)
				}
				switch st.Kind {
				case KindSelect, KindShow, KindDescribe, KindExplain, KindAnalyzeProfile:
				default:
					t.Fatalf("%s: unexpected kind %q", d, st.Kind)
				}
				if !opts.AllowExplainAnalyze && containsExplainAnalyze(st) {
					t.Fatalf("%s: EXPLAIN ANALYZE accepted by default", d)
				}
				// A suffix on the same line is accepted only when it is swallowed by a line comment,
				// which adds no tokens.
				if _, err := Validate(d, sql+"; DROP TABLE t", opts); err == nil {
					a, errA := lex(d, sql)
					b, errB := lex(d, sql+"; DROP TABLE t")
					if errA != nil || errB != nil || !reflect.DeepEqual(a, b) {
						t.Fatalf("%s: accepted appended statement to %q", d, sql)
					}
				}
				// A newline ends any line comment, so appended statements are always visible.
				for _, tail := range []string{
					"\n; DROP TABLE t", "\nDROP TABLE t", "\r\nINSERT INTO t VALUES (1)", "\n;\nDELETE FROM t", "\r; TRUNCATE TABLE t",
				} {
					if _, err := Validate(d, sql+tail, opts); err == nil {
						t.Fatalf("%s: accepted %q appended to %q", d, tail, sql)
					}
				}
			}
			if accepted[0] && (!accepted[1] || !reflect.DeepEqual(statements[0], statements[1])) {
				t.Fatalf("%s: AllowExplainAnalyze changed the result for %q", d, sql)
			}
			if !accepted[0] && accepted[1] && !containsExplainAnalyze(statements[1]) {
				t.Fatalf("%s: AllowExplainAnalyze widened the default for %q", d, sql)
			}
		}
	})
}

func ExampleValidate() {
	st, err := Validate(StarRocks, "EXPLAIN VERBOSE SELECT * FROM catalog.db.t", Options{})
	fmt.Println(st.Kind, st.Variant, st.Target.Kind, err)
	_, err = Validate(StarRocks, "SELECT 1; DROP TABLE t", Options{})
	fmt.Println(errors.Is(err, ErrRejected))
	// Output:
	// EXPLAIN VERBOSE SELECT <nil>
	// true
}
