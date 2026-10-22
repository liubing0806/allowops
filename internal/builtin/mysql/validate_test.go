package mysql

import (
	"strings"
	"testing"
)

// Each family has at least two spellings, including comments, case and whitespace.
var attacks = map[string][]string{
	"multiple":          {"SELECT 1; SELECT 2", "sElEcT 1; /* separator */\nSHOW TABLES"},
	"outfile":           {"SELECT 1 INTO OUTFILE '/tmp/x'", "select 1 into/**/OuTfIlE '/tmp/x'"},
	"dumpfile":          {"SELECT 1 INTO DUMPFILE '/tmp/x'", "select 1 INTO\nDuMpFiLe '/tmp/x'"},
	"load_file":         {"SELECT LOAD_FILE('/etc/passwd')", "select LoAd_FiLe/**/('/etc/passwd')"},
	"sleep":             {"SELECT SLEEP(1)", "select (select SlEeP(1))"},
	"benchmark":         {"SELECT BENCHMARK(100,1)", "select BeNcHmArK\n(100,1)"},
	"get_lock":          {"SELECT GET_LOCK('x',1)", "select GeT_LoCk/**/('x', 1)"},
	"other_locks":       {"SELECT RELEASE_LOCK('x')", "select release_all_locks()", "SELECT IS_FREE_LOCK('x')", "SELECT IS_USED_LOCK('x')"},
	"for_update":        {"SELECT * FROM t FOR UPDATE", "select * from t for/**/UpDaTe"},
	"share_lock":        {"SELECT * FROM t LOCK IN SHARE MODE", "select * from t lock\nin/**/share mode", "SELECT * FROM t FOR SHARE"},
	"assignment":        {"SELECT @x := 1", "select (@X/**/:= 2)", "SELECT 1 INTO @x", "SELECT 1 into @X, @y"},
	"set":               {"SET @x=1", "sEt/**/SESSION sql_mode=''"},
	"call":              {"CALL p()", "cAlL\n`p`()"},
	"handler":           {"HANDLER t OPEN", "hAnDlEr/**/t READ FIRST"},
	"lock_tables":       {"LOCK TABLES t READ", "LoCk/**/TABLES t WRITE"},
	"version_comment":   {"SELECT /*!50000 SLEEP(1) */ 1", "/*! SELECT 1 */", "select 1 /*!80000 into outfile '/tmp/x' */"},
	"other_comments":    {"SELECT /*M! SLEEP(1) */ 1", "SELECT /*+ SET_VAR(max_execution_time=0) */ 1"},
	"explain":           {"EXPLAIN ANALYZE SELECT 1", "explain delete from t", "EXPLAIN SELECT SLEEP(1)", "EXPLAIN SELECT * FROM t FOR UPDATE"},
	"unknown_functions": {"SELECT evil()", "SELECT db.abs(1)", "SELECT `sleep`(1)", "SELECT sys.sys_exec('id')", "SELECT `abs`/**/(1)", "SELECT `abs`\v(1)"},
	"writes":            {"UPDATE t SET x=1", "DELETE FROM t", "INSERT INTO t VALUES(1)", "CREATE TABLE t(x INT)"},
	"nested":            {"WITH c AS (SELECT SLEEP(1)) SELECT * FROM c", "SELECT 1 UNION SELECT LOAD_FILE('/etc/passwd')"},
	"invalid":           {"", "SELECT", "SELECT 'unterminated", "SELECT 1\x00", "SELECT ?", "SELECT 1 PROCEDURE ANALYSE()"},
}

func TestRejectSQL(t *testing.T) {
	for family, cases := range attacks {
		t.Run(family, func(t *testing.T) {
			for _, sql := range cases {
				if err := validateSQL(sql); err == nil {
					t.Errorf("accepted forbidden SQL %q", sql)
				}
			}
		})
	}
}

func TestAllowSQL(t *testing.T) {
	for _, sql := range []string{
		"SELECT 1", "sElEcT /* ordinary */ 1; -- trailing\n", "SELECT '; SLEEP(1)' AS `FOR UPDATE`",
		"SELECT * FROM t WHERE id=1", "SELECT COUNT(*), SUM(x), AVG(x), MIN(x), MAX(x) FROM t",
		"WITH c AS (SELECT 1 AS x) SELECT * FROM c", "SELECT 1 UNION ALL SELECT 2",
		"SHOW TABLES", "show full columns from t", "SHOW CREATE TABLE t", "SHOW VARIABLES LIKE 'version%'",
		"DESC t", "describe `t`", "EXPLAIN SELECT * FROM t", "EXPLAIN FORMAT=JSON SELECT 1",
		"SELECT COALESCE(NULL, 1), CONCAT('a', 'b'), NOW(), DATABASE()",
		"SELECT ROW_NUMBER() OVER (ORDER BY x) FROM t", "SELECT @@version, @x",
	} {
		if err := validateSQL(sql); err != nil {
			t.Errorf("rejected %q: %v", sql, err)
		}
	}
}

func TestSQLLength(t *testing.T) {
	if err := validateSQL("SELECT '" + strings.Repeat("a", 4000) + "'"); err == nil {
		t.Fatal("accepted oversized SQL")
	}
}

func FuzzValidateSQL(f *testing.F) {
	f.Add("SELECT 1")
	f.Add(`SELECT 'a\'b'`)
	f.Add("SELECT * FROM fixture.items JOIN private.items USING (id)")
	f.Add("SHOW COLUMNS FROM private.items IN fixture")
	for _, cases := range attacks {
		for _, sql := range cases {
			f.Add(sql)
		}
	}
	f.Fuzz(func(t *testing.T, sql string) {
		err := validateSQL(sql)
		if err == nil {
			if validateSQL(sql) != nil {
				t.Fatal("validation is not deterministic")
			}
			// End a possible trailing line comment before adding a statement.
			if validateSQL(sql+"\n; DELETE FROM t") == nil {
				t.Fatal("accepted appended write")
			}
			for _, cfg := range []Config{
				{StatementTypes: []string{"SELECT"}},
				{StatementTypes: []string{"SHOW"}, ShowTypes: []string{"TABLES"}},
				{StatementTypes: []string{"DESCRIBE"}},
				{StatementTypes: []string{"EXPLAIN", "SELECT"}},
				{Databases: []string{"fixture"}},
				{Databases: []string{"fixture"}, ShowTypes: []string{"DATABASES", "PROCESSLIST", "VARIABLES", "STATUS"}},
			} {
				if validateSQLConfig(sql, cfg) == nil && validateSQLConfig(sql+"\n; DELETE FROM t", cfg) == nil {
					t.Fatal("restricted validation accepted appended write")
				}
			}
		} else if validateSQLConfig(sql, Config{StatementTypes: []string{"SELECT", "SHOW", "DESCRIBE", "EXPLAIN"}}) == nil {
			t.Fatal("restricted validation widened the default")
		}
	})
}
