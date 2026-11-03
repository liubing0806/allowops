package sqlguard

import "strings"

// Attack corpora. Each family has at least two spellings, including comments,
// case and whitespace. "common" entries must be rejected under both dialects;
// the dialect maps hold spellings whose meaning depends on the dialect.
var attacksCommon = map[string][]string{
	"writes": {
		"INSERT INTO t VALUES (1)", "insert/**/into t select 1", "UPDATE t SET x = 1", "uPdAtE t\nSET x=1",
		"DELETE FROM t", "delete from t where 1=1", "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
		"REPLACE INTO t VALUES (1)",
	},
	"ddl": {
		"CREATE TABLE t (x INT)", "create/**/table t as select 1", "DROP TABLE t", "dRoP\nDATABASE d",
		"ALTER TABLE t ADD COLUMN y INT", "alter table t drop column y", "TRUNCATE TABLE t", "truncate t",
		"CREATE VIEW v AS SELECT 1", "CREATE OR REPLACE VIEW v AS SELECT 1",
	},
	"admin": {
		"GRANT ALL ON t TO u", "grant select on t to u", "REVOKE ALL ON t FROM u", "revoke select on t from u",
		"SET x = 1", "set/**/session x = 1", "RESET x", "reset all",
		"KILL 1", "kill query 'abc'", "ADMIN SET FRONTEND CONFIG ('x'='1')", "admin show frontend config",
		"INSTALL PLUGIN FROM 'x'", "UNINSTALL PLUGIN x", "LOAD LABEL l (DATA INFILE('x') INTO TABLE t)",
		"EXPORT TABLE t TO 'x'", "SUBMIT TASK AS SELECT 1", "CANCEL LOAD", "REFRESH MATERIALIZED VIEW m",
		"OPTIMIZE TABLE t", "VACUUM TABLE t", "ROLLBACK", "COMMIT", "USE db", "use `db`", "CALL p()",
		"ANALYZE TABLE t", "analyze\nTABLE t UPDATE HISTOGRAM ON c", "ANALYZE FULL TABLE t",
	},
	"nested_writes": {
		"WITH c AS (SELECT 1) INSERT INTO t SELECT * FROM c",
		"WITH c AS (SELECT 1) DELETE FROM t WHERE x IN (SELECT * FROM c)",
		"WITH c AS (SELECT 1) UPDATE t SET x = 1",
		"SELECT 1 UNION SELECT 2 INTO x", "(SELECT 1) DROP TABLE t",
		"SELECT * FROM t WHERE x = 1 -- ok\n DELETE FROM t",
	},
	"multiple": {
		"SELECT 1; SELECT 2", "sElEcT 1; /* separator */\nSHOW TABLES", "SELECT 1;;", ";SELECT 1", ";",
		"SELECT 1; DROP TABLE t", "SELECT 1;\n-- comment\nDROP TABLE t", "SHOW TABLES; SHOW TABLES",
		"SELECT ';' ; DELETE FROM t", "SELECT 1 /* x */ ; /* y */ DROP TABLE t",
	},
	"comment_hidden": {
		"SELECT 1 /* ; */ ; DROP TABLE t", "SELECT 1 -- x\n; DROP TABLE t", "SELECT 1 -- x\r; DROP TABLE t",
		"SELECT 1 -- x\rDROP TABLE t", "SELECT 1 /* x */ DROP TABLE t", "SELECT /* a */ 1 /* b */ ; /* c */ DELETE FROM t",
		"SELECT 1 /**/;/**/DROP/**/TABLE/**/t",
	},
	"unclosed": {
		"SELECT 'abc", "SELECT 'abc''", "SELECT 1 /* abc", "SELECT 1 /* abc *", "SELECT 1 /*", "/*",
		"SELECT 'a' || 'b", "SELECT \"abc", "SELECT \"a\"\"", "SHOW TABLES LIKE 'x",
	},
	"hint_and_params": {
		"SELECT /*+ SET_VAR(query_timeout=1) */ 1", "select /*+ BROADCAST(t) */ * from t", "SELECT 1 /*+ x */",
		"SELECT /* set_var(query_timeout=1) */ 1", "SELECT /* SET_VAR(a=1) */ 1", "SELECT 1 -- Set_Var(a=1)\n",
		"/*+ x */ SELECT 1", "/* x set_var */ SELECT 1",
		"SELECT /*! SLEEP(1) */ 1", "SELECT /*!50000 1 */", "/*! SELECT 1 */", "SELECT /*M! x */ 1", "SELECT /*m! x */ 1",
	},
	"hash": {
		// StarRocks drops "#" and parses what follows, so it is not a comment (measured on 3.3).
		"SELECT 1 # ; INSERT INTO t VALUES (1)", "SELECT 1 # + 1", "SELECT # 1", "SELECT 1 #", "SELECT 1 #2", "SELECT 1 # 2",
		"SELECT 1 #\n+ 1", "SELECT 1 # x\nDROP TABLE t", "SELECT 1 # x\r; DROP TABLE t", "SELECT 1 #set_var(a=1)\n",
		"SELECT 1 # x\n; SELECT 2", "#SELECT 1", "SELECT 1 /* a */ # b", "SELECT a#b FROM t", "SELECT 1\n#\nFROM t",
		"SELECT 1 -- ok\n# x", "SELECT 1 # -- x", "SELECT 1 # /* x */ + 1",
	},
	"nested_comment": {
		"SELECT /* a /* b */ c */ 1", "SELECT 1 /* a /* b */", "SELECT /* /*/ 1", "/* /* */ */ SELECT 1",
	},
	"dash_dash": {
		"SELECT 1--1", "SELECT 1 --x", "SELECT 1 --", "SELECT 1 --;DROP TABLE t", "SELECT 1 --\x01",
	},
	"assignment_and_params": {
		"SELECT (a := 1)", "select (a/**/:=2)", "SELECT ?", "SELECT * FROM t WHERE a = ?", "SELECT 1 WHERE x IN (?, ?)",
	},
	"unicode_space": {
		"SELECT\u00a01", "SELECT\u30001", "SELECT\u20031", "SELECT\u20091", "SELECT\u202f1", "SELECT\u180e1",
		"SELECT\u200b1", "\ufeffSELECT 1", "SELECT 1\u00a0", "SELECT 1;\u3000DROP TABLE t", "SELECT\u20281", "SELECT\u20291",
		"SELECT\u00851", "SELECT 1 FROM\u00a0t", "SELECT 1\u3000-- x\n",
	},
	"non_ascii_outside_quotes": {
		"SELECT 订单 FROM t", "SELECT * FROM 订单表", "SELECT \u00e9 FROM t", "SELECT 1 AS \uff41", "SELECT \uff24\uff32\uff2f\uff30",
		"SELECT 1 FROM t WHERE x \uff1d 1", "SELECT \u017fleep(1)", "SELECT 1 \u2212 1", "SELECT \u2018a\u2019",
	},
	"control_chars": {
		"SELECT 1\x00", "SELECT\x001", "SELECT 1\x01", "SELECT\x0b1", "SELECT\x0c1", "SELECT 1\x1b[0m", "SELECT 1\x7f",
		"SELECT 1\u0085", "SELECT 1 -- x\u2028DROP TABLE t", "SELECT 1 -- x\u2029DROP TABLE t", "SELECT 1 -- x\u0085DROP TABLE t", "SELECT '\u2028'", "SELECT 1 /* \u2029 */", "SELECT \"\u2028\" FROM t", "SELECT '\x00'", "SELECT '\x1f'", "SELECT /* \x00 */ 1", "SELECT 1 -- \x00\n",
	},
	"invalid_utf8": {
		"SELECT '\xff'", "SELECT 1 \xc3", "SELECT \xe4\xb8 1",
	},
	"empty": {
		"", " ", "\n\t", "-- only a comment", "/* only a comment */", "-- x\n",
	},
	"punctuation": {
		"SELECT 1 \\ 2", "SELECT $1", "SELECT a$b", "SELECT 1 WHERE x = \\N",
	},
	"not_a_statement": {
		"foo", "SELECT", "SHOW", "EXPLAIN", "DESC", "DESCRIBE", "WITH", "123", "(", "()", "( )", "'SELECT 1'", "`SELECT` 1",
		"\"SELECT\" 1", "BEGIN", "START TRANSACTION", "FLUSH TABLES", "LOCK TABLES t READ", "HANDLER t OPEN",
		"PREPARE s FROM 'select 1'", "EXECUTE s", "DEALLOCATE PREPARE s",
	},
	"explain_target": {
		"EXPLAIN INSERT INTO t VALUES (1)", "explain delete from t", "EXPLAIN SHOW TABLES", "EXPLAIN DESC t",
		"EXPLAIN EXPLAIN SELECT 1", "EXPLAIN CREATE TABLE t (x INT)", "EXPLAIN SELECT 1; DROP TABLE t",
		"EXPLAIN SELECT 1 INTO OUTFILE '/tmp/x'", "EXPLAIN",
	},
	"outfile": {
		"SELECT 1 INTO OUTFILE '/tmp/x'", "select 1 into/**/OuTfIlE '/tmp/x'", "SELECT 1 INTO DUMPFILE '/tmp/x'",
		"select 1 INTO\nDuMpFiLe '/tmp/x'", "SELECT * FROM t INTO OUTFILE '/tmp/x' FIELDS TERMINATED BY ','",
		"SELECT 1 INTO @x", "SELECT 1 into @X, @y", "SELECT a INTO b FROM t", "SELECT * INTO new_table FROM t",
		"WITH c AS (SELECT 1) SELECT * FROM c INTO OUTFILE '/tmp/x'",
	},
	"long_input": {
		"SELECT '" + strings.Repeat("a", 4000) + "'", "SELECT " + strings.Repeat("1,", 2000) + "1", "SELECT 1 /* " + strings.Repeat("x", 4000) + " */",
		"SELECT '" + strings.Repeat("中", 4000) + "'", "SELECT 1 -- " + strings.Repeat("y", 4000),
	},
}

var attacksStarRocks = map[string][]string{
	"dangerous_functions": {
		"SELECT SLEEP(1)", "select (select SlEeP(1))", "SELECT sleep (1)", "SELECT sleep\n(1)", "SELECT sleep/**/(1)",
		"SELECT sleep -- c\n(1)", "SELECT db.sleep(1)", "SELECT `sleep`(1)", "SELECT `SLEEP` /**/ (1)", "SELECT `db`.`sleep`(1)",
		"SELECT * FROM FILES(\"path\"=\"s3://b/x\", \"format\"=\"parquet\")", "select * from files ('path'='s3://b/x')",
		"SELECT * FROM `files`('path'='x')", "SELECT * FROM t JOIN files/**/('path'='x') f ON 1=1",
		"WITH c AS (SELECT SLEEP(1)) SELECT * FROM c", "SELECT 1 UNION SELECT sleep(1)", "DESC FILES('path'='x')",
		"SELECT `sleep ` (1)", "SELECT `ſleep`(1)",
	},
	"unclosed": {
		"SELECT `abc", "SELECT `a``", "SELECT 'a\\'", "SELECT 'a\\", "SELECT \"a\\\"", "SELECT 'abc\\'; DROP TABLE t",
	},
	"analyze_profile": {
		"ANALYZE PROFILE", "ANALYZE PROFILE FROM", "ANALYZE PROFILE FROM x", "ANALYZE PROFILE FROM 1",
		"ANALYZE PROFILE FROM 'a' DROP TABLE t", "ANALYZE PROFILE FROM 'a', x", "ANALYZE PROFILE FROM 'a',",
		"ANALYZE PROFILE FROM 'a', 1,", "ANALYZE PROFILE FROM 'a', 1 2", "ANALYZE PROFILE FROM 'a'; DROP TABLE t",
		"ANALYZE PROFILE FROM 'a', 1; DROP TABLE t", "ANALYZE PROFILE FROM 'a', -1", "ANALYZE PROFILE FROM 'a', 1.5",
		"ANALYZE PROFILE FROM 'a', 1e3", "ANALYZE PROFILE FROM 'a', (1)", "ANALYZE PROFILE FROM 'a' WHERE 1=1",
		"ANALYZE PROFILE 'a'", "ANALYZE PROFILE FROM `a`", "ANALYZE PROFILES FROM 'a'", "ANALYZE PROFILE FROM 'a' /*+ x */",
	},
	"show": {
		"SHOW PROC '/frontends'", "SHOW PROC", "SHOW GRANTS", "SHOW LOAD", "SHOW EXPORT", "SHOW ROUTINE LOAD",
		"SHOW CREATE CATALOG c", "SHOW CREATE ROUTINE LOAD r", "SHOW", "SHOW 1", "SHOW 'TABLES'", "SHOW `TABLES`",
		"SHOW FULL", "SHOW TABLES; DROP TABLE t", "SHOW TABLES FROM d WHERE x = 1 INTO OUTFILE 'x'",
		"SHOW TABLES LIKE (SELECT sleep(1))", "SHOW CREATE TABLE t; SHOW CREATE TABLE u", "SHOW FILES IN x",
		"SHOW CREATE TABLE t SET x = 1", "SHOW TABLES CREATE",
	},
	"describe": {
		"DESC SELECT 1", "DESCRIBE WITH c AS (SELECT 1) SELECT * FROM c", "DESC (SELECT 1)", "DESC", "DESC 'x'",
		"DESC t; DROP TABLE t", "DESC VALUES (1)",
	},
	"explain_analyze_default": {
		"EXPLAIN ANALYZE SELECT 1", "explain analyze select * from t", "EXPLAIN\nANALYZE\n/**/SELECT 1",
		"EXPLAIN ANALYZE WITH c AS (SELECT 1) SELECT * FROM c", "EXPLAIN ANALYZE INSERT INTO t SELECT 1",
		"EXPLAIN ANALYZE DELETE FROM t",
	},
	"explain_variants": {
		"EXPLAIN LOGICAL", "EXPLAIN VERBOSE", "EXPLAIN COSTS", "EXPLAIN LOGICAL INSERT INTO t SELECT 1",
		"EXPLAIN VERBOSE DELETE FROM t", "EXPLAIN COSTS COSTS SELECT 1", "EXPLAIN LOGICAL VERBOSE SELECT 1",
		"EXPLAIN PLAN FOR SELECT 1", "EXPLAIN FORMAT=JSON SELECT 1", "EXPLAIN SCHEDULER SELECT 1",
		"EXPLAIN VERBOSE ANALYZE SELECT 1",
	},
	"braces_and_backslash": {
		"SELECT 1 \\", "SELECT \\1", "SELECT @@x := 1", "SELECT @x := 1", "SELECT (@x/**/:= 2)",
	},
	"values": {
		"VALUES (1)", "values (1), (2)",
	},
}

var attacksDremio = map[string][]string{
	"dangerous_functions": {
		"SELECT * FROM TABLE(src.external_query('select 1'))", "SELECT * FROM TABLE(src.EXTERNAL_QUERY('select 1'))",
		"select * from table ( src . external_query ( 'select 1' ) )", "SELECT external_query('x')",
		"SELECT * FROM TABLE(\"src\".\"external_query\"('select 1'))", "SELECT * FROM TABLE(src.external_query /**/ ('x'))",
		"SELECT * FROM TABLE(unknown_fn('x'))", "SELECT * FROM TABLE(src.table_history('t'))", "SELECT * FROM TABLE(table_history)",
		"SELECT * FROM TABLE(\"ſ\"('x'))", "SELECT * FROM TABLE('table_history'('x'))", "SELECT * FROM TABLE()", "SELECT * FROM TABLE(",
		"SELECT * FROM TABLE((table_history('t')))", "SELECT * FROM TABLE(table_history('t'), external_query('x'))",
		"SELECT * FROM TABLE(table_history(external_query('x')))", "SELECT * FROM t, TABLE(external_query('x'))",
		"SELECT * FROM TABLE(table_history ('t')) JOIN TABLE(other('t')) ON 1=1", "WITH c AS (SELECT external_query('x')) SELECT * FROM c",
		"SELECT \"external_query\"('x')", "SELECT \"EXTERNAL_QUERY\" /**/ ('x')", "SELECT * FROM TABLE(\"table_history \"('t'))",
	},
	"hash_and_backtick": {
		"SELECT 1 # x", "SELECT 1 # x\nDROP TABLE t", "SELECT 1 #", "SELECT `a` FROM t", "SELECT 1 FROM `t`", "SELECT `",
		"SELECT * FROM t WHERE a = 1 #\n; DROP TABLE t",
	},
	"braces_and_at": {
		"SELECT {fn now()}", "SELECT {d '2020-01-01'}", "SELECT @x", "SELECT @@version", "SELECT 1 }",
	},
	"analyze": {
		"ANALYZE PROFILE FROM 'a'", "ANALYZE TABLE t", "EXPLAIN ANALYZE SELECT 1", "EXPLAIN ANALYZE INSERT INTO t SELECT 1",
	},
	"show": {
		"SHOW PROC", "SHOW GRANTS", "SHOW COLUMNS FROM t", "SHOW PROCESSLIST", "SHOW VARIABLES", "SHOW",
		"SHOW TABLES; DROP TABLE t", "SHOW CREATE TABLE t; SHOW TABLES", "SHOW TABLES CREATE", "SHOW TABLES INTO x",
		"SHOW FILES IN x SET y",
	},
	"describe": {
		"DESC SELECT 1", "DESCRIBE WITH c AS (SELECT 1) SELECT * FROM c", "DESC", "DESC VALUES (1)", "DESC t; DROP TABLE t",
	},
	"explain_variants": {
		"EXPLAIN SELECT 1", "EXPLAIN PLAN", "EXPLAIN PLAN FOR", "EXPLAIN PLAN FOR INSERT INTO t SELECT 1",
		"EXPLAIN PLAN WITH IMPLEMENTATION FOR DELETE FROM t", "EXPLAIN PLAN WITH IMPLEMENTATION SELECT 1",
		"EXPLAIN PLAN WITHOUT IMPLEMENTATION FOR SELECT 1", "EXPLAIN PLAN INCLUDING ALL ATTRIBUTES FOR SELECT 1",
		"EXPLAIN PLAN WITH TYPE FOR SELECT 1", "EXPLAIN LOGICAL SELECT 1", "EXPLAIN VERBOSE SELECT 1",
		"EXPLAIN PLAN FOR SHOW TABLES", "EXPLAIN PLAN FOR SELECT 1; DROP TABLE t", "EXPLAIN PLAN FOR EXPLAIN PLAN FOR SELECT 1",
		"EXPLAIN PLAN FOR SELECT 1 INTO x", "EXPLAIN PLAN FOR REFRESH REFLECTION r",
	},
	"dremio_ddl": {
		"CREATE VDS v AS SELECT 1", "ALTER TABLE t REFRESH METADATA", "ALTER SESSION SET x = 1", "ALTER SYSTEM SET x = 1",
		"COPY INTO t FROM '@s'", "CREATE TABLE t AS SELECT 1", "ALTER TABLE t DELETE FILES", "OPTIMIZE TABLE t REWRITE DATA",
		"VACUUM TABLE t EXPIRE SNAPSHOTS", "ROLLBACK TABLE t TO SNAPSHOT '1'", "KILL JOB 'x'",
		"ALTER PDS p REFRESH METADATA", "DROP VIEW v", "CREATE ROLE r", "USE src",
	},
	"dash_variants": {
		"SELECT 1--1", "SELECT --x\n1",
	},
}
