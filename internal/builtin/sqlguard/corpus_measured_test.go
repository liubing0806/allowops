package sqlguard

// Statements taken from measurements of StarRocks 3.3 and Dremio 24.1 (the
// lexical rules, write paths and side effects that the guard has to agree
// with). Each rejected statement is either executed by the server or hides
// something from the guard; each accepted statement is read by the server the
// same way the guard reads it.

var attacksMeasuredCommon = map[string][]string{
	// Calcite-based lexers treat "//" as a line comment. A quote after it is
	// invisible to the server but opens a string for the guard.
	"double_slash": {
		"SELECT 1 // x", "SELECT 1 //", "SELECT 4 // 2", "SELECT 1 /// x", "SELECT 1 /* x */ // y",
		"SELECT 1 // '\n FROM TABLE(src.external_query('select 1')) -- '",
		"SELECT 1 // '\n FROM files('path'='x') -- '",
		"SELECT 1 // \"\n, sleep(1) -- \"",
		"//\nSELECT 1",
	},
	// Dremio rewrites /* set_var.x='v' */ into a StarRocks SET_VAR hint.
	"set_var_dotted": {
		"/* set_var.pipeline_dop='2',set_var.enable_profile='true' */ SELECT count(*) AS c FROM src.db.fact_orders WHERE store_id = 8",
		"/* set_var.pipeline_dop='3' */ /* set_var.enable_profile='true' */ SELECT 1",
		"SELECT /* set_var.pipeline_dop='4' */ count(*) FROM t",
		"SELECT /*+ SET_VAR(pipeline_dop=5) */ count(*) FROM t",
		"SELECT 1 -- set_var.pipeline_dop='2'\n",
		"EXPLAIN /* set_var.x='1' */ SELECT 1",
		"SELECT 1 /* SET_VAR.query_timeout='1' */",
	},
	"multiple_measured": {
		"SELECT 1; INSERT INTO t VALUES (11, 'multi-1')",
		"SELECT 1; SET query_timeout=1; SELECT sleep(3)",
		"SELECT 1 -- x\n; INSERT INTO t VALUES (13, 'dash-comment')",
		"SELECT 1;;",
	},
}

var attacksMeasuredStarRocks = map[string][]string{
	// StarRocks reads both '' and \ as escapes, in single and double quotes.
	"backslash_strings": {
		`SELECT 'a\\'; INSERT INTO t VALUES (14, 'bs-escape'); --'`,
		`SELECT "a\\"; INSERT INTO t VALUES (14, "bs-escape"); --"`,
		`SELECT 'a\\' ; DROP TABLE t -- '`,
		`SELECT 'a''; DROP TABLE t; --'; DROP TABLE t`,
		`SELECT 'a\'' ; DROP TABLE t -- '`,
	},
	"measured_comments": {
		"SELECT 1 /*! + 1 */", "SELECT 1 /*!50000 + 1 */", "SELECT /*! 1 */ 2", "SELECT 1 /*+ x */ + 1",
		"SELECT 1 /* a /* b */ + 1 */", "SELECT 1 /* a /* b */ + 1", "SELECT 1--1", "SELECT 1 --1", "SELECT 1 --", "SELECT 1 /* unterminated",
		"SELECT 'unterminated", "SELECT `unterminated",
		"SELECT 1 #2", "SELECT 1 # 2", "SELECT 1 #", "SELECT # 1", "SELECT 1 # + 1", "SELECT 1 #\n+ 1",
		"SELECT 1 # ; INSERT INTO t VALUES (12, 'hash-comment')",
	},
	// Statements the server executes for a SELECT-only account.
	"measured_writes": {
		"SELECT 1 INTO OUTFILE \"file:///tmp/x\"", "SELECT * FROM t INTO OUTFILE \"file:///tmp/x\" FORMAT AS CSV",
		"CREATE TEMPORARY TABLE demo_dw.t (id INT)", "SET PASSWORD = PASSWORD('x')", "SET PASSWORD FOR u = PASSWORD('x')",
		"SET CATALOG default_catalog", "USE demo_dw", "KILL QUERY 1", "KILL CONNECTION 1", "KILL 1",
		"ADMIN SET FRONTEND CONFIG (\"profile_info_reserved_num\" = \"500\")", "ADMIN SET REPLICA STATUS PROPERTIES(\"tablet_id\"=\"1\")",
		"SET GLOBAL query_timeout = 300", "SET sql_mode='NO_BACKSLASH_ESCAPES'", "SET enable_profile=true", "SET query_timeout=1",
		"EXPORT TABLE t TO \"file:///x\"", "DROP VIEW IF EXISTS v", "ALTER SYSTEM ADD BACKEND \"h:9050\"", "INSTALL PLUGIN FROM \"x\"",
		"CREATE USER x IDENTIFIED BY \"p\"", "GRANT SELECT ON ALL TABLES IN DATABASE d TO USER u", "CREATE DATABASE d",
		"UPDATE t SET v = 9 WHERE id = 1", "TRUNCATE TABLE t", "DELETE FROM t WHERE id = 1", "INSERT INTO t SELECT * FROM t",
		"INSERT INTO FILES('path'='file:///tmp/x', 'format'='csv') SELECT 1",
	},
	"files_function": {
		"SELECT * FROM FILES('path'='file:///etc/hostname','format'='csv')",
		"SELECT * FROM FILES('path'='file:///tmp/nonexistent*','format'='csv')",
		"SELECT * FROM FILES('path'='s3://bucket/x.parquet','format'='parquet')",
		"select * from files ('path'='file:///etc/hostname', 'format'='csv')",
		"SELECT * FROM t JOIN FILES(\"path\"=\"file:///etc/hostname\", \"format\"=\"csv\") f ON 1 = 1",
	},
	// get_query_profile returns other accounts' statements and profiles.
	"profile_function": {
		"SELECT get_query_profile('0b1c4f9c-3a8e-11ef-9c1f-0242ac120002')", "SELECT length(get_query_profile('id'))",
		"SELECT GET_QUERY_PROFILE ('x')", "SELECT `get_query_profile`('x')", "SELECT get_query_profile/**/('x')",
		"SELECT db.get_query_profile('x')", "WITH c AS (SELECT get_query_profile('x')) SELECT * FROM c",
		"SELECT 1 UNION SELECT get_query_profile('x')", "EXPLAIN SELECT get_query_profile('x')", "SELECT `Get_Query_Profile` /* c */ ('x')",
	},
	"explain_measured": {
		"EXPLAIN SCHEMA SELECT 1", "EXPLAIN ANALYZE DELETE FROM t WHERE id = 1",
		"EXPLAIN ANALYZE INSERT INTO t SELECT 1, \"x\"",
	},
}

var attacksMeasuredDremio = map[string][]string{
	// Dremio cuts /* ... */ out of the raw text, quotes included, and the
	// set_var entries in it become a SET_VAR hint (measured with EXPLAIN PLAN FOR).
	"set_var_in_quotes": {
		`SELECT 1 FROM t WHERE 'x' <> '/* set_var.pipeline_dop=2 */'`,
		`SELECT 1 AS "/* set_var.pipeline_dop=3 */" FROM t`,
		`SELECT 1 FROM t WHERE 'x' <> '/* SET_VAR.pipeline_dop=2 */'`,
		`SELECT 1 AS "/* Set_Var.pipeline_dop=3 */" FROM t`,
		`SELECT 1 FROM t WHERE 'x' <> 'a /* b /* set_var.pipeline_dop=2 */'`,
		`SELECT 1 FROM t WHERE 'x' <> '/*' AND 'y' <> ' set_var.pipeline_dop=2 */'`,
		`SELECT 1 AS "/*" FROM t WHERE 'y' <> ' set_var.pipeline_dop=2 */'`,
		`SELECT 1 FROM t WHERE 'x' <> '/*' AND set_var.pipeline_dop = 2 AND 'y' <> '*/'`,
	},
	// Every Dremio account is an administrator, so the guard is the only write boundary.
	"measured_writes": {
		`CREATE VIEW "@user".v_probe AS SELECT user_id, city FROM "src-main".demo_db.dim_user`,
		`CREATE OR REPLACE VIEW "@user".v_probe AS SELECT 1`, `DROP VIEW "@user".v_probe`,
		`TRUNCATE TABLE "src-scratch".scratch.t`, `ALTER PDS "src-main".demo_db.dim_user REFRESH METADATA`,
		`ALTER SESSION SET "planner.slice_target" = 100000`, `ALTER SYSTEM SET "planner.slice_target" = 100000`,
		`CREATE TABLE "src-scratch".scratch.t AS SELECT 1 AS a`, `CREATE TABLE "src-scratch".scratch.t (id INT)`,
		`ALTER TABLE "src-scratch".scratch.t ADD COLUMNS (c INT)`, `DROP TABLE "src-scratch".scratch.t`,
		`GRANT SELECT ON TABLE t TO USER u`, `CREATE ROLE r`, `CREATE USER u`,
		`INSERT INTO "src-scratch".scratch.t SELECT 71 AS id, 'note' AS note`, `INSERT INTO "src-scratch".scratch.t VALUES (51, 'x')`,
		`INSERT INTO "src-scratch".scratch.t SELECT user_id, user_name FROM "src-main".demo_db.dim_user WHERE user_id < 3`,
		`DELETE FROM "src-scratch".scratch.t WHERE id = 1`, `UPDATE "src-scratch".scratch.t SET note = 'x'`,
		`EXPLAIN PLAN FOR INSERT INTO "src-scratch".scratch.t VALUES (1, 'x')`,
	},
	// external_query runs any statement on the data source, also while the plan is built.
	"external_query": {
		`SELECT * FROM TABLE("src-main".external_query('SELECT 1 AS a, ''x'' AS b'))`,
		`SELECT * FROM TABLE("src-main".external_query('SELECT count(*) AS c FROM demo_dw.dim_user'))`,
		`SELECT * FROM TABLE("src-scratch".external_query('INSERT INTO scratch.t VALUES (41, ''via-external-query'')'))`,
		`SELECT * FROM TABLE("src-scratch".external_query('CREATE TABLE scratch.t (id INT)'))`,
		`SELECT * FROM TABLE("src-scratch".external_query('DROP TABLE scratch.t'))`,
		`SELECT * FROM TABLE("src-main"."external_query"('SELECT 1'))`, `SELECT * FROM TABLE("src-main".EXTERNAL_QUERY('SELECT 1'))`,
		`VALUES (1), (external_query('x'))`, `SELECT (SELECT * FROM TABLE(src.external_query('x')))`,
	},
	// EXPLAIN PLAN FOR executes external_query while planning.
	"explain_external_query": {
		`EXPLAIN PLAN FOR SELECT * FROM TABLE("src-scratch".external_query('INSERT INTO scratch.t VALUES (61, ''explain-external-query'')'))`,
		`EXPLAIN PLAN WITH IMPLEMENTATION FOR SELECT * FROM TABLE("src-scratch".external_query('INSERT INTO scratch.t VALUES (61, ''x'')'))`,
		`explain plan for select * from table("src".external_query('x'))`,
		`EXPLAIN PLAN FOR WITH c AS (SELECT * FROM TABLE(src.external_query('x'))) SELECT * FROM c`,
		`EXPLAIN PLAN FOR SELECT * FROM TABLE ( "src" . external_query /**/ ( 'x' ) )`,
		`EXPLAIN PLAN FOR SELECT * FROM TABLE("src"."EXTERNAL_QUERY"('x'))`,
		`EXPLAIN PLAN FOR SELECT external_query('x')`,
	},
	// Statements that start with an allowed keyword but reach a table function or an
	// unlisted statement form.
	"table_functions": {
		`SELECT * FROM TABLE(src.some_proc('x'))`, `SELECT * FROM TABLE("src-main"."dir/file.csv"(type => 'text'))`,
		`SELECT * FROM TABLE(copy_errors('t', 'job'))`, `SELECT * FROM TABLE(table_partitions('t'))`,
		`DESCRIBE TABLE(src.external_query('select 1'))`, `DESC TABLE(external_query('x'))`,
		`SHOW FILES IN TABLE(src.external_query('x'))`, `SHOW TABLES LIKE external_query('x')`,
		`SELECT * FROM t WHERE x = (SELECT a FROM TABLE(src.external_query('x')))`,
		`SELECT * FROM TABLE(table_history('t')), TABLE(table_unknown('t'))`,
	},
	"show_measured": {
		`SHOW CREATE VIEW "src-main".demo_db.v`, `SHOW CREATE VIEW`, `SHOW TBLPROPERTIES "src-main".demo_db.t`,
	},
}

var allowMeasuredCommon = []allowCase{
	{"SELECT 5 --\ttab", sel},
	{"SELECT 1 -- 1", sel},
	{"SELECT 1 -- ; INSERT INTO t VALUES (13, 'dash-comment')", sel},
	{"SELECT 1 -- # not code\n", sel},
	{"/* lead */ SELECT 1;", sel},
	{"-- lead\nSELECT 1", sel},
	{"(SELECT 1)", sel},
	{"SELECT '//', 'http://example.invalid/x' /* // */ -- //\n", sel},
}

var allowMeasuredStarRocks = []allowCase{
	{`SELECT 'a''b', 'a\'b', 'a\\', 'tab\there', "dq\"x"`, sel},
	{`SELECT 'a\' OR 1=1 -- '`, sel},
	{`SELECT length('\\'), length('\\\\'), length('it''s'), length('x\ny')`, sel},
	// The server reports a syntax error (1064) and executes nothing; the guard finds no second statement either.
	{`SELECT 'x\' ; INSERT INTO t VALUES (14,'bs-escape') ; --'`, sel},
	{"SELECT count(*) FROM default_catalog.demo_dw.dim_user", sel},
	{"SELECT `user_id`, `user_name` FROM `demo_dw`.`dim_user` LIMIT 1", sel},
	{`SELECT "user_id" FROM demo_dw.dim_user LIMIT 1`, sel},
	{"SELECT '#' , 1", sel},
	{"SELECT 1 /* # */", sel},
	{"SELECT `get_query_profile`, get_query_profile, 'get_query_profile(1)' FROM t", sel},
	{"SHOW CREATE VIEW v", show("CREATE VIEW")},
	{"SHOW PROFILELIST LIMIT 2", show("PROFILELIST")},
	{"ANALYZE PROFILE FROM '0b1c4f9c-3a8e-11ef-9c1f-0242ac120002', 0", Statement{Kind: KindAnalyzeProfile}},
}

var allowMeasuredDremio = []allowCase{
	// "/*" in quotes is fine while set_var does not follow it; Dremio reads these as comments without a hint.
	{`SELECT 'a/*b*/c', "x/*y" FROM t WHERE 'z' <> 'q'`, sel},
	{`SELECT 1 FROM t WHERE 'set_var.a=1' <> 'x/*'`, sel},
	{`SELECT 1 FROM t WHERE 'x' <> '/*' AND 'y' <> '*/'`, sel},
	{`SHOW SCHEMAS LIKE '%demo%'`, show("SCHEMAS")},
	{`SHOW TABLES IN "src-main".demo_db`, show("TABLES")},
	{`SHOW FUNCTIONS LIKE '%sum%'`, show("FUNCTIONS")},
	{`DESCRIBE "src-main".demo_db.fact_orders`, Statement{Kind: KindDescribe}},
	{`DESC "src-main".demo_db.fact_orders`, Statement{Kind: KindDescribe}},
	{`VALUES (1, 'a'), (2, 'b')`, sel},
	{`SHOW CREATE TABLE "src-main".demo_db.dim_user`, show("CREATE TABLE")},
	{`SHOW PARTITIONS "src-main".demo_db.dim_user`, show("PARTITIONS")},
	{`SHOW FILES IN "src-main".demo_db`, show("FILES")},
	{`SELECT TABLE_NAME FROM INFORMATION_SCHEMA."TABLES" WHERE TABLE_SCHEMA = 'src-main.demo_db'`, sel},
	{`SELECT count(*) FROM INFORMATION_SCHEMA.SCHEMATA`, sel},
	{`SELECT * FROM TABLE(table_history('x'))`, sel},
	{`SELECT * FROM TABLE(table_snapshot('x'))`, sel},
	{`SELECT * FROM TABLE(table_files('x'))`, sel},
	{`EXPLAIN PLAN FOR SELECT p.category, count(*) AS c FROM "src-main".demo_db.fact_orders f JOIN "src-main".demo_db.dim_product p ON f.product_id = p.product_id WHERE f.store_id = 3 GROUP BY p.category`, explain("PLAN FOR", sel)},
	{`EXPLAIN PLAN WITH IMPLEMENTATION FOR SELECT 1`, explain("PLAN WITH IMPLEMENTATION FOR", sel)},
	{`SELECT 'external_query', "external_query" FROM t`, sel},
}
