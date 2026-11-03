package catalog

import (
	"strings"
	"testing"
)

// An apostrophe inside a comment must not pair with the opening quote of a
// real literal. Comments are replaced as a whole before literals are.
func TestExampleMySQLStatementTextRedactsLiteralsAfterCommentApostrophe(t *testing.T) {
	c := loadExamples(t)
	cases := []redactionCase{
		{"SELECT /* it's a report */ SLEEP(25), pw FROM users WHERE id=1 AND pw = 'SuperSecretPw1'", "SuperSecretPw1"},
		{"SELECT /* a'b */ 1 FROM t WHERE x='cmtsecret2' /* c'd */ AND y='cmtsecret3'", "cmtsecret2"},
		{"SELECT /* a'b */ 1 FROM t WHERE x='cmtsecret2' /* c'd */ AND y='cmtsecret3'", "cmtsecret3"},
		{"SELECT pw FROM u WHERE pw='cmtsecret4' -- it's done", "cmtsecret4"},
		{"SELECT 1 -- it's a note\nFROM u WHERE pw='cmtsecret5'", "cmtsecret5"},
		{"SELECT /* unterminated it's\nFROM u WHERE pw='cmtsecret6'", "cmtsecret6"},
		{"SELECT 'a /* b' , pw='cmtsecret7' , 'c */ d'", "cmtsecret7"},
	}
	for _, name := range []string{"mysql_processlist", "mysql_slow_log", "mysql_error_log"} {
		checkRedactionCases(t, name, exampleRedactor(t, c, name), cases)
	}
}

// Error logs at the default verbosity carry full statement text, for example
// the binary log warning for unsafe statements and replication errors.
func TestExampleMySQLErrorLogRedactsSQLLiterals(t *testing.T) {
	r := exampleRedactor(t, loadExamples(t), "mysql_error_log")
	checkRedactionCases(t, "mysql_error_log", r, append([]redactionCase{
		{"2026-10-22T13:30:42.688880Z 29 [Warning] [MY-010908] [Server] Unsafe statement written to the binary log using statement format. Statement: UPDATE users SET pw='UnsafeStmtPw77', phone='x' WHERE id=1 LIMIT 1", "UnsafeStmtPw77"},
		{`2026-10-22T13:30:42.688880Z 31 [ERROR] [MY-010584] [Repl] Replica SQL: Could not execute Update_rows event; Query: "INSERT INTO t VALUES (\"errdqsecret1\")"`, "errdqsecret1"},
		{"2026-10-22T13:30:42.688880Z 31 [Warning] Statement: SELECT 0xDEADBEEF7 FROM t", "DEADBEEF7"},
		{"2026-10-22T13:30:42.688880Z 0 [System] [MY-010931] [Server] ready for connections. Version: 8.0.46", ""},
	}, sqlLiteralCases...))
}

// The slow log search must not take a caller pattern: a pattern is matched
// against the original text, so hit and miss reveal replaced literals one
// character at a time. The action returns the last lines, redacted, and the
// match filter runs after redaction.
func TestExampleMySQLSlowLogHasNoCallerPattern(t *testing.T) {
	a, ok := loadExamples(t).Actions["mysql_slow_log"]
	if !ok {
		t.Fatal("mysql_slow_log missing")
	}
	for name := range a.Params {
		if strings.Contains(name, "pattern") || strings.Contains(name, "fixed") || strings.Contains(name, "exclude") {
			t.Errorf("mysql_slow_log still takes caller search parameter %q", name)
		}
	}
	if a.Builtin != "" {
		t.Errorf("builtin %q matches caller patterns on the original text", a.Builtin)
	}
	if len(a.Exec) == 0 || a.Exec[0] != "/usr/bin/tail" {
		t.Fatalf("exec = %v, want tail of the last lines", a.Exec)
	}
	lines, ok := a.Params["lines"]
	if !ok || lines.Type != "int" || lines.Max == nil || lines.Min == nil {
		t.Fatalf("lines must be a bounded int parameter: %+v", lines)
	}
	path := a.Params["path"]
	if path.Type != "path" || len(path.AllowedRoots) == 0 {
		t.Fatalf("path must be a path parameter with allowed roots: %+v", path)
	}
	for _, root := range path.AllowedRoots {
		if root != "/var/log/mysql" && root != "/var/log/mariadb" {
			t.Errorf("allowed root %q is wider than the database log directories", root)
		}
	}
	hasMatch := false
	for _, f := range a.Filters {
		hasMatch = hasMatch || f == "match"
	}
	if !hasMatch {
		t.Error("match filter must stay available; it runs after redaction")
	}
	checkRedactionCases(t, "mysql_slow_log", exampleRedactor(t, loadExamples(t), "mysql_slow_log"), sqlLiteralCases)
}

// A keyword in the middle of the key name still marks a credential.
func TestExampleMySQLConfigViewRedactsKeywordInsideKeyName(t *testing.T) {
	r := exampleRedactor(t, loadExamples(t), "mysql_config_view")
	checkRedactionCases(t, "mysql_config_view", r, []redactionCase{
		{"secret_key = abc123", "abc123"},
		{"token_value=zzz", "zzz"},
		{"client-secret-id = idval1", "idval1"},
		{"validate_password.dictionary=dictval2", "dictval2"},
		{"# my_pwd_file = pwdfileval3", "pwdfileval3"},
		{"ssl-key-passwd=x4", "x4"},
		{"token=abc5", "abc5"},
		{"port=3306", ""},
		{"max_connections = 100", ""},
		{"[mysqld]", ""},
	})
}
