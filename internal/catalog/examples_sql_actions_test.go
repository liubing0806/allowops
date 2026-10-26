package catalog

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// The SQL example actions validate the statement before the credential file is
// read. Pointing the credential at a missing file separates the two outcomes:
// an accepted statement fails with the credential error, a refused one fails
// with its own reason. Parameter regexes (for example the EXPLAIN prefix of
// starrocks_explain) are applied before the handler and are not part of this test.
func TestSQLExampleActionsAcceptTheirOwnStatements(t *testing.T) {
	c := loadExamples(t)
	missing := filepath.Join(t.TempDir(), "missing.json")
	cases := []struct {
		action, sql string
		accepted    bool
	}{
		{"starrocks_query_readonly", "SELECT count(*) FROM demo_dw.fact_orders", true},
		{"starrocks_query_readonly", "SHOW TABLES", true},
		{"starrocks_query_readonly", "DROP TABLE demo_dw.fact_orders", false},
		{"starrocks_explain", "EXPLAIN SELECT count(*) FROM demo_dw.fact_orders", true},
		{"starrocks_explain", "EXPLAIN ANALYZE SELECT count(*) FROM demo_dw.fact_orders", false},
		{"dremio_query_readonly", `SELECT count(*) FROM "src".demo_dw.dim_user`, true},
		{"dremio_query_readonly", `DROP TABLE "src".demo_dw.dim_user`, false},
		{"dremio_explain", `EXPLAIN PLAN FOR SELECT count(*) FROM "src".demo_dw.dim_user`, true},
		{"dremio_explain", `EXPLAIN PLAN FOR INSERT INTO "src".demo_dw.dim_user VALUES (1)`, false},
	}
	for _, tc := range cases {
		a, ok := c.Actions[tc.action]
		if !ok {
			t.Fatalf("example action %s does not exist", tc.action)
		}
		config := map[string]any{}
		for k, v := range a.BuiltinConfig {
			config[k] = v
		}
		config["credential"] = missing
		_, err := Builtins[a.Builtin].Run(context.Background(), config, map[string]any{"sql": tc.sql})
		if err == nil {
			t.Fatalf("%s %q: no error although the credential file does not exist", tc.action, tc.sql)
		}
		reachedCredential := strings.Contains(err.Error(), "credential")
		if reachedCredential != tc.accepted {
			t.Errorf("%s %q: accepted=%v, want %v (error: %v)", tc.action, tc.sql, reachedCredential, tc.accepted, err)
		}
	}
}
