package mysql

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func restrictedConfig(t *testing.T, restriction string) Config {
	t.Helper()
	c := Config{Address: "tcp://127.0.0.1:1", Credential: "/missing/mysql.json"}
	if err := json.Unmarshal([]byte(restriction), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDatabaseRestrictions(t *testing.T) {
	c := restrictedConfig(t, `{"databases":["fixture"]}`)
	for _, database := range []string{"fixture", "Fixture", "other"} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Run(ctx, c, Params{Database: database, SQL: "SELECT 1"})
		if database == "fixture" && !errors.Is(err, context.Canceled) || database != "fixture" && (err == nil || !strings.Contains(err.Error(), "databases")) {
			t.Errorf("database=%s: %v", database, err)
		}
	}
}

func TestDatabaseSQLReferences(t *testing.T) {
	c := restrictedConfig(t, `{"databases":["fixture","reporting"]}`)
	for _, tc := range []struct {
		sql     string
		allowed bool
	}{
		{"SELECT 1", true}, {"SELECT * FROM items", true},
		{"SELECT * FROM `fixture`.`items`", true},
		{"SELECT fixture.items.id, fixture.items.* FROM fixture.items", true},
		{"SELECT * FROM fixture.items JOIN reporting.items USING (id)", true},
		{"WITH c AS (SELECT * FROM reporting.items) SELECT * FROM c", true},
		{"SELECT * FROM (SELECT * FROM reporting.items) AS s", true},
		{"EXPLAIN SELECT * FROM reporting.items", true},
		{"DESC reporting.items", true}, {"DESCRIBE fixture.items", true},
		{"SHOW TABLES", true}, {"SHOW FULL TABLES IN reporting", true},
		{"SHOW TABLE STATUS FROM fixture", true}, {"SHOW CREATE DATABASE reporting", true},
		{"SHOW CREATE TABLE reporting.items", true}, {"SHOW CREATE VIEW fixture.items", true},
		{"SHOW COLUMNS FROM items IN reporting", true}, {"SHOW INDEX FROM reporting.items", true},
		{"SHOW TRIGGERS FROM fixture", true}, {"SHOW EVENTS IN reporting", true},
		{"SELECT * FROM private.items", false}, {"SELECT * FROM Fixture.items", false},
		{"SELECT * FROM `private`.`items`", false},
		{"SELECT * FROM fixture.items JOIN private.items USING (id)", false},
		{"SELECT * FROM items WHERE id IN (SELECT id FROM private.items)", false},
		{"SELECT * FROM (SELECT * FROM private.items) AS s", false},
		{"WITH c AS (SELECT * FROM private.items) SELECT * FROM c", false},
		{"SELECT * FROM fixture.items UNION SELECT * FROM private.items", false},
		{"EXPLAIN SELECT * FROM private.items", false}, {"DESC private.items", false},
		{"SELECT private.items.id FROM fixture.items", false},
		{"SELECT private.items.* FROM fixture.items", false},
		{"SHOW TABLES FROM private", false}, {"SHOW FULL TABLES IN private", false},
		{"SHOW TABLE STATUS IN private", false}, {"SHOW CREATE DATABASE private", false},
		{"SHOW CREATE TABLE private.items", false}, {"SHOW CREATE VIEW private.items", false},
		{"SHOW COLUMNS FROM items IN private", false}, {"SHOW COLUMNS FROM private.items", false},
		{"SHOW COLUMNS FROM private.items IN fixture", false},
		{"SHOW COLUMNS FROM fixture.items IN private", false},
		{"SHOW INDEX FROM items IN private", false}, {"SHOW TRIGGERS IN private", false},
		{"SHOW EVENTS FROM private", false},
		{"SHOW TABLES WHERE EXISTS (SELECT 1 FROM private.items)", false},
		{"SHOW ENGINES", false}, {"SHOW WARNINGS", false},
	} {
		t.Run(tc.sql, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := Run(ctx, c, Params{Database: "fixture", SQL: tc.sql})
			if tc.allowed && !errors.Is(err, context.Canceled) || !tc.allowed && (err == nil || !strings.Contains(err.Error(), "databases") || !strings.Contains(err.Error(), "fixture")) {
				t.Fatalf("allowed=%v: %v", tc.allowed, err)
			}
			// Omitting databases preserves the existing SQL acceptance rules.
			if err := validateSQL(tc.sql); err != nil {
				t.Fatalf("default validation changed: %v", err)
			}
		})
	}
	for _, database := range []string{"information_schema", "mysql", "performance_schema", "sys"} {
		sql := "SELECT * FROM " + database + ".items"
		_, err := Run(context.Background(), c, Params{Database: "fixture", SQL: sql})
		if err == nil || !strings.Contains(err.Error(), "databases") {
			t.Errorf("system database %s bypass: %v", database, err)
		}
		explicit := c
		explicit.Databases = []string{"fixture", database}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := Run(ctx, explicit, Params{Database: "fixture", SQL: sql}); !errors.Is(err, context.Canceled) {
			t.Errorf("explicit system database %s: %v", database, err)
		}
	}
	// USE remains outside the default read-only statement whitelist.
	for _, sql := range []string{"USE fixture", "USE private"} {
		if _, err := Run(context.Background(), c, Params{Database: "fixture", SQL: sql}); !errors.Is(err, errSQL) {
			t.Errorf("USE must remain rejected: %v", err)
		}
	}
}

func TestDatabaseServerShowOptIn(t *testing.T) {
	for _, tc := range []struct {
		kind string
		sqls []string
	}{
		{"DATABASES", []string{"SHOW DATABASES", "SHOW SCHEMAS LIKE 'fixture%'"}},
		{"PROCESSLIST", []string{"SHOW PROCESSLIST", "SHOW FULL PROCESSLIST"}},
		{"VARIABLES", []string{"SHOW VARIABLES", "SHOW GLOBAL VARIABLES", "SHOW SESSION VARIABLES"}},
		{"STATUS", []string{"SHOW STATUS", "SHOW GLOBAL STATUS", "SHOW SESSION STATUS"}},
	} {
		for _, sql := range tc.sqls {
			t.Run(sql, func(t *testing.T) {
				c := restrictedConfig(t, `{"databases":["fixture"]}`)
				_, err := Run(context.Background(), c, Params{Database: "fixture", SQL: sql})
				if err == nil || !strings.Contains(err.Error(), "show_types") || !strings.Contains(err.Error(), tc.kind) {
					t.Fatalf("server SHOW requires explicit show_types: %v", err)
				}
				c.ShowTypes = []string{strings.ToLower(tc.kind)}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if _, err := Run(ctx, c, Params{Database: "fixture", SQL: sql}); !errors.Is(err, context.Canceled) {
					t.Fatalf("explicit server SHOW: %v", err)
				}
				c.ShowTypes = []string{"TABLES"}
				if _, err := Run(context.Background(), c, Params{Database: "fixture", SQL: sql}); err == nil || !strings.Contains(err.Error(), "show_types") {
					t.Fatalf("server SHOW escaped show_types: %v", err)
				}
			})
		}
	}
}

func TestDirectConfigRestrictions(t *testing.T) {
	for _, tc := range []struct{ config, field, sql string }{
		{`{"databases":[""]}`, "databases", "SELECT 1"},
		{`{"statement_types":["SHOW"]}`, "statement_types", "SELECT 1"},
		{`{"statement_types":["DELETE"]}`, "statement_types", "SELECT 1"},
		{`{"show_types":["TABLES"]}`, "show_types", "SHOW DATABASES"},
		{`{"show_types":["INVALID"]}`, "show_types", "SHOW TABLES"},
	} {
		_, err := Run(context.Background(), restrictedConfig(t, tc.config), Params{Database: "fixture", SQL: tc.sql})
		if err == nil || !strings.Contains(err.Error(), tc.field) {
			t.Errorf("%s / %s: %v", tc.config, tc.sql, err)
		}
	}
}

func TestStatementTypeRestrictions(t *testing.T) {
	for _, tc := range []struct {
		types, sql string
		allowed    bool
	}{
		{`["SELECT"]`, "select 1", true}, {`["SELECT"]`, "WITH c AS (SELECT 1) SELECT * FROM c", true},
		{`["SELECT"]`, "SELECT 1 UNION SELECT 2", true}, {`["SELECT"]`, "SHOW TABLES", false},
		{`["SHOW"]`, "show full tables", true}, {`["SHOW"]`, "DESC t", false},
		{`["DESCRIBE"]`, "DESC t", true}, {`["DESCRIBE"]`, "describe t id", true},
		{`["DESCRIBE"]`, "EXPLAIN t", true}, {`["DESCRIBE"]`, "SHOW COLUMNS FROM t", false},
		{`["EXPLAIN"]`, "EXPLAIN SELECT 1", false}, {`["SELECT"]`, "EXPLAIN SELECT 1", false},
		{`["SELECT","EXPLAIN"]`, "EXPLAIN SELECT 1 UNION SELECT 2", true},
		{`["SELECT","EXPLAIN"]`, "DESC SELECT 1", true},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Run(ctx, restrictedConfig(t, `{"statement_types":`+tc.types+`}`), Params{Database: "fixture", SQL: tc.sql})
		if tc.allowed && !errors.Is(err, context.Canceled) || !tc.allowed && (err == nil || !strings.Contains(err.Error(), "statement_types")) {
			t.Errorf("types=%s sql=%s allowed=%v: %v", tc.types, tc.sql, tc.allowed, err)
		}
	}
}

func TestShowTypeRestrictions(t *testing.T) {
	for _, tc := range []struct {
		kind            string
		allowed, denied []string
	}{
		{"TABLES", []string{"SHOW TABLES", "show /*comment*/ full tables FROM fixture LIKE 'items%'"}, []string{"SHOW TABLE STATUS", "SHOW DATABASES"}},
		{"DATABASES", []string{"SHOW DATABASES", "SHOW SCHEMAS LIKE 'fixture%'"}, []string{"SHOW TABLES"}},
		{"PROCESSLIST", []string{"SHOW PROCESSLIST", "SHOW FULL PROCESSLIST"}, []string{"SHOW STATUS"}},
		{"VARIABLES", []string{"SHOW VARIABLES", "SHOW GLOBAL VARIABLES LIKE 'version%'", "SHOW SESSION VARIABLES"}, []string{"SHOW STATUS"}},
		{"STATUS", []string{"SHOW STATUS", "SHOW GLOBAL STATUS", "SHOW SESSION STATUS"}, []string{"SHOW VARIABLES"}},
		{"CREATE TABLE", []string{"SHOW CREATE TABLE items"}, []string{"SHOW CREATE DATABASE fixture", "SHOW CREATE VIEW items"}},
		{"COLUMNS", []string{"SHOW COLUMNS FROM items", "SHOW FIELDS FROM items", "SHOW FULL COLUMNS FROM items"}, []string{"SHOW INDEX FROM items"}},
	} {
		data, err := json.Marshal(map[string]any{"show_types": []string{tc.kind}})
		if err != nil {
			t.Fatal(err)
		}
		c := restrictedConfig(t, string(data))
		for _, allowed := range []bool{true, false} {
			sqls := tc.denied
			if allowed {
				sqls = tc.allowed
			}
			for _, sql := range sqls {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				_, err := Run(ctx, c, Params{Database: "fixture", SQL: sql})
				if allowed && !errors.Is(err, context.Canceled) || !allowed && (err == nil || !strings.Contains(err.Error(), "show_types")) {
					t.Errorf("kind=%s sql=%s allowed=%v: %v", tc.kind, sql, allowed, err)
				}
			}
		}
	}
	// DESCRIBE is a separate statement type even though its child AST is ShowColumns.
	c := restrictedConfig(t, `{"statement_types":["DESCRIBE"],"show_types":["TABLES"]}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Run(ctx, c, Params{Database: "fixture", SQL: "DESCRIBE items"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DESCRIBE classification: %v", err)
	}
}
