package starrocks

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/builtin/credfile"
	"github.com/liubing0806/allowops/internal/builtin/sqlguard"
)

// The integration tests need the local environment of test/starrocks-dremio
// (./test/starrocks-dremio/up.sh). They run only when ALLOWOPS_STARROCKS_ADDR
// is set, for example to 127.0.0.1:29030. Account passwords are read from
// ALLOWOPS_STARROCKS_STATE (default: test/starrocks-dremio/.state) inside the
// test process; they are never logged, passed in arguments or written to files
// except the 0600 credential files of the root helper in a private temp dir.
const (
	envAddr   = "ALLOWOPS_STARROCKS_ADDR"
	envState  = "ALLOWOPS_STARROCKS_STATE"
	envHelper = "ALLOWOPS_STARROCKS_ROOT_HELPER"
)

func integrationAddress(t *testing.T) string {
	t.Helper()
	addr := os.Getenv(envAddr)
	if addr == "" {
		t.Skipf("%s is not set; start the local environment (test/starrocks-dremio/up.sh) and set it to the FE MySQL address, for example 127.0.0.1:29030", envAddr)
	}
	if !strings.HasPrefix(addr, "tcp://") {
		addr = "tcp://" + addr
	}
	return addr
}

func stateCredential(t *testing.T, key string) credfile.Credential {
	t.Helper()
	dir := os.Getenv(envState)
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "test", "starrocks-dremio", ".state")
	}
	data, err := os.ReadFile(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatalf("read credentials of the local environment: %v", err)
	}
	var accounts map[string]struct{ UserName, Password string }
	if err := json.Unmarshal(data, &accounts); err != nil {
		t.Fatal("parse credentials of the local environment")
	}
	account, ok := accounts[key]
	if !ok || account.UserName == "" {
		t.Fatalf("no account %q in the local environment", key)
	}
	return credfile.Credential{Username: account.UserName, Password: account.Password}
}

func integrationConfig(address string) Config {
	return Config{Address: address, MaxRows: 500, MaxBytes: 1 << 20, Timeout: 10 * time.Second}
}

// execUnchecked runs a statement without the lexical guard. Only these tests
// do this, to check what the database itself refuses and to run statements
// that the guard rejects on purpose (sleep).
func execUnchecked(ctx context.Context, cfg Config, database, sql string, cred credfile.Credential) (Result, error) {
	return runQuery(ctx, cfg, Params{Database: database, SQL: sql}, cred, nil)
}

func TestIntegrationQueryAccount(t *testing.T) {
	address := integrationAddress(t)
	cred := stateCredential(t, "sr_query")
	cfg := integrationConfig(address)
	ctx := context.Background()
	query := func(t *testing.T, cfg Config, database, sql string) Result {
		t.Helper()
		if _, err := sqlguard.Validate(sqlguard.StarRocks, sql, sqlguard.Options{}); err != nil {
			t.Fatalf("the guard rejects %q: %v", sql, err)
		}
		result, err := execUnchecked(ctx, cfg, database, sql, cred)
		if err != nil {
			t.Fatalf("%q: %v", sql, err)
		}
		return result
	}

	t.Run("select", func(t *testing.T) {
		got := query(t, cfg, "demo_dw", "SELECT count(*) AS n FROM dim_user")
		if got.Output != "n\n10000\n" || got.Rows != 1 || got.Truncated {
			t.Fatalf("got %+v", got)
		}
		got = query(t, cfg, "", "WITH c AS (SELECT city, count(*) AS n FROM demo_dw.dim_user GROUP BY city) SELECT count(*) AS cities FROM c")
		if got.Rows != 1 || !strings.HasPrefix(got.Output, "cities\n") {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("three part name", func(t *testing.T) {
		got := query(t, cfg, "", "SELECT count(*) AS n FROM default_catalog.demo_dw.dim_product")
		if got.Output != "n\n1000\n" {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("explain", func(t *testing.T) {
		for _, sql := range []string{
			"EXPLAIN SELECT count(*) FROM demo_dw.fact_orders", "EXPLAIN LOGICAL SELECT count(*) FROM demo_dw.fact_orders",
			"EXPLAIN VERBOSE SELECT count(*) FROM demo_dw.fact_orders", "EXPLAIN COSTS SELECT count(*) FROM demo_dw.fact_orders",
		} {
			got := query(t, cfg, "", sql)
			if got.Rows == 0 || got.Truncated || !strings.Contains(strings.ToLower(got.Output), "scan") {
				t.Errorf("%s: %+v", sql, got)
			}
		}
	})
	t.Run("describe", func(t *testing.T) {
		got := query(t, cfg, "demo_dw", "DESC dim_user")
		for _, column := range []string{"user_id", "user_name", "city"} {
			if !strings.Contains(got.Output, column) {
				t.Errorf("DESC lacks %s: %q", column, got.Output)
			}
		}
	})
	t.Run("show", func(t *testing.T) {
		got := query(t, cfg, "demo_dw", "SHOW TABLES")
		for _, table := range []string{"dim_user", "dim_product", "fact_orders"} {
			if !strings.Contains(got.Output, table) {
				t.Errorf("SHOW TABLES lacks %s: %q", table, got.Output)
			}
		}
		got = query(t, cfg, "", "SHOW CREATE TABLE demo_dw.dim_user")
		if got.Rows != 1 || !strings.Contains(got.Output, "CREATE TABLE") || strings.Count(got.Output, "\n") != 2 {
			t.Errorf("SHOW CREATE TABLE: %q", got.Output)
		}
		if got = query(t, cfg, "", "SHOW DATABASES"); !strings.Contains(got.Output, "demo_dw") {
			t.Errorf("SHOW DATABASES: %q", got.Output)
		}
	})
	t.Run("tsv and null", func(t *testing.T) {
		got := query(t, cfg, "", `SELECT NULL AS missing, 'a\tb' AS tabbed, '' AS empty`)
		if got.Output != "missing\ttabbed\tempty\n\\N\ta\\tb\t\n" || got.Rows != 1 {
			t.Fatalf("got %q", got.Output)
		}
	})
	t.Run("session default database", func(t *testing.T) {
		got := query(t, cfg, "demo_dw", "SELECT database() AS db")
		if got.Output != "db\ndemo_dw\n" {
			t.Fatalf("got %q", got.Output)
		}
		if got = query(t, cfg, "", "SELECT database() AS db"); got.Rows != 1 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("session query_timeout", func(t *testing.T) {
		for _, tc := range []struct {
			timeout time.Duration
			want    string
		}{{time.Second, "1"}, {1500 * time.Millisecond, "2"}, {10 * time.Second, "10"}} {
			c := cfg
			c.Timeout = tc.timeout
			if got := query(t, c, "", "SELECT @@query_timeout AS t"); got.Output != "t\n"+tc.want+"\n" {
				t.Errorf("timeout %v: got %q; want query_timeout %s", tc.timeout, got.Output, tc.want)
			}
		}
	})
	t.Run("row truncation", func(t *testing.T) {
		c := cfg
		c.MaxRows = 3
		start := time.Now()
		// 500000 rows: only the first 4 may be read, the rest is not drained.
		got := query(t, c, "demo_dw", "SELECT order_id FROM fact_orders")
		if got.Rows != 3 || !got.Truncated || strings.Count(got.Output, "\n") != 4 {
			t.Fatalf("got %+v", got)
		}
		t.Logf("truncated read of 500000 rows took %v", time.Since(start))
		if time.Since(start) > 5*time.Second {
			t.Errorf("truncated read took %v", time.Since(start))
		}
		c.MaxRows = 500
		if got := query(t, c, "demo_dw", "SELECT order_id FROM fact_orders LIMIT 500"); got.Rows != 500 || got.Truncated {
			t.Errorf("exact limit: %+v", got)
		}
		if got := query(t, c, "demo_dw", "SELECT order_id FROM fact_orders LIMIT 501"); got.Rows != 500 || !got.Truncated {
			t.Errorf("over limit: %+v", got)
		}
	})
	t.Run("byte truncation", func(t *testing.T) {
		c := cfg
		c.MaxBytes = 64
		got := query(t, c, "demo_dw", "SELECT origin_data FROM fact_orders LIMIT 100")
		if !got.Truncated || len(got.Output) > 64 {
			t.Fatalf("got %d bytes, %d rows, truncated %v", len(got.Output), got.Rows, got.Truncated)
		}
		c.MaxBytes = 1 << 20
		if got := query(t, c, "demo_dw", "SELECT order_id FROM fact_orders LIMIT 100"); got.Truncated || got.Rows != 100 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("server errors expose only the code", func(t *testing.T) {
		_, err := execUnchecked(ctx, cfg, "", "SELECT * FROM demo_dw.no_such_secret_table", cred)
		if err == nil || err.Error() != "starrocks query failed (code 5502)" {
			t.Fatalf("got %v", err)
		}
		_, err = execUnchecked(ctx, cfg, "", "SELECT FROM", cred)
		if err == nil || !strings.HasPrefix(err.Error(), "starrocks query failed (code 1064)") {
			t.Fatalf("syntax error: %v", err)
		}
		_, err = execUnchecked(ctx, cfg, "no_such_database", "SELECT 1", cred)
		if err == nil || strings.Contains(err.Error(), "no_such_database") {
			t.Fatalf("unknown default database: %v", err)
		}
	})
	t.Run("account without access", func(t *testing.T) {
		_, err := execUnchecked(ctx, cfg, "", "SELECT count(*) FROM starrocks_audit_db__.starrocks_audit_tbl__", cred)
		if err == nil || err.Error() != "starrocks query failed (code 5203)" {
			t.Fatalf("got %v", err)
		}
	})
}

// The database refuses writes from the SELECT-only account. These
// statements bypass the guard on purpose; the guard rejects them as well
// (see the unit tests), so this checks the second layer of the boundary.
func TestIntegrationDatabaseRefusesWrites(t *testing.T) {
	address := integrationAddress(t)
	cred := stateCredential(t, "sr_query")
	cfg := integrationConfig(address)
	for _, sql := range []string{
		"INSERT INTO scratch.t_write_probe VALUES (900001, 'p2-denied')",
		"DELETE FROM scratch.t_write_probe WHERE id = 900001",
		"TRUNCATE TABLE scratch.t_write_probe",
		"CREATE DATABASE p2_denied_database",
		"CREATE TABLE demo_dw.t_p2_denied (id INT) DISTRIBUTED BY HASH(id) BUCKETS 1 PROPERTIES (\"replication_num\"=\"1\")",
		"DROP TABLE demo_dw.dim_product",
		"ALTER TABLE demo_dw.dim_product ADD COLUMN p2_denied INT",
		"GRANT SELECT ON ALL TABLES IN DATABASE demo_dw TO USER allowops_query",
		"INSTALL PLUGIN FROM \"/tmp/p2-denied.zip\"",
	} {
		result, err := execUnchecked(context.Background(), cfg, "", sql, cred)
		if err == nil || err.Error() != "starrocks query failed (code 5203)" || result != (Result{}) {
			t.Errorf("%.60q: got %+v, %v; want code 5203", sql, result, err)
		}
	}
}

func TestIntegrationTimeouts(t *testing.T) {
	address := integrationAddress(t)
	cred := stateCredential(t, "sr_query")
	cfg := integrationConfig(address)
	cfg.Timeout = time.Second

	// The guard rejects sleep(); the test bypasses it to get a slow statement.
	if _, err := sqlguard.Validate(sqlguard.StarRocks, "SELECT sleep(3)", sqlguard.Options{}); !errors.Is(err, sqlguard.ErrRejected) {
		t.Fatalf("sleep must be rejected by the guard: %v", err)
	}
	t.Run("server timeout is query_timeout", func(t *testing.T) {
		// The client deadline is later than the server limit, so the server's error is seen.
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		start := time.Now()
		result, err := execUnchecked(ctx, cfg, "", "SELECT sleep(3)", cred)
		elapsed := time.Since(start)
		if err == nil || err.Error() != "starrocks query failed (code 5024)" || result != (Result{}) {
			t.Fatalf("got %+v, %v after %v; want code 5024", result, err, elapsed)
		}
		if elapsed < 900*time.Millisecond || elapsed > 2900*time.Millisecond {
			t.Errorf("timeout after %v; want about 1s", elapsed)
		}
	})
	t.Run("client deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
		defer cancel()
		start := time.Now()
		_, err := execUnchecked(ctx, cfg, "", "SELECT sleep(30)", cred)
		elapsed := time.Since(start)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %v after %v; want the context deadline", err, elapsed)
		}
		if elapsed > 3*time.Second {
			t.Errorf("returned after %v", elapsed)
		}
		// The abandoned query must also end on the server: the account
		// shows no running query a few seconds later.
		diag := stateCredential(t, "sr_diag")
		deadline := time.Now().Add(8 * time.Second)
		for {
			running, err := execUnchecked(context.Background(), integrationConfig(address), "", "SHOW PROC '/current_queries'", diag)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(running.Output, "\tallowops_query\t") {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("query of the client that timed out is still running:\n%s", running.Output)
			}
			time.Sleep(500 * time.Millisecond)
		}
	})
}

// The public Run applies the credential file rules, so it needs a root-owned
// file. The helper test below runs as root in a user namespace (unshare -Ur
// maps the current user to uid 0, and the files it owns appear root-owned);
// the credential check stays as strict as in production.
func TestIntegrationPublicRunAsRoot(t *testing.T) {
	address := integrationAddress(t)
	if os.Getenv(envHelper) == "1" {
		t.Skip("the helper runs in TestIntegrationRootHelper")
	}
	if os.Geteuid() == 0 {
		t.Skip("already root; run TestIntegrationRootHelper directly with " + envHelper + "=1")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probe := exec.Command("unshare", "-Ur", "true")
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("cannot create a user namespace (unshare -Ur): %v %s", err, out)
	}
	cmd := exec.Command("unshare", "-Ur", exe, "-test.run=^TestIntegrationRootHelper$", "-test.v", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), envHelper+"=1", envAddr+"="+strings.TrimPrefix(address, "tcp://"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("root helper failed: %v\n%s", err, out)
	}
	t.Logf("root helper:\n%s", out)
	if !strings.Contains(string(out), "--- PASS: TestIntegrationRootHelper") {
		t.Fatalf("root helper did not run:\n%s", out)
	}
}

func writeCredentialFile(t *testing.T, dir, name string, cred credfile.Credential, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// Runs the public Run and RunRedacted with root-owned 0600 credential files.
func TestIntegrationRootHelper(t *testing.T) {
	if os.Getenv(envHelper) != "1" {
		t.Skip("runs only as a child of TestIntegrationPublicRunAsRoot")
	}
	if os.Geteuid() != 0 {
		t.Fatal("helper must run as root")
	}
	address := integrationAddress(t)
	dir := t.TempDir()
	queryFile := writeCredentialFile(t, dir, "query.json", stateCredential(t, "sr_query"), 0600)
	writerFile := writeCredentialFile(t, dir, "writer.json", stateCredential(t, "sr_dremio_rw"), 0600)
	cfg := Config{Credential: queryFile, Address: address}
	ctx := context.Background()

	t.Run("statements", func(t *testing.T) {
		for _, tc := range []struct {
			sql, contains string
		}{
			{"SELECT count(*) AS n FROM demo_dw.dim_user", "n\n10000\n"},
			{"EXPLAIN SELECT count(*) FROM demo_dw.fact_orders", "PLAN FRAGMENT"},
			{"DESC demo_dw.dim_user", "user_name"},
			{"SHOW TABLES FROM demo_dw", "fact_orders"},
			{"SHOW CREATE TABLE demo_dw.dim_user", "CREATE TABLE"},
		} {
			got, err := Run(ctx, cfg, Params{SQL: tc.sql})
			if err != nil || !strings.Contains(got.Output, tc.contains) || got.Truncated {
				t.Errorf("%q: got %+v, %v", tc.sql, got, err)
			}
		}
		got, err := Run(ctx, cfg, Params{Database: "demo_dw", SQL: "SHOW TABLES"})
		if err != nil || !strings.Contains(got.Output, "dim_user") {
			t.Errorf("default database: %+v, %v", got, err)
		}
	})
	t.Run("limits", func(t *testing.T) {
		c := cfg
		c.MaxRows = 2
		got, err := Run(ctx, c, Params{SQL: "SELECT order_id FROM demo_dw.fact_orders"})
		if err != nil || got.Rows != 2 || !got.Truncated || strings.Count(got.Output, "\n") != 3 {
			t.Fatalf("rows: %+v, %v", got, err)
		}
		c = cfg
		c.MaxBytes = 40
		got, err = Run(ctx, c, Params{SQL: "SELECT origin_data FROM demo_dw.fact_orders LIMIT 50"})
		if err != nil || !got.Truncated || got.Rows >= 50 {
			t.Fatalf("bytes: %+v, %v", got, err)
		}
	})
	t.Run("restrictions", func(t *testing.T) {
		c := cfg
		c.StatementTypes, c.ShowTypes = []string{"SHOW"}, []string{"TABLES"}
		if got, err := Run(ctx, c, Params{Database: "demo_dw", SQL: "SHOW TABLES"}); err != nil || got.Rows == 0 {
			t.Errorf("allowed: %+v, %v", got, err)
		}
		for _, sql := range []string{"SELECT 1", "SHOW DATABASES", "DESC demo_dw.dim_user"} {
			if got, err := Run(ctx, c, Params{SQL: sql}); err == nil || got.Output != "" {
				t.Errorf("%q must be refused: %+v, %v", sql, got, err)
			}
		}
	})
	t.Run("explain analyze is opt in", func(t *testing.T) {
		sql := "EXPLAIN ANALYZE SELECT count(*) FROM demo_dw.fact_orders"
		if _, err := Run(ctx, cfg, Params{SQL: sql}); !errors.Is(err, sqlguard.ErrRejected) {
			t.Fatalf("default: %v", err)
		}
		c := cfg
		c.AllowExplainAnalyze = true
		got, err := Run(ctx, c, Params{SQL: sql})
		if err != nil || got.Rows == 0 {
			t.Fatalf("enabled: %+v, %v", got, err)
		}
		if _, err := Run(ctx, c, Params{SQL: "EXPLAIN ANALYZE INSERT INTO scratch.t_write_probe SELECT 1, 'x'"}); !errors.Is(err, sqlguard.ErrRejected) {
			t.Fatalf("INSERT target: %v", err)
		}
	})
	t.Run("profile statements are rejected", func(t *testing.T) {
		c := cfg
		c.AllowExplainAnalyze = true
		for _, sql := range []string{"SHOW PROFILELIST", "SHOW PROFILELIST LIMIT 3", "ANALYZE PROFILE FROM '00000000-0000-0000-0000-000000000000'", "SELECT get_query_profile('00000000-0000-0000-0000-000000000000')"} {
			if got, err := Run(ctx, c, Params{SQL: sql}); !errors.Is(err, sqlguard.ErrRejected) || got != (Result{}) {
				t.Errorf("%q: %+v, %v", sql, got, err)
			}
		}
	})
	t.Run("redaction", func(t *testing.T) {
		mask := func(s string) string { return strings.ReplaceAll(s, "token-12345", "[REDACTED]") }
		got, err := RunRedacted(ctx, cfg, Params{SQL: "SELECT 'my token-12345' AS token_value, 7 AS n"}, mask)
		if err != nil || got.Output != "token_value\tn\nmy [REDACTED]\t7\n" {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		c := cfg
		c.Timeout = time.Second
		start := time.Now()
		// A slow statement that the guard allows: a cross join of 500000 rows with itself.
		_, err := Run(ctx, c, Params{SQL: "SELECT count(*) FROM demo_dw.fact_orders a CROSS JOIN demo_dw.fact_orders b"})
		if err == nil || (!errors.Is(err, context.DeadlineExceeded) && err.Error() != "starrocks query failed (code 5024)") {
			t.Fatalf("got %v", err)
		}
		if time.Since(start) > 4*time.Second {
			t.Errorf("returned after %v", time.Since(start))
		}
	})
	t.Run("credential file rules", func(t *testing.T) {
		wide := writeCredentialFile(t, dir, "wide.json", stateCredential(t, "sr_query"), 0644)
		if _, err := Run(ctx, Config{Credential: wide, Address: address}, Params{SQL: "SELECT 1"}); err == nil || !strings.Contains(err.Error(), "mode 0600") {
			t.Errorf("mode 0644: %v", err)
		}
		link := filepath.Join(dir, "link.json")
		if err := os.Symlink(queryFile, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Run(ctx, Config{Credential: link, Address: address}, Params{SQL: "SELECT 1"}); err == nil {
			t.Error("symlink accepted")
		}
		wrong := stateCredential(t, "sr_query")
		wrong.Password += "-wrong"
		bad := writeCredentialFile(t, dir, "bad.json", wrong, 0600)
		_, err := Run(ctx, Config{Credential: bad, Address: address}, Params{SQL: "SELECT 1"})
		if err == nil || strings.Contains(err.Error(), wrong.Password) {
			t.Errorf("wrong password: %v", err)
		}
	})
	// The write-capable account would carry out these statements if the guard
	// let them through. None of them may change the probe table.
	t.Run("rejected statements are not executed", func(t *testing.T) {
		writer := stateCredential(t, "sr_dremio_rw")
		count := func() string {
			got, err := execUnchecked(ctx, integrationConfig(address), "", "SELECT count(*) AS n FROM scratch.t_write_probe WHERE id >= 910000", writer)
			if err != nil {
				t.Fatal(err)
			}
			return got.Output
		}
		cleanup := func() {
			_, _ = execUnchecked(ctx, integrationConfig(address), "", "DELETE FROM scratch.t_write_probe WHERE id >= 910000", writer)
		}
		cleanup()
		defer cleanup()
		// Control: this account can write, so a leaked statement would show.
		if _, err := execUnchecked(ctx, integrationConfig(address), "", "INSERT INTO scratch.t_write_probe VALUES (910000, 'p2-control')", writer); err != nil {
			t.Fatalf("control insert: %v", err)
		}
		if got := count(); got != "n\n1\n" {
			t.Fatalf("control: %q", got)
		}
		cleanup()
		if got := count(); got != "n\n0\n" {
			t.Fatalf("control cleanup: %q", got)
		}
		wcfg := Config{Credential: writerFile, Address: address}
		for _, sql := range []string{
			"SELECT 1 # ; INSERT INTO scratch.t_write_probe VALUES (910001, 'p2-hash')",
			"SELECT 1; INSERT INTO scratch.t_write_probe VALUES (910002, 'p2-multi')",
			"SELECT 1;; INSERT INTO scratch.t_write_probe VALUES (910003, 'p2-double')",
			"INSERT INTO scratch.t_write_probe VALUES (910004, 'p2-direct')",
			"SELECT 1 /*! ; INSERT INTO scratch.t_write_probe VALUES (910006, 'p2-exec-comment') */",
			"INSERT INTO scratch.t_write_probe SELECT 910007, 'p2-select' INTO OUTFILE 'file:///tmp/p2'",
			"SELECT * FROM FILES('path'='file:///etc/hostname','format'='csv')",
			"SELECT get_query_profile('00000000-0000-0000-0000-000000000000')",
			"SELECT 1 INTO OUTFILE 'file:///tmp/p2-outfile'",
			"TRUNCATE TABLE scratch.t_write_probe",
		} {
			if got, err := Run(ctx, wcfg, Params{SQL: sql}); !errors.Is(err, sqlguard.ErrRejected) || got != (Result{}) {
				t.Errorf("%.60q: got %+v, %v; want a rejection", sql, got, err)
			}
		}
		// In StarRocks \' does not end a string, so the guard reads this as one
		// string followed by garbage, as the server does: it is not rejected, the
		// server reports a syntax error (1064), and nothing is written.
		escape := "SELECT 'x\\' ; INSERT INTO scratch.t_write_probe VALUES (910005, 'p2-escape') ; --'"
		if got, err := Run(ctx, wcfg, Params{SQL: escape}); err == nil || errors.Is(err, sqlguard.ErrRejected) || err.Error() != "starrocks query failed (code 1064)" || got != (Result{}) {
			t.Errorf("backslash escape: got %+v, %v; want a server syntax error", got, err)
		}
		if got := count(); got != "n\n0\n" {
			t.Fatalf("a rejected statement was executed: %q", got)
		}
	})
}
