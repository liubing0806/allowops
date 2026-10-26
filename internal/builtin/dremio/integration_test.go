package dremio

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/liubing0806/allowops/internal/builtin/credfile"
	"github.com/liubing0806/allowops/internal/builtin/sqlguard"
)

// The integration tests need the local environment of test/starrocks-dremio
// (./test/starrocks-dremio/up.sh). They run only when ALLOWOPS_DREMIO_URL is
// set, for example to http://127.0.0.1:29047. Account passwords are read from
// ALLOWOPS_DREMIO_STATE (default: test/starrocks-dremio/.state) inside the test
// process; they are never logged, passed in arguments or written to files.
//
// The checks that a rejected statement was not executed also need the
// StarRocks root account and ALLOWOPS_STARROCKS_ADDR (for example
// 127.0.0.1:29030) to look at the data source behind Dremio.
//
// ALLOWOPS_DREMIO_SOURCE and ALLOWOPS_DREMIO_SCRATCH_SOURCE name the Dremio data
// sources that point at the demo_dw tables and at the scratch database.
//
// The credential file of the handler must be root-owned, which a test process
// is not. The tests replace readCredential with a reader of the state file and
// run everything else of RunRedacted unchanged. The ownership and mode checks
// belong to package credfile and are tested there.
const (
	envURL    = "ALLOWOPS_DREMIO_URL"
	envState  = "ALLOWOPS_DREMIO_STATE"
	envSRAddr = "ALLOWOPS_STARROCKS_ADDR"
	// The names of the Dremio data sources that point at the StarRocks of the
	// local environment: one with the demo_dw tables, one with the scratch database.
	envSource  = "ALLOWOPS_DREMIO_SOURCE"
	envScratch = "ALLOWOPS_DREMIO_SCRATCH_SOURCE"
)

// expand replaces {src} and {scratch} in a statement by the quoted names of the
// data sources.
func expand(sql string) string {
	return strings.NewReplacer("{src}", `"`+os.Getenv(envSource)+`"`, "{scratch}", `"`+os.Getenv(envScratch)+`"`).Replace(sql)
}

func integrationURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv(envURL)
	if u == "" {
		t.Skipf("%s is not set; start the local environment (test/starrocks-dremio/up.sh) and set it to the Dremio REST address, for example http://127.0.0.1:29047", envURL)
	}
	return u
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

// integration prepares the public pipeline: the credential comes from the state file.
func integration(t *testing.T) (Config, credfile.Credential) {
	t.Helper()
	base := integrationURL(t)
	for _, env := range []string{envSource, envScratch} {
		if os.Getenv(env) == "" {
			t.Skipf("%s is not set; set it to the name of a Dremio data source of the local environment", env)
		}
	}
	cred := stateCredential(t, "dremio_user")
	original := readCredential
	readCredential = func(string) (credfile.Credential, error) { return cred, nil }
	t.Cleanup(func() { readCredential = original })
	return Config{Credential: testCredPath, URL: base, MaxRows: 500, MaxBytes: 1 << 20, Timeout: 10 * time.Second}, cred
}

func query(t *testing.T, cfg Config, sql string) Result {
	t.Helper()
	result, err := RunRedacted(context.Background(), cfg, Params{SQL: expand(sql)}, nil)
	if err != nil {
		t.Fatalf("%q: %v", sql, err)
	}
	return result
}

// execUnchecked runs a statement without the lexical guard, like runQuery in
// the handler would. Only these tests do this: to run a statement that the
// guard rejects on purpose and to prove that the checks below can see a change.
func execUnchecked(ctx context.Context, cfg Config, sql string, cred credfile.Credential) (Result, error) {
	cfg = cfg.normalized()
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	return runQuery(ctx, cfg, Params{SQL: expand(sql)}, cred, nil)
}

func TestIntegrationReadQueries(t *testing.T) {
	cfg, _ := integration(t)

	t.Run("select", func(t *testing.T) {
		got := query(t, cfg, `SELECT count(*) AS n FROM {src}.demo_dw.dim_user`)
		if got.Output != "n\n10000\n" || got.Rows != 1 || got.Truncated {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("join and aggregate", func(t *testing.T) {
		got := query(t, cfg, `SELECT p.category, count(*) AS c FROM {src}.demo_dw.fact_orders f JOIN {src}.demo_dw.dim_product p ON f.product_id = p.product_id WHERE f.store_id = 3 GROUP BY p.category ORDER BY p.category`)
		if !strings.HasPrefix(got.Output, "category\tc\n") || got.Rows == 0 || got.Truncated {
			t.Fatalf("got %+v", got)
		}
		total := 0
		for _, line := range strings.Split(strings.TrimSpace(got.Output), "\n")[1:] {
			var n int
			if _, err := fmt.Sscanf(line[strings.LastIndex(line, "\t")+1:], "%d", &n); err != nil {
				t.Fatalf("count in %q: %v", line, err)
			}
			total += n
		}
		want := query(t, cfg, `SELECT count(*) AS c FROM {src}.demo_dw.fact_orders WHERE store_id = 3`)
		if want.Output != fmt.Sprintf("c\n%d\n", total) {
			t.Errorf("grouped counts add up to %d, direct count is %q", total, want.Output)
		}
	})
	t.Run("with and values", func(t *testing.T) {
		got := query(t, cfg, `WITH c AS (SELECT city, count(*) AS n FROM {src}.demo_dw.dim_user GROUP BY city) SELECT count(*) AS cities FROM c`)
		if got.Rows != 1 || !strings.HasPrefix(got.Output, "cities\n") {
			t.Fatalf("got %+v", got)
		}
		got = query(t, cfg, `VALUES (1, 'a'), (2, 'b')`)
		if got.Output != "EXPR$0\tEXPR$1\n1\ta\n2\tb\n" {
			t.Fatalf("got %q", got.Output)
		}
	})
	t.Run("explain plan", func(t *testing.T) {
		for _, sql := range []string{
			`EXPLAIN PLAN FOR SELECT count(*) FROM {src}.demo_dw.fact_orders WHERE store_id = 3`,
			`EXPLAIN PLAN WITH IMPLEMENTATION FOR SELECT count(*) FROM {src}.demo_dw.fact_orders WHERE store_id = 3`,
		} {
			got := query(t, cfg, sql)
			if !strings.HasPrefix(got.Output, "text\n") || got.Rows != 1 || !strings.Contains(got.Output, "fact_orders") {
				t.Errorf("%s: %.200q", sql, got.Output)
			}
		}
	})
	t.Run("show", func(t *testing.T) {
		got := query(t, cfg, `SHOW SCHEMAS`)
		if !strings.HasPrefix(got.Output, "SCHEMA_NAME\n") || !strings.Contains(got.Output, "demo_dw") || got.Truncated {
			t.Errorf("SHOW SCHEMAS: %q", got.Output)
		}
		got = query(t, cfg, `SHOW TABLES IN {src}.demo_dw`)
		for _, table := range []string{"dim_user", "dim_product", "fact_orders"} {
			if !strings.Contains(got.Output, table) {
				t.Errorf("SHOW TABLES lacks %s: %q", table, got.Output)
			}
		}
		got = query(t, cfg, `SHOW CREATE TABLE {src}.demo_dw.dim_user`)
		if got.Rows != 1 || !strings.Contains(got.Output, "CREATE TABLE") || !strings.Contains(got.Output, `\n`) {
			t.Errorf("SHOW CREATE TABLE: %.200q", got.Output)
		}
		got = query(t, cfg, `SHOW PARTITIONS {src}.demo_dw.dim_user`)
		if !strings.HasPrefix(got.Output, "PARTITION_NAME\t") {
			t.Errorf("SHOW PARTITIONS: %.200q", got.Output)
		}
	})
	t.Run("describe", func(t *testing.T) {
		for _, sql := range []string{`DESCRIBE {src}.demo_dw.fact_orders`, `DESC {src}.demo_dw.fact_orders`} {
			got := query(t, cfg, sql)
			if !strings.HasPrefix(got.Output, "COLUMN_NAME\tDATA_TYPE\t") || !strings.Contains(got.Output, "order_id") {
				t.Errorf("%s: %.200q", sql, got.Output)
			}
		}
	})
	t.Run("null nested and numbers", func(t *testing.T) {
		got := query(t, cfg, `SELECT CAST(NULL AS VARCHAR) AS nothing, CAST(9223372036854775807 AS BIGINT) AS big, CAST(1.0 AS FLOAT) AS f, TRUE AS flag, 'tab' || CHR(9) || 'x' AS tabbed`)
		if got.Output != "nothing\tbig\tf\tflag\ttabbed\n"+`\N`+"\t9223372036854775807\t1.0\ttrue\t"+`tab\tx`+"\n" {
			t.Fatalf("got %q", got.Output)
		}
		got = query(t, cfg, `SELECT CONVERT_FROM('{"a":1.0,"b":[1,2],"s":"x"}', 'json') AS j`)
		if got.Output != "j\n"+`{"a":1.0,"b":[1,2],"s":"x"}`+"\n" {
			t.Fatalf("nested value: %q", got.Output)
		}
		// Dremio sends DECIMAL as a JSON number with every digit; a conversion
		// through float64 would turn this into 1.2345678901234567e+19.
		got = query(t, cfg, `SELECT CAST('12345678901234567890.123456789' AS DECIMAL(38,9)) AS d, CAST(CAST('12345678901234567890.123456789' AS DECIMAL(38,9)) AS VARCHAR) AS s`)
		if got.Output != "d\ts\n12345678901234567890.123456789\t12345678901234567890.123456789\n" {
			t.Fatalf("decimal: %q", got.Output)
		}
	})
	t.Run("truncation", func(t *testing.T) {
		const users = `SELECT user_id FROM {src}.demo_dw.dim_user`
		for _, tc := range []struct {
			name      string
			maxRows   int
			sql       string
			wantRows  int
			wantTrunc bool
		}{
			{"default page", 0, users, 500, true},
			{"max_rows 7", 7, users, 7, true},
			{"exactly max_rows", 7, users + " LIMIT 7", 7, false},
			{"one over max_rows", 7, users + " LIMIT 8", 7, true},
			{"exactly a page", 0, users + " LIMIT 500", 500, false},
			{"one over a page", 0, users + " LIMIT 501", 500, true},
			{"below a page", 0, users + " LIMIT 499", 499, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := cfg
				c.MaxRows = tc.maxRows
				got := query(t, c, tc.sql)
				if got.Rows != tc.wantRows || got.Truncated != tc.wantTrunc || strings.Count(got.Output, "\n") != tc.wantRows+1 {
					t.Errorf("rows=%d truncated=%v lines=%d; want %d, %v", got.Rows, got.Truncated, strings.Count(got.Output, "\n"), tc.wantRows, tc.wantTrunc)
				}
			})
		}
		// SHOW reports rowCount 0 whatever it returns, so it is cut by the rows read.
		all := query(t, cfg, `SHOW SCHEMAS`)
		if all.Rows < 4 || all.Truncated {
			t.Fatalf("SHOW SCHEMAS: %+v", all)
		}
		for _, tc := range []struct {
			maxRows, wantRows int
			wantTrunc         bool
		}{{all.Rows, all.Rows, false}, {all.Rows - 1, all.Rows - 1, true}, {1, 1, true}} {
			c := cfg
			c.MaxRows = tc.maxRows
			if got := query(t, c, `SHOW SCHEMAS`); got.Rows != tc.wantRows || got.Truncated != tc.wantTrunc {
				t.Errorf("SHOW SCHEMAS with max_rows %d: rows=%d truncated=%v", tc.maxRows, got.Rows, got.Truncated)
			}
		}
		c := cfg
		c.MaxBytes = 200
		got := query(t, c, `SELECT user_name FROM {src}.demo_dw.dim_user`)
		if len(got.Output) > 200 || !got.Truncated || got.Rows == 0 {
			t.Errorf("max_bytes 200: %d bytes, rows=%d truncated=%v", len(got.Output), got.Rows, got.Truncated)
		}
	})
	t.Run("job failure", func(t *testing.T) {
		_, err := RunRedacted(context.Background(), cfg, Params{SQL: expand(`SELECT * FROM {src}.demo_dw.no_such_table`)}, nil)
		if err == nil || err.Error() != "dremio job FAILED (object not found)" {
			t.Fatalf("got %v", err)
		}
		// A statement that the guard accepts and the server's parser refuses.
		_, err = RunRedacted(context.Background(), cfg, Params{SQL: `SELECT secret_marker_xyz FROM`}, nil)
		if err == nil || !strings.HasPrefix(err.Error(), "dremio job FAILED (") || strings.Contains(err.Error(), "secret_marker_xyz") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("login failure", func(t *testing.T) {
		wrong := credfile.Credential{Username: "no-such-user", Password: "wrong-password-1"}
		previous := readCredential
		defer func() { readCredential = previous }()
		readCredential = func(string) (credfile.Credential, error) { return wrong, nil }
		_, err := RunRedacted(context.Background(), cfg, Params{SQL: "SELECT 1"}, nil)
		if err == nil || err.Error() != "dremio login failed (status 401)" || strings.Contains(err.Error(), wrong.Password) {
			t.Fatalf("got %v", err)
		}
	})
}

// A logout must invalidate the token: sessions last 720 hours, so a token
// that survives would pile up with every call.
func TestIntegrationLogoutInvalidatesToken(t *testing.T) {
	cfg, cred := integration(t)
	c := newClient(cfg.URL)
	ctx := context.Background()
	token, err := c.login(ctx, cred)
	if err != nil {
		t.Fatal(err)
	}
	status := func() int {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.URL+"/api/v3/catalog", nil)
		req.Header.Set("Authorization", "_dremio"+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if got := status(); got != 200 {
		t.Fatalf("catalog with a fresh token: %d", got)
	}
	if err := c.logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if got := status(); got != 401 {
		t.Fatalf("catalog after logout: %d; want 401", got)
	}
}

type jobInfo struct{ ID, State, QueryText string }

// dremioJobs lists recent jobs of the cluster through the job listing.
func dremioJobs(t *testing.T, cfg Config, cred credfile.Credential) []jobInfo {
	t.Helper()
	ctx := context.Background()
	c := newClient(cfg.URL)
	token, err := c.login(ctx, cred)
	if err != nil {
		t.Fatal(err)
	}
	defer c.logout(ctx, token)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.URL+"/apiv2/jobs-listing/v1.0?limit=30&offset=0&sort=st&order=DESCENDING", nil)
	req.Header.Set("Authorization", "_dremio"+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var listing struct {
		Jobs []struct {
			ID        string `json:"id"`
			State     string `json:"state"`
			QueryText string `json:"queryText"`
		} `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil || resp.StatusCode != 200 {
		t.Fatalf("job listing: status %d, %v", resp.StatusCode, err)
	}
	out := make([]jobInfo, len(listing.Jobs))
	for i, j := range listing.Jobs {
		out[i] = jobInfo{j.ID, j.State, j.QueryText}
	}
	return out
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// A timeout cancels the job on the Dremio side: the job listing shows it as CANCELED.
func TestIntegrationTimeoutCancelsJob(t *testing.T) {
	cfg, cred := integration(t)
	cfg.Timeout = 2 * time.Second
	marker := "p3-timeout-" + randomHex(t, 6)
	// A self join on a sum has no join key, so it runs far longer than the timeout.
	sql := `SELECT count(*) AS c FROM {src}.demo_dw.fact_orders a, {src}.demo_dw.fact_orders b WHERE a.order_id + b.order_id = 7919 /* ` + marker + ` */`
	if _, err := sqlguard.Validate(sqlguard.Dremio, expand(sql), sqlguard.Options{}); err != nil {
		t.Fatalf("the guard rejects the slow query: %v", err)
	}
	start := time.Now()
	_, err := RunRedacted(context.Background(), cfg, Params{SQL: expand(sql)}, nil)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v after %v; want the deadline error", err, elapsed)
	}
	if elapsed > cfg.Timeout+cleanupTimeout+time.Second {
		t.Errorf("returned after %v for a timeout of %v", elapsed, cfg.Timeout)
	}
	var id, state string
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		for _, j := range dremioJobs(t, cfg, cred) {
			if strings.Contains(j.QueryText, marker) {
				id, state = j.ID, j.State
			}
		}
		if state == "CANCELED" {
			break
		}
	}
	if id == "" || state != "CANCELED" {
		t.Fatalf("job %q is %q on the Dremio side; want CANCELED", id, state)
	}
}

// The same through a cancelled context.
func TestIntegrationContextCancelCancelsJob(t *testing.T) {
	cfg, cred := integration(t)
	marker := "p3-cancel-" + randomHex(t, 6)
	sql := `SELECT count(*) AS c FROM {src}.demo_dw.fact_orders a, {src}.demo_dw.fact_orders b WHERE a.order_id + b.order_id = 7919 /* ` + marker + ` */`
	ctx, stop := context.WithCancel(context.Background())
	go func() {
		time.Sleep(1500 * time.Millisecond)
		stop()
	}()
	_, err := RunRedacted(ctx, cfg, Params{SQL: expand(sql)}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v; want context.Canceled", err)
	}
	var state string
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && state != "CANCELED"; time.Sleep(500 * time.Millisecond) {
		for _, j := range dremioJobs(t, cfg, cred) {
			if strings.Contains(j.QueryText, marker) {
				state = j.State
			}
		}
	}
	if state != "CANCELED" {
		t.Fatalf("job is %q on the Dremio side; want CANCELED", state)
	}
}

// starRocksRoot opens the StarRocks behind the data sources, to prepare data
// and to look at it after a rejected statement.
func starRocksRoot(t *testing.T) *sql.DB {
	t.Helper()
	addr := os.Getenv(envSRAddr)
	if addr == "" {
		t.Skipf("%s is not set; set it to the StarRocks FE address of the local environment, for example 127.0.0.1:29030", envSRAddr)
	}
	root := stateCredential(t, "sr_root")
	dc := mysqldriver.NewConfig()
	dc.User, dc.Passwd, dc.Net, dc.Addr, dc.Timeout = root.Username, root.Password, "tcp", strings.TrimPrefix(addr, "tcp://"), 10*time.Second
	connector, err := mysqldriver.NewConnector(dc)
	if err != nil {
		t.Fatal("configure the StarRocks connection")
	}
	db := sql.OpenDB(connector)
	t.Cleanup(func() { db.Close() })
	return db
}

func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// Statements that the guard rejects must not reach the server. The data
// source behind Dremio (StarRocks, account with write grants on the scratch
// database) shows whether anything ran. Each case has a control: the same
// statement without the guard does change the data, so the check can fail.
func TestIntegrationRejectedStatementsAreNotExecuted(t *testing.T) {
	cfg, cred := integration(t)
	sr := starRocksRoot(t)
	table := "p3_probe_" + randomHex(t, 4)
	scratch := "scratch." + table
	if _, err := sr.Exec(fmt.Sprintf(`CREATE TABLE %s (id INT, note VARCHAR(64)) DUPLICATE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 1 PROPERTIES ("replication_num"="1")`, scratch)); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	t.Cleanup(func() { _, _ = sr.Exec("DROP TABLE IF EXISTS " + scratch + " FORCE") })
	dremioTable := `{scratch}.scratch.` + table
	seed := func(t *testing.T) {
		t.Helper()
		if _, err := sr.Exec("TRUNCATE TABLE " + scratch); err != nil {
			t.Fatal(err)
		}
		if _, err := sr.Exec(fmt.Sprintf("INSERT INTO %s VALUES (1, 'seed'), (2, 'seed')", scratch)); err != nil {
			t.Fatal(err)
		}
		if n := countRows(t, sr, scratch); n != 2 {
			t.Fatalf("seeded %d rows", n)
		}
	}
	rejected := func(t *testing.T, sql string) {
		t.Helper()
		result, err := RunRedacted(context.Background(), cfg, Params{SQL: expand(sql)}, nil)
		if !errors.Is(err, sqlguard.ErrRejected) || result != (Result{}) {
			t.Fatalf("%.80q: got %+v, %v; want a guard rejection", sql, result, err)
		}
	}
	view := "p3_view_" + randomHex(t, 4)
	homeView := fmt.Sprintf(`"@%s".%s`, cred.Username, view)
	viewExists := func() bool {
		_, err := execUnchecked(context.Background(), cfg, "SELECT count(*) AS n FROM "+homeView, cred)
		return err == nil
	}
	t.Cleanup(func() { _, _ = execUnchecked(context.Background(), cfg, "DROP VIEW IF EXISTS "+homeView, cred) })

	t.Run("external_query write", func(t *testing.T) {
		seed(t)
		insert := fmt.Sprintf(`SELECT * FROM TABLE({scratch}.external_query('INSERT INTO scratch.%s VALUES (9, ''external'')'))`, table)
		rejected(t, insert)
		rejected(t, "EXPLAIN PLAN FOR "+insert)
		rejected(t, "EXPLAIN PLAN WITH IMPLEMENTATION FOR "+insert)
		rejected(t, fmt.Sprintf(`SELECT * FROM TABLE({scratch}.external_query('DELETE FROM scratch.%s'))`, table))
		if n := countRows(t, sr, scratch); n != 2 {
			t.Fatalf("%d rows after the rejected statements; want the 2 seeded rows", n)
		}
		// Control: without the guard, Dremio runs the write even inside EXPLAIN PLAN FOR.
		_, _ = execUnchecked(context.Background(), cfg, "EXPLAIN PLAN FOR "+insert, cred)
		if n := countRows(t, sr, scratch); n != 3 {
			t.Fatalf("control: %d rows after the unchecked EXPLAIN PLAN FOR; want 3, so this check could not have seen a write", n)
		}
	})
	t.Run("truncate", func(t *testing.T) {
		seed(t)
		rejected(t, "TRUNCATE TABLE "+dremioTable)
		rejected(t, "TRUNCATE "+dremioTable)
		rejected(t, "SELECT 1; TRUNCATE TABLE "+dremioTable)
		if n := countRows(t, sr, scratch); n != 2 {
			t.Fatalf("%d rows after the rejected statements; want 2", n)
		}
		if _, err := execUnchecked(context.Background(), cfg, "TRUNCATE TABLE "+dremioTable, cred); err != nil {
			t.Fatalf("control TRUNCATE: %v", err)
		}
		if n := countRows(t, sr, scratch); n != 0 {
			t.Fatalf("control: %d rows after the unchecked TRUNCATE; want 0", n)
		}
	})
	t.Run("create view", func(t *testing.T) {
		create := "CREATE VIEW " + homeView + ` AS SELECT user_id FROM {src}.demo_dw.dim_user`
		rejected(t, create)
		rejected(t, "CREATE OR REPLACE VIEW "+homeView+` AS SELECT 1 AS one`)
		if viewExists() {
			t.Fatal("the view exists after the rejected statements")
		}
		if _, err := execUnchecked(context.Background(), cfg, create, cred); err != nil {
			t.Fatalf("control CREATE VIEW: %v", err)
		}
		if !viewExists() {
			t.Fatal("control: the view does not exist after the unchecked CREATE VIEW")
		}
	})
	t.Run("alter system", func(t *testing.T) {
		const option = `SELECT * FROM sys.options WHERE name = 'planner.slice_target'`
		before := query(t, cfg, option)
		if before.Rows != 1 {
			t.Fatalf("option row: %q", before.Output)
		}
		rejected(t, `ALTER SYSTEM SET "planner.slice_target" = 12345`)
		rejected(t, `ALTER SYSTEM RESET "planner.slice_target"`)
		rejected(t, `ALTER SESSION SET "planner.slice_target" = 12345`)
		rejected(t, `ALTER SYSTEM SET "planner.slice_target" = 12345; SELECT 1`)
		if after := query(t, cfg, option); after.Output != before.Output {
			t.Fatalf("system option changed:\nbefore %q\n after %q", before.Output, after.Output)
		}
	})
	t.Run("multiple statements", func(t *testing.T) {
		seed(t)
		rejected(t, fmt.Sprintf("SELECT 1; INSERT INTO %s VALUES (8, 'multi')", dremioTable))
		rejected(t, fmt.Sprintf("SELECT 1;\nDELETE FROM %s", dremioTable))
		rejected(t, "SELECT 1; SELECT 2")
		if n := countRows(t, sr, scratch); n != 2 {
			t.Fatalf("%d rows after the rejected statements; want 2", n)
		}
	})
	t.Run("insert and drop", func(t *testing.T) {
		seed(t)
		rejected(t, fmt.Sprintf("INSERT INTO %s SELECT 5, 'insert'", dremioTable))
		rejected(t, "DROP TABLE "+dremioTable)
		rejected(t, "DELETE FROM "+dremioTable)
		if n := countRows(t, sr, scratch); n != 2 {
			t.Fatalf("%d rows after the rejected statements; want 2", n)
		}
	})
}
