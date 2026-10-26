package starrocks

import (
	"context"
	sqldriver "database/sql/driver"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/liubing0806/allowops/internal/builtin/credfile"
	"github.com/liubing0806/allowops/internal/builtin/sqlguard"
)

func baseConfig() Config {
	return Config{Credential: "/etc/allowops/credentials/starrocks.json", Address: "tcp://127.0.0.1:9030"}
}

// missingCredential points at a file that does not exist: a request that gets
// as far as reading it fails with "cannot open credential file", and a request
// that is rejected earlier never reaches it.
func missingCredential() Config {
	return Config{Credential: "/missing/starrocks.json", Address: "tcp://127.0.0.1:1"}
}

func TestConfigValidate(t *testing.T) {
	base := baseConfig()
	for _, address := range []string{base.Address, "tcp://[::1]:9030", "tcp://fe.example.internal:9030"} {
		c := base
		c.Address = address
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", address, err)
		}
	}
	for _, address := range []string{
		"", "127.0.0.1:9030", "localhost:9030", "tcp://localhost", "tcp://user:pass@host:9030", "tcp://host:9030?multiStatements=true",
		"tcp://host:9030/", "tcp://host:0", "tcp://host:65536", "tcp://:9030", "tcp://host:9030#frag",
		"unix:///tmp/starrocks.sock", "unix://host/tmp/sock", "http://host:9030",
	} {
		c := base
		c.Address = address
		if c.Validate() == nil {
			t.Errorf("accepted address %q", address)
		}
	}
	for _, c := range []Config{
		{Credential: "relative", Address: base.Address},
		{Credential: "", Address: base.Address},
		{Credential: base.Credential, Address: base.Address, MaxRows: -1},
		{Credential: base.Credential, Address: base.Address, MaxRows: 501},
		{Credential: base.Credential, Address: base.Address, MaxBytes: -1},
		{Credential: base.Credential, Address: base.Address, MaxBytes: 1<<20 + 1},
		{Credential: base.Credential, Address: base.Address, Timeout: -1},
		{Credential: base.Credential, Address: base.Address, Timeout: time.Nanosecond},
		{Credential: base.Credential, Address: base.Address, Timeout: 11 * time.Second},
	} {
		if c.Validate() == nil {
			t.Errorf("accepted invalid config %+v", c)
		}
	}
	for _, c := range []Config{
		{Credential: base.Credential, Address: base.Address, MaxRows: 500, MaxBytes: 1 << 20, Timeout: 10 * time.Second},
		{Credential: base.Credential, Address: base.Address, MaxRows: 1, MaxBytes: 1, Timeout: time.Millisecond},
	} {
		if err := c.Validate(); err != nil {
			t.Errorf("rejected tightened config %+v: %v", c, err)
		}
	}
}

func TestConfigDefaults(t *testing.T) {
	got := baseConfig().normalized()
	if got.MaxRows != 500 || got.MaxBytes != 1<<20 || got.Timeout != 10*time.Second {
		t.Fatalf("defaults: %+v", got)
	}
	c := baseConfig()
	c.MaxRows, c.MaxBytes, c.Timeout = 7, 1024, 2*time.Second
	if got := c.normalized(); got.MaxRows != 7 || got.MaxBytes != 1024 || got.Timeout != 2*time.Second {
		t.Fatalf("tightened values must be kept: %+v", got)
	}
}

func TestConfigRestrictionLists(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*Config)
		wantErr string // empty: valid
	}{
		{"statement_types subset", func(c *Config) { c.StatementTypes = []string{"SELECT", "EXPLAIN"} }, ""},
		{"statement_types all", func(c *Config) { c.StatementTypes = []string{"SELECT", "SHOW", "DESCRIBE", "EXPLAIN"} }, ""},
		{"statement_types case-insensitive", func(c *Config) { c.StatementTypes = []string{"select"} }, ""},
		{"statement_types empty", func(c *Config) { c.StatementTypes = []string{} }, "statement_types"},
		{"statement_types unknown", func(c *Config) { c.StatementTypes = []string{"DELETE"} }, "SELECT, SHOW, DESCRIBE, EXPLAIN"},
		{"statement_types analyze profile", func(c *Config) { c.StatementTypes = []string{"ANALYZE PROFILE"} }, "statement_types"},
		{"show_types subset", func(c *Config) { c.ShowTypes = []string{"TABLES", "CREATE TABLE", "COLUMNS"} }, ""},
		{"show_types case-insensitive", func(c *Config) { c.ShowTypes = []string{"tables"} }, ""},
		{"show_types empty", func(c *Config) { c.ShowTypes = []string{} }, "show_types"},
		{"show_types unknown", func(c *Config) { c.ShowTypes = []string{"SELECT"} }, "TABLES"},
		{"show_types profilelist", func(c *Config) { c.ShowTypes = []string{"TABLES", "PROFILELIST"} }, "PROFILELIST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := baseConfig()
			tc.mutate(&c)
			err := c.Validate()
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("got %v; want error containing %q", err, tc.wantErr)
			}
		})
	}
	// Every SHOW type except PROFILELIST can be listed.
	for _, name := range sqlguard.ShowTypes(sqlguard.StarRocks) {
		c := baseConfig()
		c.ShowTypes = []string{name}
		if err := c.Validate(); (name == "PROFILELIST") == (err == nil) {
			t.Errorf("show_types [%s]: %v", name, err)
		}
	}
}

func TestParamsAndCancellationBeforeIO(t *testing.T) {
	c := missingCredential()
	for _, database := range []string{"a-b", "a;DROP DATABASE x", "x/y", "数据库", strings.Repeat("x", 65), "x\n", "x y"} {
		_, err := Run(context.Background(), c, Params{Database: database, SQL: "SELECT 1"})
		if err == nil || err.Error() != "invalid database name" {
			t.Errorf("%q: %v", database, err)
		}
	}
	// An empty database is allowed: the connection has no default database.
	// A valid database name reaches the credential file.
	for _, database := range []string{"", "demo_dw", strings.Repeat("x", 64)} {
		_, err := Run(context.Background(), c, Params{Database: database, SQL: "SELECT 1"})
		if err == nil || err.Error() != "cannot open credential file" {
			t.Errorf("%q: %v", database, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := Run(ctx, c, Params{Database: database, SQL: "SELECT 1"}); !errors.Is(err, context.Canceled) {
			t.Errorf("cancelled %q: %v", database, err)
		}
	}
	if _, err := Run(context.Background(), Config{Credential: "relative", Address: "tcp://127.0.0.1:1"}, Params{SQL: "SELECT 1"}); err == nil || err.Error() != "credential must be an absolute file path" {
		t.Errorf("invalid config: %v", err)
	}
}

// Each statement must be rejected by the lexical guard before the credential
// file is read and before any connection is made.
func TestSQLRejectedBeforeCredentialIO(t *testing.T) {
	for _, sql := range []string{
		"", "   ", "INSERT INTO t VALUES (1)", "DELETE FROM t", "UPDATE t SET a = 1", "DROP TABLE t", "CREATE TABLE t (id INT)",
		"TRUNCATE TABLE t", "SET query_timeout = 3600", "USE demo_dw", "KILL 1",
		// The server drops '#' and parses the rest, so a statement after '#' runs.
		"SELECT 1 # ; INSERT INTO t VALUES (1)", "SELECT 1 #", "SELECT # 1",
		// The server runs every statement of one request.
		"SELECT 1; INSERT INTO t VALUES (1)", "SELECT 1; SELECT 2", "SELECT 1;;",
		// File and profile access that a SELECT-only account has.
		"SELECT * FROM t INTO OUTFILE 'file:///tmp/x'", "SELECT * FROM t INTO DUMPFILE '/tmp/x'",
		"SELECT * FROM FILES('path'='file:///etc/hostname','format'='csv')",
		"SELECT get_query_profile('abc')", "SELECT sleep(1)", "SELECT /*+ SET_VAR(query_timeout=3600) */ 1",
		"EXPLAIN ANALYZE SELECT 1", "SELECT 1 /*! + 1 */",
		"SELECT 'unterminated", "SELECT 1 /* unterminated", strings.Repeat("x", 4001),
	} {
		result, err := Run(context.Background(), missingCredential(), Params{Database: "demo_dw", SQL: sql})
		if !errors.Is(err, sqlguard.ErrRejected) || result != (Result{}) {
			t.Errorf("%.40q: got %+v, %v; want a rejection before credential IO", sql, result, err)
		}
		if err != nil && strings.Contains(err.Error(), "cannot open credential file") {
			t.Errorf("%.40q read the credential file", sql)
		}
	}
}

func TestAcceptedSQLReachesCredential(t *testing.T) {
	for _, sql := range []string{
		"SELECT 1", "select * from demo_dw.fact_orders limit 3", "SELECT a.x FROM default_catalog.demo_dw.t a", "SELECT 1;",
		"WITH c AS (SELECT 1) SELECT * FROM c", "(SELECT 1) UNION ALL (SELECT 2)", "SELECT array_map(x -> x + 1, [1,2])",
		"SHOW TABLES", "SHOW DATABASES", "SHOW CREATE TABLE demo_dw.fact_orders", "SHOW FULL COLUMNS FROM demo_dw.fact_orders", "SHOW PARTITIONS FROM demo_dw.fact_orders",
		"DESC demo_dw.fact_orders", "DESCRIBE demo_dw.fact_orders",
		"EXPLAIN SELECT 1", "EXPLAIN LOGICAL SELECT 1", "EXPLAIN VERBOSE SELECT 1", "EXPLAIN COSTS SELECT 1",
		"SELECT count(*) FROM `demo_dw`.`fact_orders` WHERE a = '#'", "SELECT 1 -- comment",
	} {
		_, err := Run(context.Background(), missingCredential(), Params{Database: "demo_dw", SQL: sql})
		if err == nil || err.Error() != "cannot open credential file" {
			t.Errorf("%.50q: %v", sql, err)
		}
	}
}

// SHOW PROFILELIST and ANALYZE PROFILE read other accounts' statements and
// profiles. No configuration can turn them on.
func TestProfileStatementsAlwaysRejected(t *testing.T) {
	configs := []func(*Config){
		func(*Config) {},
		func(c *Config) { c.StatementTypes = []string{"SELECT", "SHOW", "DESCRIBE", "EXPLAIN"} },
		func(c *Config) { c.ShowTypes = []string{"TABLES", "DATABASES"} },
		func(c *Config) { c.AllowExplainAnalyze = true },
	}
	for _, sql := range []string{
		"SHOW PROFILELIST", "show profilelist limit 5", "SHOW FULL PROFILELIST",
		"ANALYZE PROFILE FROM 'a1b2c3d4-0000-0000-0000-000000000000'", "ANALYZE PROFILE FROM 'abc', 0",
	} {
		for i, mutate := range configs {
			c := missingCredential()
			mutate(&c)
			result, err := Run(context.Background(), c, Params{SQL: sql})
			if !errors.Is(err, sqlguard.ErrRejected) || !strings.Contains(err.Error(), "profile") || result != (Result{}) {
				t.Errorf("config %d %q: got %+v, %v", i, sql, result, err)
			}
		}
	}
}

func TestStatementTypeRestrictions(t *testing.T) {
	for _, tc := range []struct {
		name           string
		mutate         func(*Config)
		sql, wantError string // wantError empty: reaches the credential file
	}{
		{"select only, SELECT", func(c *Config) { c.StatementTypes = []string{"SELECT"} }, "SELECT 1", ""},
		{"select only, WITH", func(c *Config) { c.StatementTypes = []string{"SELECT"} }, "WITH c AS (SELECT 1) SELECT * FROM c", ""},
		{"select only, SHOW", func(c *Config) { c.StatementTypes = []string{"SELECT"} }, "SHOW TABLES", "statement_types"},
		{"select only, DESC", func(c *Config) { c.StatementTypes = []string{"SELECT"} }, "DESC t", "statement_types"},
		{"select only, EXPLAIN", func(c *Config) { c.StatementTypes = []string{"SELECT"} }, "EXPLAIN SELECT 1", "statement_types"},
		{"show only, SELECT", func(c *Config) { c.StatementTypes = []string{"SHOW"} }, "SELECT 1", "statement_types"},
		{"show only, SHOW", func(c *Config) { c.StatementTypes = []string{"SHOW"} }, "SHOW TABLES", ""},
		{"describe only, DESC", func(c *Config) { c.StatementTypes = []string{"DESCRIBE"} }, "DESC t", ""},
		{"describe only, SHOW COLUMNS", func(c *Config) { c.StatementTypes = []string{"DESCRIBE"} }, "SHOW COLUMNS FROM t", "statement_types"},
		// The EXPLAIN target must satisfy statement_types too, as in mysql_query (G31).
		{"explain only, EXPLAIN SELECT", func(c *Config) { c.StatementTypes = []string{"EXPLAIN"} }, "EXPLAIN SELECT 1", "statement_types"},
		{"explain and select", func(c *Config) { c.StatementTypes = []string{"EXPLAIN", "SELECT"} }, "EXPLAIN SELECT 1", ""},
		{"explain and select, EXPLAIN VERBOSE", func(c *Config) { c.StatementTypes = []string{"explain", "select"} }, "EXPLAIN VERBOSE SELECT 1", ""},
		{"explain and select, SHOW", func(c *Config) { c.StatementTypes = []string{"EXPLAIN", "SELECT"} }, "SHOW TABLES", "statement_types"},
		{"show_types TABLES, SHOW TABLES", func(c *Config) { c.ShowTypes = []string{"TABLES"} }, "SHOW TABLES", ""},
		{"show_types TABLES, SHOW FULL TABLES", func(c *Config) { c.ShowTypes = []string{"TABLES"} }, "SHOW FULL TABLES FROM demo_dw", ""},
		{"show_types TABLES, SHOW DATABASES", func(c *Config) { c.ShowTypes = []string{"TABLES"} }, "SHOW DATABASES", "show_types"},
		{"show_types DATABASES, SHOW SCHEMAS", func(c *Config) { c.ShowTypes = []string{"DATABASES"} }, "SHOW SCHEMAS", ""},
		{"show_types CREATE TABLE, SHOW COLUMNS", func(c *Config) { c.ShowTypes = []string{"CREATE TABLE"} }, "SHOW COLUMNS FROM t", "show_types"},
		{"show_types COLUMNS, SHOW FIELDS", func(c *Config) { c.ShowTypes = []string{"COLUMNS"} }, "SHOW FIELDS FROM t", ""},
		{"show_types do not limit SELECT", func(c *Config) { c.ShowTypes = []string{"TABLES"} }, "SELECT 1", ""},
		{"show_types do not limit DESC", func(c *Config) { c.ShowTypes = []string{"TABLES"} }, "DESC t", ""},
		{"statement_types and show_types, SHOW denied by type", func(c *Config) {
			c.StatementTypes, c.ShowTypes = []string{"SHOW"}, []string{"TABLES"}
		}, "SHOW DATABASES", "show_types"},
		{"EXPLAIN ANALYZE needs the option", func(*Config) {}, "EXPLAIN ANALYZE SELECT 1", "sqlguard:"},
		{"EXPLAIN ANALYZE with the option", func(c *Config) { c.AllowExplainAnalyze = true }, "EXPLAIN ANALYZE SELECT 1", ""},
		{"EXPLAIN ANALYZE with the option, INSERT target", func(c *Config) { c.AllowExplainAnalyze = true }, "EXPLAIN ANALYZE INSERT INTO t SELECT 1", "sqlguard:"},
		{"EXPLAIN ANALYZE needs EXPLAIN and SELECT", func(c *Config) {
			c.AllowExplainAnalyze, c.StatementTypes = true, []string{"EXPLAIN"}
		}, "EXPLAIN ANALYZE SELECT 1", "statement_types"},
		{"EXPLAIN ANALYZE with EXPLAIN and SELECT", func(c *Config) {
			c.AllowExplainAnalyze, c.StatementTypes = true, []string{"EXPLAIN", "SELECT"}
		}, "EXPLAIN ANALYZE SELECT 1", ""},
		{"EXPLAIN ANALYZE without EXPLAIN", func(c *Config) {
			c.AllowExplainAnalyze, c.StatementTypes = true, []string{"SELECT"}
		}, "EXPLAIN ANALYZE SELECT 1", "statement_types"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := missingCredential()
			tc.mutate(&c)
			result, err := Run(context.Background(), c, Params{SQL: tc.sql})
			if result != (Result{}) {
				t.Fatalf("result %+v", result)
			}
			switch {
			case tc.wantError == "" && (err == nil || err.Error() != "cannot open credential file"):
				t.Fatalf("got %v; want to reach the credential file", err)
			case tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)):
				t.Fatalf("got %v; want error containing %q", err, tc.wantError)
			}
		})
	}
}

// A restriction error names the setting and the legal values, and never
// contains the SQL.
func TestRestrictionErrorsDoNotEchoSQL(t *testing.T) {
	c := missingCredential()
	c.StatementTypes = []string{"SHOW"}
	_, err := Run(context.Background(), c, Params{SQL: "SELECT 'secret-literal-1'"})
	if err == nil || strings.Contains(err.Error(), "secret-literal-1") || !strings.Contains(err.Error(), "SHOW") {
		t.Fatalf("got %v", err)
	}
	_, err = Run(context.Background(), missingCredential(), Params{SQL: "INSERT INTO t VALUES ('secret-literal-2')"})
	if err == nil || strings.Contains(err.Error(), "secret-literal-2") {
		t.Fatalf("got %v", err)
	}
}

func TestValidatePanicRecovered(t *testing.T) {
	original := validate
	defer func() { validate = original }()
	// Legacy panic(nil) must also be rejected, even though recover returns nil.
	t.Setenv("GODEBUG", "panicnil=1")
	for _, value := range []any{"SQL password=must-not-leak", errors.New("boom password=must-not-leak"), nil} {
		validate = func(sqlguard.Dialect, string, sqlguard.Options) (sqlguard.Statement, error) { panic(value) }
		result, err := Run(context.Background(), missingCredential(), Params{SQL: "SELECT 1"})
		if err == nil || strings.Contains(err.Error(), "must-not-leak") || strings.Contains(err.Error(), "cannot open credential file") || result != (Result{}) {
			t.Errorf("panic(%v): got %+v, %v; want a fixed rejection before credential IO", value, result, err)
		}
		if !errors.Is(err, sqlguard.ErrRejected) {
			t.Errorf("panic(%v): %v is not a rejection", value, err)
		}
	}
	validate = original
	if _, err := Run(context.Background(), missingCredential(), Params{SQL: "SELECT 1"}); err == nil || err.Error() != "cannot open credential file" {
		t.Fatalf("valid query after panic rejection: %v", err)
	}
}

// The credential file rules are those of credfile; Run must apply them and
// must not read the password from anywhere else.
func TestCredentialFileChecks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "starrocks.json")
	if err := os.WriteFile(path, []byte(`{"username":"reader","password":"p"}`), 0644); err != nil {
		t.Fatal(err)
	}
	c := Config{Credential: path, Address: "tcp://127.0.0.1:1"}
	_, err := Run(context.Background(), c, Params{SQL: "SELECT 1"})
	if err == nil || !strings.Contains(err.Error(), "mode 0600") {
		t.Fatalf("wide permissions: %v", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = Run(context.Background(), c, Params{SQL: "SELECT 1"})
	if os.Geteuid() != 0 && (err == nil || !strings.Contains(err.Error(), "root-owned")) {
		t.Fatalf("non-root owner: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	c.Credential = link
	if _, err := Run(context.Background(), c, Params{SQL: "SELECT 1"}); err == nil || err.Error() != "cannot open credential file" {
		t.Fatalf("symlink: %v", err)
	}
}

// A rejected statement must not open a connection. The accepted case below
// proves that the listener sees a connection when one is made.
func TestRejectedSQLOpensNoConnection(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer l.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conn.Close()
		}
	}()
	address := "tcp://" + l.Addr().String()
	for _, sql := range []string{"SELECT 1; INSERT INTO t VALUES (1)", "SELECT 1 # ; INSERT INTO t VALUES (1)", "SELECT * FROM t INTO OUTFILE 'x'"} {
		if _, err := Run(context.Background(), Config{Credential: "/missing/starrocks.json", Address: address}, Params{SQL: sql}); !errors.Is(err, sqlguard.ErrRejected) {
			t.Fatalf("%q: %v", sql, err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("rejected statements opened %d connections", n)
	}
	cfg := Config{Address: address}.normalized()
	cfg.Timeout = time.Second
	if _, err := runQuery(context.Background(), cfg, Params{SQL: "SELECT 1"}, credfile.Credential{Username: "u"}, nil); err == nil {
		t.Fatal("handshake with a closing listener must fail")
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n == 0 {
		t.Fatal("control: an accepted statement did not connect")
	}
}

func TestDriverConfig(t *testing.T) {
	cfg := Config{Address: "tcp://fe.example:9030", Timeout: 3 * time.Second}
	dc, err := driverConfig(cfg, Params{Database: "demo_dw"}, credfile.Credential{Username: "reader", Password: "a:b@/"})
	if err != nil {
		t.Fatal(err)
	}
	if dc.Net != "tcp" || dc.Addr != "fe.example:9030" || dc.User != "reader" || dc.Passwd != "a:b@/" || dc.DBName != "demo_dw" || dc.Timeout != 3*time.Second {
		t.Fatalf("config %+v", dc)
	}
	if dc.MultiStatements || dc.AllowAllFiles || dc.InterpolateParams || dc.ClientFoundRows || len(dc.Params) != 0 {
		t.Fatalf("unsafe driver options: %+v", dc)
	}
	dc, err = driverConfig(cfg, Params{}, credfile.Credential{Username: "reader"})
	if err != nil || dc.DBName != "" {
		t.Fatalf("empty database: %+v, %v", dc, err)
	}
	if _, err := driverConfig(Config{Address: "unix:///tmp/x.sock"}, Params{}, credfile.Credential{Username: "u"}); err == nil {
		t.Fatal("driverConfig accepted a unix address")
	}
}

// fixture is a small database/sql driver that records the statements and
// serves canned rows, so that session order, row conversion and limits are
// tested without a server and without bypassing the credential checks of Run.
type fixture struct {
	columns   []string
	rows      [][]sqldriver.Value
	total     int // when positive, rows are generated: one int64 column
	rowErr    error
	execErr   map[int]error // 1-based Exec call number
	queryErr  error
	executed  []string
	queried   []string
	nextCalls int
}

func (f *fixture) Connect(context.Context) (sqldriver.Conn, error) { return &fixtureConn{f}, nil }
func (f *fixture) Driver() sqldriver.Driver                        { return fixtureDriver{} }

type fixtureDriver struct{}

func (fixtureDriver) Open(string) (sqldriver.Conn, error) { return nil, errors.New("use connector") }

type fixtureConn struct{ f *fixture }

func (*fixtureConn) Prepare(string) (sqldriver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*fixtureConn) Close() error                 { return nil }
func (*fixtureConn) Begin() (sqldriver.Tx, error) { return nil, errors.New("unexpected begin") }

func (c *fixtureConn) ExecContext(_ context.Context, s string, _ []sqldriver.NamedValue) (sqldriver.Result, error) {
	c.f.executed = append(c.f.executed, s)
	if err := c.f.execErr[len(c.f.executed)]; err != nil {
		return nil, err
	}
	return sqldriver.RowsAffected(0), nil
}

func (c *fixtureConn) QueryContext(_ context.Context, s string, _ []sqldriver.NamedValue) (sqldriver.Rows, error) {
	c.f.queried = append(c.f.queried, s)
	if c.f.queryErr != nil {
		return nil, c.f.queryErr
	}
	return &fixtureRows{f: c.f}, nil
}

type fixtureRows struct {
	f     *fixture
	index int
}

func (r *fixtureRows) Columns() []string { return r.f.columns }
func (*fixtureRows) Close() error        { return nil }

func (r *fixtureRows) Next(dest []sqldriver.Value) error {
	r.f.nextCalls++
	if r.f.total > 0 {
		if r.index == r.f.total {
			return io.EOF
		}
		dest[0] = int64(r.index)
		r.index++
		return nil
	}
	if r.index == len(r.f.rows) {
		if r.f.rowErr != nil {
			return r.f.rowErr
		}
		return io.EOF
	}
	copy(dest, r.f.rows[r.index])
	r.index++
	return nil
}

func limits(rows int, bytes int64) Config {
	return Config{MaxRows: rows, MaxBytes: bytes, Timeout: 2 * time.Second}
}

func TestExecuteResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		f      *fixture
		cfg    Config
		want   Result
		wantIO error
	}{
		{"empty", &fixture{columns: []string{"value"}}, limits(2, 1<<20), Result{Output: "value\n"}, nil},
		{"exact rows", &fixture{columns: []string{"value"}, rows: [][]sqldriver.Value{{int64(1)}, {int64(2)}}}, limits(2, 1<<20), Result{Output: "value\n1\n2\n", Rows: 2}, nil},
		{"over row limit", &fixture{columns: []string{"value"}, rows: [][]sqldriver.Value{{int64(1)}, {int64(2)}, {int64(3)}}}, limits(2, 1<<20), Result{Output: "value\n1\n2\n", Rows: 2, Truncated: true}, nil},
		{"escape and NULL", &fixture{columns: []string{"value"}, rows: [][]sqldriver.Value{{"a\tb\nc\rd\\e\x00"}, {nil}, {`\N`}, {""}}}, limits(4, 1<<20), Result{Output: "value\na\\tb\\nc\\rd\\\\e\\0\n\\N\n\\\\N\n\n", Rows: 4}, nil},
		{"several columns", &fixture{columns: []string{"id", "note", "missing"}, rows: [][]sqldriver.Value{{int64(7), "x\ty", nil}}}, limits(5, 1<<20), Result{Output: "id\tnote\tmissing\n7\tx\\ty\t\\N\n", Rows: 1}, nil},
		{"header is escaped", &fixture{columns: []string{"a\tb"}}, limits(5, 1<<20), Result{Output: "a\\tb\n"}, nil},
		// "value\n" is 6 bytes and every row "N\n" is 2: 10 bytes hold the header and two rows.
		{"exact byte limit", &fixture{columns: []string{"value"}, rows: [][]sqldriver.Value{{int64(1)}, {int64(2)}}}, limits(10, 10), Result{Output: "value\n1\n2\n", Rows: 2}, nil},
		{"over byte limit", &fixture{columns: []string{"value"}, rows: [][]sqldriver.Value{{int64(1)}, {int64(2)}, {int64(3)}}}, limits(10, 10), Result{Output: "value\n1\n2\n", Rows: 2, Truncated: true}, nil},
		{"a row is never cut in the middle", &fixture{columns: []string{"value"}, rows: [][]sqldriver.Value{{"abcdefgh"}, {"x"}}}, limits(10, 10), Result{Output: "value\n", Truncated: true}, nil},
		{"row error", &fixture{columns: []string{"value"}, rowErr: errors.New("row failure")}, limits(2, 1<<20), Result{}, errors.New("row failure")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := execute(context.Background(), tc.f, tc.cfg, "SELECT 1", nil)
			if tc.wantIO != nil {
				if err == nil || strings.Contains(err.Error(), "row failure") || got != (Result{}) {
					t.Fatalf("got %+v, %v; want a failure without the driver message", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tc.want)
			}
			if len(tc.f.queried) != 1 || tc.f.queried[0] != "SELECT 1" {
				t.Fatalf("queried %q", tc.f.queried)
			}
		})
	}
}

func TestExecuteMasksHeaderAndCellsBeforeLimits(t *testing.T) {
	mask := func(s string) string { return strings.ReplaceAll(s, "secret", "[REDACTED]") }
	f := &fixture{columns: []string{"secret_col", "v"}, rows: [][]sqldriver.Value{{"my secret", "1"}, {"ok", nil}}}
	got, err := execute(context.Background(), f, limits(5, 1<<20), "SELECT 1", mask)
	want := Result{Output: "[REDACTED]_col\tv\nmy [REDACTED]\t1\nok\t\\N\n", Rows: 2}
	if err != nil || got != want {
		t.Fatalf("got %+v, %v; want %+v", got, err, want)
	}
	// The byte limit applies to the masked text: "[REDACTED]" is longer than "secret".
	f = &fixture{columns: []string{"v"}, rows: [][]sqldriver.Value{{"secret"}, {"secret"}}}
	got, err = execute(context.Background(), f, limits(5, int64(len("v\n[REDACTED]\n"))), "SELECT 1", mask)
	if err != nil || got.Rows != 1 || !got.Truncated || got.Output != "v\n[REDACTED]\n" || strings.Contains(got.Output, "secret") {
		t.Fatalf("got %+v, %v", got, err)
	}
	// A rule that relates the name cell to the value cell sees the whole row (SHOW VARIABLES).
	rowMask := func(s string) string {
		if strings.HasPrefix(s, "report_password\t") {
			return "[REDACTED:row]"
		}
		return s
	}
	f = &fixture{columns: []string{"Variable_name", "Value"}, rows: [][]sqldriver.Value{{"report_password", "rp_s3cr3t"}, {"max_connections", "151"}}}
	got, err = execute(context.Background(), f, limits(5, 1<<20), "SHOW VARIABLES", rowMask)
	if err != nil || got.Output != "Variable_name\tValue\n[REDACTED:row]\nmax_connections\t151\n" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

// The row limit is applied while reading: a truncated result must not read the
// rest of a large result set (sql_select_limit cannot be relied on).
func TestExecuteStopsReadingAtTheLimit(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		rows int
	}{
		{"rows", limits(3, 1<<20), 3},
		{"bytes", limits(100, int64(len("value\n0\n1\n2\n"))), 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fixture{columns: []string{"value"}, total: 1_000_000}
			got, err := execute(context.Background(), f, tc.cfg, "SELECT 1", nil)
			if err != nil || !got.Truncated || got.Rows != tc.rows {
				t.Fatalf("got %+v, %v", got, err)
			}
			if f.nextCalls > tc.rows+1 {
				t.Fatalf("read %d rows for a limit of %d", f.nextCalls, tc.rows)
			}
		})
	}
}

// No read-only transaction, no max_execution_time; only query_timeout,
// rounded up to whole seconds, set before the query, and a failure is an error.
func TestSessionTimeout(t *testing.T) {
	for _, tc := range []struct {
		timeout time.Duration
		want    string
	}{
		{time.Millisecond, "SET query_timeout = 1"},
		{20 * time.Millisecond, "SET query_timeout = 1"},
		{time.Second, "SET query_timeout = 1"},
		{time.Second + time.Millisecond, "SET query_timeout = 2"},
		{1500 * time.Millisecond, "SET query_timeout = 2"},
		{9*time.Second + time.Nanosecond, "SET query_timeout = 10"},
		{10 * time.Second, "SET query_timeout = 10"},
	} {
		f := &fixture{columns: []string{"value"}}
		cfg := limits(5, 1<<20)
		cfg.Timeout = tc.timeout
		if _, err := execute(context.Background(), f, cfg, "SELECT 1", nil); err != nil {
			t.Fatal(err)
		}
		if len(f.executed) != 1 || f.executed[0] != tc.want {
			t.Errorf("timeout %v: executed %q; want [%s]", tc.timeout, f.executed, tc.want)
		}
		for _, s := range append(f.executed, f.queried...) {
			if strings.Contains(strings.ToLower(s), "transaction") || strings.Contains(s, "max_execution_time") || strings.Contains(s, "sql_select_limit") {
				t.Errorf("unexpected session statement %q", s)
			}
		}
	}
}

func TestSessionFailureStopsBeforeQuery(t *testing.T) {
	f := &fixture{columns: []string{"value"}, execErr: map[int]error{1: &mysqldriver.MySQLError{Number: 1064, Message: "bad secret"}}}
	got, err := execute(context.Background(), f, limits(5, 1<<20), "SELECT 1", nil)
	if err == nil || err.Error() != "starrocks initialize session failed (code 1064)" || got != (Result{}) || len(f.queried) != 0 {
		t.Fatalf("got %+v, %v, queried %q", got, err, f.queried)
	}
	f = &fixture{columns: []string{"value"}, execErr: map[int]error{1: errors.New("server error with secret")}}
	_, err = execute(context.Background(), f, limits(5, 1<<20), "SELECT 1", nil)
	if err == nil || strings.Contains(err.Error(), "secret") || len(f.queried) != 0 {
		t.Fatalf("got %v, queried %q", err, f.queried)
	}
}

func TestServerErrorsExposeOnlyTheCode(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&mysqldriver.MySQLError{Number: 5203, Message: "Access denied; you need INSERT on t_secret"}, "starrocks query failed (code 5203)"},
		{&mysqldriver.MySQLError{Number: 5024, Message: "Query timeout. Query exceeded time limit of 1 seconds"}, "starrocks query failed (code 5024)"},
		{&mysqldriver.MySQLError{Number: 1064, Message: "Unexpected input 'secret'"}, "starrocks query failed (code 1064)"},
		{errors.New("driver failure with secret"), "starrocks query failed"},
	} {
		f := &fixture{columns: []string{"value"}, queryErr: tc.err}
		got, err := execute(context.Background(), f, limits(5, 1<<20), "SELECT 1", nil)
		if err == nil || err.Error() != tc.want || got != (Result{}) {
			t.Errorf("got %+v, %v; want %q", got, err, tc.want)
		}
	}
	// A result-read failure reports the code too.
	f := &fixture{columns: []string{"value"}, rowErr: &mysqldriver.MySQLError{Number: 5024, Message: "timeout secret"}}
	if _, err := execute(context.Background(), f, limits(5, 1<<20), "SELECT 1", nil); err == nil || err.Error() != "starrocks read result failed (code 5024)" {
		t.Fatalf("got %v", err)
	}
}

func TestExecuteHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fixture{columns: []string{"value"}}
	if _, err := execute(ctx, f, limits(5, 1<<20), "SELECT 1", nil); !errors.Is(err, context.Canceled) || len(f.queried) != 0 {
		t.Fatalf("got %v, queried %q", err, f.queried)
	}
	// An error after the deadline is reported as the deadline, not as the driver failure.
	ctx, cancel = context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	f = &fixture{columns: []string{"value"}, queryErr: &mysqldriver.MySQLError{Number: 5024, Message: "x"}}
	if _, err := execute(ctx, f, limits(5, 1<<20), "SELECT 1", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}
