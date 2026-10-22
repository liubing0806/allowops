package mysql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
)

func TestConfig(t *testing.T) {
	base := Config{Credential: "/etc/allowops/mysql.json", Address: "tcp://127.0.0.1:3306"}
	for _, address := range []string{base.Address, "tcp://[::1]:3306", "unix:///tmp/mysql.sock"} {
		c := base
		c.Address = address
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", address, err)
		}
	}
	for _, address := range []string{"", "localhost:3306", "tcp://localhost", "tcp://user:pass@host:3306", "tcp://host:3306?multiStatements=true", "tcp://host:3306/", "tcp://host:0", "tcp://host:65536", "unix://host/tmp/sock", "unix://relative", "unix:///tmp/sock#frag", "unix:///tmp/sock?", "unix:///tmp/%00"} {
		c := base
		c.Address = address
		if c.Validate() == nil {
			t.Errorf("accepted address %q", address)
		}
	}
	for _, c := range []Config{
		{Credential: "relative", Address: base.Address},
		{Credential: base.Credential, Address: base.Address, MaxRows: -1},
		{Credential: base.Credential, Address: base.Address, MaxRows: 501},
		{Credential: base.Credential, Address: base.Address, Timeout: -1},
		{Credential: base.Credential, Address: base.Address, Timeout: time.Nanosecond},
		{Credential: base.Credential, Address: base.Address, Timeout: 11 * time.Second},
	} {
		if c.Validate() == nil {
			t.Errorf("accepted invalid config %+v", c)
		}
	}
}

func TestParamsAndCancellationBeforeIO(t *testing.T) {
	c := Config{Credential: "/missing/mysql.json", Address: "tcp://127.0.0.1:1"}
	for _, database := range []string{"", "a-b", "a;DROP DATABASE x", "x/y", "数据库", strings.Repeat("x", 65), "x\n"} {
		_, err := Run(context.Background(), c, Params{Database: database, SQL: "SELECT 1"})
		if err == nil || err.Error() != "invalid database name" {
			t.Errorf("%q: %v", database, err)
		}
	}
	for _, database := range []string{"test_01", strings.Repeat("x", 64)} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Run(ctx, c, Params{Database: database, SQL: "SELECT 1"})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%q: %v", database, err)
		}
	}
	_, err := Run(context.Background(), c, Params{Database: "test", SQL: "DELETE FROM t"})
	if !errors.Is(err, errSQL) {
		t.Fatalf("SQL must be rejected before credential IO: %v", err)
	}
	schema := ParamsSchema()
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" || schema["additionalProperties"] != false {
		t.Fatalf("unexpected schema: %v", schema)
	}
}

func TestCredential(t *testing.T) {
	for _, s := range []string{`{}`, `{"username":"x"}`, `{"username":"","password":"x"}`, `{"username":"x","password":null}`, `{"username":"x","password":"secret","dsn":"evil"}`, `{"username":"x","password":"secret"} {}`, `not secret json`} {
		_, err := decodeCredential(strings.NewReader(s))
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("unexpected credential error: %v", err)
		}
	}
	c, err := decodeCredential(strings.NewReader(`{"username":"reader","password":"a:b@/\\"}`))
	if err != nil || c.Username != "reader" || c.Password != "a:b@/\\" {
		t.Fatalf("decode credential: %+v, %v", c, err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "credential.json")
	if _, err := readCredential(path); err == nil {
		t.Fatal("accepted missing file")
	}
	if err := os.WriteFile(path, []byte(`{"username":"reader","password":""}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredential(path); err == nil {
		t.Fatal("accepted wide permissions")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = readCredential(path)
	if os.Geteuid() != 0 && err == nil {
		t.Fatal("accepted non-root owner")
	}
	if os.Geteuid() == 0 && err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredential(link); err == nil {
		t.Fatal("accepted symlink")
	}
	if _, err := readCredential(dir); err == nil {
		t.Fatal("accepted directory")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredential(fifo); err == nil {
		t.Fatal("accepted FIFO")
	}
}

// A small database/sql driver exercises row conversion and session ordering
// without bypassing ownership checks in the production Run function.
type fixture struct {
	columns  []string
	rows     [][]driver.Value
	rowErr   error
	executed []string
	failAt   int
}
type fixtureDriver struct{}

func (fixtureDriver) Open(string) (driver.Conn, error)          { return nil, errors.New("use connector") }
func (f *fixture) Connect(context.Context) (driver.Conn, error) { return &fixtureConn{f}, nil }
func (f *fixture) Driver() driver.Driver                        { return fixtureDriver{} }

type fixtureConn struct{ f *fixture }

func (*fixtureConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*fixtureConn) Close() error              { return nil }
func (*fixtureConn) Begin() (driver.Tx, error) { return nil, errors.New("unexpected begin") }
func (c *fixtureConn) ExecContext(_ context.Context, s string, _ []driver.NamedValue) (driver.Result, error) {
	c.f.executed = append(c.f.executed, s)
	if c.f.failAt == len(c.f.executed) {
		return nil, errors.New("server error with secret")
	}
	return driver.RowsAffected(0), nil
}
func (c *fixtureConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &fixtureRows{f: c.f}, nil
}

type fixtureRows struct {
	f     *fixture
	index int
}

func (r *fixtureRows) Columns() []string { return r.f.columns }
func (*fixtureRows) Close() error        { return nil }
func (r *fixtureRows) Next(dest []driver.Value) error {
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

func TestReadRows(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rows   [][]driver.Value
		limit  int
		want   Result
		rowErr error
	}{
		{"empty", nil, 2, Result{Output: "value\n"}, nil},
		{"exact", [][]driver.Value{{int64(1)}, {int64(2)}}, 2, Result{Output: "value\n1\n2\n", Rows: 2}, nil},
		{"truncated", [][]driver.Value{{int64(1)}, {int64(2)}, {int64(3)}}, 2, Result{Output: "value\n1\n2\n", Rows: 2, Truncated: true}, nil},
		{"escape", [][]driver.Value{{"a\tb\nc\rd\\e\x00"}, {nil}, {`\N`}}, 3, Result{Output: "value\na\\tb\\nc\\rd\\\\e\\0\n\\N\n\\\\N\n", Rows: 3}, nil},
		{"error", nil, 2, Result{}, errors.New("row failure")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := sql.OpenDB(&fixture{columns: []string{"value"}, rows: tc.rows, rowErr: tc.rowErr})
			defer db.Close()
			rows, err := db.Query("test")
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			got, err := readRows(rows, tc.limit)
			if !errors.Is(err, tc.rowErr) || got != tc.want {
				t.Fatalf("got %+v, %v; want %+v, %v", got, err, tc.want, tc.rowErr)
			}
		})
	}
}

func TestReadRowsByteLimit(t *testing.T) {
	big := strings.Repeat("x", 30000)
	bigRows := [][]driver.Value{{big}, {big}, {big}}
	bigLine := big + "\n"
	upper := func(s string) string { return strings.ToUpper(s) + "!!" }
	for _, tc := range []struct {
		name  string
		rows  [][]driver.Value
		limit int64
		mask  func(string) string
		want  Result
	}{
		{"default limit truncates and drops the partial row", bigRows, builtin.DefaultMySQLMaxResponseBytes, nil,
			Result{Output: "value\n" + bigLine + bigLine, Rows: 2, Truncated: true}},
		{"larger configured limit passes", bigRows, 128 << 10, nil,
			Result{Output: "value\n" + bigLine + bigLine + bigLine, Rows: 3}},
		{"exactly at limit", [][]driver.Value{{"abc"}, {"def"}}, 14, nil,
			Result{Output: "value\nabc\ndef\n", Rows: 2}},
		{"one byte under limit drops the last row", [][]driver.Value{{"abc"}, {"def"}}, 13, nil,
			Result{Output: "value\nabc\n", Rows: 1, Truncated: true}},
		{"escaped size counts", [][]driver.Value{{"\t\t\t\t"}}, 14, nil,
			Result{Output: "value\n", Truncated: true}},
		{"redacted size counts", [][]driver.Value{{"abc"}}, 11, upper,
			Result{Output: "VALUE!!\n", Truncated: true}},
		{"header alone over the limit", [][]driver.Value{{"a"}}, 3, nil,
			Result{Output: "value\n", Truncated: true}},
		{"no rows never truncates", nil, 3, nil,
			Result{Output: "value\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := sql.OpenDB(&fixture{columns: []string{"value"}, rows: tc.rows})
			defer db.Close()
			rows, err := db.Query("test")
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			got, err := readRowsRedacted(rows, DefaultMaxRows, tc.limit, tc.mask)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got rows=%d truncated=%v len=%d; want rows=%d truncated=%v len=%d", got.Rows, got.Truncated, len(got.Output), tc.want.Rows, tc.want.Truncated, len(tc.want.Output))
			}
		})
	}
}

func TestMaxResponseBytesConfig(t *testing.T) {
	base := Config{Credential: "/etc/allowops/mysql.json", Address: "tcp://127.0.0.1:3306"}
	for _, n := range []int64{0, 1, 64 << 10, 16 << 20} {
		c := base
		c.MaxResponseBytes = n
		if err := c.Validate(); err != nil {
			t.Errorf("max_response_bytes %d: %v", n, err)
		}
	}
	for _, n := range []int64{-1, 16<<20 + 1} {
		c := base
		c.MaxResponseBytes = n
		if c.Validate() == nil {
			t.Errorf("accepted max_response_bytes %d", n)
		}
	}
}

func TestReadOnlySession(t *testing.T) {
	want := []string{"SET SESSION sql_mode = 'IGNORE_SPACE'", "SET NAMES utf8mb4 COLLATE utf8mb4_bin", "SET SESSION max_execution_time = 2", "START TRANSACTION READ ONLY"}
	for failAt := 0; failAt <= len(want); failAt++ {
		f := &fixture{failAt: failAt}
		db := sql.OpenDB(f)
		conn, err := db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		err = beginReadOnly(context.Background(), conn, 1500*time.Microsecond)
		conn.Close()
		db.Close()
		expected := want
		if failAt > 0 {
			expected = want[:failAt]
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Errorf("failure %d: %v", failAt, err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(f.executed, expected) {
			t.Errorf("got %v, want %v", f.executed, expected)
		}
	}
}
