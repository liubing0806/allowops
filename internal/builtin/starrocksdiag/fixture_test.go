package starrocksdiag

import (
	"context"
	sqldriver "database/sql/driver"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	testQueryID = "b6e3e384-ced5-11f1-b155-5ee444682bc1"
	testCredent = "/etc/allowops/credentials/starrocks-diag.json"
)

func baseConfig() Config {
	return Config{Credential: testCredent, Address: "tcp://127.0.0.1:9030"}
}

// missingCredential points at a file that does not exist: a request that gets
// as far as reading it fails with "cannot open credential file", and a request
// that is rejected earlier never reaches it.
func missingCredential() Config {
	return Config{Credential: "/missing/starrocks.json", Address: "tcp://127.0.0.1:1"}
}

func limits(rows int, bytes int64) Config {
	return Config{MaxRows: rows, MaxBytes: bytes, Timeout: 2 * time.Second, MaxProfileBytes: 16 << 20}
}

// reply is the canned answer to one statement.
type reply struct {
	columns []string
	rows    [][]sqldriver.Value
	err     error
}

// fixture is a small database/sql driver that records every statement in
// order ("exec: ..." and "query: ...") and answers queries through handle.
type fixture struct {
	handle func(stmt string) reply
	log    []string
}

func (f *fixture) queried() []string {
	var out []string
	for _, s := range f.log {
		if rest, ok := strings.CutPrefix(s, "query: "); ok {
			out = append(out, rest)
		}
	}
	return out
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
	c.f.log = append(c.f.log, "exec: "+s)
	if c.f.handle != nil {
		if r := c.f.handle(s); r.err != nil {
			return nil, r.err
		}
	}
	return sqldriver.RowsAffected(0), nil
}

func (c *fixtureConn) QueryContext(_ context.Context, s string, _ []sqldriver.NamedValue) (sqldriver.Rows, error) {
	c.f.log = append(c.f.log, "query: "+s)
	r := reply{columns: []string{"value"}}
	if c.f.handle != nil {
		r = c.f.handle(s)
	}
	if r.err != nil {
		return nil, r.err
	}
	return &fixtureRows{r: r}, nil
}

type fixtureRows struct {
	r     reply
	index int
}

func (r *fixtureRows) Columns() []string { return r.r.columns }
func (*fixtureRows) Close() error        { return nil }

func (r *fixtureRows) Next(dest []sqldriver.Value) error {
	if r.index == len(r.r.rows) {
		return io.EOF
	}
	copy(dest, r.r.rows[r.index])
	r.index++
	return nil
}

func profileSample(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("../starrocksprofile/testdata/" + name + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
