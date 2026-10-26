// Package srconn holds the StarRocks connection helpers shared by the
// starrocks builtins: address parsing, driver configuration, error reporting,
// the session timeout and bounded TSV reading.
package srconn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/liubing0806/allowops/internal/builtin/credfile"
	"github.com/liubing0806/allowops/internal/builtin/tsv"
)

// ParseAddress accepts only tcp://host:port and returns host:port.
func ParseAddress(address string) (string, error) {
	invalid := errors.New("address must be tcp://host:port without credentials or options")
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "tcp" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Path != "" {
		return "", invalid
	}
	host, port, err := net.SplitHostPort(u.Host)
	n, parseErr := strconv.Atoi(port)
	if err != nil || host == "" || parseErr != nil || n < 1 || n > 65535 {
		return "", invalid
	}
	return u.Host, nil
}

// DriverConfig builds the connection from structured fields only. NewConfig
// leaves multi-statements, LOCAL INFILE, parameter interpolation and TLS off.
// The context, not a read timeout, bounds the query.
func DriverConfig(address string, timeout time.Duration, database string, cred credfile.Credential) (*mysqldriver.Config, error) {
	host, err := ParseAddress(address)
	if err != nil {
		return nil, err
	}
	dc := mysqldriver.NewConfig()
	dc.User, dc.Passwd, dc.DBName = cred.Username, cred.Password, database
	dc.Net, dc.Addr = "tcp", host
	dc.Timeout = timeout
	return dc, nil
}

// QueryError hides server messages, which can contain SQL literals and
// credentials; it exposes codes only. The context error wins when the
// context ended.
func QueryError(ctx context.Context, stage string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var server *mysqldriver.MySQLError
	if errors.As(err, &server) {
		return fmt.Errorf("starrocks %s failed (code %d)", stage, server.Number)
	}
	return fmt.Errorf("starrocks %s failed", stage)
}

// SetQueryTimeout sets query_timeout, which counts whole seconds and must be
// at least 1, so the timeout is rounded up. The statement must succeed:
// without it the server limit would be its default of 300 s.
func SetQueryTimeout(ctx context.Context, conn *sql.Conn, timeout time.Duration) error {
	seconds := int64((timeout + time.Second - 1) / time.Second)
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("SET query_timeout = %d", seconds)); err != nil {
		return QueryError(ctx, "initialize session", err)
	}
	return nil
}

// Result is TSV text; callers redact it unless a mask was given to ReadRows.
type Result struct {
	Output    string
	Rows      int
	Truncated bool
}

// ReadRows reads at most maxRows rows and maxBytes bytes of TSV, header
// included. It reads one row more than it returns to find out whether the
// result is truncated.
func ReadRows(rows *sql.Rows, maxRows int, maxBytes int64, mask func(string) string) (Result, error) {
	if mask == nil {
		mask = func(s string) string { return s }
	}
	columns, err := rows.Columns()
	if err != nil {
		return Result{}, err
	}
	for i, column := range columns {
		columns[i] = mask(column)
	}
	var out strings.Builder
	tsv.WriteRow(&out, columns)
	result := Result{}
	values := make([]sql.NullString, len(columns))
	dest := make([]any, len(columns))
	for i := range values {
		dest[i] = &values[i]
	}
	for rows.Next() {
		if result.Rows == maxRows {
			result.Truncated = true
			break
		}
		if err := rows.Scan(dest...); err != nil {
			return Result{}, err
		}
		line := strings.Join(tsv.MaskRow(values, mask), "\t") + "\n"
		if int64(out.Len()+len(line)) > maxBytes {
			result.Truncated = true
			break
		}
		out.WriteString(line)
		result.Rows++
	}
	if err := rows.Err(); err != nil {
		return Result{}, err
	}
	result.Output = out.String()
	return result, nil
}
