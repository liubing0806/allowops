// Package starrocks implements the self-contained starrocks_query builtin: one
// read-only statement, validated by the lexical guard in package sqlguard, is
// sent to a StarRocks frontend over the MySQL protocol.
//
// The read-only boundary has three layers: the database account (SELECT only),
// the lexical guard, and the session timeout together with the result limits.
// StarRocks 3.3 has no read-only transaction and no max_execution_time, and
// sql_select_limit is overridden by an explicit LIMIT, so the handler sets only
// query_timeout and cuts the result off while reading it.
package starrocks

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/builtin/credfile"
	"github.com/liubing0806/allowops/internal/builtin/sqlguard"
	"github.com/liubing0806/allowops/internal/builtin/tsv"
)

const databasePattern = `^[a-zA-Z0-9_]{1,64}$`

var databaseName = regexp.MustCompile(databasePattern)

// Config is trusted catalog configuration. Zero limits select the defaults,
// which are also the maximum: configuration can only tighten them.
//
// There is no databases or catalogs setting. The guard is lexical and cannot
// tell db.table from alias.column, so the range of readable tables comes from
// the grants of the database account.
type Config struct {
	Credential string `yaml:"credential" json:"credential"`
	Address    string `yaml:"address" json:"address"`
	MaxRows    int    `yaml:"max_rows" json:"max_rows"`
	// MaxBytes limits the TSV text, header included. A row that does not fit
	// is not returned.
	MaxBytes int64         `yaml:"max_bytes" json:"max_bytes"`
	Timeout  time.Duration `yaml:"timeout" json:"timeout"`
	// StatementTypes is a nonempty subset of SELECT, SHOW, DESCRIBE, EXPLAIN.
	// The target of an EXPLAIN must be allowed as well.
	StatementTypes []string `yaml:"statement_types" json:"statement_types"`
	// ShowTypes is a nonempty subset of the SHOW types of sqlguard except PROFILELIST.
	ShowTypes []string `yaml:"show_types" json:"show_types"`
	// AllowExplainAnalyze permits EXPLAIN ANALYZE of a SELECT or WITH query,
	// which executes the query.
	AllowExplainAnalyze bool `yaml:"allow_explain_analyze" json:"allow_explain_analyze"`
}

// Params are the caller's parameters. An empty Database leaves the connection
// without a default database.
type Params struct {
	Database string `yaml:"database" json:"database"`
	SQL      string `yaml:"sql" json:"sql"`
}

// Result contains unredacted TSV unless a mask was given; callers must redact
// before exposing it.
type Result struct {
	Output    string `json:"output"`
	Rows      int    `json:"rows"`
	Truncated bool   `json:"truncated"`
}

var allowedStatementTypes = []string{"SELECT", "SHOW", "DESCRIBE", "EXPLAIN"}

// profileList is rejected whatever the configuration: SHOW PROFILELIST and
// ANALYZE PROFILE return the statements and profiles of other accounts.
const profileList = "PROFILELIST"

func allowedShowTypes() []string {
	return slices.DeleteFunc(sqlguard.ShowTypes(sqlguard.StarRocks), func(name string) bool { return name == profileList })
}

func containsFold(values []string, value string) bool {
	return slices.ContainsFunc(values, func(allowed string) bool { return strings.EqualFold(allowed, value) })
}

func (c Config) Validate() error {
	if !filepath.IsAbs(c.Credential) {
		return errors.New("credential must be an absolute file path")
	}
	if c.MaxRows < 0 || c.MaxRows > builtin.DefaultStarRocksMaxRows {
		return fmt.Errorf("max_rows must be between 0 and %d", builtin.DefaultStarRocksMaxRows)
	}
	if c.MaxBytes < 0 || c.MaxBytes > builtin.DefaultStarRocksMaxBytes {
		return fmt.Errorf("max_bytes must be between 0 and %d", builtin.DefaultStarRocksMaxBytes)
	}
	if c.Timeout < 0 || c.Timeout > builtin.DefaultTimeout || (c.Timeout > 0 && c.Timeout < time.Millisecond) {
		return errors.New("timeout must be zero or between 1ms and 10s")
	}
	for _, list := range []struct {
		name            string
		values, allowed []string
	}{
		{"statement_types", c.StatementTypes, allowedStatementTypes},
		{"show_types", c.ShowTypes, allowedShowTypes()},
	} {
		if list.values != nil && len(list.values) == 0 {
			return fmt.Errorf("%s must be a nonempty subset of: %s", list.name, strings.Join(list.allowed, ", "))
		}
		for _, value := range list.values {
			if list.name == "show_types" && strings.EqualFold(value, profileList) {
				return errors.New("show_types cannot contain PROFILELIST: starrocks_query never runs profile statements")
			}
			if !containsFold(list.allowed, value) {
				return fmt.Errorf("%s may only contain: %s", list.name, strings.Join(list.allowed, ", "))
			}
		}
	}
	_, err := parseAddress(c.Address)
	return err
}

// normalized replaces zero limits with the defaults.
func (c Config) normalized() Config {
	if c.MaxRows == 0 {
		c.MaxRows = builtin.DefaultStarRocksMaxRows
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = builtin.DefaultStarRocksMaxBytes
	}
	if c.Timeout == 0 {
		c.Timeout = builtin.DefaultTimeout
	}
	return c
}

// parseAddress accepts only tcp://host:port and returns host:port.
func parseAddress(address string) (string, error) {
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

// validate is replaceable so that a test can make the guard panic.
var validate = sqlguard.Validate

var errValidatePanic = fmt.Errorf("%w: SQL could not be validated", sqlguard.ErrRejected)

var errProfile = fmt.Errorf("%w: profile statements (SHOW PROFILELIST, ANALYZE PROFILE) are not available in starrocks_query", sqlguard.ErrRejected)

// validateSQL runs the guard and then the restrictions of the configuration.
// A restriction can only narrow what the guard accepts.
func validateSQL(sql string, cfg Config) (err error) {
	// The guard must not take the process down, and a panic value can contain the SQL.
	returned := false
	defer func() {
		if !returned {
			_ = recover()
			err = errValidatePanic
		}
	}()
	st, err := validate(sqlguard.StarRocks, sql, sqlguard.Options{AllowExplainAnalyze: cfg.AllowExplainAnalyze})
	returned = true
	if err != nil {
		return err
	}
	if st.Kind == sqlguard.KindAnalyzeProfile || st.Kind == sqlguard.KindShow && st.ShowType == profileList {
		return errProfile
	}
	return cfg.checkStatement(st)
}

func (c Config) checkStatement(st sqlguard.Statement) error {
	if c.StatementTypes != nil && !containsFold(c.StatementTypes, string(st.Kind)) {
		return fmt.Errorf("statement_types allows only: %s", strings.Join(c.StatementTypes, ", "))
	}
	switch st.Kind {
	case sqlguard.KindShow:
		if c.ShowTypes != nil && !containsFold(c.ShowTypes, st.ShowType) {
			return fmt.Errorf("show_types allows only: %s", strings.Join(c.ShowTypes, ", "))
		}
	case sqlguard.KindExplain:
		// The EXPLAIN target must satisfy statement_types as well (as in mysql_query, G31).
		return c.checkStatement(*st.Target)
	}
	return nil
}

func Run(ctx context.Context, cfg Config, p Params) (Result, error) {
	return RunRedacted(ctx, cfg, p, nil)
}

// RunRedacted applies the caller's policy to original column names and cells
// before TSV encoding. The SQL is validated before the credential file is read
// and before any connection is made.
func RunRedacted(ctx context.Context, cfg Config, p Params, mask func(string) string) (result Result, err error) {
	if err := cfg.Validate(); err != nil {
		return result, err
	}
	if p.Database != "" && !databaseName.MatchString(p.Database) {
		return result, errors.New("invalid database name")
	}
	if err := validateSQL(p.SQL, cfg); err != nil {
		return result, err
	}
	cfg = cfg.normalized()
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	cred, err := credfile.Read(cfg.Credential)
	if err != nil {
		return result, err
	}
	return runQuery(ctx, cfg, p, cred, mask)
}

// runQuery receives validated parameters and normalized limits. It does not
// validate the SQL; tests use it to send statements that the guard rejects.
func runQuery(ctx context.Context, cfg Config, p Params, cred credfile.Credential, mask func(string) string) (Result, error) {
	dc, err := driverConfig(cfg, p, cred)
	if err != nil {
		return Result{}, err
	}
	connector, err := mysqldriver.NewConnector(dc)
	if err != nil {
		return Result{}, errors.New("cannot configure starrocks connection")
	}
	return execute(ctx, connector, cfg, p.SQL, mask)
}

// driverConfig builds the connection from structured fields only. NewConfig
// leaves multi-statements, LOCAL INFILE, parameter interpolation and TLS off.
// The context, not a read timeout, bounds the query.
func driverConfig(cfg Config, p Params, cred credfile.Credential) (*mysqldriver.Config, error) {
	address, err := parseAddress(cfg.Address)
	if err != nil {
		return nil, err
	}
	dc := mysqldriver.NewConfig()
	dc.User, dc.Passwd, dc.DBName = cred.Username, cred.Password, p.Database
	dc.Net, dc.Addr = "tcp", address
	dc.Timeout = cfg.Timeout
	return dc, nil
}

func execute(ctx context.Context, connector sqldriver.Connector, cfg Config, query string, mask func(string) string) (Result, error) {
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return Result{}, queryError(ctx, "connect", err)
	}
	defer conn.Close()
	if err := initSession(ctx, conn, cfg.Timeout); err != nil {
		return Result{}, err
	}
	// Cancelling the query context drops the connection. A truncated result
	// uses that instead of reading the rest of a large result set.
	queryCtx, stop := context.WithCancel(ctx)
	defer stop()
	rows, err := conn.QueryContext(queryCtx, query)
	if err != nil {
		return Result{}, queryError(ctx, "query", err)
	}
	defer rows.Close()
	result, err := readRows(rows, cfg.MaxRows, cfg.MaxBytes, mask)
	if err != nil {
		return Result{}, queryError(ctx, "read result", err)
	}
	if result.Truncated {
		stop()
		_ = rows.Close()
	} else if err := rows.Close(); err != nil {
		return Result{}, queryError(ctx, "close result", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return result, nil
}

// initSession sets query_timeout, the only session variable. It counts whole
// seconds and must be at least 1, so the timeout is rounded up. The statement
// must succeed: without it the server limit would be its default of 300 s.
func initSession(ctx context.Context, conn *sql.Conn, timeout time.Duration) error {
	seconds := int64((timeout + time.Second - 1) / time.Second)
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("SET query_timeout = %d", seconds)); err != nil {
		return queryError(ctx, "initialize session", err)
	}
	return nil
}

// Server error messages can contain SQL literals and credentials; expose codes only.
func queryError(ctx context.Context, stage string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var server *mysqldriver.MySQLError
	if errors.As(err, &server) {
		return fmt.Errorf("starrocks %s failed (code %d)", stage, server.Number)
	}
	return fmt.Errorf("starrocks %s failed", stage)
}

// readRows reads at most maxRows rows and maxBytes bytes of TSV, header
// included. It reads one row more than it returns to find out whether the
// result is truncated.
func readRows(rows *sql.Rows, maxRows int, maxBytes int64, mask func(string) string) (Result, error) {
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
