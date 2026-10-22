// Package mysql implements the self-contained mysql_query builtin.
package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	driver "github.com/go-sql-driver/mysql"
)

const (
	DefaultMaxRows  = 500
	DefaultTimeout  = 10 * time.Second
	databasePattern = `^[a-zA-Z0-9_]{1,64}$`
)

var databaseName = regexp.MustCompile(databasePattern)

// Config is trusted catalog configuration. Zero limits select the defaults.
type Config struct {
	Credential     string        `yaml:"credential" json:"credential"`
	Address        string        `yaml:"address" json:"address"`
	MaxRows        int           `yaml:"max_rows" json:"max_rows"`
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
	Databases      []string      `yaml:"databases" json:"databases"`
	StatementTypes []string      `yaml:"statement_types" json:"statement_types"`
	ShowTypes      []string      `yaml:"show_types" json:"show_types"`
}

type Params struct {
	Database string `yaml:"database" json:"database"`
	SQL      string `yaml:"sql" json:"sql"`
}

// Result contains unredacted TSV; callers must redact before exposing it.
type Result struct {
	Output    string `json:"output"`
	Rows      int    `json:"rows"`
	Truncated bool   `json:"truncated"`
}

func (c Config) Validate() error {
	if !filepath.IsAbs(c.Credential) {
		return errors.New("credential must be an absolute file path")
	}
	if c.MaxRows < 0 || c.MaxRows > DefaultMaxRows {
		return errors.New("max_rows must be between 0 and 500")
	}
	if c.Timeout < 0 || c.Timeout > DefaultTimeout || (c.Timeout > 0 && c.Timeout < time.Millisecond) {
		return errors.New("timeout must be zero or between 1ms and 10s")
	}
	if err := c.validateRestrictions(); err != nil {
		return err
	}
	_, _, err := parseAddress(c.Address)
	return err
}

func parseAddress(address string) (string, string, error) {
	u, err := url.Parse(address)
	invalid := errors.New("address must be tcp://host:port or unix:///absolute/socket without credentials or options")
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", "", invalid
	}
	switch u.Scheme {
	case "tcp":
		if u.Path != "" {
			return "", "", invalid
		}
		host, port, err := net.SplitHostPort(u.Host)
		n, parseErr := strconv.Atoi(port)
		if err != nil || host == "" || parseErr != nil || n < 1 || n > 65535 {
			return "", "", invalid
		}
		return "tcp", u.Host, nil
	case "unix":
		if u.Host != "" || !filepath.IsAbs(u.Path) || u.Path == "/" || strings.ContainsRune(u.Path, 0) {
			return "", "", invalid
		}
		return "unix", u.Path, nil
	}
	return "", "", invalid
}

func ParamsSchema() map[string]any {
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type":    "object", "additionalProperties": false,
		"required": []string{"database", "sql"},
		"properties": map[string]any{
			"database": map[string]any{"type": "string", "pattern": databasePattern, "minLength": 1, "maxLength": 64},
			"sql":      map[string]any{"type": "string", "minLength": 1, "maxLength": maxSQLLength},
		},
	}
}

type credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func readCredential(path string) (credential, error) {
	var c credential
	// O_NONBLOCK prevents a FIFO/device path from blocking before fstat rejects it.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return c, errors.New("cannot open credential file")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return c, errors.New("cannot inspect credential file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode() != 0600 {
		return c, errors.New("credential file must be a regular root-owned file with mode 0600")
	}
	if info.Size() > 16384 {
		return c, errors.New("credential file is too large")
	}
	return decodeCredential(io.LimitReader(f, 16385))
}

func decodeCredential(r io.Reader) (credential, error) {
	var fields struct {
		Username *string `json:"username"`
		Password *string `json:"password"`
	}
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&fields); err != nil || fields.Username == nil || *fields.Username == "" || fields.Password == nil {
		return credential{}, errors.New("credential must contain JSON username and password strings")
	}
	if d.Decode(new(any)) != io.EOF {
		return credential{}, errors.New("credential must contain exactly one JSON object")
	}
	return credential{Username: *fields.Username, Password: *fields.Password}, nil
}

func Run(ctx context.Context, cfg Config, p Params) (result Result, err error) {
	return RunRedacted(ctx, cfg, p, nil)
}

// RunRedacted applies the caller's policy to original columns and cells before TSV encoding.
func RunRedacted(ctx context.Context, cfg Config, p Params, mask func(string) string) (result Result, err error) {
	if err := cfg.Validate(); err != nil {
		return result, err
	}
	if !databaseName.MatchString(p.Database) {
		return result, errors.New("invalid database name")
	}
	if cfg.Databases != nil && !slices.Contains(cfg.Databases, p.Database) {
		return result, fmt.Errorf("databases allows only: %s", strings.Join(cfg.Databases, ", "))
	}
	if err := validateSQLConfig(p.SQL, cfg); err != nil {
		return result, err
	}
	if cfg.MaxRows == 0 {
		cfg.MaxRows = DefaultMaxRows
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	cred, err := readCredential(cfg.Credential)
	if err != nil {
		return result, err
	}
	return runQueryRedacted(ctx, cfg, p, cred, mask)
}

// runQuery receives validated parameters and normalized limits from Run.
func runQuery(ctx context.Context, cfg Config, p Params, cred credential) (result Result, err error) {
	return runQueryRedacted(ctx, cfg, p, cred, nil)
}

func runQueryRedacted(ctx context.Context, cfg Config, p Params, cred credential, mask func(string) string) (result Result, err error) {
	dc := driver.NewConfig()
	dc.User, dc.Passwd, dc.DBName = cred.Username, cred.Password, p.Database
	dc.Net, dc.Addr, _ = parseAddress(cfg.Address)
	dc.Timeout, dc.ReadTimeout, dc.WriteTimeout = cfg.Timeout, cfg.Timeout, cfg.Timeout
	dc.Collation = "utf8mb4_bin"
	// NewConfig defaults MultiStatements and AllowAllFiles to false.
	connector, err := driver.NewConnector(dc)
	if err != nil {
		return result, errors.New("cannot configure mysql connection")
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return result, queryError(ctx, "connect", err)
	}
	defer conn.Close()
	if err := beginReadOnly(ctx, conn, cfg.Timeout); err != nil {
		return result, err
	}
	defer func() {
		// A cancelled request must not suppress the rollback attempt.
		cleanup, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		if _, rollbackErr := conn.ExecContext(cleanup, "ROLLBACK"); rollbackErr != nil && err == nil {
			err = queryError(cleanup, "rollback", rollbackErr)
			result = Result{}
		}
	}()
	rows, err := conn.QueryContext(ctx, p.SQL)
	if err != nil {
		return result, queryError(ctx, "query", err)
	}
	defer rows.Close()
	result, err = readRowsRedacted(rows, cfg.MaxRows, mask)
	if err != nil {
		return Result{}, queryError(ctx, "read result", err)
	}
	if err := rows.Close(); err != nil {
		return Result{}, queryError(ctx, "close result", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return result, nil
}

func beginReadOnly(ctx context.Context, conn *sql.Conn, timeout time.Duration) error {
	// Round up: max_execution_time=0 disables the server limit.
	ms := (timeout + time.Millisecond - 1) / time.Millisecond
	for _, statement := range []string{
		"SET SESSION sql_mode = '" + sessionSQLMode + "'",
		"SET NAMES utf8mb4 COLLATE utf8mb4_bin",
		fmt.Sprintf("SET SESSION max_execution_time = %d", ms),
		"START TRANSACTION READ ONLY",
	} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return queryError(ctx, "initialize read-only session", err)
		}
	}
	return nil
}

// Server error messages can contain SQL literals and credentials; expose codes only.
func queryError(ctx context.Context, stage string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var server *driver.MySQLError
	if errors.As(err, &server) {
		return fmt.Errorf("mysql %s failed (code %d)", stage, server.Number)
	}
	return fmt.Errorf("mysql %s failed", stage)
}

func readRows(rows *sql.Rows, maxRows int) (Result, error) {
	return readRowsRedacted(rows, maxRows, nil)
}

func readRowsRedacted(rows *sql.Rows, maxRows int, mask func(string) string) (Result, error) {
	if mask == nil {
		mask = func(s string) string { return s }
	}
	columns, err := rows.Columns()
	if err != nil {
		return Result{}, err
	}
	var out strings.Builder
	for i, column := range columns {
		columns[i] = mask(column)
	}
	writeTSV(&out, columns)
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
		for i, v := range values {
			if i > 0 {
				out.WriteByte('\t')
			}
			if v.Valid {
				out.WriteString(escapeTSV(mask(v.String)))
			} else {
				out.WriteString(`\N`)
			}
		}
		out.WriteByte('\n')
		result.Rows++
	}
	if err := rows.Err(); err != nil {
		return Result{}, err
	}
	result.Output = out.String()
	return result, nil
}

var tsvEscaper = strings.NewReplacer("\\", "\\\\", "\t", `\t`, "\n", `\n`, "\r", `\r`, "\x00", `\0`)

func escapeTSV(s string) string { return tsvEscaper.Replace(s) }
func writeTSV(out *strings.Builder, fields []string) {
	for i, field := range fields {
		if i > 0 {
			out.WriteByte('\t')
		}
		out.WriteString(escapeTSV(field))
	}
	out.WriteByte('\n')
}
