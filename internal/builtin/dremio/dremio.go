// Package dremio implements the self-contained dremio_query builtin: one
// read-only statement, validated by the lexical guard in package sqlguard, runs
// as a Dremio job through the REST API v3 and its first page of rows comes back
// as TSV.
//
// Dremio 24.1 has no permission boundary: every user is an administrator. The
// guard is therefore the only write restriction on the Dremio side, and the
// accounts of the data sources behind Dremio must be limited to reading.
// docs/builtin-dremio.md describes the boundary.
//
// A call logs in, submits the statement, polls the job, reads one page of the
// result and logs out. When the call times out or its context ends, the job is
// cancelled and the session is closed on a separate short deadline.
package dremio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/builtin/credfile"
	"github.com/liubing0806/allowops/internal/builtin/sqlguard"
)

// Config is trusted catalog configuration. Zero limits select the defaults,
// which are also the maximum: configuration can only tighten them.
//
// There is no setting for the range of readable objects. The guard is lexical
// and does not read object names, and Dremio has no permissions to restrict
// them, so the range comes from the accounts of the data sources.
type Config struct {
	Credential string `yaml:"credential" json:"credential"`
	// URL is http:// or https:// with host and port, without path or query.
	// HTTPS verifies the server with the system root certificates.
	URL string `yaml:"url" json:"url"`
	// MaxRows is at most one result page: Dremio returns 500 rows per request.
	MaxRows int `yaml:"max_rows" json:"max_rows"`
	// MaxBytes limits the TSV text, header included. A row that does not fit
	// is not returned.
	MaxBytes int64         `yaml:"max_bytes" json:"max_bytes"`
	Timeout  time.Duration `yaml:"timeout" json:"timeout"`
	// StatementTypes is a nonempty subset of SELECT, SHOW, DESCRIBE, EXPLAIN.
	// The target of an EXPLAIN must be allowed as well.
	StatementTypes []string `yaml:"statement_types" json:"statement_types"`
	// ShowTypes is a nonempty subset of the Dremio SHOW types of sqlguard.
	ShowTypes []string `yaml:"show_types" json:"show_types"`
}

// Params are the caller's parameters. Names in the SQL must be complete paths:
// the job runs without a default context.
type Params struct {
	SQL string `yaml:"sql" json:"sql"`
}

// Result contains unredacted TSV unless a mask was given; callers must redact
// before exposing it.
type Result struct {
	Output    string `json:"output"`
	Rows      int    `json:"rows"`
	Truncated bool   `json:"truncated"`
}

const (
	// maxPage is the largest page the results endpoint serves.
	maxPage = 500
	// maxControlBody bounds the responses of login, submit, status, cancel and logout.
	maxControlBody = 256 << 10
	// maxResultBody bounds the response of one results request. The rows are
	// JSON objects that repeat every column name, so this is well above max_bytes.
	maxResultBody = 16 << 20
	// cleanupTimeout bounds the cancel and logout requests after the call
	// ended. They use a context of their own, because the caller's has expired.
	cleanupTimeout = 3 * time.Second
	pollInitial    = 25 * time.Millisecond
	pollMax        = 500 * time.Millisecond
)

var allowedStatementTypes = []string{"SELECT", "SHOW", "DESCRIBE", "EXPLAIN"}

func allowedShowTypes() []string { return sqlguard.ShowTypes(sqlguard.Dremio) }

func containsFold(values []string, value string) bool {
	return slices.ContainsFunc(values, func(allowed string) bool { return strings.EqualFold(allowed, value) })
}

func (c Config) Validate() error {
	if !filepath.IsAbs(c.Credential) {
		return errors.New("credential must be an absolute file path")
	}
	if c.MaxRows < 0 || c.MaxRows > builtin.DefaultDremioMaxRows {
		return fmt.Errorf("max_rows must be between 0 and %d", builtin.DefaultDremioMaxRows)
	}
	if c.MaxBytes < 0 || c.MaxBytes > builtin.DefaultDremioMaxBytes {
		return fmt.Errorf("max_bytes must be between 0 and %d", builtin.DefaultDremioMaxBytes)
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
			if !containsFold(list.allowed, value) {
				return fmt.Errorf("%s may only contain: %s", list.name, strings.Join(list.allowed, ", "))
			}
		}
	}
	_, err := parseURL(c.URL)
	return err
}

// normalized replaces zero limits with the defaults.
func (c Config) normalized() Config {
	if c.MaxRows == 0 {
		c.MaxRows = builtin.DefaultDremioMaxRows
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = builtin.DefaultDremioMaxBytes
	}
	if c.Timeout == 0 {
		c.Timeout = builtin.DefaultTimeout
	}
	return c
}

// parseURL accepts only http(s)://host:port and returns it without a trailing slash.
func parseURL(raw string) (string, error) {
	invalid := errors.New("url must be http://host:port or https://host:port without credentials, path or options")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", invalid
	}
	host, port, err := net.SplitHostPort(u.Host)
	n, parseErr := strconv.Atoi(port)
	if err != nil || host == "" || parseErr != nil || n < 1 || n > 65535 {
		return "", invalid
	}
	return u.Scheme + "://" + u.Host, nil
}

// validate and readCredential are replaceable so that tests can make the guard
// panic and read a credential file that is not root-owned.
var (
	validate       = sqlguard.Validate
	readCredential = credfile.Read
)

var errValidatePanic = fmt.Errorf("%w: SQL could not be validated", sqlguard.ErrRejected)

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
	st, err := validate(sqlguard.Dremio, sql, sqlguard.Options{})
	returned = true
	if err != nil {
		return err
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
// and before any request is sent.
func RunRedacted(ctx context.Context, cfg Config, p Params, mask func(string) string) (Result, error) {
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	if err := validateSQL(p.SQL, cfg); err != nil {
		return Result{}, err
	}
	cfg = cfg.normalized()
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	cred, err := readCredential(cfg.Credential)
	if err != nil {
		return Result{}, err
	}
	return runQuery(ctx, cfg, p, cred, mask)
}

// runQuery receives validated parameters and normalized limits. It does not
// validate the SQL; tests use it to send statements that the guard rejects.
func runQuery(ctx context.Context, cfg Config, p Params, cred credfile.Credential, mask func(string) string) (Result, error) {
	base, err := parseURL(cfg.URL)
	if err != nil {
		return Result{}, err
	}
	c := newClient(base)
	defer c.close()
	token, err := c.login(ctx, cred)
	if err != nil {
		return Result{}, err
	}
	var jobID string
	finished := false
	defer func() {
		// The session lasts 720 hours, so it is closed on every path. A job
		// that has not reached a final state is cancelled first. Both
		// requests run after the caller's context may have expired.
		cleanup, done := context.WithTimeout(context.Background(), cleanupTimeout)
		defer done()
		if jobID != "" && !finished {
			_ = c.cancel(cleanup, token, jobID)
		}
		_ = c.logout(cleanup, token)
	}()
	if jobID, err = c.submit(ctx, token, p.SQL); err != nil {
		return Result{}, err
	}
	state, message, err := c.wait(ctx, token, jobID)
	if err != nil {
		return Result{}, err
	}
	finished = true
	if state != stateCompleted {
		return Result{}, jobError(state, message)
	}
	return c.fetch(ctx, token, jobID, cfg, mask)
}
