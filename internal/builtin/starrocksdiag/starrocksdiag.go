// Package starrocksdiag implements the self-contained starrocks_diag builtin:
// fixed diagnostic statements for a StarRocks frontend (cluster state, running
// queries, slow queries from the audit table, query profiles) and the
// host-side summary of a query profile.
//
// The handler never runs a statement that the caller supplied, except for the
// optional profile_run op, which is off by default and validates the SQL with
// the StarRocks lexical guard first. The statements are fixed so that the
// account may hold SYSTEM OPERATE (SHOW FRONTENDS, SHOW PROC, ...), which also
// allows KILL and configuration changes; no statement here uses them.
package starrocksdiag

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
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
	"github.com/liubing0806/allowops/internal/builtin/srconn"
	"github.com/liubing0806/allowops/internal/builtin/starrocksprofile"
)

// The ops of starrocks_diag.
const (
	OpCluster        = "cluster"
	OpRunning        = "running"
	OpSlowQueries    = "slow_queries"
	OpProfileList    = "profile_list"
	OpProfileAnalyze = "profile_analyze"
	OpProfileSummary = "profile_summary"
	OpProfileRun     = "profile_run"
)

// DefaultAuditTable is the table that the AuditLoader plugin creates.
const DefaultAuditTable = "starrocks_audit_db__.starrocks_audit_tbl__"

// auditColumns maps the logical column names of slow_queries to the columns of
// the AuditLoader table. builtin_config.audit_columns can rename them.
var auditColumns = []struct{ key, column string }{
	{"query_id", "queryId"}, {"timestamp", "timestamp"}, {"user", "user"}, {"db", "db"}, {"state", "state"}, {"query_time", "queryTime"},
	{"scan_bytes", "scanBytes"}, {"scan_rows", "scanRows"}, {"return_rows", "returnRows"}, {"cpu_cost_ns", "cpuCostNs"},
	{"mem_cost_bytes", "memCostBytes"}, {"stmt", "stmt"},
}

// stmtChars bounds the SQL text that slow_queries returns per row.
const stmtChars = 1000

// Parameter bounds.
const (
	DefaultLimit       = 20
	MaxSinceMinutes    = 10080
	DefaultSinceMinute = 60
	MaxMinDurationMs   = 86400000
)

// Components of the cluster op.
var components = []string{"all", "frontends", "backends", "compute_nodes"}

var clusterStatements = []struct{ component, statement string }{
	{"frontends", "SHOW FRONTENDS"}, {"backends", "SHOW BACKENDS"}, {"compute_nodes", "SHOW COMPUTE NODES"},
}

// States of the audit table.
var States = []string{"any", "EOF", "OK", "ERR"}

// QueryIDPattern is the only accepted form of a query ID.
const QueryIDPattern = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`

var (
	queryID        = regexp.MustCompile(QueryIDPattern)
	identifier     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	databaseName   = regexp.MustCompile(`^[a-zA-Z0-9_]{1,64}$`)
	terminalEscape = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")
)

// pollInterval is the wait between two reads of a profile that is not registered yet.
var pollInterval = 200 * time.Millisecond

// Config is trusted catalog configuration. Zero limits select the defaults,
// which are also the maximum: configuration can only tighten them.
type Config struct {
	Credential string `yaml:"credential" json:"credential"`
	Address    string `yaml:"address" json:"address"`
	MaxRows    int    `yaml:"max_rows" json:"max_rows"`
	// MaxBytes limits the TSV text or the summary JSON, header included.
	MaxBytes int64         `yaml:"max_bytes" json:"max_bytes"`
	Timeout  time.Duration `yaml:"timeout" json:"timeout"`
	// MaxProfileBytes limits the profile text that profile_summary parses.
	MaxProfileBytes int64 `yaml:"max_profile_bytes" json:"max_profile_bytes"`
	// AuditTable is [database.]table of the audit log; names come from here
	// only and must be identifiers.
	AuditTable string `yaml:"audit_table" json:"audit_table"`
	// AuditColumns renames columns of the audit table by logical name.
	AuditColumns map[string]string `yaml:"audit_columns" json:"audit_columns"`
	// AllowProfileRun enables the profile_run op, which executes the caller's SELECT.
	AllowProfileRun bool `yaml:"allow_profile_run" json:"allow_profile_run"`
}

// Params are the caller's parameters. Which fields apply depends on Op;
// validateParams checks them per op.
type Params struct {
	Op            string
	Component     string
	SinceMinutes  int
	MinDurationMs int
	State         string
	Limit         int
	QueryID       string
	TopN          int
	SQL           string
	Database      string
}

// Result is unredacted TSV or summary JSON unless a mask was given; callers
// must redact before exposing it.
type Result struct {
	Output    string `json:"output"`
	Rows      int    `json:"rows"`
	Truncated bool   `json:"truncated"`
}

// Ops returns the ops that the configuration enables, in documentation order.
func Ops(cfg Config) []string {
	ops := []string{OpCluster, OpRunning, OpSlowQueries, OpProfileList, OpProfileAnalyze, OpProfileSummary}
	if cfg.AllowProfileRun {
		ops = append(ops, OpProfileRun)
	}
	return ops
}

func validAuditTable(name string) bool {
	parts := strings.Split(name, ".")
	if len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if !identifier.MatchString(part) {
			return false
		}
	}
	return true
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
	if c.MaxProfileBytes < 0 || c.MaxProfileBytes > builtin.DefaultStarRocksProfileBytes {
		return fmt.Errorf("max_profile_bytes must be between 0 and %d", builtin.DefaultStarRocksProfileBytes)
	}
	if c.Timeout < 0 || c.Timeout > builtin.DefaultTimeout || (c.Timeout > 0 && c.Timeout < time.Millisecond) {
		return errors.New("timeout must be zero or between 1ms and 10s")
	}
	if c.AuditTable != "" && !validAuditTable(c.AuditTable) {
		return errors.New("audit_table must be table or database.table, each an identifier of letters, digits and underscores")
	}
	for key, column := range c.AuditColumns {
		if !slices.ContainsFunc(auditColumns, func(a struct{ key, column string }) bool { return a.key == key }) {
			return fmt.Errorf("audit_columns has an unknown key %q", key)
		}
		if !identifier.MatchString(column) {
			return fmt.Errorf("audit_columns.%s must be an identifier of letters, digits and underscores", key)
		}
	}
	_, err := srconn.ParseAddress(c.Address)
	return err
}

// normalized replaces zero limits and empty names with the defaults. It
// does not modify the caller's AuditColumns.
func (c Config) normalized() Config {
	if c.MaxRows == 0 {
		c.MaxRows = builtin.DefaultStarRocksMaxRows
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = builtin.DefaultStarRocksMaxBytes
	}
	if c.MaxProfileBytes == 0 {
		c.MaxProfileBytes = builtin.DefaultStarRocksProfileBytes
	}
	if c.Timeout == 0 {
		c.Timeout = builtin.DefaultTimeout
	}
	if c.AuditTable == "" {
		c.AuditTable = DefaultAuditTable
	}
	columns := make(map[string]string, len(auditColumns))
	for _, a := range auditColumns {
		columns[a.key] = a.column
	}
	maps.Copy(columns, c.AuditColumns)
	c.AuditColumns = columns
	return c
}

// normalized fills the defaults of the parameters that have one.
func (p Params) normalized() Params {
	if p.Component == "" {
		p.Component = "all"
	}
	if p.SinceMinutes == 0 {
		p.SinceMinutes = DefaultSinceMinute
	}
	if p.State == "" {
		p.State = "any"
	}
	if p.Limit == 0 {
		p.Limit = DefaultLimit
	}
	if p.TopN == 0 {
		p.TopN = starrocksprofile.DefaultTopN
	}
	return p
}

// quoteLiteral renders s as a StarRocks string literal. StarRocks treats the
// backslash as an escape character, so it is doubled as well.
func quoteLiteral(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, "'", "''", "\x00", `\0`, "\n", `\n`, "\r", `\r`).Replace(s) + "'"
}

func quoteIdentifier(name string) string { return "`" + name + "`" }

// validate is replaceable so that a test can make the guard panic.
var validate = sqlguard.Validate

var errValidatePanic = fmt.Errorf("%w: SQL could not be validated", sqlguard.ErrRejected)

func validateRunSQL(text string) (err error) {
	returned := false
	defer func() {
		if !returned {
			_ = recover() // a panic value can contain the SQL
			err = errValidatePanic
		}
	}()
	if strings.TrimSpace(text) == "" {
		return errors.New("sql is required for profile_run")
	}
	st, err := validate(sqlguard.StarRocks, text, sqlguard.Options{})
	returned = true
	if err != nil {
		return err
	}
	if st.Kind != sqlguard.KindSelect {
		return fmt.Errorf("%w: profile_run accepts only SELECT or WITH queries", sqlguard.ErrRejected)
	}
	return nil
}

// validateParams checks the parameters of the op. The configuration must be normalized.
func validateParams(cfg Config, p Params) error {
	if p.Op == OpProfileRun && !cfg.AllowProfileRun {
		return errors.New("op profile_run is disabled; set builtin_config.allow_profile_run to enable it")
	}
	if !slices.Contains(Ops(cfg), p.Op) {
		return fmt.Errorf("op must be one of: %s", strings.Join(Ops(cfg), ", "))
	}
	hasID := p.Op == OpProfileAnalyze || p.Op == OpProfileSummary
	if p.QueryID != "" && !hasID {
		return fmt.Errorf("query_id is not used by op %s", p.Op)
	}
	if p.Op != OpProfileRun && (p.SQL != "" || p.Database != "") {
		if p.SQL != "" {
			return fmt.Errorf("sql is not used by op %s", p.Op)
		}
		return fmt.Errorf("database is not used by op %s", p.Op)
	}
	explicitLimit := p.Limit != 0
	p = p.normalized()
	switch p.Op {
	case OpCluster:
		if !slices.Contains(components, p.Component) {
			return fmt.Errorf("component must be one of: %s", strings.Join(components, ", "))
		}
	case OpSlowQueries:
		if p.SinceMinutes < 1 || p.SinceMinutes > MaxSinceMinutes {
			return fmt.Errorf("since_minutes must be between 1 and %d", MaxSinceMinutes)
		}
		if p.MinDurationMs < 0 || p.MinDurationMs > MaxMinDurationMs {
			return fmt.Errorf("min_duration_ms must be between 0 and %d", MaxMinDurationMs)
		}
		if !slices.Contains(States, p.State) {
			return fmt.Errorf("state must be one of: %s", strings.Join(States, ", "))
		}
		fallthrough
	case OpProfileList:
		// The default limit may exceed a tightened max_rows; the row cap then truncates.
		if p.Limit < 1 || (explicitLimit && p.Limit > cfg.MaxRows) {
			return fmt.Errorf("limit must be between 1 and %d", cfg.MaxRows)
		}
	}
	if hasID {
		if !queryID.MatchString(p.QueryID) {
			return errors.New("query_id must be a query ID in UUID format")
		}
	}
	if p.Op == OpProfileSummary || p.Op == OpProfileRun {
		if p.TopN < 1 || p.TopN > starrocksprofile.MaxTopN {
			return fmt.Errorf("top_n must be between 1 and %d", starrocksprofile.MaxTopN)
		}
	}
	if p.Op == OpProfileRun {
		if p.Database != "" && !databaseName.MatchString(p.Database) {
			return errors.New("invalid database name")
		}
		return validateRunSQL(p.SQL)
	}
	return nil
}

// Run executes the op and returns unredacted output.
func Run(ctx context.Context, cfg Config, p Params) (Result, error) {
	return RunRedacted(ctx, cfg, p, nil)
}

// RunRedacted applies the caller's policy to column names and cells before
// TSV encoding, and to the strings of a summary. The parameters are validated
// before the credential file is read and before any connection is made.
func RunRedacted(ctx context.Context, cfg Config, p Params, mask func(string) string) (Result, error) {
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	cfg = cfg.normalized()
	if err := validateParams(cfg, p); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	cred, err := credfile.Read(cfg.Credential)
	if err != nil {
		return Result{}, err
	}
	return runWithCredential(ctx, cfg, p, cred, mask)
}

// runWithCredential receives validated parameters and a normalized
// configuration. It does not validate the parameters; tests use it to send
// ops with the credential of the local environment.
func runWithCredential(ctx context.Context, cfg Config, p Params, cred credfile.Credential, mask func(string) string) (Result, error) {
	database := ""
	if p.Op == OpProfileRun {
		database = p.Database
	}
	dc, err := srconn.DriverConfig(cfg.Address, cfg.Timeout, database, cred)
	if err != nil {
		return Result{}, err
	}
	connector, err := mysqldriver.NewConnector(dc)
	if err != nil {
		return Result{}, errors.New("cannot configure starrocks connection")
	}
	return runOp(ctx, connector, cfg, p, mask)
}

// runOp runs the op on a dedicated connection. The configuration must be normalized.
func runOp(ctx context.Context, connector sqldriver.Connector, cfg Config, p Params, mask func(string) string) (Result, error) {
	if p.Op == OpProfileRun && !cfg.AllowProfileRun {
		return Result{}, errors.New("op profile_run is disabled")
	}
	p = p.normalized()
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if mask == nil {
		mask = func(s string) string { return s }
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return Result{}, srconn.QueryError(ctx, "connect", err)
	}
	defer conn.Close()
	if err := srconn.SetQueryTimeout(ctx, conn, cfg.Timeout); err != nil {
		return Result{}, err
	}
	switch p.Op {
	case OpCluster:
		return runCluster(ctx, conn, cfg, p, mask)
	case OpRunning:
		return runTSV(ctx, conn, cfg, "SHOW PROC '/current_queries'", mask)
	case OpSlowQueries:
		return runTSV(ctx, conn, cfg, slowQuerySQL(cfg, p), mask)
	case OpProfileList:
		return runTSV(ctx, conn, cfg, "SHOW PROFILELIST LIMIT "+strconv.Itoa(p.Limit), mask)
	case OpProfileAnalyze:
		// ANALYZE PROFILE colours its text with terminal escapes.
		return runTSV(ctx, conn, cfg, "ANALYZE PROFILE FROM "+quoteLiteral(p.QueryID), func(s string) string {
			return mask(terminalEscape.ReplaceAllString(s, ""))
		})
	case OpProfileSummary:
		text, err := fetchProfile(ctx, conn, p.QueryID, cfg.MaxProfileBytes)
		if err != nil {
			return Result{}, err
		}
		return summarize(text, p.TopN, cfg.MaxBytes, nil, mask)
	case OpProfileRun:
		return runProfile(ctx, conn, cfg, p, mask)
	}
	return Result{}, fmt.Errorf("op must be one of: %s", strings.Join(Ops(cfg), ", "))
}

func runTSV(ctx context.Context, conn *sql.Conn, cfg Config, statement string, mask func(string) string) (Result, error) {
	r, err := queryTSV(ctx, conn, statement, cfg.MaxRows, cfg.MaxBytes, mask)
	return Result{Output: r.Output, Rows: r.Rows, Truncated: r.Truncated}, err
}

// queryTSV cancels the query when the result is truncated, which drops the
// connection instead of reading the rest of a large result set.
func queryTSV(ctx context.Context, conn *sql.Conn, statement string, maxRows int, maxBytes int64, mask func(string) string) (srconn.Result, error) {
	queryCtx, stop := context.WithCancel(ctx)
	defer stop()
	rows, err := conn.QueryContext(queryCtx, statement)
	if err != nil {
		return srconn.Result{}, srconn.QueryError(ctx, "query", err)
	}
	defer rows.Close()
	result, err := srconn.ReadRows(rows, maxRows, maxBytes, mask)
	if err != nil {
		return srconn.Result{}, srconn.QueryError(ctx, "read result", err)
	}
	if result.Truncated {
		stop()
		_ = rows.Close()
	} else if err := rows.Close(); err != nil {
		return srconn.Result{}, srconn.QueryError(ctx, "close result", err)
	}
	if err := ctx.Err(); err != nil {
		return srconn.Result{}, err
	}
	return result, nil
}

// runCluster concatenates the sections "# <component>"; the row and byte
// limits are shared by the sections.
func runCluster(ctx context.Context, conn *sql.Conn, cfg Config, p Params, mask func(string) string) (Result, error) {
	var out strings.Builder
	result := Result{}
	for _, c := range clusterStatements {
		if p.Component != "all" && p.Component != c.component {
			continue
		}
		header := "# " + c.component + "\n"
		if int64(out.Len()+len(header)) > cfg.MaxBytes {
			result.Truncated = true
			break
		}
		r, err := queryTSV(ctx, conn, c.statement, cfg.MaxRows-result.Rows, cfg.MaxBytes-int64(out.Len()+len(header)), mask)
		if err != nil {
			return Result{}, err
		}
		out.WriteString(header)
		out.WriteString(r.Output)
		result.Rows += r.Rows
		if r.Truncated {
			result.Truncated = true
			break
		}
	}
	result.Output = out.String()
	return result, nil
}

// slowQuerySQL builds the audit table query. Table and column names come
// from the validated configuration; the numbers are formatted as integers and
// the state comes from a fixed set, so no caller text reaches the statement.
func slowQuerySQL(cfg Config, p Params) string {
	column := func(key string) string { return quoteIdentifier(cfg.AuditColumns[key]) }
	var selected []string
	for _, a := range auditColumns {
		expr := column(a.key)
		if a.key == "stmt" {
			expr = fmt.Sprintf("LEFT(%s, %d)", expr, stmtChars)
		}
		selected = append(selected, expr+" AS "+quoteIdentifier(a.key))
	}
	table := make([]string, 0, 2)
	for _, part := range strings.Split(cfg.AuditTable, ".") {
		table = append(table, quoteIdentifier(part))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SELECT %s FROM %s WHERE %s >= DATE_SUB(NOW(), INTERVAL %d SECOND) AND %s >= %d",
		strings.Join(selected, ", "), strings.Join(table, "."), column("timestamp"), p.SinceMinutes*60, column("query_time"), p.MinDurationMs)
	if p.State != "" && p.State != "any" {
		fmt.Fprintf(&b, " AND %s = %s", column("state"), quoteLiteral(p.State))
	}
	fmt.Fprintf(&b, " ORDER BY %s DESC LIMIT %d", column("query_time"), p.Limit)
	return b.String()
}

var errProfileNotFound = errors.New("the profile of the query was not found (it may not be registered yet, may have been evicted, or the query never produced one)")

// fetchProfile reads the profile text with get_query_profile. An empty or
// missing profile is errProfileNotFound.
func fetchProfile(ctx context.Context, conn *sql.Conn, id string, maxBytes int64) (string, error) {
	rows, err := conn.QueryContext(ctx, "SELECT get_query_profile("+quoteLiteral(id)+")")
	if err != nil {
		return "", srconn.QueryError(ctx, "query", err)
	}
	defer rows.Close()
	var text sql.NullString
	if rows.Next() {
		if err := rows.Scan(&text); err != nil {
			return "", srconn.QueryError(ctx, "read result", err)
		}
	}
	if err := rows.Err(); err != nil {
		return "", srconn.QueryError(ctx, "read result", err)
	}
	if !text.Valid || text.String == "" {
		return "", errProfileNotFound
	}
	if int64(len(text.String)) > maxBytes {
		return "", fmt.Errorf("the profile is larger than max_profile_bytes (%d bytes)", maxBytes)
	}
	return text.String, nil
}

// summaryOutput is the JSON of profile_summary and profile_run.
type summaryOutput struct {
	ResultRows *int `json:"result_rows,omitempty"`
	starrocksprofile.Summary
}

// summarize parses the profile and encodes the summary. Slow operators are
// dropped from the end of the list until the JSON fits maxBytes.
func summarize(text string, topN int, maxBytes int64, resultRows *int, mask func(string) string) (Result, error) {
	profile, err := starrocksprofile.Parse(text)
	if err != nil {
		return Result{}, fmt.Errorf("the profile cannot be parsed: %w", err)
	}
	out := summaryOutput{ResultRows: resultRows, Summary: starrocksprofile.Summarize(profile, topN, starrocksprofile.DefaultThresholds())}
	out.Summary.Redact(mask)
	full := len(out.TopOperators)
	for {
		data, err := json.Marshal(out)
		if err != nil {
			return Result{}, err
		}
		if int64(len(data)) <= maxBytes {
			return Result{Output: string(data), Rows: 1, Truncated: out.OperatorsOmitted > 0}, nil
		}
		if len(out.TopOperators) == 0 {
			return Result{}, errors.New("the summary does not fit max_bytes")
		}
		out.TopOperators = out.TopOperators[:len(out.TopOperators)/2]
		out.OperatorsOmitted = full - len(out.TopOperators)
	}
}

// runProfile executes the caller's SELECT with enable_profile, discards the
// result rows and summarizes the profile of the query. The SQL has passed the
// guard in validateParams.
func runProfile(ctx context.Context, conn *sql.Conn, cfg Config, p Params, mask func(string) string) (Result, error) {
	if _, err := conn.ExecContext(ctx, "SET enable_profile = true"); err != nil {
		return Result{}, srconn.QueryError(ctx, "initialize session", err)
	}
	rows, err := conn.QueryContext(ctx, p.SQL)
	if err != nil {
		return Result{}, srconn.QueryError(ctx, "query", err)
	}
	count := 0
	for rows.Next() {
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Result{}, srconn.QueryError(ctx, "read result", err)
	}
	var id string
	if err := conn.QueryRowContext(ctx, "SELECT last_query_id()").Scan(&id); err != nil {
		return Result{}, srconn.QueryError(ctx, "query", err)
	}
	if !queryID.MatchString(id) {
		return Result{}, errors.New("starrocks returned an unexpected query ID")
	}
	for {
		text, err := fetchProfile(ctx, conn, id, cfg.MaxProfileBytes)
		if err == nil {
			return summarize(text, p.TopN, cfg.MaxBytes, &count, mask)
		}
		if !errors.Is(err, errProfileNotFound) {
			return Result{}, err
		}
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}
