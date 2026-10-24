package mysql

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	parsermysql "github.com/pingcap/tidb/pkg/parser/mysql"
	_ "github.com/pingcap/tidb/pkg/parser/test_driver" // Standalone AST value constructors.
)

const maxSQLLength = 4000

var errSQL = errors.New("SQL must be one supported read-only statement without unsafe expressions")

// Both parser and connection use IGNORE_SPACE, so built-in function names have
// consistent resolution. Quoted function identifiers are rejected separately.
const sessionSQLMode = "IGNORE_SPACE"

func validateSQL(sql string) (err error) {
	return validateSQLConfig(sql, Config{})
}

func validateSQLConfig(sql string, cfg Config) (err error) {
	// Parser drivers may panic on malformed literals. Reject them without exposing
	// the panic value, which can include untrusted SQL or sensitive literals.
	accepted := false
	defer func() {
		if !accepted {
			_ = recover()
			err = errSQL
		}
	}()
	if !utf8.ValidString(sql) || utf8.RuneCountInString(sql) > maxSQLLength || strings.ContainsRune(sql, 0) {
		return errSQL
	}
	if err := checkLexical(sql); err != nil {
		return err
	}
	p := parser.New()
	p.SetSQLMode(parsermysql.ModeIgnoreSpace)
	stmts, warnings, err := p.ParseSQL(sql)
	if err != nil || len(warnings) != 0 || len(stmts) != 1 {
		return errSQL
	}
	v := &readOnlyVisitor{}
	_, ok := stmts[0].Accept(v)
	if !ok || v.bad {
		return errSQL
	}
	accepted = true
	if cfg.Databases != nil {
		v := &databaseVisitor{cfg: cfg}
		if _, ok := stmts[0].Accept(v); !ok {
			return v.err
		}
	}
	return cfg.validateStatement(stmts[0])
}

// Unqualified references use the already validated connection database. Check
// every explicit schema using its original spelling, including nested queries.
type databaseVisitor struct {
	cfg Config
	err error
}

func (v *databaseVisitor) check(database string) {
	if database != "" && !slices.Contains(v.cfg.Databases, database) {
		v.err = fmt.Errorf("databases allows only: %s", strings.Join(v.cfg.Databases, ", "))
	}
}

func (v *databaseVisitor) Enter(n ast.Node) (ast.Node, bool) {
	switch x := n.(type) {
	case *ast.TableName:
		v.check(x.Schema.O)
	case *ast.ColumnName:
		v.check(x.Schema.O)
	case *ast.SelectField:
		// SelectField.Accept does not visit WildCard in this parser version.
		if x.WildCard != nil {
			v.check(x.WildCard.Schema.O)
		}
	case *ast.ShowStmt:
		v.check(x.DBName)
		// ShowStmt.Accept does not visit Procedure in this parser version.
		if x.Procedure != nil {
			v.check(x.Procedure.Schema.O)
		}
		switch x.Tp {
		case ast.ShowDatabases, ast.ShowProcessList, ast.ShowVariables, ast.ShowStatus:
			if !containsFold(v.cfg.ShowTypes, showType(x.Tp)) {
				v.err = errors.New("databases requires explicit show_types for server-wide SHOW; legal values: DATABASES, PROCESSLIST, VARIABLES, STATUS")
			}
		case ast.ShowTables, ast.ShowTableStatus, ast.ShowTriggers, ast.ShowEvents, ast.ShowOpenTables:
			// An omitted DBName uses the connection database.
		default:
			if x.DBName == "" && x.Table == nil && x.Procedure == nil {
				v.err = fmt.Errorf("databases cannot determine the target database; allows only: %s", strings.Join(v.cfg.Databases, ", "))
			}
		}
	}
	return n, v.err != nil
}

func (v *databaseVisitor) Leave(n ast.Node) (ast.Node, bool) { return n, v.err == nil }

var allowedStatementTypes = []string{"SELECT", "SHOW", "DESCRIBE", "EXPLAIN"}
var allowedShowTypes = []string{"TABLES", "DATABASES", "PROCESSLIST", "VARIABLES", "STATUS", "CREATE TABLE", "COLUMNS"}

func containsFold(values []string, value string) bool {
	return slices.ContainsFunc(values, func(allowed string) bool { return strings.EqualFold(allowed, value) })
}

func (c Config) validateRestrictions() error {
	if c.Databases != nil && len(c.Databases) == 0 {
		return fmt.Errorf("databases must be a nonempty list matching %s", databasePattern)
	}
	for _, database := range c.Databases {
		if !databaseName.MatchString(database) {
			return fmt.Errorf("databases must contain names matching %s", databasePattern)
		}
	}
	for _, list := range []struct {
		name            string
		values, allowed []string
	}{
		{"statement_types", c.StatementTypes, allowedStatementTypes},
		{"show_types", c.ShowTypes, allowedShowTypes},
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
	return nil
}

// Called only after the existing recursive read-only validation succeeds.
// ExplainSym table is a Describe operation, represented as Explain(ShowColumns).
func (c Config) validateStatement(stmt ast.StmtNode) error {
	var kind string
	switch x := stmt.(type) {
	case *ast.SelectStmt, *ast.SetOprStmt:
		kind = "SELECT"
	case *ast.ShowStmt:
		kind = "SHOW"
		if c.ShowTypes != nil && !containsFold(c.ShowTypes, showType(x.Tp)) {
			return fmt.Errorf("show_types allows only: %s", strings.Join(c.ShowTypes, ", "))
		}
	case *ast.ExplainStmt:
		kind = "EXPLAIN"
		if show, ok := x.Stmt.(*ast.ShowStmt); ok && show.Tp == ast.ShowColumns {
			kind = "DESCRIBE"
		}
	}
	if c.StatementTypes != nil && !containsFold(c.StatementTypes, kind) {
		return fmt.Errorf("statement_types allows only: %s", strings.Join(c.StatementTypes, ", "))
	}
	if explain, ok := stmt.(*ast.ExplainStmt); ok && kind == "EXPLAIN" {
		// The EXPLAIN target must satisfy the statement_types restriction as well (builtin-config G31).
		return c.validateStatement(explain.Stmt)
	}
	return nil
}

func showType(tp ast.ShowStmtType) string {
	switch tp {
	case ast.ShowTables:
		return "TABLES"
	case ast.ShowDatabases:
		return "DATABASES"
	case ast.ShowProcessList:
		return "PROCESSLIST"
	case ast.ShowVariables:
		return "VARIABLES"
	case ast.ShowStatus:
		return "STATUS"
	case ast.ShowCreateTable:
		return "CREATE TABLE"
	case ast.ShowColumns:
		return "COLUMNS"
	}
	return ""
}

// checkLexical handles only comments and quoting; the parser handles SQL syntax.
// It also prevents quoting a whitelisted built-in name to invoke a stored function.
func checkLexical(s string) error {
	quotedIdentifier := false
	for i := 0; i < len(s); {
		c := s[i]
		if unicode.IsSpace(rune(c)) {
			i++
			continue
		}
		if c == '#' || (c == '-' && i+1 < len(s) && s[i+1] == '-' && (i+2 == len(s) || unicode.IsSpace(rune(s[i+2])))) {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(s) && s[i+1] == '*' {
			if i+2 < len(s) && (s[i+2] == '!' || s[i+2] == '+') {
				return errSQL
			}
			if i+3 < len(s) && (s[i+2] == 'M' || s[i+2] == 'm') && s[i+3] == '!' {
				return errSQL
			}
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return errSQL
			}
			i += end + 4
			continue
		}
		if quotedIdentifier && c == '(' {
			return errSQL
		}
		quotedIdentifier = false
		if c == '\'' || c == '"' || c == '`' {
			quote := c
			i++
			closed := false
			for i < len(s) {
				if s[i] == '\\' && quote != '`' {
					i += 2
					continue
				}
				if s[i] == quote {
					i++
					if i < len(s) && s[i] == quote {
						i++
						continue
					}
					closed = true
					break
				}
				i++
			}
			if !closed {
				return errSQL
			}
			quotedIdentifier = quote == '`'
			continue
		}
		i++
	}
	return nil
}

type readOnlyVisitor struct{ bad bool }

func (v *readOnlyVisitor) Enter(n ast.Node) (ast.Node, bool) {
	if _, ok := n.(ast.StmtNode); ok {
		switch x := n.(type) {
		case *ast.SelectStmt:
			v.bad = x.Kind != ast.SelectStmtKindSelect || x.SelectIntoOpt != nil || x.LockInfo != nil || len(x.TableHints) != 0
		case *ast.SetOprStmt, *ast.ShowStmt:
		case *ast.ExplainStmt:
			v.bad = x.Analyze || x.Explore || x.Stmt == nil || x.PlanDigest != "" || x.ReplayerFile != "" || x.SQLDigest != ""
		default:
			v.bad = true
		}
	}
	switch x := n.(type) {
	case *ast.VariableExpr:
		v.bad = v.bad || x.Value != nil
	case *ast.FuncCallExpr:
		v.bad = v.bad || x.Schema.O != "" || !safeFunction(x.FnName.L)
	case *ast.AggregateFuncExpr:
		v.bad = v.bad || !safeFunction(strings.ToLower(x.F))
	case *ast.WindowFuncExpr:
		v.bad = v.bad || !safeFunction(strings.ToLower(x.Name))
	case ast.ParamMarkerExpr, *ast.TableOptimizerHint:
		v.bad = true
	}
	return n, v.bad
}

func (v *readOnlyVisitor) Leave(n ast.Node) (ast.Node, bool) { return n, !v.bad }

// Intentionally finite: unknown/UDF/stored functions cannot be proven read-only.
func safeFunction(name string) bool {
	switch name {
	case "abs", "ceil", "ceiling", "floor", "round", "truncate", "mod", "pow", "power", "sqrt",
		"count", "sum", "avg", "min", "max", "group_concat", "bit_and", "bit_or", "bit_xor",
		"stddev", "stddev_pop", "stddev_samp", "variance", "var_pop", "var_samp",
		"coalesce", "if", "ifnull", "nullif", "greatest", "least", "isnull",
		"concat", "concat_ws", "length", "char_length", "character_length", "lower", "upper",
		"lcase", "ucase", "trim", "ltrim", "rtrim", "substring", "substr", "left", "right",
		"replace", "locate", "instr", "reverse", "hex", "unhex", "ascii", "ord",
		"date", "time", "year", "month", "day", "dayofmonth", "dayofweek", "dayofyear",
		"hour", "minute", "second", "date_format", "str_to_date", "datediff", "timestampdiff",
		"timestampadd", "date_add", "date_sub", "extract", "unix_timestamp", "from_unixtime",
		"now", "current_timestamp", "curdate", "current_date", "curtime", "current_time", "utc_timestamp",
		"database", "schema", "version", "connection_id", "user", "current_user",
		"json_extract", "json_unquote", "json_length", "json_type", "json_valid", "json_keys",
		"json_array", "json_object", "json_contains", "json_arrayagg", "json_objectagg",
		"row_number", "rank", "dense_rank", "percent_rank", "cume_dist", "ntile",
		"lag", "lead", "first_value", "last_value", "nth_value":
		return true
	}
	return false
}
