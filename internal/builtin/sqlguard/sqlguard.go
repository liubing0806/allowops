// Package sqlguard validates caller-supplied SQL for the StarRocks and Dremio
// read-only handlers. It is a lexical allow list, not a parser: it splits the
// text into tokens, accepts one statement that starts with an allowed keyword,
// and rejects forbidden keywords, functions and comments.
//
// The guard is only one layer of the read-only boundary. It cannot see view
// definitions or server-side plugin effects, so the database account must also
// be limited to read privileges.
//
// The guard and the server must agree on where strings, identifiers and
// comments begin and end. Spellings that the two could read differently are
// rejected instead of interpreted; docs/builtin-sqlguard.md lists them.
package sqlguard

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxLength is the longest accepted SQL text, counted in characters.
const MaxLength = 4000

// Dialect selects the lexical rules and the keyword lists.
type Dialect int

const (
	StarRocks Dialect = iota + 1
	Dremio
)

func (d Dialect) String() string {
	switch d {
	case StarRocks:
		return "StarRocks"
	case Dremio:
		return "Dremio"
	}
	return fmt.Sprintf("Dialect(%d)", int(d))
}

// Options widens the default rules. The zero value is the strictest.
type Options struct {
	// AllowExplainAnalyze permits StarRocks EXPLAIN ANALYZE with a SELECT or
	// WITH target. The statement executes its target.
	AllowExplainAnalyze bool
}

// Kind is the type of an accepted statement.
type Kind string

const (
	KindSelect         Kind = "SELECT" // SELECT, WITH, set queries, and VALUES in Dremio
	KindShow           Kind = "SHOW"
	KindDescribe       Kind = "DESCRIBE" // DESC and DESCRIBE
	KindExplain        Kind = "EXPLAIN"
	KindAnalyzeProfile Kind = "ANALYZE PROFILE" // StarRocks only
)

// Statement describes an accepted statement.
type Statement struct {
	Kind Kind
	// ShowType is the normalized SHOW type, for example "TABLES" or
	// "CREATE TABLE". It is empty unless Kind is KindShow.
	ShowType string
	// Variant is the normalized EXPLAIN variant, for example "LOGICAL",
	// "VERBOSE", "COSTS", "ANALYZE", "PLAN FOR" or "PLAN WITH IMPLEMENTATION FOR".
	// It is empty for a plain StarRocks EXPLAIN and for other kinds.
	Variant string
	// Target is the statement an EXPLAIN runs or plans. It has passed the same
	// validation as a top-level statement.
	Target *Statement
}

// ErrRejected matches every error that Validate returns for rejected SQL.
var ErrRejected = errors.New("sqlguard: SQL rejected")

// RejectError carries the reason a statement was rejected. The reason is a
// fixed text and never contains the SQL.
type RejectError struct{ Reason string }

func (e *RejectError) Error() string { return "sqlguard: " + e.Reason }

func (e *RejectError) Is(target error) bool { return target == ErrRejected }

func reject(reason string) error { return &RejectError{Reason: reason} }

// Validate accepts exactly one read-only statement of the dialect and reports
// its kind. On rejection it returns a zero Statement and an error that matches
// ErrRejected.
func Validate(d Dialect, sql string, opts Options) (Statement, error) {
	if d != StarRocks && d != Dremio {
		return Statement{}, reject("unknown dialect")
	}
	if err := precheck(sql); err != nil {
		return Statement{}, err
	}
	toks, err := lex(d, sql)
	if err != nil {
		return Statement{}, err
	}
	// One statement; a single trailing semicolon is optional.
	if n := len(toks); n > 0 && isPunct(toks[n-1], ";") {
		toks = toks[:n-1]
	}
	if len(toks) == 0 {
		return Statement{}, reject("empty statement")
	}
	if slices.ContainsFunc(toks, func(t token) bool { return isPunct(t, ";") }) {
		return Statement{}, reject("only one statement is allowed")
	}
	g := guard{d: d, opts: opts}
	st, scanFrom, err := g.statement(toks, false)
	if err != nil {
		return Statement{}, err
	}
	if err := g.scan(toks, scanFrom); err != nil {
		return Statement{}, err
	}
	return st, nil
}

func precheck(s string) error {
	if !utf8.ValidString(s) {
		return reject("SQL is not valid UTF-8")
	}
	if utf8.RuneCountInString(s) > MaxLength {
		return reject(fmt.Sprintf("SQL is longer than %d characters", MaxLength))
	}
	for _, r := range s {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		// U+2028 and U+2029 end a line in some lexers, so they are treated like control characters.
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return reject("SQL contains a control character")
		}
	}
	return nil
}

type guard struct {
	d    Dialect
	opts Options
}

// statement checks the first keyword and the keywords that select a variant.
// It returns the index of the first token that scan has to check; the
// keywords of a SHOW type before it may be on the deny list (CREATE).
func (g guard) statement(toks []token, explainTarget bool) (Statement, int, error) {
	i := 0
	for i < len(toks) && isPunct(toks[i], "(") {
		i++
	}
	if i == len(toks) || toks[i].kind != tWord {
		return Statement{}, 0, reject("statement must start with a keyword")
	}
	if len(toks) == i+1 {
		return Statement{}, 0, reject("statement is incomplete")
	}
	first := toks[i].text
	if first == "SELECT" || first == "WITH" || (first == "VALUES" && g.d == Dremio) {
		return Statement{Kind: KindSelect}, 0, nil
	}
	if i > 0 || explainTarget {
		return Statement{}, 0, reject("only a query may be parenthesized or explained")
	}
	switch first {
	case "SHOW":
		return g.show(toks)
	case "DESC", "DESCRIBE":
		// DESC <query> is EXPLAIN in some servers; accept only a table name.
		next := toks[1]
		if next.kind == tQuoted || (next.kind == tWord && !slices.Contains([]string{"SELECT", "WITH", "VALUES"}, next.text)) {
			return Statement{Kind: KindDescribe}, 0, nil
		}
		return Statement{}, 0, reject("DESCRIBE requires a table name")
	case "EXPLAIN":
		return g.explain(toks)
	case "ANALYZE":
		if g.d == StarRocks {
			return g.analyzeProfile(toks)
		}
	}
	return Statement{}, 0, reject("statement type is not allowed")
}

func (g guard) show(toks []token) (Statement, int, error) {
	i := 1
	for i < len(toks) && toks[i].kind == tWord && slices.Contains(showModifiers, toks[i].text) {
		i++
	}
	for _, t := range showTypesOf(g.d) {
		for _, form := range t.forms {
			if matchWords(toks[i:], form) {
				return Statement{Kind: KindShow, ShowType: t.name}, i + len(form), nil
			}
		}
	}
	return Statement{}, 0, reject("SHOW type is not allowed")
}

func (g guard) explain(toks []token) (Statement, int, error) {
	rest := toks[1:]
	var variant string
	switch g.d {
	case StarRocks:
		if rest[0].kind == tWord {
			switch rest[0].text {
			case "LOGICAL", "VERBOSE", "COSTS":
				variant, rest = rest[0].text, rest[1:]
			case "ANALYZE":
				if !g.opts.AllowExplainAnalyze {
					return Statement{}, 0, reject("EXPLAIN ANALYZE executes the target statement and is disabled")
				}
				variant, rest = "ANALYZE", rest[1:]
				if len(rest) == 0 || rest[0].kind != tWord || (rest[0].text != "SELECT" && rest[0].text != "WITH") {
					return Statement{}, 0, reject("EXPLAIN ANALYZE requires a SELECT or WITH target")
				}
			}
		}
	case Dremio:
		switch {
		case matchWords(rest, []string{"PLAN", "FOR"}):
			variant, rest = "PLAN FOR", rest[2:]
		case matchWords(rest, []string{"PLAN", "WITH", "IMPLEMENTATION", "FOR"}):
			variant, rest = "PLAN WITH IMPLEMENTATION FOR", rest[4:]
		default:
			return Statement{}, 0, reject("EXPLAIN variant is not allowed")
		}
	}
	if len(rest) == 0 {
		return Statement{}, 0, reject("EXPLAIN requires a target statement")
	}
	target, _, err := g.statement(rest, true)
	if err != nil {
		return Statement{}, 0, err
	}
	return Statement{Kind: KindExplain, Variant: variant, Target: &target}, 0, nil
}

// analyzeProfile accepts ANALYZE PROFILE FROM '<query id>' [, <integer>]... and
// nothing else, which keeps ANALYZE TABLE out.
func (g guard) analyzeProfile(toks []token) (Statement, int, error) {
	if !matchWords(toks, []string{"ANALYZE", "PROFILE", "FROM"}) || len(toks) < 4 || toks[3].kind != tString {
		return Statement{}, 0, reject("only ANALYZE PROFILE FROM '<query id>' is allowed")
	}
	rest := toks[4:]
	for len(rest) > 0 {
		if len(rest) < 2 || !isPunct(rest[0], ",") || rest[1].kind != tNumber {
			return Statement{}, 0, reject("ANALYZE PROFILE accepts only a list of integers after the query id")
		}
		rest = rest[2:]
	}
	return Statement{Kind: KindAnalyzeProfile}, 0, nil
}

func matchWords(toks []token, words []string) bool {
	if len(toks) < len(words) {
		return false
	}
	for i, w := range words {
		if toks[i].kind != tWord || toks[i].text != w {
			return false
		}
	}
	return true
}

// scan applies the keyword and function rules to toks[from:].
func (g guard) scan(toks []token, from int) error {
	deniedFunctions := deniedFunctionsOf(g.d)
	for i := from; i < len(toks); i++ {
		t := toks[i]
		call := i+1 < len(toks) && isPunct(toks[i+1], "(")
		if t.kind == tWord {
			// TRUNCATE(x, n) is a numeric function; TRUNCATE as a statement fails the first-keyword check.
			if slices.Contains(deniedKeywords, t.text) && !(t.text == "TRUNCATE" && call) {
				return reject("keyword " + t.text + " is not allowed")
			}
			if t.text == "TABLE" && call && g.d == Dremio && !tableFunctionAllowed(toks[i+2:]) {
				return reject("only table_history, table_snapshot, table_manifests and table_files are allowed in TABLE(...)")
			}
		}
		if call && (t.kind == tWord || t.kind == tQuoted) {
			name := strings.ToLower(t.text)
			if t.kind == tQuoted {
				// Servers fold case with their own Unicode rules, so a non-ASCII name cannot be compared reliably.
				if strings.ContainsFunc(t.text, func(r rune) bool { return r >= utf8.RuneSelf }) {
					return reject("quoted function name must be ASCII")
				}
				name = strings.TrimSpace(name)
			}
			if slices.Contains(deniedFunctions, name) {
				return reject("function " + name + " is not allowed")
			}
		}
	}
	return nil
}

// tableFunctionAllowed checks the tokens after "TABLE (": an unqualified
// allowed function name followed by "(".
func tableFunctionAllowed(toks []token) bool {
	return len(toks) >= 2 && (toks[0].kind == tWord || toks[0].kind == tQuoted) && isPunct(toks[1], "(") &&
		slices.Contains(dremioTableFunctions, strings.ToLower(toks[0].text))
}
