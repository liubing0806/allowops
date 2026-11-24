package guardrails

import (
	"go/ast"
	"go/format"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

func (f *sourceFile) checkDDL() {
	ast.PreorderStack(f.tree, nil, func(n ast.Node, parents []ast.Node) bool {
		if f.exempt(n, maintenance) {
			return false
		}
		switch expr := n.(type) {
		case *ast.BasicLit:
			if expr.Kind != token.STRING {
				return true
			}
		case *ast.BinaryExpr:
			if expr.Op != token.ADD {
				return true
			}
		default:
			return true
		}
		// Inspect a concatenation once. Calls inside its dynamic operands
		// are still visited and their own string arguments checked.
		for i := len(parents) - 1; i >= 0; i-- {
			if _, ok := parents[i].(*ast.ParenExpr); ok {
				continue
			}
			if sum, ok := parents[i].(*ast.BinaryExpr); ok && sum.Op == token.ADD {
				return true
			}
			break
		}
		var sql sqlExpression
		sql.append(n.(ast.Expr))
		query := sql.text.String()
		offset, operation := ddlOperation(query)
		if operation != "" && !f.auditPartitionDrop(query, n, parents) {
			pos := sql.position(f.positions, offset)
			f.report(pos, ddlRule, operation+" in runtime SQL. Move schema changes to internal/store/migrations or document maintenance with "+maintenance+" <reason>")
		}
		return true
	})
}

const dynamicOperand = "\x00" // cannot occur in PostgreSQL statement text

type literalPart struct {
	start int
	lit   *ast.BasicLit
}

type sqlExpression struct {
	text  strings.Builder
	parts []literalPart
}

func (s *sqlExpression) append(expr ast.Expr) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			s.append(e.X)
			s.append(e.Y)
			return
		}
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			value, _ := strconv.Unquote(e.Value)
			s.parts = append(s.parts, literalPart{s.text.Len(), e})
			s.text.WriteString(value)
			return
		}
	}
	s.text.WriteString(dynamicOperand)
}

// Report the literal containing the first keyword. Inside multiline raw
// strings the physical line comes from the Go file (also correct for CRLF).
func (s *sqlExpression) position(file *token.File, offset int) token.Pos {
	i := len(s.parts) - 1
	for s.parts[i].start > offset {
		i--
	}
	part := s.parts[i]
	if part.lit.Value[0] == '`' {
		before := part.lit.Value[1 : 1+offset-part.start]
		if last := strings.LastIndexByte(before, '\n'); last >= 0 {
			line := file.PositionFor(part.lit.Pos(), false).Line + strings.Count(before, "\n")
			return file.LineStart(line) + token.Pos(len(before)-last-1)
		}
	}
	return part.lit.Pos()
}

// audit.(*Store).Prune in retention.go calls audit.dropPartition in sql.go
// with expired partition names. Permit its drop prefix followed by the
// sanitized partition identifier. A different target needs its own review.
func (f *sourceFile) auditPartitionDrop(query string, n ast.Node, parents []ast.Node) bool {
	if f.path != "internal/gateway/audit/sql.go" {
		return false
	}
	prefix, dynamic := strings.CutSuffix(query, dynamicOperand)
	if !dynamic || !strings.EqualFold(strings.TrimSpace(prefix), "DROP TABLE") {
		return false
	}
	sum, ok := n.(*ast.BinaryExpr)
	if !ok || !f.sanitizedPartitionName(sum.Y) {
		return false
	}
	for i := len(parents) - 1; i >= 0; i-- {
		switch fn := parents[i].(type) {
		case *ast.FuncLit:
			return false
		case *ast.FuncDecl:
			return fn.Recv == nil && fn.Name.Name == "dropPartition"
		}
	}
	return false
}

// Compare just the vetted operand in canonical Go syntax, independent of
// whitespace and import alias. Changes to the deletion target need review.
func (f *sourceFile) sanitizedPartitionName(expr ast.Expr) bool {
	var operand strings.Builder
	if err := format.Node(&operand, token.NewFileSet(), ast.Unparen(expr)); err != nil {
		return false
	}
	for _, spec := range f.tree.Imports {
		if importPath(spec) != "github.com/jackc/pgx/v5" {
			continue
		}
		alias := "pgx"
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		if operand.String() == alias+".Identifier{name}.Sanitize()" {
			return true
		}
	}
	return false
}

// Match SQL tokens, not substrings in prose, data values or identifiers.
// Require a target (including format verbs and dynamic identifiers): a bare
// keyword pair also occurs as a SHOW subtype in the MySQL read-only validator.
func ddlOperation(query string) (int, string) {
	lower := strings.ToLower(query)
	if !strings.Contains(lower, "table") && !strings.Contains(lower, "partition") {
		return 0, ""
	}
	var statement []sqlToken
	for rest := query; ; {
		trimmed := strings.TrimLeft(rest, " \t\r\n\f\v")
		if trimmed == "" {
			// A writer can append an identifier in a later call. Preserve
			// the difference between a padded SQL prefix and a bare label.
			if rest != "" {
				statement = append(statement, sqlToken{dynamicOperand, len(query)})
			}
			return statementDDL(statement)
		}
		rest = trimmed
		start := len(query) - len(rest)
		word := sqlLexeme.FindString(rest)
		rest = rest[len(word):]
		switch {
		case word == ";":
			if offset, op := statementDDL(statement); op != "" {
				return offset, op
			}
			statement = statement[:0]
		case strings.HasPrefix(word, "--"):
			continue
		case word == "/*":
			rest = afterBlockComment(rest)
		case len(word) >= 2 && word[0] == '$' && word[len(word)-1] == '$':
			_, rest, _ = strings.Cut(rest, word)
			statement = append(statement, sqlToken{"'", start})
		default:
			statement = append(statement, sqlToken{strings.ToUpper(word), start})
		}
	}
}

type sqlToken struct {
	word   string
	offset int
}

func statementDDL(tokens []sqlToken) (int, string) {
	// PostgreSQL permits table definitions inside a schema definition.
	inSchema := len(tokens) >= 2 && tokens[0].word == "CREATE" && tokens[1].word == "SCHEMA"
	tableStatement := false
	for i := 0; i+2 < len(tokens); i++ {
		first := tokens[i].word
		if first == "TABLE" && (tokens[0].word == "CREATE" || tokens[0].word == "ALTER") {
			tableStatement = true
		}
		start := i == 0 || tokens[i-1].word == dynamicOperand
		if start || inSchema {
			if operation := tableOperation(tokens[i:]); operation != "" {
				return tokens[i].offset, operation
			}
		}
		if first == "PARTITION" && tokens[i+1].word == "OF" && (start || tableStatement) && sqlTarget.MatchString(tokens[i+2].word) {
			return tokens[i].offset, "PARTITION OF"
		}
	}
	return 0, ""
}

// statementDDL supplies at least three tokens. GLOBAL/LOCAL qualify only a
// temporary table, whereas FOREIGN is valid for all three table commands.
func tableOperation(tokens []sqlToken) string {
	verb := tokens[0].word
	if verb != "CREATE" && verb != "ALTER" && verb != "DROP" {
		return ""
	}
	tableIndex := 1
	switch tokens[1].word {
	case "GLOBAL", "LOCAL":
		if verb != "CREATE" || (tokens[2].word != "TEMP" && tokens[2].word != "TEMPORARY") {
			return ""
		}
		tableIndex += 2
	case "TEMP", "TEMPORARY", "UNLOGGED":
		if verb != "CREATE" {
			return ""
		}
		tableIndex++
	case "FOREIGN":
		tableIndex++
	}
	if tableIndex+1 >= len(tokens) || tokens[tableIndex].word != "TABLE" || !sqlTarget.MatchString(tokens[tableIndex+1].word) {
		return ""
	}
	var words []string
	for _, part := range tokens[:tableIndex+1] {
		words = append(words, part.word)
	}
	return strings.Join(words, " ")
}

// Quoted text is one opaque token, so even a semicolon inside it cannot
// start a statement. Dollar quotes and nested block comments need matching
// delimiters and are consumed by the caller.
var sqlLexeme = regexp.MustCompile("(?is)^(?:" + strings.Join([]string{
	`--[^\r\n]*`, `/\*`, // comments
	`\$(?:[\pL_][\pL\pN_]*)?\$`,    // dollar-quote opener
	`E'(?:''|\\.|[^'\\])*(?:'|\z)`, // PostgreSQL escape string
	`'(?:''|[^'])*(?:'|\z)`,        // string
	`"(?:""|[^"])*(?:"|\z)`,        // quoted identifier
	"`(?:``|[^`])*(?:`|\\z)",       // MySQL quoted identifier
	`[\pL\pN_][\pL\pN_$]*`, `.`,    // word or one symbol
}, "|") + ")")

var sqlTarget = regexp.MustCompile(`^[\pL_"\x60%\x00]`)

func afterBlockComment(rest string) string {
	for depth := 1; depth > 0; {
		i := strings.IndexAny(rest, "/*")
		if i < 0 {
			return ""
		}
		rest = rest[i:]
		switch {
		case strings.HasPrefix(rest, "/*"):
			depth++
		case strings.HasPrefix(rest, "*/"):
			depth--
		default:
			rest = rest[1:]
			continue
		}
		rest = rest[2:]
	}
	return rest
}
