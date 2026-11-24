// Package guardrails checks architectural constraints on AllowOps Go sources.
package guardrails

import (
	"bytes"
	"cmp"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Violation identifies the physical source location, relative to the scanned root.
type Violation struct {
	File    string
	Line    int
	Column  int
	Rule    string
	Message string
}

const (
	ddlRule   = "no-runtime-ddl"
	errorRule = "no-silent-error-drop"
	poolRule  = "no-raw-pgxpool-new"

	maintenance = "//allowops:ddl-maintenance"
	ignoreError = "//allowops:ignore-error"
	poolPackage = "github.com/jackc/pgx/v5/pgxpool"
)

type sourceFile struct {
	path       string
	tree       *ast.File
	positions  *token.File
	directives map[directive]bool
	violations []Violation
}

// Analyze scans non-test Go files for DDL, including build-tagged sources.
// Type-based rules use files selected for the current build.
// A parse or type resolution failure is an analysis error, never a clean result.
func Analyze(root string) ([]Violation, error) {
	fset := token.NewFileSet()
	var files []*sourceFile
	err := fs.WalkDir(os.DirFS(root), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", ".claude":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		tree, err := parser.ParseFile(fset, path, src, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		f := &sourceFile{path: path, tree: tree, positions: fset.File(tree.Pos())}
		f.collectDirectives(src)
		if !strings.HasPrefix(path, "internal/store/migrations/") {
			f.checkDDL()
		}
		files = append(files, f)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := checkTypedRules(root, fset, files); err != nil {
		return nil, err
	}
	var violations []Violation
	for _, f := range files {
		violations = append(violations, f.violations...)
	}
	slices.SortFunc(violations, func(a, b Violation) int {
		return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line),
			cmp.Compare(a.Column, b.Column), cmp.Compare(a.Rule, b.Rule))
	})
	return violations, nil
}

func (f *sourceFile) report(pos token.Pos, rule, message string) {
	p := f.positions.PositionFor(pos, false)
	f.violations = append(f.violations, Violation{
		File: f.path, Line: p.Line, Column: p.Column, Rule: rule, Message: message,
	})
}

func (f *sourceFile) checksErrors() bool {
	return strings.HasPrefix(f.path, "cmd/allowops-gateway/") || strings.HasPrefix(f.path, "internal/agent/")
}

func (f *sourceFile) checksPool() bool {
	if f.path == "internal/store/store.go" || strings.HasPrefix(f.path, "internal/testpg/") {
		return false
	}
	for _, spec := range f.tree.Imports {
		if importPath(spec) == poolPackage {
			return true
		}
	}
	return false
}

func importPath(spec *ast.ImportSpec) string {
	path, _ := strconv.Unquote(spec.Path.Value) // The Go parser validated the literal.
	return path
}

type directive struct {
	pos  token.Pos
	name string
}

// Bind a leading comment group to the first token on the very next physical
// line. A blank line, a trailing comment, or a sibling on the same line cannot
// transfer an exemption. Both directives can appear in the same comment group.
func (f *sourceFile) collectDirectives(src []byte) {
	for _, group := range f.tree.Comments {
		for _, c := range group.List {
			fields := strings.Fields(c.Text)
			if len(fields) < 2 || (fields[0] != maintenance && fields[0] != ignoreError) {
				continue
			}
			p := f.positions.PositionFor(c.Pos(), false)
			if len(bytes.TrimSpace(src[p.Offset-p.Column+1:p.Offset])) != 0 {
				continue
			}
			next := f.positions.PositionFor(group.End(), false).Line + 1
			if next > f.positions.LineCount() {
				continue
			}
			start := f.positions.Offset(f.positions.LineStart(next))
			if len(bytes.TrimSpace(src[f.positions.Offset(group.End()):start])) != 0 {
				continue // Code already followed the comment group on its last line.
			}
			offset := len(src) - len(bytes.TrimLeft(src[start:], " \t"))
			if f.directives == nil {
				f.directives = make(map[directive]bool)
			}
			f.directives[directive{f.positions.Pos(offset), fields[0]}] = true
		}
	}
}

func (f *sourceFile) exempt(n ast.Node, name string) bool {
	switch n.(type) {
	case ast.Stmt, *ast.FuncDecl, *ast.GenDecl, *ast.ValueSpec:
		return f.directives[directive{n.Pos(), name}]
	}
	return false
}
