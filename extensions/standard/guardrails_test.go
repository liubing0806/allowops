package standard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestPluginSourceBoundaries(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.WalkDir("..", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, violation := range pluginSourceViolations(file) {
			t.Errorf("%s: %s", fset.Position(violation.pos), violation.message)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type sourceViolation struct {
	pos     token.Pos
	message string
}

func pluginSourceViolations(file *ast.File) []sourceViolation {
	var violations []sourceViolation
	report := func(node ast.Node, message string) {
		violations = append(violations, sourceViolation{node.Pos(), message})
	}
	imports := make(map[string]string)
	for _, spec := range file.Imports {
		path, _ := strconv.Unquote(spec.Path.Value)
		if slices.Contains(strings.Split(path, "/"), "internal") {
			report(spec, "plugin imports an internal package")
		}
		if path == "net" || path == "net/http" {
			name := filepath.Base(path)
			if spec.Name != nil {
				name = spec.Name.Name
			}
			if name == "." {
				report(spec, "plugin dot-imports a network package")
			}
			imports[name] = path
		}
	}
	networkSelector := func(expr ast.Expr) (string, string) {
		selector, ok := expr.(*ast.SelectorExpr)
		if !ok {
			return "", ""
		}
		ident, ok := selector.X.(*ast.Ident)
		if !ok || ident.Obj != nil {
			return "", ""
		}
		return imports[ident.Name], selector.Sel.Name
	}
	checkClientConstruction := func(node ast.Node, expr ast.Expr) {
		path, name := networkSelector(expr)
		if path == "net/http" && (name == "Client" || name == "Transport") {
			report(node, "plugin constructs an HTTP client or transport; use Host.HTTPClient")
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.SelectorExpr:
			path, name := networkSelector(n)
			switch path {
			case "net":
				if strings.HasPrefix(name, "Dial") {
					report(n, "plugin uses a direct network dialer")
				}
			case "net/http":
				switch name {
				case "Get", "Post", "PostForm", "Head", "Do", "DefaultClient", "DefaultTransport":
					report(n, "plugin bypasses Host.HTTPClient")
				}
			}
		case *ast.CompositeLit:
			checkClientConstruction(n, n.Type)
		case *ast.CallExpr:
			if fn, ok := n.Fun.(*ast.Ident); ok && fn.Name == "new" && fn.Obj == nil && len(n.Args) == 1 {
				checkClientConstruction(n, n.Args[0])
			}
		}
		return true
	})
	return violations
}

func TestPluginSourceBoundaryDetector(t *testing.T) {
	source := `package fixture
import (
    n "net"
    web "net/http"
    "example.com/internal/opaque"
)
func sample(host interface{ HTTPClient() *web.Client }) {
    n.Dial("tcp", "example.invalid:80")
    web.Get("https://example.invalid")
    _ = web.DefaultTransport
    _ = &web.Client{}
    _ = new(web.Client)
    host.HTTPClient().Get("https://example.invalid")
}`
	file, err := parser.ParseFile(token.NewFileSet(), "sample.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(pluginSourceViolations(file)); got != 6 {
		t.Fatalf("violations = %d, want 6", got)
	}
}
