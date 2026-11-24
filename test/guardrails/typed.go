package guardrails

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/token"
	"go/types"
	"io"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
)

// Type-check whole packages for one build so methods, aliases and calls
// resolve exactly as in Go. Other packages only need the syntax checks.
func checkTypedRules(root string, fset *token.FileSet, files []*sourceFile) error {
	type packageID struct{ dir, name string }
	packages := make(map[packageID][]*sourceFile)
	for _, f := range files {
		if f.checksErrors() || f.checksPool() {
			id := packageID{path.Dir(f.path), f.tree.Name.Name}
			packages[id] = nil
		}
	}
	target, buildFlags := currentBuild()
	imports := make(map[string]bool)
	var order []packageID
	for _, f := range files {
		id := packageID{path.Dir(f.path), f.tree.Name.Name}
		if _, needed := packages[id]; !needed {
			continue
		}
		// MatchFile applies go/build/constraint and GOOS/GOARCH filename suffixes.
		match, err := target.MatchFile(filepath.Join(root, filepath.FromSlash(id.dir)), path.Base(f.path))
		if err != nil {
			return fmt.Errorf("select %s for type checking: %w", f.path, err)
		}
		if !match {
			continue
		}
		if len(packages[id]) == 0 {
			order = append(order, id)
		}
		packages[id] = append(packages[id], f)
		for _, spec := range f.tree.Imports {
			imports[importPath(spec)] = true
		}
	}
	imp, err := moduleImporter(root, fset, slices.Sorted(maps.Keys(imports)), buildFlags)
	if err != nil {
		return err
	}
	conf := types.Config{Importer: imp, Sizes: types.SizesFor("gc", target.GOARCH)}
	for _, id := range order {
		var trees []*ast.File
		for _, f := range packages[id] {
			trees = append(trees, f.tree)
		}
		info := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue), Uses: make(map[*ast.Ident]types.Object)}
		if _, err := conf.Check(id.dir, fset, trees, info); err != nil {
			return fmt.Errorf("type-check %s: %w", id.dir, err)
		}
		for _, f := range packages[id] {
			if f.checksErrors() {
				f.checkErrors(info)
			}
			if f.checksPool() {
				f.checkPool(info)
			}
		}
	}
	return nil
}

// go/build.Default provides platform and release tags. The test binary
// records the additional flags needed by both MatchFile and go list.
func currentBuild() (build.Context, []string) {
	target := build.Default
	var tags, flags []string
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "-tags":
				tags = append(tags, strings.Split(setting.Value, ",")...)
				flags = append(flags, "-tags="+setting.Value)
			case "-race", "-asan", "-msan":
				if setting.Value == "true" {
					tags = append(tags, strings.TrimPrefix(setting.Key, "-"))
					flags = append(flags, setting.Key)
				}
			}
		}
	}
	target.BuildTags = append(tags, target.BuildTags...)
	return target, flags
}

// go/importer needs a module-aware lookup. Ask the Go toolchain for the
// direct imports' compiler export data in one invocation, honoring go.mod
// replacements without adding a dependency on x/tools/go/packages.
func moduleImporter(root string, fset *token.FileSet, paths, buildFlags []string) (types.Importer, error) {
	exports := make(map[string]string)
	if len(paths) > 0 {
		args := append([]string{"list", "-mod=readonly", "-export", "-json=ImportPath,Export"}, buildFlags...)
		args = append(args, "--")
		args = append(args, paths...)
		cmd := exec.Command("go", args...)
		cmd.Dir = root
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("load Go export data: %w\n%s", err, stderr.String())
		}
		decoder := json.NewDecoder(bytes.NewReader(output))
		for {
			var pkg struct{ ImportPath, Export string }
			err := decoder.Decode(&pkg)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("decode go list output: %w", err)
			}
			exports[pkg.ImportPath] = pkg.Export
		}
	}
	return importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		if exports[path] == "" {
			return nil, fmt.Errorf("go list returned no export file for %s", path)
		}
		return os.Open(exports[path])
	}), nil
}

func (f *sourceFile) checkPool(info *types.Info) {
	for n := range ast.Preorder(f.tree) {
		id, ok := n.(*ast.Ident)
		if !ok || (id.Name != "New" && id.Name != "NewWithConfig") {
			continue
		}
		fn, ok := info.Uses[id].(*types.Func)
		if ok && fn.Pkg() != nil && fn.Pkg().Path() == poolPackage && fn.Parent() == fn.Pkg().Scope() {
			f.report(id.Pos(), poolRule, "reference to raw pool constructor pgxpool."+id.Name+". Use internal/store.Open or pass its existing pool")
		}
	}
}

var errorInterface = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)

func (f *sourceFile) checkErrors(info *types.Info) {
	ast.Inspect(f.tree, func(n ast.Node) bool {
		if f.exempt(n, ignoreError) {
			return false
		}
		switch n := n.(type) {
		case *ast.ExprStmt:
			f.checkReceive(n.X, info)
		case *ast.AssignStmt:
			for i, lhs := range n.Lhs {
				f.checkDiscardedResult(lhs, i, n.Rhs, info)
			}
		case *ast.ValueSpec:
			for i, name := range n.Names {
				f.checkDiscardedResult(name, i, n.Values, info)
			}
		}
		return true
	})
}

func (f *sourceFile) checkReceive(expr ast.Expr, info *types.Info) {
	recv, ok := ast.Unparen(expr).(*ast.UnaryExpr)
	if !ok || recv.Op != token.ARROW {
		return
	}
	channel, ok := info.TypeOf(recv.X).Underlying().(*types.Chan)
	if ok && types.Implements(channel.Elem(), errorInterface) {
		f.report(recv.Pos(), errorRule, "receive from "+types.ExprString(recv.X)+" discards an error. Bind and handle it or document "+ignoreError+" <reason>")
	}
}

func (f *sourceFile) checkDiscardedResult(lhs ast.Expr, slot int, values []ast.Expr, info *types.Info) {
	id, ok := ast.Unparen(lhs).(*ast.Ident)
	if !ok || id.Name != "_" || len(values) == 0 {
		return
	}
	// A single initializer can supply a tuple. In a list of initializers
	// each expression supplies exactly one value at its corresponding position.
	rhs := values[0]
	if len(values) > 1 {
		rhs = values[slot]
		slot = 0
	}
	call, ok := ast.Unparen(rhs).(*ast.CallExpr)
	if !ok {
		if slot == 0 { // the second value of a comma-ok receive is a bool
			f.checkReceive(rhs, info)
		}
		return
	}
	if info.Types[call.Fun].IsType() {
		return
	}
	result := info.TypeOf(call)
	if tuple, ok := result.(*types.Tuple); ok {
		result = tuple.At(slot).Type()
	}
	if types.Implements(result, errorInterface) {
		f.report(lhs.Pos(), errorRule, "blank identifier discards error from "+types.ExprString(call.Fun)+". Handle it or document "+ignoreError+" <reason>")
	}
}
