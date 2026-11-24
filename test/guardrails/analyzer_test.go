package guardrails

import (
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestCleanModule(t *testing.T) {
	checkFixture(t, map[string]string{
		"go.mod":                              "module github.com/jackc/pgx/v5\n\ngo 1.26\n",
		"pgxpool/pool.go":                     "package pgxpool\nfunc New() {}",
		"internal/store/store.go":             "package store\nimport \"github.com/jackc/pgx/v5/pgxpool\"\nfunc Open() { pgxpool.New() }",
		"internal/store/migrations/create.go": "package migrations\nconst schema = \"CREATE TABLE tasks (id int)\"",
		"internal/agent/session.go":           "package agent\nfunc retry(session func() error) error { return session() }",
		"cmd/allowops-gateway/main.go": `package main
func wait(auditErrors <-chan error) error {
	select { case err := <-auditErrors: return err }
}
`,
	})
}

func TestDDLStrings(t *testing.T) {
	checkFixture(t, map[string]string{
		"queries.go": `package queries
// CREATE TABLE ignored (id int)
func queries(name string) {
	_ = ("cRe" + ("AtE\x20T" + "aBLe")) + " t (id int)" // want no-runtime-ddl
	_ = "aLtEr\nTABLE \"renamed\" ADD COLUMN id int" // want no-runtime-ddl
	_ = "DR" + "OP " + "TABLE " + name // want no-runtime-ddl
	_ = "DROP TABLE " // want no-runtime-ddl
	_ = name + " PARTI" + ("TION" + " OF parent") // want no-runtime-ddl
	_ = "CREATE TEMP TABLE child PARTITION OF parent" // want no-runtime-ddl
	_ = "CREATE SCHEMA tenant CREATE TABLE inventory (id int)" // want no-runtime-ddl
	_ = "SELECT 1; /* comment */ DrOp /* old */ TABLE t" // want no-runtime-ddl
	_ = ` + "`-- CREATE TABLE in a comment\r\n  ALTER TABLE audit ADD COLUMN k int -- // want no-runtime-ddl\r\n`" + `
	_ = "create table tasks partition of archived_tasks" // want no-runtime-ddl
	_ = "SELECT 'x; DROP TABLE str', 'it''s; ALTER TABLE t', \"a; DROP TABLE b\""
	_ = "SELECT $body$; DROP TABLE data; $body$, $$; CREATE TABLE data; $$"
	_ = "/* a /* b */ DROP TABLE nope; */ SELECT 1 -- ; DROP TABLE ignored"
	_ = "SHOW CREATE TABLE users"
	_ = "CREATE TABLE"
	_ = "a partition of work; recreation is outside the scope"
	_ = "Create a partition of the input"
	_ = "failed to create table metadata"
	_ = "recreate table x; drop tablespace x; alter tabletop x; PARTITION OFTEN x"
	_ = "create table_count; drop_table x; prepartition of x"
	_ = "SELECT '" + "DROP TABLE nope" + "'"
	_ = func(s string) string { return s }("DROP TABLE nested") + name // want no-runtime-ddl
}
`,
		"internal/store/migrations/step.go":     "package migrations\nconst query = \"CREATE TABLE valid (id int)\"",
		"internal/store/migrations-old/step.go": "package old\nconst query = \"DROP TABLE old\" // want no-runtime-ddl",
		"queries_test.go":                       "package queries\nconst fixture = \"DROP TABLE fixtures\"",
		"tagged.go":                             "//go:build other_target\n\npackage queries\nconst ddl = \"DROP TABLE tagged\" // want no-runtime-ddl",
		"mapped.go":                             "package queries\n//line generated.go:800\nconst schema = \"ALTER TABLE t ADD id int\" // want no-runtime-ddl",
	})
}

func TestDDLExemptions(t *testing.T) {
	checkFixture(t, map[string]string{
		"go.mod":        "module github.com/jackc/pgx/v5\n\ngo 1.26\n",
		"identifier.go": "package pgx\ntype Identifier []string\nfunc (i Identifier) Sanitize() string { return i[0] }",
		"offline/maintenance.go": `package audit
//allowops:ddl-maintenance offline schema upgrade
func migrate() {
	_ = "DROP TABLE obsolete"
}
func run() {
	//allowops:ddl-maintenance prune old partitions
	_ = "DROP TABLE old"; _ = "ALTER TABLE next ADD x int" // want no-runtime-ddl
	//allowops:ddl-maintenance
	_ = "CREATE TABLE missing_reason" // want no-runtime-ddl
	//allowops:ddl-maintenance-next typo
	_ = "DROP TABLE wrong_directive" // want no-runtime-ddl
	//allowops:ddl-maintenance detached

	_ = "DROP TABLE detached" // want no-runtime-ddl
	_ = "SELECT 1" //allowops:ddl-maintenance trailing
	_ = "DROP TABLE trailing" // want no-runtime-ddl
	//allowops:ignore-error unrelated
	_ = "DROP TABLE unrelated" // want no-runtime-ddl
}
func dropPartition(name string) {
	_ = "DROP TABLE " + name // want no-runtime-ddl
}
`,
		"internal/gateway/audit/sql.go": `package audit
import "github.com/jackc/pgx/v5"
func dropPartition(name string) {
	_ = "DROP TABLE " + pgx.Identifier{name}.Sanitize()
	_ = "DROP TABLE " + name // want no-runtime-ddl
	_ = "DROP TABLE unrelated" // want no-runtime-ddl
	_ = "CREATE TABLE " + name // want no-runtime-ddl
}
func runtimeQuery(name string) {
	_ = "DROP TABLE " + name // want no-runtime-ddl
}
`,
	})
}

func TestDDLTableModifiers(t *testing.T) {
	checkFixture(t, map[string]string{"queries.go": `package queries
var queries = []string{
	"CREATE TEMP TABLE t (id int)", // want no-runtime-ddl
	"CREATE TEMPORARY TABLE t (id int)", // want no-runtime-ddl
	"CREATE LOCAL TEMP TABLE t (id int)", // want no-runtime-ddl
	"CREATE GLOBAL /* scope */ TEMPORARY TABLE t (id int)", // want no-runtime-ddl
	"CREATE UNLOGGED TABLE t (id int)", // want no-runtime-ddl
	"create foreign table ft (id int) server remote", // want no-runtime-ddl
	"ALTER FOREIGN TABLE ft RENAME TO renamed", // want no-runtime-ddl
	"DROP FOREIGN TABLE IF EXISTS ft", // want no-runtime-ddl
	"SHOW CREATE TABLE t",
	"SELECT 'drop foreign table ft'",
	"failed to create temporary table t",
	"CREATE TEMP VIEW v AS SELECT 1",
	"CREATE TABLESPACE t",
	"CREATE FOREIGN TABLE",
	"ALTER TEMP TABLE t",
	"CREATE GLOBAL UNLOGGED TABLE t",
}
`})
}

func TestErrorResultSlots(t *testing.T) {
	checkFixture(t, map[string]string{
		"internal/operations/run.go": `package operations
type Outcome = error
func Run() (int, Outcome) { return 0, nil }
`,
		"internal/agent/methods.go": `package agent
type connection struct{}
func (connection) session() (int, error) { return 0, nil }
type counter struct{}
func (counter) session() (int, bool) { return 0, false }
func firstError() (error, int) { return nil, 0 }
func numbers() (int, int) { return 0, 0 }
`,
		"internal/agent/run.go": `package agent
import (
	"os"
	"example.test/guardrails/internal/operations"
)
func run(renew func() error) {
	_ = os.Remove("file") // want no-silent-error-drop
	_, _ = os.LookupEnv("key")
	duration, _ := (connection{}).session() // want no-silent-error-drop
	count, _ := (counter{}).session()
	_, _ = operations.Run() // want no-silent-error-drop
	_, value := firstError() // want no-silent-error-drop
	_, _ = numbers()
	_, _ = len("x"), renew() // want no-silent-error-drop
	_, _ = renew(), renew() // want no-silent-error-drop no-silent-error-drop
	_, err := (connection{}).session()
	_ = err
	_ = error(nil)
	_ = duration + count + value
}
`,
		"internal/agentextra/outside.go":     "package other\nimport \"os\"\nfunc f() { _ = os.Remove(\"file\") }",
		"cmd/allowops-agent/outside.go":      "package main\nimport \"os\"\nfunc f() { _ = os.Remove(\"file\") }",
		"cmd/allowops-gateway/sub/worker.go": "package worker\nfunc f(run func() error) { _ = run() } // want no-silent-error-drop",
		"internal/agent/run_test.go":         "package agent\nfunc example(run func() error) { _ = run() }",
	})
}

func TestErrorReceivesAndExemptions(t *testing.T) {
	checkFixture(t, map[string]string{
		"cmd/allowops-gateway/main.go": `package main
type worker struct { ReportErrors <-chan error }
func (w worker) Errors() <-chan error { return w.ReportErrors }
func listen(auditErrs <-chan error, done <-chan struct{}, w worker, run func() error) {
	errChans := []<-chan error{auditErrs}
	select {
	case <-auditErrs: // want no-silent-error-drop
	case <-w.ReportErrors: // want no-silent-error-drop
	case <-w.Errors(): // want no-silent-error-drop
	case <-errChans[0]: // want no-silent-error-drop
	case _, ok := <-auditErrs: // want no-silent-error-drop
		_ = ok
	case err := <-auditErrs:
		if err != nil { return }
	case <-done:
	//allowops:ignore-error only waiting for the goroutine to exit
	case <-auditErrs:
	}
	//allowops:ignore-error best effort cleanup
	_ = run(); _ = run() // want no-silent-error-drop
	//allowops:ignore-error
	_ = run() // want no-silent-error-drop
	//allowops:ignore-error detached by an intervening statement
	/* detail */ _ = 1
	_ = run() // want no-silent-error-drop
	//allowops:ddl-maintenance unrelated
	_ = run() // want no-silent-error-drop
	//allowops:ignore-error detached

	_ = run() // want no-silent-error-drop
}
//allowops:ignore-error best effort shutdown
func shutdown(run func() error) {
	_ = run()
}
`,
	})
}

func TestPoolConstructorIdentity(t *testing.T) {
	checkFixture(t, map[string]string{
		// A local replacement provides compiler export data for the real import
		// path, without a network request or a third-party test dependency.
		"go.mod":                      "module example.test/guardrails\n\ngo 1.26\nrequire github.com/jackc/pgx/v5 v5.0.0\nreplace github.com/jackc/pgx/v5 => ./fixture/pgx\n",
		"fixture/pgx/go.mod":          "module github.com/jackc/pgx/v5\n\ngo 1.26\n",
		"fixture/pgx/pgxpool/pool.go": "package pgxpool\nfunc New() {}\nfunc NewWithConfig() {}",
		"internal/store/store.go": `package store
import "github.com/jackc/pgx/v5/pgxpool"
func Open() { pgxpool.New(); pgxpool.NewWithConfig() }
`,
		"internal/store/other.go": `package store
import "github.com/jackc/pgx/v5/pgxpool"
func raw() { pgxpool.New() } // want no-raw-pgxpool-new
`,
		"internal/store/migrations/step.go": `package migrations
import pool "github.com/jackc/pgx/v5/pgxpool"
func bad() { (pool.NewWithConfig)() } // want no-raw-pgxpool-new
`,
		"client/aliased.go": `package client
import dbpool "github.com/jackc/pgx/v5/pgxpool"
func open() {
	//allowops:ddl-maintenance unrelated
	dbpool.New() // want no-raw-pgxpool-new
	open := dbpool.New // want no-raw-pgxpool-new
	open()
	register(dbpool.NewWithConfig) // want no-raw-pgxpool-new
	dbpool := struct{New func()}{func(){}}
	dbpool.New()
	register(dbpool.New)
}
func register(func()) {}
`,
		"client/dot.go": `package client
import . "github.com/jackc/pgx/v5/pgxpool"
func openDot() {
	NewWithConfig() // want no-raw-pgxpool-new
	register(New) // want no-raw-pgxpool-new
	NewWithConfig := func() {}
	NewWithConfig()
}
`,
		"client/other.go": `package client
import pgxpool "errors"
func other() { pgxpool.New("other package") }
`,
		"client/raw_test.go": "package client\nimport p \"github.com/jackc/pgx/v5/pgxpool\"\nfunc testRaw() { p.New() }",
	})
}

func TestDiscardedChannelValues(t *testing.T) {
	checkFixture(t, map[string]string{"internal/agent/worker.go": `package agent
type failure struct{}
func (*failure) Error() string { return "failure" }
type completions <-chan error
func wait(finished completions, done <-chan error, details <-chan *failure, deferred, stderrClosed <-chan struct{}) {
	select {
	case <-finished: // want no-silent-error-drop
	case _ = <-done: // want no-silent-error-drop
	case _, ok := <-finished: // want no-silent-error-drop
		_ = ok
	case <-deferred:
	case <-stderrClosed:
	}
	<-finished // want no-silent-error-drop
	<-details // want no-silent-error-drop
	_ = (<-done) // want no-silent-error-drop
	_, open := <-finished // want no-silent-error-drop
	_, _ = <-finished // want no-silent-error-drop
	_, _ = 1, <-finished // want no-silent-error-drop
	result, _ := <-finished
	_, _ = result, open
	<-deferred
	_ = <-stderrClosed
	//allowops:ignore-error owner handles the worker failure
	<-finished
}
`})
}

func TestDiscardedDeclarations(t *testing.T) {
	checkFixture(t, map[string]string{"internal/agent/worker.go": `package agent
import "os"
var _ = os.Remove("x") // want no-silent-error-drop
type agent struct{}
func (agent) session() (int, error) { return 0, nil }
func run(a agent, finished <-chan error) {
	var delay, _ = a.session() // want no-silent-error-drop
	var _, ok = <-finished // want no-silent-error-drop
	var _, _ = 1, os.Remove("x") // want no-silent-error-drop
	var _, err = a.session()
	var _ error
	var (
		//allowops:ignore-error best effort cleanup
		_ = os.Remove("x")
		_ = os.Remove("y") // want no-silent-error-drop
	)
	_, _, _ = delay, ok, err
}
`})
}

func TestDiscardedConcreteErrors(t *testing.T) {
	checkFixture(t, map[string]string{"cmd/allowops-gateway/run.go": `package main
import (
	"errors"
	"os"
)
type failure struct{}
func (*failure) Error() string { return "failure" }
func run(err error, pathError func() *os.PathError, result func() (int, *failure), value func() failure) {
	_ = pathError() // want no-silent-error-drop
	_, _ = result() // want no-silent-error-drop
	_ = value()
	_ = (*failure)(nil)
	if _, ok := errors.AsType[*os.PathError](err); ok {
		return
	}
	_, _ = errors.AsType[*os.PathError](err) // want no-silent-error-drop
}
`})
}

func TestExcludedDirectories(t *testing.T) {
	checkFixture(t, map[string]string{
		"web/node_modules/dependency/source.go":  "package dependency\nconst ddl = \"DROP TABLE outside\"",
		".claude/worktrees/nested/runtime.go":    "package nested\nconst ddl = \"DROP TABLE outside\"",
		"web/node_modules-local/owned/source.go": "package owned\nconst ddl = \"DROP TABLE inside\" // want no-runtime-ddl",
		"tools/.claude-config/owned/runtime.go":  "package owned\nconst ddl = \"DROP TABLE inside\" // want no-runtime-ddl",
	})
}

func TestTypedBuildConstraints(t *testing.T) {
	checkFixture(t, map[string]string{
		"internal/agent/current.go": "//go:build " + runtime.GOOS + "\n\npackage agent\nfunc platform() error { return nil }",
		"internal/agent/other.go":   "//go:build !" + runtime.GOOS + "\n\npackage agent\nfunc platform() int { return 0 }\nconst ddl = \"DROP TABLE t\" // want no-runtime-ddl",
		"internal/agent/use.go":     "package agent\nfunc use() { _ = platform() } // want no-silent-error-drop",
	})
}

func TestAnalysisErrors(t *testing.T) {
	for _, tc := range []struct{ path, source, diagnostic string }{
		{"bad.go", "package !", "bad.go:1"},
		{"internal/agent/bad.go", "package agent\nfunc f() { _ = undefined() }", "undefined"},
		{"internal/agent/import.go", "package agent\nimport _ \"example.test/guardrails/missing\"", "example.test/guardrails/missing"},
	} {
		root := writeFixture(t, map[string]string{tc.path: tc.source})
		if _, err := Analyze(root); err == nil || !strings.Contains(err.Error(), tc.diagnostic) {
			t.Errorf("Analyze(%s) error = %v, want diagnostic containing %q", tc.path, err, tc.diagnostic)
		}
	}
}

func writeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	t.Setenv("GOWORK", "off")
	t.Setenv("GOPROXY", "off")
	root := t.TempDir()
	if _, ok := files["go.mod"]; !ok {
		files["go.mod"] = "module example.test/guardrails\n\ngo 1.26\n"
	}
	for path, source := range files {
		name := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// Each "// want rule" marks the expected physical line. Compare the entire
// sorted result: every unmarked line and file must be clean.
func checkFixture(t *testing.T, files map[string]string) {
	t.Helper()
	found, err := Analyze(writeFixture(t, files))
	if err != nil {
		t.Fatal(err)
	}
	type finding struct {
		file string
		line int
		rule string
	}
	var got, want []finding
	for _, path := range slices.Sorted(maps.Keys(files)) {
		for i, line := range strings.Split(files[path], "\n") {
			if _, rules, ok := strings.Cut(line, "// want "); ok {
				for _, rule := range strings.Fields(rules) {
					want = append(want, finding{path, i + 1, rule})
				}
			}
		}
	}
	for i, v := range found {
		if v.Column < 1 || v.Message == "" {
			t.Errorf("missing diagnostic details: %+v", v)
		}
		if i > 0 && found[i-1].File == v.File && found[i-1].Line == v.Line && found[i-1].Column >= v.Column {
			t.Errorf("expected distinct, ordered column positions: %+v, %+v", found[i-1], v)
		}
		got = append(got, finding{v.File, v.Line, v.Rule})
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got %v\nwant %v", got, want)
	}
}
