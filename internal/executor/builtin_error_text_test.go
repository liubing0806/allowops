package executor

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/liubing0806/allowops/internal/redact"
)

// failingHandler is a builtin whose Run returns a fixed error, so tests can
// choose the error text without depending on a real backend.
type failingHandler struct{ err error }

func (failingHandler) Parameters(map[string]any) (map[string]params.Definition, error) {
	return map[string]params.Definition{}, nil
}
func (failingHandler) ValidateConfig(map[string]any) error { return nil }
func (h failingHandler) Run(context.Context, map[string]any, map[string]any) (catalog.BuiltinResult, error) {
	return catalog.BuiltinResult{ExitCode: 1}, h.err
}

func failingAction(t *testing.T, err error) catalog.Action {
	t.Helper()
	const name = "failing_test_handler"
	catalog.Builtins[name] = failingHandler{err: err}
	t.Cleanup(func() { delete(catalog.Builtins, name) })
	return localBuiltinAction(name, nil)
}

func TestBuiltinHandlerErrorTextInStderr(t *testing.T) {
	root := t.TempDir()
	credential := filepath.Join(t.TempDir(), "credential.json")
	cases := []struct {
		name   string
		action catalog.Action
		input  map[string]any
		want   string
	}{
		{
			"starrocks_query rejects DROP",
			localBuiltinAction("starrocks_query", map[string]any{"credential": credential, "address": "tcp://127.0.0.1:1", "statement_types": []string{"SELECT"}}),
			map[string]any{"sql": "DROP TABLE t"},
			"sqlguard",
		},
		{
			"starrocks_query statement type not allowed",
			localBuiltinAction("starrocks_query", map[string]any{"credential": credential, "address": "tcp://127.0.0.1:1", "statement_types": []string{"SHOW"}}),
			map[string]any{"sql": "SELECT 1"},
			"statement_types allows only: SHOW",
		},
		{
			"mysql_query rejects DROP",
			localBuiltinAction("mysql_query", map[string]any{"credential": credential, "address": "tcp://127.0.0.1:1"}),
			map[string]any{"database": "fixture", "sql": "DROP TABLE t"},
			"SQL must be one supported read-only statement",
		},
		{
			"log_search path outside allowed_roots",
			localBuiltinAction("log_search", map[string]any{"allowed_roots": []string{root}}),
			map[string]any{"path_glob": "/etc/*.conf", "pattern": "x", "fixed": false},
			"path_glob is outside allowed_roots",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := RunWithFilters(context.Background(), c.action, c.input, nil, nil)
			if err == nil {
				t.Fatalf("expected handler error, got result %+v", r)
			}
			if r.ExitCode != 1 || r.Stdout != "" {
				t.Fatalf("exit code and stdout changed: %+v", r)
			}
			if !strings.Contains(r.Stderr, c.want) {
				t.Fatalf("stderr does not carry the handler error:\n got: %q\nwant substring: %q", r.Stderr, c.want)
			}
		})
	}
}

func TestBuiltinHandlerErrorTextIsRedacted(t *testing.T) {
	a := failingAction(t, errors.New("backend refused login: password=hunter2secret user=ops"))
	r, err := RunWithFilters(context.Background(), a, map[string]any{}, nil, nil)
	if err == nil {
		t.Fatal("expected handler error")
	}
	if !strings.Contains(r.Stderr, "backend refused login") {
		t.Fatalf("stderr does not carry the handler error: %q", r.Stderr)
	}
	if strings.Contains(r.Stderr, "hunter2secret") {
		t.Fatalf("default redaction missed the password: %q", r.Stderr)
	}

	a = failingAction(t, errors.New("tenant-4242 refused"))
	a.Redact = &redact.Config{Custom: []redact.Rule{{Name: "tenant", Regex: `tenant-[0-9]+`}}}
	r, _ = RunWithFilters(context.Background(), a, map[string]any{}, nil, nil)
	if strings.Contains(r.Stderr, "tenant-4242") || !strings.Contains(r.Stderr, "refused") {
		t.Fatalf("action redact config not applied to the error text: %q", r.Stderr)
	}
}

func TestBuiltinHandlerErrorTextIsBounded(t *testing.T) {
	a := failingAction(t, errors.New("first line\nsecond line\x1b[31m "+strings.Repeat("x", 100000)))
	a.MaxOutput = catalog.Size(1 << 20)
	r, _ := RunWithFilters(context.Background(), a, map[string]any{}, nil, nil)
	if len(r.Stderr) == 0 || len(r.Stderr) > 2048 {
		t.Fatalf("error text length %d outside 1..2048", len(r.Stderr))
	}
	if strings.Count(r.Stderr, "\n") != 1 || !strings.HasSuffix(r.Stderr, "\n") || strings.Contains(r.Stderr, "\x1b") {
		t.Fatalf("error text must be one line without control characters: %q", r.Stderr)
	}
}

func TestBuiltinHandlerStderrKeptWhenPresent(t *testing.T) {
	// Handlers that already describe the failure on stderr keep their text.
	a := localBuiltinAction("failing_stderr_handler", nil)
	catalog.Builtins[a.Name] = stderrHandler{}
	t.Cleanup(func() { delete(catalog.Builtins, a.Name) })
	r, err := RunWithFilters(context.Background(), a, map[string]any{}, nil, nil)
	if err == nil || r.Stderr != "own description\n" {
		t.Fatalf("handler stderr replaced: %q %v", r.Stderr, err)
	}
}

type stderrHandler struct{ failingHandler }

func (stderrHandler) Run(context.Context, map[string]any, map[string]any) (catalog.BuiltinResult, error) {
	return catalog.BuiltinResult{ExitCode: 1, Stderr: "own description\n"}, errors.New("generic")
}
