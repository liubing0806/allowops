package executor

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/liubing0806/allowops/internal/redact"
)

func TestFiltersAfterRedaction(t *testing.T) {
	a := helperAction("output")
	a.Filters = []string{"match", "count"}
	r, err := Run(context.Background(), a, map[string]any{"match": "ssss", "count": true}, nil)
	if err != nil || r.Stdout != "0\n" {
		t.Fatalf("got %#v %v; want redacted match count 0", r, err)
	}
}

func TestStepsContinueAndStop(t *testing.T) {
	a := helperAction("exit")
	failed := a.Exec
	a.Exec = nil
	a.Steps = []catalog.Step{{Name: "failed", Exec: failed}, {Name: "next", Exec: []any{"/bin/echo", "next"}}}
	for _, mode := range []string{"", "stop"} {
		a.OnError = mode
		r, err := Run(context.Background(), a, nil, nil)
		if err != nil || r.ExitCode != 7 {
			t.Fatalf("%s => %#v %v", mode, r, err)
		}
	}
}

func TestFallbackExecution(t *testing.T) {
	a := helperAction("env")
	a.Exec = []any{"/missing/allowops-command", "fallback"}
	a.ExecFallbacks = []string{"/bin/echo"}
	r, err := Run(context.Background(), a, nil, nil)
	if err != nil || r.Stdout != "fallback\n" {
		t.Fatalf("got %#v %v", r, err)
	}
}

func TestFilterOrderAndValidation(t *testing.T) {
	for _, tc := range []struct {
		input map[string]any
		want  string
	}{
		{map[string]any{"match": "[ac]", "exclude": "a"}, "c\n"},
		{map[string]any{"match": "[bd]", "exclude": "a", "tail": int64(1)}, "d\n"},
		{map[string]any{"match": "[bd]", "exclude": "a", "head": int64(1)}, "b\n"},
		{map[string]any{"match": "[bd]", "exclude": "a", "count": true}, "2\n"},
	} {
		a := catalog.Action{Name: "lines", Description: "lines", Risk: "read", Exec: []any{"/usr/bin/printf", "a\nb\nc\nd\n"}, Timeout: "1s", MaxOutput: 1024, Filters: []string{"match", "exclude", "head", "tail", "count"}}
		// argv templates reject newline injection, so use printf's literal escape sequences.
		a.Exec[1] = `a\nb\nc\nd\n`
		r, err := Run(context.Background(), a, tc.input, nil)
		if err != nil || r.Stdout != tc.want {
			t.Fatalf("%v => %#v %v; want %q", tc.input, r, err, tc.want)
		}
	}
	for _, input := range []map[string]any{
		{"match": strings.Repeat("é", 201)}, {"match": "(?=x)"}, {"exclude": "["}, {"tail": 0}, {"head": -1}, {"head": 1.5}, {"count": "true"}, {"match": "a\nb"},
	} {
		if _, err := ParseFilters([]string{"match", "exclude", "tail", "head", "count"}, input); err == nil {
			t.Fatalf("accepted %v", input)
		}
	}
	if _, err := ParseFilters(nil, map[string]any{"match": "a"}); err == nil {
		t.Fatal("undeclared filter accepted")
	}
	// RE2 accepts nested quantifiers without exponential backtracking.
	if _, err := ParseFilters([]string{"match"}, map[string]any{"match": "(a+)+$"}); err != nil {
		t.Fatal(err)
	}
}

func TestScanLimitSeparateFromTruncation(t *testing.T) {
	a := catalog.Action{Name: "scan", Description: "scan", Risk: "read", Exec: []any{"/usr/bin/printf", `one\ntwo\nthree\n`}, Timeout: "1s", MaxOutput: 1024, MaxScan: 8}
	r, err := Run(context.Background(), a, nil, nil)
	if err != nil || !r.ScanLimitReached || r.Truncated || r.Stdout != "one\ntwo\n" {
		t.Fatalf("got %#v %v", r, err)
	}
	a.MaxScan = 14
	r, err = Run(context.Background(), a, nil, nil)
	if err != nil || r.ScanLimitReached || r.Truncated {
		t.Fatalf("exact boundary: %#v %v", r, err)
	}
	a.MaxScan = 0
	a.MaxOutput = 3
	r, err = Run(context.Background(), a, nil, nil)
	if err != nil || r.ScanLimitReached || !r.Truncated || r.Stdout != "one" {
		t.Fatalf("output cap: %#v %v", r, err)
	}
}

func TestStepsMetadataAndSharedBudget(t *testing.T) {
	a := helperAction("exit")
	failed := a.Exec
	a.Exec = nil
	a.Steps = []catalog.Step{{Name: "failed", Exec: failed}, {Name: "next", Exec: []any{"/bin/echo", "next"}}, {Name: "last", Exec: []any{"/bin/echo", "last"}}}
	a.MaxOutput = 6
	r, err := Run(context.Background(), a, nil, nil)
	if err != nil || r.ExitCode != 7 || len(r.Steps) != 3 || r.Steps[0].ExitCode == nil || *r.Steps[0].ExitCode != 7 || r.Steps[1].Stdout != "next\n" || r.Steps[2].Stdout != "l" || !r.Truncated || r.Stdout != "" {
		t.Fatalf("got %#v %v", r, err)
	}
	a.OnError = "stop"
	r, err = Run(context.Background(), a, nil, nil)
	if err != nil || !r.Steps[1].Skipped || r.Steps[1].ExitCode != nil || !r.Steps[2].Skipped {
		t.Fatalf("got %#v %v", r, err)
	}
	a = helperAction("parent")
	parent := a.Exec
	a.Exec = nil
	a.Timeout = "200ms"
	a.Steps = []catalog.Step{{Name: "timeout", Exec: parent}, {Name: "skip", Exec: []any{"/bin/echo", "skip"}}}
	r, err = Run(context.Background(), a, nil, nil)
	if err == nil || r.ExitCode != -1 || len(r.Steps) != 2 || !r.Steps[1].Skipped {
		t.Fatalf("timeout: %#v %v", r, err)
	}
}

func TestScriptFileExclusiveCreation(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "script")); err != nil {
		t.Fatal(err)
	}
	if _, err := writeScript(dir, []byte("attack")); err == nil {
		t.Fatal("followed symlink")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("target=%q %v", data, err)
	}
	if err := os.Remove(filepath.Join(dir, "script")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var wins atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := writeScript(dir, []byte("signed")); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("exclusive writes=%d", wins.Load())
	}
}

func TestMySQLBuiltinDispatchAndLimits(t *testing.T) {
	a := catalog.Action{Name: "mysql", Description: "mysql", Risk: "read", Builtin: "mysql_query", BuiltinConfig: map[string]any{"credential": "/nonexistent/credential.json", "address": "tcp://127.0.0.1:1"}, Timeout: "1s", MaxOutput: 1024}
	r, err := Run(context.Background(), a, map[string]any{"database": "test", "sql": "SELECT 1"}, nil)
	if err == nil || err.Error() != "cannot open credential file" || r.ExitCode != 1 {
		t.Fatalf("got %#v %v", r, err)
	}
	for _, config := range []map[string]any{
		{"max_rows": 501}, {"timeout": "11s"}, {"unknown": 1},
	} {
		candidate := a
		candidate.BuiltinConfig = maps.Clone(a.BuiltinConfig)
		maps.Copy(candidate.BuiltinConfig, config)
		if _, err := catalog.ValidateAction(candidate); err == nil {
			t.Fatalf("accepted %v", config)
		}
	}
	a.Params = map[string]params.Definition{"sql": {Type: params.String, Description: "short SQL", MaxLen: 8}}
	if _, err := Run(context.Background(), a, map[string]any{"database": "test", "sql": "SELECT 100"}, nil); err == nil || !strings.Contains(err.Error(), "max_len") {
		t.Fatalf("SQL restriction: %v", err)
	}
}

func FuzzFilters(f *testing.F) {
	f.Add("a", int64(2), int64(1), true)
	f.Add("a", int64(1), int64(0), false)
	f.Add("a", int64(3), int64(0), true)
	f.Add("[", int64(-1), int64(0), false)
	f.Add("(a+)+$", int64(100), int64(100), false)
	f.Fuzz(func(t *testing.T, pattern string, tail, head int64, count bool) {
		input := map[string]any{"match": pattern}
		switch uint64(tail) % 5 {
		case 1:
			input["tail"] = tail
		case 2:
			input["head"] = head
		case 3:
			input["count"] = count
		case 4:
			input["tail"] = tail
			input["head"] = head
			input["count"] = count
		}
		options, err := ParseFilters([]string{"match", "tail", "head", "count"}, input)
		if err != nil {
			return
		}
		output := &limitedOutput{limit: 32}
		r, _ := redact.New(nil)
		if err := streamStdout(strings.NewReader("aaa\nbbb\n"), output, r, options, 1024); err != nil {
			t.Fatal(err)
		}
		if output.buffer.Len() > 32 {
			t.Fatal("output exceeded limit")
		}
	})
}
