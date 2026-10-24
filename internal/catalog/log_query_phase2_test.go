package catalog

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The adapter passes level, bucket and top to the log_query builtin.
func TestLogQueryPhase2Values(t *testing.T) {
	root := t.TempDir()
	content := "2026-10-23 10:00:00.000 [main] ERROR c.y.App - failed 1\n" +
		"2026-10-23 10:01:00.000 [main] INFO  c.y.App - ok 2\n" +
		"2026-10-23 10:02:00.000 [main] ERROR c.y.App - failed 3\n"
	if err := os.WriteFile(filepath.Join(root, "app.log"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	input := func(mode string) map[string]any {
		return map[string]any{"mode": mode, "allowed_roots": []string{root}, "sources": map[string]any{
			"app": map[string]any{"type": "file", "paths": []string{root + "/app.log*"},
				"timestamp": map[string]any{"layouts": []string{"2006-01-02 15:04:05.000"}, "timezone": "Asia/Shanghai"},
				"level":     map[string]any{"regex": `^\S+ \S+ \[[^\]]*\] (?P<level>[A-Z]+)`}},
		}}
	}
	window := map[string]any{"source": "app", "since": "2026-10-23T09:00:00+08:00", "until": "2026-10-23T11:00:00+08:00", "fixed": false, "ignore_case": false}
	values := func(extra map[string]any) map[string]any {
		v := map[string]any{}
		for k, x := range window {
			v[k] = x
		}
		for k, x := range extra {
			v[k] = x
		}
		return v
	}
	run := func(mode string, extra map[string]any) map[string]any {
		t.Helper()
		r, err := logQueryHandler{}.RunBudgeted(context.Background(), input(mode), values(extra), nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(r.Stdout), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if out := run("search", map[string]any{"level": []string{"ERROR"}, "limit": int64(10), "order": "asc"}); out["matched"] != float64(2) {
		t.Fatalf("search level: %v", out)
	}
	if out := run("stats", map[string]any{"level": []string{"ERROR"}, "bucket": "30m"}); out["matched"] != float64(2) || out["bucket"] != "30m0s" {
		t.Fatalf("stats: %v", out)
	}
	if out := run("patterns", map[string]any{"top": int64(1)}); len(out["patterns"].([]any)) != 1 {
		t.Fatalf("patterns: %v", out)
	}
}
