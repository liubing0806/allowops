package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/redact"
	redisclient "github.com/redis/go-redis/v9"
)

func assertRedisOriginalStrings(t *testing.T, base catalog.Action, client *redisclient.Client, ctx context.Context) {
	t.Helper()
	a := base
	a.MaxOutput = 4096
	a.BuiltinConfig = maps.Clone(base.BuiltinConfig)
	for _, prefix := range []string{"\n", "\t", "\"", "\\"} {
		raw := prefix + builtinSecret
		if err := client.Set(ctx, "encoded", raw, 0).Err(); err != nil {
			t.Fatal(err)
		}
		if err := client.HSet(ctx, "hash", "field", raw).Err(); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			command string
			args    []string
		}{{"GET", []string{"encoded"}}, {"HGET", []string{"hash", "field"}}, {"MGET", []string{"encoded", "absent"}}} {
			t.Run(fmt.Sprintf("original/%q/%s", prefix, tc.command), func(t *testing.T) {
				input := map[string]any{"command": tc.command, "args": tc.args}
				r, err := RunWithFilters(ctx, a, input, nil, nil)
				if err != nil || r.ExitCode != 0 {
					t.Fatalf("execution: %+v err=%v", r, err)
				}
				want := any(prefix + builtinSecretMask)
				if tc.command == "MGET" {
					want = []any{prefix + builtinSecretMask, nil}
				}
				encoded, _ := json.Marshal(want)
				if r.Stdout != string(encoded)+"\n" {
					t.Errorf("original-value redaction: got %q want %q", r.Stdout, string(encoded)+"\n")
				}
				probe, err := RunWithFilters(ctx, a, input, map[string]any{"match": builtinSecret, "count": true}, nil)
				if err != nil || probe.Stdout != "0\n" {
					t.Errorf("raw-secret filter: got=%q err=%v want=0\\n", probe.Stdout, err)
				}
			})
		}
	}
	custom := &redact.Config{Builtin: []string{}, Custom: []redact.Rule{{Name: "custom", Regex: `\bCUSTOM_[A-Z]+\b`}}}
	if err := client.Set(ctx, "custom", "\nCUSTOM_SECRET", 0).Err(); err != nil {
		t.Fatal(err)
	}
	for _, inherit := range []bool{true, false} {
		a.Redact = nil
		global := custom
		if !inherit {
			a.Redact = custom
			global = nil
		}
		r, err := RunWithFilters(ctx, a, map[string]any{"command": "GET", "args": []string{"custom"}}, nil, global)
		if err != nil || r.Stdout != "\"\\n[REDACTED:custom]\"\n" {
			t.Errorf("custom inheritance=%t: got=%q err=%v", inherit, r.Stdout, err)
		}
	}
	// Explicit action policy overrides the inherited policy.
	a.Redact = &redact.Config{Builtin: []string{}}
	r, err := RunWithFilters(ctx, a, map[string]any{"command": "GET", "args": []string{"custom"}}, nil, custom)
	if err != nil || !strings.Contains(r.Stdout, "CUSTOM_SECRET") {
		t.Errorf("action override: got=%q err=%v", r.Stdout, err)
	}
}

func assertMySQLOriginalStrings(t *testing.T, base catalog.Action) {
	t.Helper()
	a := base
	a.MaxOutput = 4096
	for _, hex := range []string{"0a", "09", "22", "5c"} {
		t.Run("original/"+hex, func(t *testing.T) {
			input := map[string]any{"database": "fixture", "sql": "SELECT CONCAT(UNHEX('" + hex + "'), '" + builtinSecret + "') AS value"}
			r, err := RunWithFilters(context.Background(), a, input, nil, nil)
			if err != nil || r.ExitCode != 0 {
				t.Fatalf("execution: %+v err=%v", r, err)
			}
			if strings.Contains(r.Stdout, builtinSecret) || !strings.Contains(r.Stdout, builtinSecretMask) {
				t.Errorf("original-value redaction: got=%q want masked cell", r.Stdout)
			}
			probe, err := RunWithFilters(context.Background(), a, input, map[string]any{"match": builtinSecret, "count": true}, nil)
			if err != nil || probe.Stdout != "0\n" {
				t.Errorf("raw-secret filter: got=%q err=%v want=0\\n", probe.Stdout, err)
			}
		})
	}
	custom := &redact.Config{Builtin: []string{}, Custom: []redact.Rule{{Name: "custom", Regex: `\bCUSTOM_[A-Z]+\b`}}}
	input := map[string]any{"database": "fixture", "sql": "SELECT CONCAT(UNHEX('0a'), 'CUSTOM_SECRET') AS value"}
	for _, inherit := range []bool{true, false} {
		a.Redact = nil
		global := custom
		if !inherit {
			a.Redact = custom
			global = nil
		}
		r, err := RunWithFilters(context.Background(), a, input, nil, global)
		if err != nil || r.Stdout != "value\n\\n[REDACTED:custom]\n" {
			t.Errorf("custom inheritance=%t: got=%q err=%v", inherit, r.Stdout, err)
		}
	}
	a.Redact = nil
	input["sql"] = "SELECT NULL AS `empty`, 42 AS `number`, 'safe' AS `" + builtinSecret + "`"
	r, err := RunWithFilters(context.Background(), a, input, nil, nil)
	want := "empty\tnumber\t" + builtinSecretMask + "\n\\N\t42\tsafe\n"
	if err != nil || r.Stdout != want {
		t.Errorf("columns/null/numbers: got=%q err=%v want=%q", r.Stdout, err, want)
	}
}
