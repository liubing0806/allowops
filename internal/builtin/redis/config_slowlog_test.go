package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	redisclient "github.com/redis/go-redis/v9"
)

func rejectedBeforeCredential(t *testing.T, c Config, p Params, want string) {
	t.Helper()
	r, err := Run(context.Background(), c, p)
	if err == nil || r.ExitCode != 1 || r.Stdout != "" || strings.Contains(err.Error(), "credential") || !strings.Contains(err.Error(), want) {
		t.Fatalf("%+v: want rejection containing %q before credential read: %+v, %v", p, want, r, err)
	}
}

func TestConfigGetRejections(t *testing.T) {
	c := restrictedConfig(t, `{"commands":["CONFIG"],"config_params":["maxmemory","maxmemory-policy","dir"]}`)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "CONFIG"},
		{[]string{"GET"}, "CONFIG"},
		{[]string{"SET", "maxmemory", "1"}, "GET"},
		{[]string{"RESETSTAT"}, "GET"},
		{[]string{"REWRITE"}, "GET"},
		{[]string{"HELP"}, "GET"},
		{[]string{"GET", "*"}, "config_params"},
		{[]string{"GET", "max*"}, "config_params"},
		{[]string{"GET", "maxmemory?"}, "config_params"},
		{[]string{"GET", "[m]axmemory"}, "config_params"},
		{[]string{"GET", "notlisted"}, "config_params"},
		{[]string{"GET", "maxmemory", "notlisted"}, "config_params"},
		{[]string{"GET", "requirepass"}, "sensitive"},
		{[]string{"GET", "REQUIREPASS"}, "sensitive"},
		{[]string{"GET", "masterauth"}, "sensitive"},
		{[]string{"GET", "masteruser"}, "sensitive"},
		{[]string{"GET", "aclfile"}, "sensitive"},
		{[]string{"GET", "tls-key-file-pass"}, "sensitive"},
		{[]string{"GET", "maxmemory", "requirepass"}, "sensitive"},
		{[]string{"GET", strings.Repeat("a", 65)}, "config_params"},
	} {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			rejectedBeforeCredential(t, c, Params{Command: "config", Args: tc.args}, tc.want)
		})
	}
	many := []string{"GET"}
	for range 17 {
		many = append(many, "maxmemory")
	}
	rejectedBeforeCredential(t, c, Params{Command: "CONFIG", Args: many}, "at most")
}

func TestConfigGetRequiresExplicitOptIn(t *testing.T) {
	// CONFIG needs an allowlist of parameter names even when commands lists it.
	rejectedBeforeCredential(t, restrictedConfig(t, `{"commands":["CONFIG"]}`), Params{Command: "CONFIG", Args: []string{"GET", "maxmemory"}}, "config_params")
	// Omitted commands keeps the original 13-command default, which excludes CONFIG and SLOWLOG.
	rejectedBeforeCredential(t, restrictedConfig(t, `{"config_params":["maxmemory"]}`), Params{Command: "CONFIG", Args: []string{"GET", "maxmemory"}}, "commands")
	rejectedBeforeCredential(t, restrictedConfig(t, `{}`), Params{Command: "SLOWLOG", Args: []string{"LEN"}}, "commands")
	rejectedBeforeCredential(t, restrictedConfig(t, `{"commands":["GET"],"config_params":["maxmemory"]}`), Params{Command: "CONFIG", Args: []string{"GET", "maxmemory"}}, "commands")
}

func TestConfigParamsValidation(t *testing.T) {
	for _, config := range []string{
		`{"config_params":[]}`,
		`{"config_params":[""]}`,
		`{"config_params":["*"]}`,
		`{"config_params":["max*"]}`,
		`{"config_params":["max memory"]}`,
		`{"config_params":["requirepass"]}`,
		`{"config_params":["maxmemory","MasterAuth"]}`,
		`{"config_params":["masteruser"]}`,
		`{"config_params":["primaryauth"]}`,
		`{"config_params":["aclfile"]}`,
		`{"config_params":["acllog-max-len"]}`,
		`{"config_params":["tls-key-file-pass"]}`,
		`{"config_params":["tls-client-key-file-pass"]}`,
	} {
		c := restrictedConfig(t, config)
		c.Credential = "/etc/allowops/credentials/redis.json"
		if c.Validate() == nil {
			t.Errorf("accepted %s", config)
		}
	}
	c := restrictedConfig(t, `{"commands":["CONFIG","SLOWLOG"],"config_params":["maxmemory","Maxmemory-Policy","slowlog-max-len"]}`)
	c.Credential = "/etc/allowops/credentials/redis.json"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}

func TestSlowlogRejections(t *testing.T) {
	c := restrictedConfig(t, `{"commands":["SLOWLOG"]}`)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "SLOWLOG"},
		{[]string{"RESET"}, "GET"},
		{[]string{"reset"}, "GET"},
		{[]string{"HELP"}, "GET"},
		{[]string{"GET", "0"}, "1..128"},
		{[]string{"GET", "129"}, "1..128"},
		{[]string{"GET", "-1"}, "argument"},
		{[]string{"GET", "abc"}, "1..128"},
		{[]string{"GET", "1.5"}, "1..128"},
		{[]string{"GET", "1", "2"}, "SLOWLOG"},
		{[]string{"LEN", "1"}, "SLOWLOG"},
		{[]string{"LEN", "RESET"}, "SLOWLOG"},
	} {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			rejectedBeforeCredential(t, c, Params{Command: "slowlog", Args: tc.args}, tc.want)
		})
	}
	// SLOWLOG GET returns keys of other clients' commands, so it cannot honor key_prefixes.
	kp := restrictedConfig(t, `{"commands":["SLOWLOG"],"key_prefixes":["tenant:"]}`)
	rejectedBeforeCredential(t, kp, Params{Command: "SLOWLOG", Args: []string{"GET", "5"}}, "key_prefixes")
	rejectedBeforeCredential(t, kp, Params{Command: "SLOWLOG", Args: []string{"GET"}}, "key_prefixes")
}

func TestConfigGetAndSlowlogLocalServer(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	s := startServer(t)
	cfg := restrictedConfig(t, `{"commands":["CONFIG","SLOWLOG"],"config_params":["maxmemory","maxmemory-policy","slowlog-max-len","dir"]}`)
	cfg.Address, cfg.Credential = s.address, credentials(t)

	r, err := Run(context.Background(), cfg, Params{Command: "CONFIG", Args: []string{"GET", "maxmemory"}})
	if err != nil || r.ExitCode != 0 || r.Truncated || strings.TrimSpace(r.Stdout) != `["maxmemory","0"]` {
		t.Fatalf("CONFIG GET maxmemory: %+v, %v", r, err)
	}
	r, err = Run(context.Background(), cfg, Params{Command: "config", Args: []string{"get", "MaxMemory-Policy", "slowlog-max-len"}})
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("CONFIG GET multiple: %+v, %v", r, err)
	}
	var pairs []string
	if err := json.Unmarshal([]byte(r.Stdout), &pairs); err != nil || len(pairs) != 4 {
		t.Fatalf("CONFIG GET multiple output: %q, %v", r.Stdout, err)
	}
	// The server's requirepass is never reachable, even for names the server knows.
	s.seed(t, "CONFIG", "RESETSTAT")
	for _, name := range []string{"requirepass", "RequirePass", "*", "require*", "masterauth"} {
		r, err = Run(context.Background(), cfg, Params{Command: "CONFIG", Args: []string{"GET", name}})
		if err == nil || r.ExitCode != 1 || r.Stdout != "" || strings.Contains(r.Stdout, "local-test-password") {
			t.Fatalf("CONFIG GET %s: %+v, %v", name, r, err)
		}
	}
	stats, err := s.client.Info(context.Background(), "commandstats").Result()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stats, "cmdstat_config|get:") {
		t.Fatalf("rejected CONFIG GET reached the server:\n%s", stats)
	}
	// Response limit: output text above max_response_bytes is dropped as truncated.
	small := cfg
	small.MaxResponseBytes = 8
	r, err = Run(context.Background(), small, Params{Command: "CONFIG", Args: []string{"GET", "dir"}})
	if err != nil || r.ExitCode != 0 || !r.Truncated || r.Stdout != "" {
		t.Fatalf("CONFIG GET limit: %+v, %v", r, err)
	}

	s.seed(t, "CONFIG", "SET", "slowlog-log-slower-than", "0")
	s.seed(t, "SLOWLOG", "RESET")
	s.seed(t, "SET", "tenant:key", "super-secret-value")
	r, err = Run(context.Background(), cfg, Params{Command: "SLOWLOG", Args: []string{"LEN"}})
	if err != nil || r.ExitCode != 0 || strings.TrimSpace(r.Stdout) == "0" || strings.TrimSpace(r.Stdout) == "" {
		t.Fatalf("SLOWLOG LEN: %+v, %v", r, err)
	}
	var entries []any
	r, err = Run(context.Background(), cfg, Params{Command: "SLOWLOG", Args: []string{"GET", "128"}})
	if err != nil || r.ExitCode != 0 || json.Unmarshal([]byte(r.Stdout), &entries) != nil || len(entries) == 0 {
		t.Fatalf("SLOWLOG GET: %+v, %v", r, err)
	}
	r, err = Run(context.Background(), cfg, Params{Command: "SLOWLOG", Args: []string{"GET"}})
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("SLOWLOG GET default count: %+v, %v", r, err)
	}
	// Masking reaches the strings that remain in each summarized entry.
	r, err = RunRedacted(context.Background(), cfg, Params{Command: "SLOWLOG", Args: []string{"GET", "10"}}, func(v string) string {
		return strings.ReplaceAll(v, "SET", "***")
	})
	if err != nil || strings.Contains(r.Stdout, `"SET"`) || !strings.Contains(r.Stdout, "***") {
		t.Fatalf("SLOWLOG masking: %+v, %v", r, err)
	}
	// RESET is rejected and the log is untouched.
	before, err := s.client.Do(context.Background(), "SLOWLOG", "LEN").Int64()
	if err != nil || before == 0 {
		t.Fatalf("slowlog len: %d, %v", before, err)
	}
	r, err = Run(context.Background(), cfg, Params{Command: "SLOWLOG", Args: []string{"RESET"}})
	if err == nil || r.ExitCode != 1 {
		t.Fatalf("SLOWLOG RESET accepted: %+v, %v", r, err)
	}
	after, err := s.client.Do(context.Background(), "SLOWLOG", "LEN").Int64()
	if err != nil || after < before {
		t.Fatalf("slowlog reset: before=%d after=%d, %v", before, after, err)
	}
	small.MaxResponseBytes = 32
	r, err = Run(context.Background(), small, Params{Command: "SLOWLOG", Args: []string{"GET", "128"}})
	if err != nil || r.ExitCode != 0 || !r.Truncated || r.Stdout != "" {
		t.Fatalf("SLOWLOG GET limit: %+v, %v", r, err)
	}
}

// SLOWLOG GET must not return command arguments (keys, values) or the client
// name; each entry keeps only id, timestamp, duration, command name, argument
// count and client address.
func TestSlowlogGetSummary(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	s := startServer(t)
	cfg := restrictedConfig(t, `{"commands":["SLOWLOG"]}`)
	cfg.Address, cfg.Credential = s.address, credentials(t)

	opts := *s.client.Options()
	opts.ClientName = "client-name-marker"
	named := redisclient.NewClient(&opts)
	defer named.Close()
	ctx := context.Background()
	if err := named.Do(ctx, "CONFIG", "SET", "slowlog-log-slower-than", "0").Err(); err != nil {
		t.Fatal(err)
	}
	if err := named.Do(ctx, "SLOWLOG", "RESET").Err(); err != nil {
		t.Fatal(err)
	}
	if err := named.Do(ctx, "SET", "other-tenant:key-marker", "value-marker").Err(); err != nil {
		t.Fatal(err)
	}
	mset := []any{"MSET"}
	for i := 0; i < 40; i++ {
		mset = append(mset, fmt.Sprintf("bulk-key-%d", i), "bulk-value")
	}
	if err := named.Do(ctx, mset...).Err(); err != nil {
		t.Fatal(err)
	}

	r, err := Run(ctx, cfg, Params{Command: "SLOWLOG", Args: []string{"GET", "128"}})
	if err != nil || r.ExitCode != 0 || r.Truncated {
		t.Fatalf("SLOWLOG GET: %+v, %v", r, err)
	}
	for _, leaked := range []string{"key-marker", "value-marker", "client-name-marker", "bulk-key", "bulk-value", "slowlog-log-slower-than"} {
		if strings.Contains(r.Stdout, leaked) {
			t.Fatalf("SLOWLOG GET leaked %q:\n%s", leaked, r.Stdout)
		}
	}
	var entries [][]any
	if err := json.Unmarshal([]byte(r.Stdout), &entries); err != nil || len(entries) == 0 {
		t.Fatalf("SLOWLOG GET output: %q, %v", r.Stdout, err)
	}
	counts := map[string]float64{}
	for _, entry := range entries {
		if len(entry) != 6 {
			t.Fatalf("entry must hold id, timestamp, duration, command, argument count, address: %v", entry)
		}
		for i := 0; i < 3; i++ {
			if _, ok := entry[i].(float64); !ok {
				t.Fatalf("entry[%d] is not a number: %v", i, entry)
			}
		}
		name, ok := entry[3].(string)
		if !ok {
			t.Fatalf("entry[3] is not the command name: %v", entry)
		}
		count, ok := entry[4].(float64)
		if !ok {
			t.Fatalf("entry[4] is not the argument count: %v", entry)
		}
		if _, ok := entry[5].(string); !ok {
			t.Fatalf("entry[5] is not the client address: %v", entry)
		}
		counts[strings.ToUpper(name)] = count
	}
	if counts["SET"] != 3 {
		t.Fatalf("SET argument count = %v, want 3 (entries %v)", counts["SET"], entries)
	}
	// The server keeps 31 arguments and replaces the rest with a marker; the
	// summary reports the real count of 81.
	if counts["MSET"] != 81 {
		t.Fatalf("MSET argument count = %v, want 81 (entries %v)", counts["MSET"], entries)
	}
}

// 128 entries of the largest shape the server can store stay within the 64KB
// response limit of the catalog action.
func TestSlowlogGet128FitsDefaultLimit(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	s := startServer(t)
	cfg := restrictedConfig(t, `{"commands":["SLOWLOG"]}`)
	cfg.Address, cfg.Credential = s.address, credentials(t)
	cfg.MaxResponseBytes = 64 << 10
	ctx := context.Background()
	s.seed(t, "CONFIG", "SET", "slowlog-log-slower-than", "0")
	s.seed(t, "CONFIG", "SET", "slowlog-max-len", "256")
	s.seed(t, "SLOWLOG", "RESET")
	long := strings.Repeat("k", 4096)
	for i := 0; i < 140; i++ {
		args := []any{"MSET"}
		for j := 0; j < 100; j++ {
			args = append(args, long, long)
		}
		s.seed(t, args...)
	}
	r, err := Run(ctx, cfg, Params{Command: "SLOWLOG", Args: []string{"GET", "128"}})
	if err != nil || r.ExitCode != 0 || r.Truncated {
		t.Fatalf("SLOWLOG GET 128: truncated=%v, %v", r.Truncated, err)
	}
	var entries [][]any
	if err := json.Unmarshal([]byte(r.Stdout), &entries); err != nil || len(entries) != 128 {
		t.Fatalf("entries = %d, %v", len(entries), err)
	}
	t.Logf("128 entries use %d bytes", len(r.Stdout))
	if len(r.Stdout) > 64<<10 {
		t.Fatalf("128 entries use %d bytes, over 64KB", len(r.Stdout))
	}
}

// A client can send any argument text, including the server's truncation
// marker. The marker counts only when the entry holds the server maximum of 32
// stored arguments (31 real ones plus the marker); a shorter entry was not
// truncated, so its argument count is len(args).
func TestSummarizeSlowlogIgnoresForgedMarker(t *testing.T) {
	entry := func(args ...any) []any {
		return []any{[]any{int64(1), int64(1700000000), int64(7), args, "127.0.0.1:1", ""}}
	}
	count := func(t *testing.T, args ...any) int64 {
		t.Helper()
		out, _, err := summarizeSlowlog(entry(args...))
		if err != nil {
			t.Fatal(err)
		}
		return out.([]any)[0].([]any)[4].(int64)
	}
	if got := count(t, "SET", "k", "... (999999 more arguments)"); got != 3 {
		t.Fatalf("forged marker in a 3 argument SET: count = %d, want 3", got)
	}
	if got := count(t, "GET", "... (5 more arguments)"); got != 2 {
		t.Fatalf("forged marker in a 2 argument GET: count = %d, want 2", got)
	}
	// 31 stored arguments are fewer than the server maximum: no truncation.
	args31 := make([]any, 31)
	for i := range args31 {
		args31[i] = "a"
	}
	args31[30] = "... (50 more arguments)"
	if got := count(t, args31...); got != 31 {
		t.Fatalf("forged marker in a 31 argument entry: count = %d, want 31", got)
	}
	// A real truncation: 31 stored arguments plus the marker for 50 more.
	args32 := append(append([]any{}, args31[:30]...), "x", "... (50 more arguments)")
	if got := count(t, args32...); got != 31+50 {
		t.Fatalf("server truncation marker: count = %d, want 81", got)
	}
}

// Same forgery against a real server: SET with a forged marker is 3 arguments.
func TestSlowlogGetForgedMarkerAgainstServer(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	s := startServer(t)
	cfg := restrictedConfig(t, `{"commands":["SLOWLOG"]}`)
	cfg.Address, cfg.Credential = s.address, credentials(t)
	ctx := context.Background()
	for _, args := range [][]any{{"CONFIG", "SET", "slowlog-log-slower-than", "0"}, {"SLOWLOG", "RESET"}, {"SET", "forged-k", "... (999999 more arguments)"}} {
		if err := s.client.Do(ctx, args...).Err(); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Run(ctx, cfg, Params{Command: "SLOWLOG", Args: []string{"GET", "10"}})
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("SLOWLOG GET: %+v, %v", r, err)
	}
	var entries [][]any
	if err := json.Unmarshal([]byte(r.Stdout), &entries); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.EqualFold(e[3].(string), "set") {
			if e[4].(float64) != 3 {
				t.Fatalf("SET argument count = %v, want 3 (%s)", e[4], r.Stdout)
			}
			return
		}
	}
	t.Fatalf("no SET entry in %s", r.Stdout)
}
