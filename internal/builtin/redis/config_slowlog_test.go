package redis

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
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
	if err != nil || r.ExitCode != 0 || json.Unmarshal([]byte(r.Stdout), &entries) != nil || len(entries) == 0 || !strings.Contains(r.Stdout, "tenant:key") {
		t.Fatalf("SLOWLOG GET: %+v, %v", r, err)
	}
	r, err = Run(context.Background(), cfg, Params{Command: "SLOWLOG", Args: []string{"GET"}})
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("SLOWLOG GET default count: %+v, %v", r, err)
	}
	// Masking reaches nested slow log command arguments.
	r, err = RunRedacted(context.Background(), cfg, Params{Command: "SLOWLOG", Args: []string{"GET", "10"}}, func(v string) string {
		return strings.ReplaceAll(v, "super-secret-value", "***")
	})
	if err != nil || strings.Contains(r.Stdout, "super-secret-value") || !strings.Contains(r.Stdout, "***") {
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
