package redis

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func restrictedConfig(t *testing.T, restriction string) Config {
	t.Helper()
	c := Config{Address: "127.0.0.1:1", Credential: "/missing/redis.json"}
	if err := json.Unmarshal([]byte(restriction), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestKeyPrefixRestrictions(t *testing.T) {
	c := restrictedConfig(t, `{"key_prefixes":["tenant:","other:"]}`)
	for _, name := range []string{"GET", "MGET", "HGET", "HLEN", "TTL", "TYPE", "EXISTS", "STRLEN", "LLEN", "SCARD", "ZCARD"} {
		for _, key := range []string{"tenant:key", "other:key", "Tenant:key", "private:key", ""} {
			t.Run(name+"/"+key, func(t *testing.T) {
				args := []string{key}
				if name == "HGET" {
					args = append(args, "field")
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				r, err := Run(ctx, c, Params{Command: strings.ToLower(name), Args: args})
				allowed := strings.HasPrefix(key, "tenant:") || strings.HasPrefix(key, "other:")
				if allowed && !errors.Is(err, context.Canceled) || !allowed && (err == nil || !strings.Contains(err.Error(), "key_prefixes")) || r.ExitCode != 1 {
					t.Fatalf("allowed=%v: %+v, %v", allowed, r, err)
				}
			})
		}
	}
	for _, name := range []string{"MGET", "EXISTS"} {
		_, err := Run(context.Background(), c, Params{Command: name, Args: []string{"tenant:key", "private:key", "other:key"}})
		if err == nil || !strings.Contains(err.Error(), "key_prefixes") {
			t.Errorf("mixed %s bypass: %v", name, err)
		}
	}
}

func TestDirectConfigRestrictions(t *testing.T) {
	for _, tc := range []struct {
		config, field string
		p             Params
	}{
		{`{"commands":["GET"]}`, "commands", Params{Command: "INFO"}},
		{`{"commands":["KEYS"]}`, "commands", Params{Command: "GET", Args: []string{"key"}}},
		{`{"key_prefixes":[""]}`, "key_prefixes", Params{Command: "GET", Args: []string{"key"}}},
		{`{"info_sections":["memory"]}`, "info_sections", Params{Command: "INFO", Args: []string{"all"}}},
		{`{"info_sections":["everything"]}`, "info_sections", Params{Command: "INFO"}},
	} {
		c := restrictedConfig(t, tc.config)
		r, err := Run(context.Background(), c, tc.p)
		if err == nil || !strings.Contains(err.Error(), tc.field) || r.ExitCode != 1 {
			t.Errorf("%s: %+v, %v", tc.config, r, err)
		}
	}
}

func TestScanPrefixRestrictions(t *testing.T) {
	c := restrictedConfig(t, `{"key_prefixes":["tenant:","literal[*?:"]}`)
	for _, tc := range []struct {
		pattern string
		allowed bool
	}{
		{"tenant:*", true}, {"tenant:key", true}, {"tenant:??[ab]*", true},
		{`tenant\:*`, true}, {`literal\[\*\?:*`, true},
		{"*tenant:*", false}, {"?tenant:*", false}, {"[t]enant:*", false}, {`\*tenant:*`, false},
		{"ten*ant:*", false}, {"Tenant:*", false}, {"tenant*", false}, {"", false},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Run(ctx, c, Params{Command: "scan", Args: []string{"0", "match", tc.pattern}})
		if tc.allowed && !errors.Is(err, context.Canceled) || !tc.allowed && (err == nil || !strings.Contains(err.Error(), "key_prefixes")) {
			t.Errorf("pattern=%q allowed=%v: %v", tc.pattern, tc.allowed, err)
		}
	}
	_, err := Run(context.Background(), c, Params{Command: "SCAN", Args: []string{"0"}})
	if err == nil || !strings.Contains(err.Error(), "key_prefixes") {
		t.Errorf("SCAN without MATCH: %v", err)
	}
}

func TestRestrictedRunLocalServer(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	s := startServer(t)
	s.seed(t, "SET", "tenant:key", "allowed")
	s.seed(t, "SET", "private:key", "denied")
	c := restrictedConfig(t, `{"commands":["GET","MGET","SCAN","INFO"],"key_prefixes":["tenant:"],"info_sections":["memory","server"]}`)
	c.Address, c.Credential = s.address, credentials(t)
	for _, p := range []Params{
		{Command: "get", Args: []string{"tenant:key"}},
		{Command: "MGET", Args: []string{"tenant:key", "tenant:missing"}},
		{Command: "SCAN", Args: []string{"0", "MATCH", "tenant:*"}},
		{Command: "SCAN", Args: []string{"0", "MATCH", `tenant\:*`}},
		{Command: "INFO", Args: []string{"MEMORY"}}, {Command: "INFO"},
	} {
		r, err := Run(context.Background(), c, p)
		if err != nil || r.ExitCode != 0 || r.Truncated {
			t.Fatalf("%+v: %+v, %v", p, r, err)
		}
		if p.Command == "SCAN" && strings.Contains(r.Stdout, "private:") {
			t.Fatalf("SCAN escaped prefix: %s", r.Stdout)
		}
		if p.Command == "INFO" {
			var text string
			if err := json.Unmarshal([]byte(r.Stdout), &text); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(text, "# Memory") || strings.Contains(text, "# Clients") {
				t.Fatalf("INFO sections: %s", text)
			}
			if len(p.Args) == 0 && (strings.Index(text, "# Server") < strings.Index(text, "# Memory")) {
				t.Fatalf("INFO order: %s", text)
			}
			if len(p.Args) != 0 && strings.Contains(text, "# Server") {
				t.Fatalf("INFO explicit section: %s", text)
			}
		}
	}
	for _, p := range []Params{
		{Command: "TYPE", Args: []string{"tenant:key"}},
		{Command: "MGET", Args: []string{"tenant:key", "private:key"}},
		{Command: "SCAN", Args: []string{"0", "MATCH", "*tenant:*"}},
		{Command: "INFO", Args: []string{"clients"}},
	} {
		s.seed(t, "CONFIG", "RESETSTAT")
		r, err := Run(context.Background(), c, p)
		if err == nil || r.ExitCode != 1 || r.Stdout != "" {
			t.Fatalf("accepted %+v: %+v, %v", p, r, err)
		}
		stats, err := s.client.Info(context.Background(), "commandstats").Result()
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"type", "mget", "strlen", "scan"} {
			if strings.Contains(stats, "cmdstat_"+name+":") {
				t.Fatalf("rejected command reached server: %s", stats)
			}
		}
	}
	// Omitted info_sections retains the server's native INFO default.
	native, err := s.client.Info(context.Background()).Result()
	if err != nil {
		t.Fatal(err)
	}
	c.InfoSections = nil
	r, err := Run(context.Background(), c, Params{Command: "INFO"})
	if err != nil {
		t.Fatal(err)
	}
	var text string
	if err := json.Unmarshal([]byte(r.Stdout), &text); err != nil {
		t.Fatal(err)
	}
	// Counters and timestamps change between calls; compare section headers only.
	headers := func(text string) []string {
		var result []string
		for _, line := range strings.Split(text, "\r\n") {
			if strings.HasPrefix(line, "# ") {
				result = append(result, line)
			}
		}
		return result
	}
	if strings.Join(headers(text), ",") != strings.Join(headers(native), ",") {
		t.Fatalf("native INFO sections=%v; Run sections=%v", headers(native), headers(text))
	}
	c.InfoSections, c.MaxResponseBytes = []string{"memory", "server"}, 32
	r, err = Run(context.Background(), c, Params{Command: "INFO"})
	// A resource-cut INFO value is an incomplete JSON record. Discard it
	// rather than emitting an unrecognizable secret prefix.
	if err != nil || r.ExitCode != 0 || !r.Truncated || r.Stdout != "" {
		t.Fatalf("restricted INFO resource limit: %+v, %v", r, err)
	}
}
