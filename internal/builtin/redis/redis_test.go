package redis

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	redisclient "github.com/redis/go-redis/v9"
)

// The child sees the test user's files as root-owned without host privileges.
func inRootNamespace(t *testing.T) bool {
	t.Helper()
	if os.Geteuid() == 0 {
		return true
	}
	cmd := exec.Command("unshare", "-Ur", os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("root user-namespace test: %v\n%s", err, out)
	}
	t.Log(string(out))
	return false
}

func credentials(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "redis.json")
	if err := os.WriteFile(path, []byte(`{"username":"","password":"local-test-password"}`), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

type localServer struct {
	address string
	client  *redisclient.Client
}

// Run a private local Redis-compatible process with no TCP listener or persistence.
func startServer(t *testing.T) *localServer {
	t.Helper()
	binary, err := exec.LookPath("redis-server")
	if err != nil {
		t.Fatal("local Redis-compatible redis-server is required: ", err)
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "redis.sock")
	config := "port 0\nunixsocket " + strconv.Quote(socket) + "\nunixsocketperm 700\nsave \"\"\nappendonly no\nloglevel warning\nrequirepass local-test-password\n"
	configFile := filepath.Join(dir, "redis.conf")
	if err := os.WriteFile(configFile, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, configFile)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = logFile.Close() })
	client := redisclient.NewClient(&redisclient.Options{Network: "unix", Addr: socket, Password: "local-test-password", Protocol: 2, DisableIdentity: true, MaxRetries: -1, ContextTimeoutEnabled: true, DialTimeout: 50 * time.Millisecond, ReadTimeout: 50 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for client.Ping(ctx).Err() != nil {
		select {
		case <-ctx.Done():
			data, _ := os.ReadFile(logFile.Name())
			t.Fatalf("local Redis startup: %v\n%s", ctx.Err(), data)
		case <-time.After(10 * time.Millisecond):
		}
	}
	return &localServer{address: "unix://" + socket, client: client}
}

func (s *localServer) seed(t *testing.T, args ...any) {
	t.Helper()
	if err := s.client.Do(context.Background(), args...).Err(); err != nil {
		t.Fatal(err)
	}
}

func TestRun(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	s := startServer(t)
	s.seed(t, "SET", "text", "hello")
	s.seed(t, "HSET", "hash", "field", "value")
	s.seed(t, "RPUSH", "list", "a", "b")
	s.seed(t, "SADD", "set", "a", "b")
	s.seed(t, "ZADD", "zset", 1, "a")
	cfg := Config{Address: s.address, Credential: credentials(t)}
	for _, tc := range []struct {
		command string
		args    []string
		want    string
	}{
		{"GET", []string{"text"}, `"hello"`}, {"GET", []string{"missing"}, `null`}, {"MGET", []string{"text", "missing"}, `["hello",null]`},
		{"HGET", []string{"hash", "field"}, `"value"`}, {"HLEN", []string{"hash"}, `1`}, {"TTL", []string{"text"}, `-1`},
		{"TYPE", []string{"text"}, `"string"`}, {"EXISTS", []string{"text", "missing"}, `1`}, {"STRLEN", []string{"text"}, `5`},
		{"LLEN", []string{"list"}, `2`}, {"SCARD", []string{"set"}, `2`}, {"ZCARD", []string{"zset"}, `1`},
		{"SCAN", []string{"0", "MATCH", "text", "COUNT", "10"}, `["0",["text"]]`}, {"INFO", nil, ""},
	} {
		t.Run(tc.command+strings.Join(tc.args, "_"), func(t *testing.T) {
			r, err := Run(context.Background(), cfg, Params{Command: tc.command, Args: tc.args})
			if err != nil || r.ExitCode != 0 || r.Truncated {
				t.Fatalf("%#v %v", r, err)
			}
			if tc.want != "" && strings.TrimSpace(r.Stdout) != tc.want {
				t.Fatalf("got %q want %q", r.Stdout, tc.want)
			}
			if tc.command == "INFO" && !strings.Contains(r.Stdout, "#") {
				t.Fatalf("INFO: %q", r.Stdout)
			}
		})
	}
	r, err := Run(context.Background(), cfg, Params{Command: "get", Args: []string{"text"}})
	if err != nil || !strings.Contains(r.Stdout, "hello") {
		t.Fatalf("lowercase %#v %v", r, err)
	}
}

func TestCommandRejections(t *testing.T) {
	for _, p := range []Params{
		{Command: "KEYS", Args: []string{"*"}}, {Command: "SET", Args: []string{"key", "value"}}, {Command: "EVAL", Args: []string{"return 1", "0"}}, {Command: "FLUSHALL"}, {Command: "CONFIG", Args: []string{"GET", "*"}},
		{Command: "GET"}, {Command: "GET", Args: []string{"a", "b"}}, {Command: "HGET", Args: []string{"a"}}, {Command: "MGET"}, {Command: "INFO", Args: []string{"a", "b"}},
		{Command: "SCAN", Args: []string{"0", "COUNT", "1001"}}, {Command: "SCAN", Args: []string{"0", "COUNT", "-1"}}, {Command: "SCAN", Args: []string{"0", "COUNT", "0"}}, {Command: "SCAN", Args: []string{"-1"}},
		{Command: "SCAN", Args: []string{"0", "COUNT", "1", "COUNT", "2"}}, {Command: "SCAN", Args: []string{"0", "TYPE", "string"}}, {Command: "SCAN", Args: []string{"0", "MATCH"}},
		{Command: "GET", Args: []string{"-key"}}, {Command: "GET", Args: []string{strings.Repeat("a", 4097)}}, {Command: "GET\nSET", Args: []string{"key"}},
	} {
		t.Run(p.Command+strings.Join(p.Args, "_"), func(t *testing.T) {
			r, err := Run(context.Background(), Config{Address: "127.0.0.1:1", Credential: "/nonexistent"}, p)
			if err == nil || r.ExitCode == 0 || strings.Contains(err.Error(), "credential") {
				t.Fatalf("want command rejection before credential read: %#v %v", r, err)
			}
		})
	}
}

func TestCredentials(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	for _, kind := range []string{"missing", "wide", "symlink", "invalid-json", "extra-field", "directory", "oversize", "null"} {
		t.Run(kind, func(t *testing.T) {
			path := credentials(t)
			switch kind {
			case "missing":
				path += ".absent"
			case "wide":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := path + ".link"
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "invalid-json":
				if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "null":
				if err := os.WriteFile(path, []byte("null"), 0600); err != nil {
					t.Fatal(err)
				}
			case "extra-field":
				if err := os.WriteFile(path, []byte(`{"password":"secret","address":"evil"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				path = filepath.Dir(path)
			case "oversize":
				if err := os.WriteFile(path, []byte(strings.Repeat("x", 16385)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			r, err := Run(context.Background(), Config{Address: "127.0.0.1:1", Credential: path}, Params{Command: "GET", Args: []string{"key"}})
			if err == nil || r.ExitCode == 0 || !strings.Contains(err.Error(), "credential") || strings.Contains(err.Error(), "secret") || r.Stdout != "" {
				t.Fatalf("credentials %#v %v", r, err)
			}
		})
	}
}

func TestCredentialOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		return
	}
	path := credentials(t)
	r, err := Run(context.Background(), Config{Address: "127.0.0.1:1", Credential: path}, Params{Command: "GET", Args: []string{"key"}})
	if err == nil || r.ExitCode == 0 || !strings.Contains(err.Error(), "root") {
		t.Fatalf("owner %#v %v", r, err)
	}
}

func TestLimitsAndTimeout(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	s := startServer(t)
	s.seed(t, "SET", "key", strings.Repeat("x", 1<<20))
	cfg := Config{Address: s.address, Credential: credentials(t), MaxResponseBytes: 128}
	r, err := Run(context.Background(), cfg, Params{Command: "GET", Args: []string{"key"}})
	if err == nil || !strings.Contains(err.Error(), "response limit") || !r.Truncated || r.Stdout != "" || r.ExitCode != 1 {
		t.Fatalf("size %#v %v", r, err)
	}
	cfg.MaxScanCount = 2
	r, err = Run(context.Background(), cfg, Params{Command: "SCAN", Args: []string{"0", "COUNT", "3"}})
	if err == nil || r.ExitCode == 0 {
		t.Fatalf("SCAN limit %#v %v", r, err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			<-done
		}
	}()
	cfg.Address, cfg.Timeout = ln.Addr().String(), 20*time.Millisecond
	start := time.Now()
	r, err = Run(context.Background(), cfg, Params{Command: "GET", Args: []string{"key"}})
	if err == nil || r.ExitCode == 0 || time.Since(start) > time.Second {
		t.Fatalf("timeout %#v %v elapsed %v", r, err, time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err = Run(ctx, cfg, Params{Command: "GET", Args: []string{"key"}})
	if err == nil || r.ExitCode == 0 {
		t.Fatalf("cancelled %#v %v", r, err)
	}
}

func TestOversizedValuesAreRejectedBeforeRead(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	s := startServer(t)
	s.seed(t, "SET", "large", strings.Repeat("x", 1<<20))
	s.seed(t, "SET", "half", strings.Repeat("x", 80))
	s.seed(t, "HSET", "hash", "large", strings.Repeat("x", 1<<20))
	for _, p := range []Params{{Command: "GET", Args: []string{"large"}}, {Command: "HGET", Args: []string{"hash", "large"}}, {Command: "MGET", Args: []string{"half", "half"}}} {
		t.Run(p.Command, func(t *testing.T) {
			s.seed(t, "CONFIG", "RESETSTAT")
			r, err := Run(context.Background(), Config{Address: s.address, Credential: credentials(t), MaxResponseBytes: 128}, p)
			stats, statsErr := s.client.Info(context.Background(), "commandstats").Result()
			if statsErr != nil {
				t.Fatal(statsErr)
			}
			if err == nil || !strings.Contains(err.Error(), "response limit") || r.ExitCode != 1 || !r.Truncated || r.Stdout != "" {
				t.Fatalf("oversized %s: stdout=%d exit=%d truncated=%v error=%v\n%s", p.Command, len(r.Stdout), r.ExitCode, r.Truncated, err, stats)
			}
			if strings.Contains(stats, "cmdstat_"+strings.ToLower(p.Command)+":") {
				t.Fatalf("oversized value was read:\n%s", stats)
			}
			if p.Command == "GET" && strings.Contains(stats, "cmdstat_getrange:") {
				t.Fatalf("oversized value was read with GETRANGE:\n%s", stats)
			}
			check := "strlen"
			if p.Command == "HGET" {
				check = "hstrlen"
			}
			if !strings.Contains(stats, "cmdstat_"+check+":") {
				t.Fatalf("missing size preflight:\n%s", stats)
			}
		})
	}
}

func TestRawValueIsNotOutputTruncated(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	s := startServer(t)
	value := strings.Repeat("\x00", 64<<10)
	s.seed(t, "SET", "value", value)
	r, err := Run(context.Background(), Config{Address: s.address, Credential: credentials(t)}, Params{Command: "GET", Args: []string{"value"}})
	var decoded string
	decodeErr := json.Unmarshal([]byte(r.Stdout), &decoded)
	if err != nil || decodeErr != nil || decoded != value || r.Truncated || len(r.Stdout) <= 64<<10 {
		t.Fatalf("raw value: stdout=%d truncated=%v error=%v decode=%v", len(r.Stdout), r.Truncated, err, decodeErr)
	}
}

type afterCommandHook struct{ after func(redisclient.Cmder) }

func (h afterCommandHook) DialHook(next redisclient.DialHook) redisclient.DialHook { return next }
func (h afterCommandHook) ProcessPipelineHook(next redisclient.ProcessPipelineHook) redisclient.ProcessPipelineHook {
	return next
}
func (h afterCommandHook) ProcessHook(next redisclient.ProcessHook) redisclient.ProcessHook {
	return func(ctx context.Context, cmd redisclient.Cmder) error {
		err := next(ctx, cmd)
		if err == nil {
			h.after(cmd)
		}
		return err
	}
}

func TestGetRangeBoundsConcurrentGrowth(t *testing.T) {
	s := startServer(t)
	s.seed(t, "SET", "key", "small")
	reader := redisclient.NewClient(s.client.Options())
	defer reader.Close()
	reader.AddHook(afterCommandHook{after: func(cmd redisclient.Cmder) {
		if cmd.Name() == "strlen" {
			s.seed(t, "SET", "key", strings.Repeat("x", 1<<20))
		}
	}})
	value, truncated, err := readResponse(context.Background(), reader, []any{"GET", "key"}, 128)
	if err != nil || !truncated || value != strings.Repeat("x", 128) {
		t.Fatalf("bounded GET: value=%v truncated=%v error=%v", value, truncated, err)
	}
	stats, err := s.client.Info(context.Background(), "commandstats").Result()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stats, "cmdstat_get:") || !strings.Contains(stats, "cmdstat_getrange:") || strings.Contains(stats, "cmdstat_watch:") || strings.Contains(stats, "cmdstat_multi:") {
		t.Fatalf("unexpected read commands:\n%s", stats)
	}
}

// STRLEN equal to the limit does not prove the GETRANGE prefix is complete:
// the key may have grown in between, and an unchanged key of exactly limit
// bytes must still be returned whole.
func TestGetAtExactLimitDetectsGrowth(t *testing.T) {
	const limit = 128
	exact := strings.Repeat("x", limit)
	for _, tc := range []struct {
		name          string
		grow          bool
		wantTruncated bool
	}{{"unchanged", false, false}, {"grown after STRLEN", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			s := startServer(t)
			s.seed(t, "SET", "key", exact)
			reader := redisclient.NewClient(s.client.Options())
			defer reader.Close()
			if tc.grow {
				reader.AddHook(afterCommandHook{after: func(cmd redisclient.Cmder) {
					if cmd.Name() == "strlen" {
						s.seed(t, "SET", "key", exact+"tail")
					}
				}})
			}
			value, truncated, err := readResponse(context.Background(), reader, []any{"GET", "key"}, limit)
			if err != nil || truncated != tc.wantTruncated || value != exact {
				t.Fatalf("GET at limit: value=%q truncated=%v want %v error=%v", value, truncated, tc.wantTruncated, err)
			}
		})
	}
}

func TestResponseResourceLimits(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	s := startServer(t)
	s.seed(t, "HSET", "hash", "field", "value")
	s.seed(t, "SET", "empty", "")
	s.seed(t, "SET", strings.Repeat("long-key", 20), "value")
	cfg := Config{Address: s.address, Credential: credentials(t), MaxResponseBytes: 128}
	for _, p := range []Params{{Command: "GET", Args: []string{"empty"}}, {Command: "HGET", Args: []string{"hash", "absent"}}, {Command: "MGET", Args: []string{"hash", "absent"}}} {
		r, err := Run(context.Background(), cfg, p)
		if err != nil || r.Truncated {
			t.Fatalf("empty/missing values: %#v %v", r, err)
		}
		if p.Command == "GET" && strings.TrimSpace(r.Stdout) != `""` {
			t.Fatalf("empty GET: %q", r.Stdout)
		}
		if p.Command == "MGET" && strings.TrimSpace(r.Stdout) != `[null,null]` {
			t.Fatalf("non-string MGET: %q", r.Stdout)
		}
	}
	for _, p := range []Params{{Command: "INFO"}, {Command: "SCAN", Args: []string{"0", "COUNT", "1000"}}} {
		r, err := Run(context.Background(), cfg, p)
		if err != nil || !r.Truncated || len(r.Stdout) > 128 || r.ExitCode != 0 {
			t.Fatalf("response resource limit: %#v %v", r, err)
		}
	}
}

func TestSchemaAndConfig(t *testing.T) {
	for _, cfg := range []Config{{}, {Address: "evil", Credential: "relative"}, {Address: "127.0.0.1:6379", Credential: "/tmp/creds", MaxScanCount: 1001}} {
		if cfg.Validate() == nil {
			t.Fatalf("accepted %#v", cfg)
		}
	}
	s := ParamsSchema()
	if s["$schema"] != "https://json-schema.org/draft/2020-12/schema" || s["additionalProperties"] != false {
		t.Fatalf("schema %#v", s)
	}
	if _, err := json.Marshal(s); err != nil {
		t.Fatal(err)
	}
}
