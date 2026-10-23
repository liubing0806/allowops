package executor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/liubing0806/allowops/internal/redact"
)

func TestResourceHTTPRedaction(t *testing.T) {
	for _, tc := range []struct {
		name, body, leak string
		cap              int
		custom           *redact.Config
	}{
		{"aws", builtinSecret, "AKIAABC", 10, nil},
		{"jwt", "eyJheader.payload.signature", "eyJheader", 10, nil},
		{"url", "https://demo:password@example.invalid/", "https://de", 10, nil},
		{"custom", "BEGIN_" + strings.Repeat("s", 10000) + "_END", "BEGIN_", 20, &redact.Config{Custom: []redact.Rule{{Name: "long", Regex: `BEGIN_.*_END`}}}},
		{"default", strings.Repeat("x", (64<<10)-6) + "\n" + builtinSecret, "AKIA", 64 << 10, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.body) }))
			defer s.Close()
			a := localBuiltinAction("http_get", map[string]any{"allowed_prefixes": []string{s.URL}, "max_response_bytes": tc.cap})
			a.MaxOutput = 128 << 10
			a.Redact = tc.custom
			r, err := RunWithFilters(context.Background(), a, map[string]any{"url": s.URL}, nil, nil)
			if err != nil || r.ExitCode != 0 || !r.Truncated || !r.ResourceLimitReached {
				t.Fatalf("resource success flags: %+v err=%v", r, err)
			}
			if strings.Contains(r.Stdout, tc.leak) {
				t.Errorf("resource cap leaked partial secret %q; want no incomplete tail", tc.leak)
			}
		})
	}
}

func rootExecutorTest(t *testing.T) bool {
	t.Helper()
	if os.Geteuid() == 0 {
		return true
	}
	cmd := exec.Command("/usr/bin/unshare", "-Ur", os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("root namespace exit=%v\n%s", err, output)
	}
	t.Log(string(output))
	return false
}

// Private RESP server supplies deterministic INFO and STRLEN/GETRANGE races.
// Requests still traverse executor, the registered handler and go-redis.
func redisResponseFixture(t *testing.T, reply func([]string) any) (string, string) {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "redis.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer c.Close()
				reader := bufio.NewReader(c)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
					if err != nil {
						return
					}
					args := make([]string, n)
					for i := range args {
						line, err = reader.ReadString('\n')
						if err != nil {
							return
						}
						size, e := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "$")))
						if e != nil || size < 0 || size > 1<<20 {
							return
						}
						data := make([]byte, size+2)
						if _, err = io.ReadFull(reader, data); err != nil {
							return
						}
						args[i] = string(data[:size])
					}
					var v any
					switch strings.ToLower(args[0]) {
					case "hello":
						v = fmt.Errorf("ERR unknown command")
					case "client":
						v = "OK"
					default:
						v = reply(args)
					}
					if err := writeFixtureRESP(c, v); err != nil {
						return
					}
				}
			})
		}
	})
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	credential := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(credential, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	return "unix://" + socket, credential
}

func writeFixtureRESP(w io.Writer, v any) error {
	var err error
	switch v := v.(type) {
	case error:
		_, err = fmt.Fprintf(w, "-%s\r\n", v)
	case nil:
		_, err = io.WriteString(w, "$-1\r\n")
	case int:
		_, err = fmt.Fprintf(w, ":%d\r\n", v)
	case string:
		_, err = fmt.Fprintf(w, "$%d\r\n%s\r\n", len(v), v)
	case []any:
		_, err = fmt.Fprintf(w, "*%d\r\n", len(v))
		for _, item := range v {
			if err != nil {
				return err
			}
			err = writeFixtureRESP(w, item)
		}
	default:
		return fmt.Errorf("unsupported fixture response %T", v)
	}
	return err
}

func TestResourceRedisRedaction(t *testing.T) {
	if !rootExecutorTest(t) {
		return
	}
	address, credential := redisResponseFixture(t, func(args []string) any {
		switch strings.ToLower(args[0]) {
		case "info":
			return builtinSecret + "\r\n"
		case "scan":
			return []any{"0", []any{builtinSecret}}
		case "strlen":
			return 1 // key grows before GETRANGE
		case "getrange":
			// The key now holds the whole secret; answer the requested range.
			start, _ := strconv.Atoi(args[2])
			end, _ := strconv.Atoi(args[3])
			return builtinSecret[start:min(end+1, len(builtinSecret))]
		}
		return fmt.Errorf("ERR unexpected command")
	})
	for _, command := range []string{"INFO", "SCAN", "GET", "sections"} {
		t.Run(command, func(t *testing.T) {
			a := localBuiltinAction("redis_command", map[string]any{"address": address, "credential": credential, "max_response_bytes": 10})
			input := map[string]any{"command": command}
			switch command {
			case "SCAN":
				input["args"] = []string{"0"}
			case "GET":
				input["args"] = []string{"key"}
			case "sections":
				input["command"] = "INFO"
				a.BuiltinConfig["info_sections"] = []string{"server", "memory"}
			}
			r, err := RunWithFilters(context.Background(), a, input, nil, nil)
			if err != nil || r.ExitCode != 0 || !r.Truncated || !r.ResourceLimitReached {
				t.Fatalf("resource success flags: %+v err=%v", r, err)
			}
			if strings.Contains(r.Stdout, "AKI") {
				t.Errorf("resource cap leaked secret prefix: stdout=%q; want no incomplete record", r.Stdout)
			}
		})
	}
}
