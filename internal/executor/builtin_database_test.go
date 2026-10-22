package executor

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/moby/moby/api/types/container"
	redisclient "github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	containerexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestBuiltinRedisE2E(t *testing.T) {
	if os.Geteuid() != 0 {
		child := exec.Command("/usr/bin/unshare", "-Ur", os.Args[0], "-test.run=^TestBuiltinRedisE2E$", "-test.v")
		output, err := child.CombinedOutput()
		if err != nil {
			t.Fatalf("local root namespace: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "redis.sock")
	configPath := filepath.Join(dir, "redis.conf")
	config := "port 0\nunixsocket " + strconv.Quote(socket) + "\nunixsocketperm 700\nsave \"\"\nappendonly no\nloglevel warning\n"
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "redis.log"))
	if err != nil {
		t.Fatal(err)
	}
	server := exec.Command("/usr/bin/redis-server", configPath)
	server.Stdout = log
	server.Stderr = log
	if err := server.Start(); err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait(); _ = log.Close() })
	client := redisclient.NewClient(&redisclient.Options{Network: "unix", Addr: socket, Protocol: 2, DisableIdentity: true, MaxRetries: -1})
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for client.Ping(ctx).Err() != nil {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := client.Set(ctx, "value", builtinSecret, 0).Err(); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(credential, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	a := localBuiltinAction("redis_command", map[string]any{"address": "unix://" + socket, "credential": credential})
	a.MaxOutput = 9
	input := map[string]any{"command": "GET", "args": []any{"value"}}
	r, err := RunWithFilters(context.Background(), a, input, nil, nil)
	if err != nil || r.ExitCode != 0 || !r.Truncated || r.Stdout != "\""+builtinSecretMask[:8] {
		t.Fatalf("redact before output cap: %+v %v", r, err)
	}
	r, err = RunWithFilters(context.Background(), a, input, map[string]any{"match": "AKIA", "count": true}, nil)
	if err != nil || r.Stdout != "0\n" {
		t.Fatalf("raw-secret probe: %+v %v", r, err)
	}
	r, err = RunWithFilters(context.Background(), a, input, map[string]any{"match": "REDACTED", "count": true}, nil)
	if err != nil || r.Stdout != "1\n" || r.Truncated {
		t.Fatalf("redacted filter: %+v %v", r, err)
	}
	assertRedisOriginalStrings(t, a, client, ctx)
	a.BuiltinConfig["max_response_bytes"] = catalog.Size(4)
	r, err = RunWithFilters(context.Background(), a, input, nil, nil)
	if err == nil || r.ExitCode != 1 || !r.Truncated || !r.ResourceLimitReached || r.Stdout != "" {
		t.Fatalf("resource preflight rejection: %+v %v", r, err)
	}
	a.BuiltinConfig["max_response_bytes"] = "65KB"
	if _, err := RunWithFilters(context.Background(), a, input, nil, nil); err == nil {
		t.Fatal("widened response cap accepted")
	}
	delete(a.BuiltinConfig, "max_response_bytes")
	a.BuiltinConfig["max_scan_count"] = 1
	r, err = RunWithFilters(context.Background(), a, map[string]any{"command": "SCAN", "args": []string{"0", "COUNT", "2"}}, nil, nil)
	if err == nil || r.ExitCode != 1 {
		t.Fatalf("widened SCAN count: %+v %v", r, err)
	}
}

func TestBuiltinMySQLExecutorE2E(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	t.Setenv("TESTCONTAINERS_HOST_OVERRIDE", "127.0.0.1")
	t.Setenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", "/var/run/docker.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: testcontainers.ContainerRequest{
		Image: "mysql:8.4.6", Env: map[string]string{"MYSQL_ALLOW_EMPTY_PASSWORD": "yes", "MYSQL_DATABASE": "fixture"},
		HostConfigModifier: func(h *container.HostConfig) { h.NetworkMode = "none" },
		WaitingFor:         wait.ForLog("mysqld: ready for connections.").WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
	}, Started: true})
	if c != nil {
		t.Cleanup(func() {
			ctx, done := context.WithTimeout(context.Background(), 30*time.Second)
			defer done()
			if err := c.Terminate(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CopyFileToContainer(ctx, binary, "/tmp/allowops-executor.test", 0755); err != nil {
		t.Fatal(err)
	}
	code, out, err := c.Exec(ctx, []string{"env", "ALLOWOPS_MYSQL_EXECUTOR_HELPER=1", "/tmp/allowops-executor.test", "-test.run=^TestBuiltinMySQLExecutorRootHelper$", "-test.v"}, containerexec.Multiplexed())
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(out)
	if err != nil || code != 0 {
		t.Fatalf("root helper exit=%d err=%v\n%s", code, err, data)
	}
	t.Log(strings.TrimSpace(string(data)))
}

func TestBuiltinMySQLExecutorRootHelper(t *testing.T) {
	if os.Getenv("ALLOWOPS_MYSQL_EXECUTOR_HELPER") != "1" {
		t.Skip("runs only in the local ephemeral MySQL container")
	}
	if os.Geteuid() != 0 {
		t.Fatal("helper must run as root")
	}
	credential := filepath.Join(t.TempDir(), "credential.json")
	data, _ := json.Marshal(map[string]string{"username": "root", "password": ""})
	if err := os.WriteFile(credential, data, 0600); err != nil {
		t.Fatal(err)
	}
	a := localBuiltinAction("mysql_query", map[string]any{"address": "tcp://127.0.0.1:3306", "credential": credential})
	a.MaxOutput = catalog.Size(len("value\n") + 8)
	input := map[string]any{"database": "fixture", "sql": "SELECT '" + builtinSecret + "' AS value"}
	r, err := RunWithFilters(context.Background(), a, input, nil, nil)
	if err != nil || r.ExitCode != 0 || !r.Truncated || r.Stdout != "value\n"+builtinSecretMask[:8] {
		t.Fatalf("redact before output cap: %+v %v", r, err)
	}
	r, err = RunWithFilters(context.Background(), a, input, map[string]any{"match": "AKIA", "count": true}, nil)
	if err != nil || r.Stdout != "0\n" {
		t.Fatalf("raw-secret probe: %+v %v", r, err)
	}
	r, err = RunWithFilters(context.Background(), a, input, map[string]any{"match": "REDACTED", "count": true}, nil)
	if err != nil || r.Stdout != "1\n" || r.Truncated {
		t.Fatalf("filtered output: %+v %v", r, err)
	}
	assertMySQLOriginalStrings(t, a)
	a.MaxOutput = 1024
	a.BuiltinConfig["max_rows"] = 1
	input["sql"] = "SELECT 1 AS id UNION ALL SELECT 2"
	r, err = RunWithFilters(context.Background(), a, input, nil, nil)
	if err != nil || r.ExitCode != 0 || !r.Truncated || !r.ResourceLimitReached || r.Stdout != "id\n1\n" {
		t.Fatalf("row resource cap: %+v %v", r, err)
	}
	a.BuiltinConfig["max_rows"] = 501
	if _, err := RunWithFilters(context.Background(), a, input, nil, nil); err == nil {
		t.Fatal("widened row cap accepted")
	}
}
