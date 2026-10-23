package mysql

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	driver "github.com/go-sql-driver/mysql"
	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Only the local Unix socket is used, regardless of remote Docker environment
// settings. No existing database or user-supplied endpoint is accepted.
func TestMySQLIntegration(t *testing.T) {
	const socket = "/var/run/docker.sock"
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer probeCancel()
	probe, err := (&net.Dialer{}).DialContext(probeCtx, "unix", socket)
	if err != nil {
		t.Skipf("local Docker unavailable: %v", err)
	}
	probe.Close()
	cli, err := client.New(client.WithHost("unix://" + socket))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := cli.Ping(probeCtx, client.PingOptions{}); err != nil {
		t.Skipf("local Docker unavailable: %v", err)
	}
	t.Setenv("DOCKER_HOST", "unix://"+socket)
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	t.Setenv("TESTCONTAINERS_HOST_OVERRIDE", "127.0.0.1")
	t.Setenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", socket)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	password := rand.Text()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "mysql:8.4.6",
			Env:          map[string]string{"MYSQL_ROOT_PASSWORD": password, "MYSQL_ROOT_HOST": "%", "MYSQL_DATABASE": "fixture"},
			ExposedPorts: []string{"3306/tcp"},
			HostConfigModifier: func(h *container.HostConfig) {
				h.PortBindings = network.PortMap{network.MustParsePort("3306/tcp"): {{HostIP: netip.MustParseAddr("127.0.0.1")}}}
			},
			// Exclude the X Plugin message and wait for the final mysqld server,
			// after the temporary initialization server has stopped.
			WaitingFor: wait.ForLog("mysqld: ready for connections.").WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if c != nil {
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
			defer done()
			if err := c.Terminate(cleanup); err != nil {
				t.Errorf("terminate local MySQL: %v", err)
			}
		})
	}
	if err != nil {
		t.Fatalf("start local MySQL: %v", err)
	}
	port, err := c.MappedPort(ctx, "3306/tcp")
	if err != nil {
		t.Fatal(err)
	}
	address := net.JoinHostPort("127.0.0.1", port.Port())
	dc := driver.NewConfig()
	dc.User, dc.Passwd, dc.DBName, dc.Net, dc.Addr = "root", password, "fixture", "tcp", address
	connector, err := driver.NewConnector(dc)
	if err != nil {
		t.Fatal("configure fixture database")
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	for _, statement := range []string{"CREATE TABLE items (id INT PRIMARY KEY)", "INSERT INTO items VALUES (1),(2),(3)"} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			logs, logErr := c.Logs(ctx)
			if logErr == nil {
				data, _ := io.ReadAll(logs)
				logs.Close()
				for _, line := range strings.Split(string(data), "\n") {
					if strings.Contains(line, "ready for connections") || strings.Contains(line, "Shutting down") || strings.Contains(line, "Shutdown") {
						t.Log(line)
					}
				}
			}
			t.Fatal(queryError(ctx, "seed fixture", err))
		}
	}

	t.Run("server_read_only_transaction", func(t *testing.T) {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := beginReadOnly(ctx, conn, time.Second); err != nil {
			t.Fatal(err)
		}
		defer conn.ExecContext(ctx, "ROLLBACK")
		_, err = conn.ExecContext(ctx, "INSERT INTO items VALUES (4)")
		var server *driver.MySQLError
		if !errors.As(err, &server) || server.Number != 1792 {
			t.Fatalf("expected ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION (1792), got %v", err)
		}
		var ms int
		if err := conn.QueryRowContext(ctx, "SELECT @@session.max_execution_time").Scan(&ms); err != nil || ms != 1000 {
			t.Fatalf("max_execution_time=%d, err=%v; want 1000", ms, err)
		}
	})

	// Run requires a root-only credential file. This test exercises its exact
	// connection/query/rollback implementation with ephemeral in-memory credentials.
	cfg := Config{Address: "tcp://" + address, MaxRows: 2, MaxResponseBytes: builtin.DefaultMySQLMaxResponseBytes, Timeout: time.Second}
	cred := credential{Username: "root", Password: password}
	for _, tc := range []struct {
		name, query, output string
		count               int
		truncated           bool
	}{
		{"over_limit", "SELECT id FROM items ORDER BY id", "id\n1\n2\n", 2, true},
		{"exact_limit", "SELECT id FROM items WHERE id <= 2 ORDER BY id", "id\n1\n2\n", 2, false},
		{"empty", "SELECT id FROM items WHERE id = 0", "id\n", 0, false},
		{"tsv", "SELECT 'a\\tb\\nc' AS value, NULL AS missing", "value\tmissing\na\\tb\\nc\t\\N\n", 1, false},
		{"mode", "SELECT @@session.sql_mode AS mode", "mode\nIGNORE_SPACE\n", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSQL(tc.query); err != nil {
				t.Fatal(err)
			}
			result, err := runQuery(ctx, cfg, Params{Database: "fixture", SQL: tc.query}, cred)
			if err != nil || result.Output != tc.output || result.Rows != tc.count || result.Truncated != tc.truncated {
				t.Fatalf("got %+v, %v; want output %q, rows %d, truncated %v", result, err, tc.output, tc.count, tc.truncated)
			}
		})
	}
	t.Run("query_failure", func(t *testing.T) {
		result, err := runQuery(ctx, cfg, Params{Database: "fixture", SQL: "SELECT * FROM missing_secret_table"}, cred)
		if err == nil || strings.Contains(err.Error(), "secret") || result != (Result{}) {
			t.Fatalf("unexpected failure: %+v, %v", result, err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		lock, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if _, err := lock.ExecContext(ctx, "LOCK TABLES items WRITE"); err != nil {
			t.Fatal(err)
		}
		defer lock.ExecContext(ctx, "UNLOCK TABLES")
		short, done := context.WithTimeout(ctx, 100*time.Millisecond)
		defer done()
		_, err = runQuery(short, cfg, Params{Database: "fixture", SQL: "SELECT * FROM items"}, cred)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context deadline, got %v", err)
		}
	})
	t.Run("rollback_after_query", func(t *testing.T) {
		// The local fixture's general log proves the connection sends ROLLBACK.
		for _, statement := range []string{"SET GLOBAL log_output = 'TABLE'", "SET GLOBAL general_log = ON"} {
			if _, err := db.ExecContext(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
		defer db.ExecContext(ctx, "SET GLOBAL general_log = OFF")
		result, err := runQuery(ctx, cfg, Params{Database: "fixture", SQL: "SELECT CONNECTION_ID() AS id"}, cred)
		if err != nil {
			t.Fatal(err)
		}
		id, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(result.Output, "id\n")), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		var rollbacks int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mysql.general_log WHERE thread_id = ? AND argument = 'ROLLBACK'", id).Scan(&rollbacks); err != nil || rollbacks != 1 {
			t.Fatalf("recorded rollbacks=%d, err=%v; want 1", rollbacks, err)
		}
	})
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM items").Scan(&count); err != nil || count != 3 {
		t.Fatalf("fixture changed: count=%d, err=%v", count, err)
	}
	t.Run("public_run_with_root_credential", func(t *testing.T) {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		if err := c.CopyFileToContainer(ctx, executable, "/tmp/p12c-mysql.test", 0755); err != nil {
			t.Fatal(err)
		}
		code, output, err := c.Exec(ctx, []string{"env", "P12C_MYSQL_ROOT_HELPER=1", "/tmp/p12c-mysql.test", "-test.run=^TestMySQLRootRun$", "-test.v"}, exec.Multiplexed())
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(output)
		if err != nil || code != 0 {
			t.Fatalf("root credential test exit=%d, err=%v\n%s", code, err, data)
		}
		t.Log(strings.TrimSpace(string(data)))
	})
}

// Invoked only inside the ephemeral MySQL container. The password is inherited
// from that container's environment, never passed as a command argument.
func TestMySQLRootRun(t *testing.T) {
	if os.Getenv("P12C_MYSQL_ROOT_HELPER") != "1" {
		t.Skip("helper runs inside the local test container")
	}
	if os.Geteuid() != 0 {
		t.Fatal("container helper must run as root")
	}
	path := filepath.Join(t.TempDir(), "mysql.json")
	data, err := json.Marshal(credential{Username: "root", Password: os.Getenv("MYSQL_ROOT_PASSWORD")})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Credential: path, Address: "tcp://127.0.0.1:3306", MaxRows: 1}
	result, err := Run(context.Background(), cfg, Params{Database: "fixture", SQL: "SELECT id FROM items ORDER BY id"})
	if err != nil || result.Output != "id\n1\n" || result.Rows != 1 || !result.Truncated {
		t.Fatalf("root Run: %+v, %v", result, err)
	}
	for _, tc := range []struct {
		field           string
		values          []string
		allowed, denied Params
	}{
		{"databases", []string{"fixture"}, Params{Database: "fixture", SQL: "SELECT 1"}, Params{Database: "other", SQL: "SELECT 1"}},
		{"statement_types", []string{"SELECT"}, Params{Database: "fixture", SQL: "SELECT id FROM items"}, Params{Database: "fixture", SQL: "SHOW TABLES"}},
		{"statement_types", []string{"DESCRIBE"}, Params{Database: "fixture", SQL: "DESC items"}, Params{Database: "fixture", SQL: "SHOW COLUMNS FROM items"}},
		{"statement_types", []string{"EXPLAIN", "SELECT"}, Params{Database: "fixture", SQL: "EXPLAIN SELECT id FROM items"}, Params{Database: "fixture", SQL: "DESC items"}},
		{"show_types", []string{"TABLES"}, Params{Database: "fixture", SQL: "SHOW TABLES"}, Params{Database: "fixture", SQL: "SHOW DATABASES"}},
		{"show_types", []string{"DATABASES"}, Params{Database: "fixture", SQL: "SHOW DATABASES"}, Params{Database: "fixture", SQL: "SHOW TABLES"}},
		{"show_types", []string{"PROCESSLIST"}, Params{Database: "fixture", SQL: "SHOW FULL PROCESSLIST"}, Params{Database: "fixture", SQL: "SHOW VARIABLES"}},
		{"show_types", []string{"VARIABLES"}, Params{Database: "fixture", SQL: "SHOW SESSION VARIABLES"}, Params{Database: "fixture", SQL: "SHOW STATUS"}},
		{"show_types", []string{"STATUS"}, Params{Database: "fixture", SQL: "SHOW GLOBAL STATUS"}, Params{Database: "fixture", SQL: "SHOW VARIABLES"}},
		{"show_types", []string{"CREATE TABLE"}, Params{Database: "fixture", SQL: "SHOW CREATE TABLE items"}, Params{Database: "fixture", SQL: "SHOW CREATE DATABASE fixture"}},
		{"show_types", []string{"COLUMNS"}, Params{Database: "fixture", SQL: "SHOW FULL COLUMNS FROM items"}, Params{Database: "fixture", SQL: "SHOW INDEX FROM items"}},
	} {
		t.Run(tc.field+"/"+strings.Join(tc.values, "+"), func(t *testing.T) {
			narrow := cfg
			switch tc.field {
			case "databases":
				narrow.Databases = tc.values
			case "statement_types":
				narrow.StatementTypes = tc.values
			case "show_types":
				narrow.ShowTypes = tc.values
			}
			result, err := Run(context.Background(), narrow, tc.allowed)
			if err != nil || result.Rows == 0 {
				t.Fatalf("allowed %+v: %+v, %v", tc.allowed, result, err)
			}
			result, err = Run(context.Background(), narrow, tc.denied)
			if err == nil || !strings.Contains(err.Error(), tc.field) || result.Output != "" {
				t.Fatalf("denied %+v: %+v, %v", tc.denied, result, err)
			}
		})
	}
	t.Run("database_sql_references", func(t *testing.T) {
		narrow := cfg
		narrow.Databases = []string{"fixture"}
		for _, query := range []string{
			"SELECT id FROM fixture.items", "WITH c AS (SELECT id FROM fixture.items) SELECT * FROM c",
			"EXPLAIN SELECT id FROM fixture.items", "SHOW TABLES IN fixture", "SHOW CREATE TABLE fixture.items",
		} {
			result, err := Run(context.Background(), narrow, Params{Database: "fixture", SQL: query})
			if err != nil || result.Rows == 0 {
				t.Fatalf("allowed %s: %+v, %v", query, result, err)
			}
		}
		for _, query := range []string{
			"SELECT User FROM mysql.user", "WITH c AS (SELECT User FROM mysql.user) SELECT * FROM c",
			"EXPLAIN SELECT User FROM mysql.user", "SHOW TABLES IN mysql", "SHOW CREATE TABLE mysql.user",
		} {
			result, err := Run(context.Background(), narrow, Params{Database: "fixture", SQL: query})
			if err == nil || !strings.Contains(err.Error(), "databases") || result.Output != "" {
				t.Fatalf("denied %s: %+v, %v", query, result, err)
			}
		}
		for _, tc := range []struct{ kind, query string }{
			{"DATABASES", "SHOW DATABASES"}, {"PROCESSLIST", "SHOW FULL PROCESSLIST"},
			{"VARIABLES", "SHOW GLOBAL VARIABLES"}, {"STATUS", "SHOW SESSION STATUS"},
		} {
			narrow.ShowTypes = nil
			result, err := Run(context.Background(), narrow, Params{Database: "fixture", SQL: tc.query})
			if err == nil || !strings.Contains(err.Error(), "show_types") || result.Output != "" {
				t.Fatalf("server SHOW requires opt-in: %+v, %v", result, err)
			}
			narrow.ShowTypes = []string{tc.kind}
			result, err = Run(context.Background(), narrow, Params{Database: "fixture", SQL: tc.query})
			if err != nil || result.Rows == 0 {
				t.Fatalf("explicit server SHOW: %+v, %v", result, err)
			}
		}
	})
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), cfg, Params{Database: "fixture", SQL: "SELECT 1"}); err == nil {
		t.Fatal("Run accepted wide credential permissions")
	}
}
