package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
)

func TestMetricsAddressConfiguration(t *testing.T) {
	for _, address := range []string{"", "127.0.0.1:9090", ":9090"} {
		file := filepath.Join(t.TempDir(), "gateway.yaml")
		doc := "{}"
		if address != "" {
			doc = fmt.Sprintf("metrics_address: %q\n", address)
		}
		if err := os.WriteFile(file, []byte(doc), 0600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := decodeConfiguration(f)
		f.Close()
		if err != nil || cfg.MetricsAddress != address {
			t.Fatalf("decode %q: address=%q error=%v", doc, cfg.MetricsAddress, err)
		}
	}
}

func TestMetricsEndpointAndShutdown(t *testing.T) {
	dsn := testpg.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	agent, err := hostconn.New(db, nil, hostconn.DefaultConfig(), hostconn.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := startMetrics(listener, db, agent)
	defer stop()
	address := listener.Addr().String()
	client := &http.Client{Timeout: 3 * time.Second}
	scrape := func() map[string]string {
		t.Helper()
		response, err := client.Get("http://" + address + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if contentType := response.Header.Get("Content-Type"); response.StatusCode != http.StatusOK || contentType != "text/plain; version=0.0.4" {
			t.Fatalf("status=%d content type=%q", response.StatusCode, contentType)
		}
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		values := make(map[string]string)
		for line := range strings.SplitSeq(string(body), "\n") {
			if name, value, ok := strings.Cut(line, " "); ok && name != "#" {
				if !strings.Contains(string(body), "# TYPE "+name+" gauge\n") {
					t.Fatalf("expected gauge type for %s", name)
				}
				values[name] = value
			}
		}
		return values
	}
	const expiryMetric = "allowops_catalog_min_expiry_seconds"
	if got := scrape()[expiryMetric]; got != "NaN" {
		t.Fatalf("expiry without catalogs=%q, want NaN", got)
	}
	_, err = db.Pool.Exec(ctx, `INSERT INTO catalog_versions(catalog_id, version, dsse, digest, expires_at, action_names) VALUES
		('soon', 1, $1, $2, now()+interval '1 minute', ARRAY['test']),
		('soon', 2, $1, $2, now()+interval '2 hours', ARRAY['test']),
		('later', 1, $1, $2, now()+interval '3 hours', ARRAY['test']),
		('expired', 1, $1, $2, now()+interval '10 minutes', ARRAY['test']),
		('expired', 2, $1, $2, now()-interval '1 hour', ARRAY['test'])`, []byte("fixture"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := db.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	values := scrape()
	pool := db.Pool.Stat()
	for name, want := range map[string]string{
		"allowops_gateway_up":             "1",
		"allowops_connected_hosts":        "0",
		"allowops_db_pool_total_conns":    fmt.Sprint(pool.TotalConns()),
		"allowops_db_pool_acquired_conns": "1",
		"allowops_db_pool_idle_conns":     fmt.Sprint(pool.IdleConns()),
		"allowops_db_pool_max_conns":      fmt.Sprint(pool.MaxConns()),
	} {
		if got := values[name]; got != want {
			t.Errorf("%s=%q, want %q", name, got, want)
		}
	}
	if seconds, err := strconv.ParseFloat(values[expiryMetric], 64); err != nil || !(seconds >= 7190 && seconds <= 7200) {
		t.Fatalf("expiry from active current catalogs=%q, want about 7200 seconds", values[expiryMetric])
	}
	stop()
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err == nil {
		connection.Close()
		t.Fatal("metrics listener accepted a connection after shutdown")
	}
}
