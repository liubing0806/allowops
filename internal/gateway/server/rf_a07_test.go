package server_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRFA07ListenerFailureReadiness(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Only this additional gateway's listener has this application_name.
	original := f.store
	cfg := original.Pool.Config()
	name := fmt.Sprintf("rf-a07-%d", time.Now().UnixNano())
	cfg.ConnConfig.RuntimeParams["application_name"] = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	traced := *original
	traced.Pool = pool
	f.store = &traced
	g := f.start(t)
	f.store = original
	g.server.Output = availableOutput{}
	_, cert := f.join(t, g, "rf-a07-host")
	_, hello := open(t, g, cert, "2.3.4")
	t.Logf("own connected generation=%s application_name=%s", hello.ConnectionId, name)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: g.roots, MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	check := func(path string, want int) {
		t.Helper()
		response, err := client.Get("https://" + g.address + path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Errorf("%s status=%d body=%s; want %d", path, response.StatusCode, body, want)
		}
	}
	check("/health/ready", http.StatusOK)
	var pid int32
	if err := original.Pool.QueryRow(ctx, "SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND query='LISTEN allowops_gateway'", name).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	var killed bool
	if err := original.Pool.QueryRow(ctx, "SELECT pg_terminate_backend($1)", pid).Scan(&killed); err != nil || !killed {
		t.Fatalf("terminate own listener pid=%d result=%t error=%v", pid, killed, err)
	}
	t.Logf("terminated only own LISTEN backend pid=%d", pid)
	select {
	case event := <-f.disconnects:
		t.Logf("host disconnected generation=%s", event.ConnectionID)
	case <-ctx.Done():
		t.Fatal("listener failure did not disconnect own host")
	}
	if err := original.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
	var one int
	if err := pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("query pool health=%d error=%v", one, err)
	}
	check("/health/live", http.StatusOK)
	check("/health/ready", http.StatusServiceUnavailable)
}
