package server_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/liubing0806/allowops/internal/store"
)

type availableOutput struct{}

func (availableOutput) Check(context.Context) error { return nil }

type unavailableOutput struct{}

func (unavailableOutput) Check(context.Context) error {
	return errors.New("secret must never reach health response")
}

func TestHealthHTTPS(t *testing.T) {
	f := setup(t)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.a.roots, MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	check := func(path string, status int, degraded bool) {
		t.Helper()
		r, err := client.Get("https://" + f.a.address + path)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var body struct {
			Degraded   bool   `json:"degraded"`
			PostgreSQL string `json:"postgresql"`
			Output     string `json:"output"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != status || body.Degraded != degraded {
			t.Fatalf("%s status=%d degraded=%t; want %d %t", path, r.StatusCode, body.Degraded, status, degraded)
		}
	}
	f.a.server.Output = availableOutput{}
	check("/health/ready", http.StatusOK, false)
	f.a.server.Output = unavailableOutput{}
	check("/health/live", http.StatusOK, false)
	check("/health/ready", http.StatusOK, true)
	if _, err := f.store.Pool.Exec(context.Background(), "INSERT INTO goose_db_version(version_id,is_applied) VALUES ($1,true)", store.SchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	check("/health/ready", http.StatusServiceUnavailable, true)
	check("/health/live", http.StatusOK, false)
	if _, err := f.store.Pool.Exec(context.Background(), "ALTER TABLE goose_db_version RENAME TO health_test_versions"); err != nil {
		t.Fatal(err)
	}
	check("/health/ready", http.StatusServiceUnavailable, true)
	check("/health/live", http.StatusOK, false)
}
