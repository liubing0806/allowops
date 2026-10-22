package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHealthCommand(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--url", srv.URL + "/health/ready", "--ca-file", path}
	t.Setenv("ALLOWOPS_DATABASE_URL", "")
	if err := runWithAudit(append([]string{"health"}, args...), nil); err != nil {
		t.Fatal(err)
	}
	status = http.StatusServiceUnavailable
	if err := runHealth(args); err == nil {
		t.Fatal("unhealthy response accepted")
	}
	if err := runHealth([]string{"--url", "https://secret-user:secret-password@localhost/health/ready"}); err == nil || strings.Contains(err.Error(), "secret-password") {
		t.Fatal("URL credentials accepted or leaked")
	}
}
