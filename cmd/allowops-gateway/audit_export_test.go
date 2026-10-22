package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"gopkg.in/yaml.v3"
)

func TestGatewayAuditExport(t *testing.T) {
	dsn := testpg.Start(t)
	ctx := context.Background()
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	dir := t.TempDir()
	persistent := filepath.Join(dir, "persistent-audit")
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "tls.pem"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := configuration{Address: "127.0.0.1:0", TLSCertificate: certPath, TLSKey: keyPath, CACertificate: filepath.Join(dir, "ca.pem"), CAKey: filepath.Join(dir, "ca.key"), Gateway: hostconn.DefaultConfig(), Identity: api.Config{Origin: "https://localhost"}}
	cfg.Jobs = job.DefaultConfig()
	cfg.Output = output.Config{Bucket: "fixture", Region: "us-east-1", Endpoint: "http://127.0.0.1:1"}
	cfg.Audit.ExportDirectory = persistent
	cfg.Audit.CursorName = "designated-instance"
	binary := filepath.Join(dir, "allowops-gateway")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	start := func(t *testing.T, enabled *bool) func() {
		t.Helper()
		config, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		// Encode the new setting as YAML so the regression compiles against main.
		var document map[string]any
		if err := yaml.Unmarshal(config, &document); err != nil {
			t.Fatal(err)
		}
		auditConfig := document["audit"].(map[string]any)
		delete(auditConfig, "export")
		if enabled != nil {
			auditConfig["export"] = map[string]any{"enabled": *enabled}
		}
		config, err = yaml.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "gateway.yaml")
		if err := os.WriteFile(path, config, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(binary, "serve", "--config", path)
		command.Env = append(os.Environ(), "ALLOWOPS_DATABASE_URL="+dsn)
		logs := new(safeBuffer)
		command.Stdout = logs
		command.Stderr = logs
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		stopped := false
		t.Cleanup(func() {
			if !stopped {
				command.Process.Kill()
				<-done
			}
		})
		until := time.Now().Add(5 * time.Second)
		for !strings.Contains(logs.String(), "gateway serving ") {
			select {
			case err := <-done:
				stopped = true
				t.Fatalf("serve before ready: %v\n%s", err, logs.String())
			default:
			}
			if time.Now().After(until) {
				t.Fatalf("serve not ready: %s", logs.String())
			}
			time.Sleep(10 * time.Millisecond)
		}
		return func() {
			t.Helper()
			if stopped {
				return
			}
			if err := command.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				stopped = true
				if err != nil {
					t.Fatalf("serve stop: %v\n%s", err, logs.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("serve did not stop")
			}
		}
	}
	next := func(t *testing.T) uint64 {
		t.Helper()
		var n uint64
		if err := db.Pool.QueryRow(ctx, "SELECT COALESCE((SELECT next_seq FROM audit_export_cursors WHERE name=$1),0)", cfg.Audit.CursorName).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	waitNext := func(t *testing.T, want uint64) {
		t.Helper()
		until := time.Now().Add(3 * time.Second)
		for {
			if got := next(t); got >= want {
				return
			}
			if time.Now().After(until) {
				t.Fatalf("export next_seq=%d, want >=%d", next(t), want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	off, on := false, true
	for _, tc := range []struct {
		name    string
		enabled *bool
	}{{"default_disabled", nil}, {"explicit_disabled", &off}} {
		t.Run(tc.name, func(t *testing.T) {
			stop := start(t, tc.enabled)
			defer stop()
			until := time.Now().Add(1200 * time.Millisecond)
			for time.Now().Before(until) {
				if got := next(t); got != 0 {
					t.Fatalf("disabled exporter created cursor next_seq=%d, want 0", got)
				}
				time.Sleep(10 * time.Millisecond)
			}
			files, _ := filepath.Glob(filepath.Join(persistent, "*.jsonl"))
			if len(files) != 0 {
				t.Fatalf("disabled exporter created %d files", len(files))
			}
		})
	}
	t.Run("enabled_pause_resume", func(t *testing.T) {
		stop := start(t, &on)
		defer func() { stop() }()
		a := audit.New(db.Pool, audit.Config{})
		event, err := a.Append(ctx, audit.Payload{SubjectID: "fixture", Operation: "export_enabled"})
		if err != nil {
			t.Fatal(err)
		}
		waitNext(t, event.Seq+1)
		stop()
		saved := next(t)
		later, err := a.Append(ctx, audit.Payload{SubjectID: "fixture", Operation: "export_paused"})
		if err != nil {
			t.Fatal(err)
		}
		if got := next(t); got != saved {
			t.Fatalf("stopped exporter advanced next_seq=%d, want %d", got, saved)
		}
		stop = start(t, &on)
		waitNext(t, later.Seq+1)
		stop()
		files, err := filepath.Glob(filepath.Join(persistent, "*.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		var data []byte
		for _, file := range files {
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, b...)
		}
		v, err := audit.VerifyReader(bytes.NewReader(data), audit.VerifyOptions{From: 1, To: later.Seq}, audit.Config{})
		if err != nil || !v.Valid {
			t.Fatalf("resumed files valid=%t checked=%d err=%v", v.Valid, v.CheckedCount, err)
		}
		t.Logf("designated exporter stopped and resumed: next_seq=%d, verified events=%d", next(t), v.CheckedCount)
	})
}
