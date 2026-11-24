package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/server"
)

func tlsFixture(t *testing.T, serial int64, notAfter time.Time, roots *x509.CertPool) (certPEM, keyPEM []byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("fixture certificate could not be trusted")
	}
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestGatewayTLSCertificateReload(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.pem"), filepath.Join(dir, "tls.key")
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path+".new", data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".new", path); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	initial, initialKey := tlsFixture(t, 1, time.Now().Add(time.Hour), roots)
	replacement, replacementKey := tlsFixture(t, 2, time.Now().Add(time.Hour), roots)
	expired, expiredKey := tlsFixture(t, 3, time.Now().Add(-time.Minute), roots)
	write(certPath, initial)
	write(keyPath, initialKey)
	loader, err := loadCertificateFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	previous := slog.Default()
	var logs safeBuffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	srv := server.New(&hostconn.Service{CA: &hostconn.CA{}}, *loader.current, server.WithCertificateSource(loader.GetCertificate))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	t.Cleanup(func() {
		_ = listener.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	assertSerial := func(serverName string, want int64) {
		t.Helper()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", listener.Addr().String(), &tls.Config{
			RootCAs: roots, MinVersion: tls.VersionTLS13, ServerName: serverName, NextProtos: []string{"http/1.1"},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if got := conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64(); got != want {
			t.Fatalf("server name %q certificate serial=%d, want %d", serverName, got, want)
		}
	}
	checkOnNextHandshake := func() {
		loader.mu.Lock()
		loader.nextCheck = time.Time{}
		loader.mu.Unlock()
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	get := func(path string, wantStatus int) *tls.ConnectionState {
		t.Helper()
		response, err := client.Get("https://" + listener.Addr().String() + path)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != wantStatus {
			t.Fatalf("public listener %s status=%d, want %d", path, response.StatusCode, wantStatus)
		}
		return response.TLS
	}
	assertSerial("", 1)
	existing := get("/health/live", http.StatusOK)
	write(certPath, replacement)
	checkOnNextHandshake()
	assertSerial("", 1) // The old private key cannot be used with the replacement certificate.
	write(keyPath, []byte("invalid PEM"))
	checkOnNextHandshake()
	assertSerial("localhost", 1)
	if count := strings.Count(logs.String(), "reload gateway TLS certificate failed"); count != 2 {
		t.Fatalf("expected a log for each failed replacement, got %q", logs.String())
	}
	write(keyPath, replacementKey)
	loader.mu.Lock()
	nextCheck := loader.nextCheck
	loader.mu.Unlock()
	time.Sleep(time.Until(nextCheck))
	assertSerial("", 2)
	assertSerial("localhost", 2)
	if reused := get("/health/live", http.StatusOK); reused != existing {
		t.Fatal("rotation dropped the existing HTTPS connection")
	}
	write(certPath, expired)
	write(keyPath, expiredKey)
	checkOnNextHandshake()
	assertSerial("", 2)

	get("/metrics", http.StatusNotFound)
}
