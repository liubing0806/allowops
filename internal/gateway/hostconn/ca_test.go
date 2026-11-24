package hostconn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCAControlsIdentity(t *testing.T) {
	dir := t.TempDir()
	ca, err := OpenCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	u, _ := url.Parse("spiffe://attacker/other")
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "other"}, DNSNames: []string{"admin"}, URIs: []*url.URL{u}}, key)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ca.Issue("host-123", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(issued.PEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "host-123" || len(cert.DNSNames) != 0 || len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://allowops/hosts/host-123" {
		t.Fatalf("unapproved certificate identity: %+v", cert)
	}
	info, _ := os.Stat(filepath.Join(dir, "ca.key"))
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key permissions %o, want 0600", info.Mode().Perm())
	}
	if _, err := OpenCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "ca.key"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")); err == nil {
		t.Fatal("accepted readable CA private key")
	}
}

func TestVersionCompatibility(t *testing.T) {
	for _, tc := range []struct {
		agent  string
		accept bool
	}{
		{"2.3.4", true}, {"2.3.4+build.9", true}, {"2.3.4-rc.1", true}, {"1.99.0", true}, {"2.3.5", false}, {"3.0.0", false}, {"0.9.0", false}, {"2.03.4", false}, {"2.3", false}, {"2.3.4-01", false},
	} {
		t.Run(tc.agent, func(t *testing.T) {
			if err := CheckVersion("2.3.4", tc.agent); (err == nil) != tc.accept {
				t.Fatalf("CheckVersion=%v, accept=%v", err, tc.accept)
			}
		})
	}
	if err := CheckVersion("2.3.4-rc.2", "2.3.4-rc.10"); err == nil {
		t.Fatal("accepted newer numeric prerelease")
	}
	if err := CheckVersion("2.3.4-rc.2", "2.3.4"); err == nil {
		t.Fatal("accepted newer release")
	}
}

type caCreationStopped struct{}

func TestOpenCAAfterInterruptedCreation(t *testing.T) {
	defer func() { openCAStep = func(int) {} }()
	for stop := 1; ; stop++ {
		dir := t.TempDir()
		certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
		openCAStep = func(step int) {
			if step == stop {
				panic(caCreationStopped{})
			}
		}
		stopped := func() (stopped bool) {
			defer func() {
				if r := recover(); r != nil {
					if _, ok := r.(caCreationStopped); !ok {
						panic(r)
					}
					stopped = true
				}
			}()
			OpenCA(certPath, keyPath)
			return false
		}()
		openCAStep = func(int) {}
		if !stopped {
			if stop == 1 {
				t.Fatal("CA creation reported no steps")
			}
			return
		}
		ca, err := OpenCA(certPath, keyPath)
		if err != nil {
			t.Fatalf("open after creation stopped at step %d: %v", stop, err)
		}
		again, err := OpenCA(certPath, keyPath)
		if err != nil || !bytes.Equal(again.PEM, ca.PEM) {
			t.Fatalf("reopen after step %d changed the CA: %v", stop, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		if strings.Join(names, ",") != "ca.key,ca.pem" {
			t.Fatalf("files after step %d: %v", stop, names)
		}
	}
}

func TestOpenCARejectsKeyWithoutCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if _, err := OpenCA(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCA(certPath, keyPath); err == nil {
		t.Fatal("accepted a CA key without its certificate")
	}
	if _, err := os.Lstat(certPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created a certificate for an existing key: %v", err)
	}
}

func TestCADeriveKey(t *testing.T) {
	dir1, dir2 := t.TempDir(), t.TempDir()
	ca1, err := OpenCA(filepath.Join(dir1, "ca.pem"), filepath.Join(dir1, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	ca1Reopened, err := OpenCA(filepath.Join(dir1, "ca.pem"), filepath.Join(dir1, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := OpenCA(filepath.Join(dir2, "ca.pem"), filepath.Join(dir2, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	k1, err := ca1.DeriveKey("domain-a")
	if err != nil || len(k1) != 32 {
		t.Fatalf("DeriveKey len=%d err=%v", len(k1), err)
	}
	k1Again, err := ca1Reopened.DeriveKey("domain-a")
	if err != nil || !bytes.Equal(k1, k1Again) {
		t.Fatalf("reopened CA derived different key: err=%v", err)
	}
	k1OtherDomain, err := ca1.DeriveKey("domain-b")
	if err != nil || bytes.Equal(k1, k1OtherDomain) {
		t.Fatalf("different domain derived same key: err=%v", err)
	}
	k2, err := ca2.DeriveKey("domain-a")
	if err != nil || bytes.Equal(k1, k2) {
		t.Fatalf("different CA derived same key: err=%v", err)
	}
	var nilCA *CA
	if _, err := nilCA.DeriveKey("domain-a"); err == nil {
		t.Fatal("nil CA derived key")
	}
}
