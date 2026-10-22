package hostconn

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type CA struct {
	certificate *x509.Certificate
	key         crypto.Signer
	PEM         []byte
}

type IssuedCertificate struct {
	PEM                   []byte
	Serial                string
	ExpiresAt, RenewAfter time.Time
}

// OpenCA creates a CA only when both files are absent. Existing keys must be
// regular files with exactly 0600 permissions. A partially provisioned CA fails.
func OpenCA(certPath, keyPath string) (*CA, error) {
	_, certErr := os.Lstat(certPath)
	_, keyErr := os.Lstat(keyPath)
	if errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist) {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		serial, err := randomSerial()
		if err != nil {
			return nil, err
		}
		now := time.Now()
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "allowops host CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
		if err != nil {
			return nil, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := exclusiveFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
			return nil, err
		}
		if err := exclusiveFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
			os.Remove(keyPath)
			return nil, err
		}
	} else if certErr != nil || keyErr != nil {
		return nil, fmt.Errorf("CA files must both exist or both be absent")
	}
	// O_NOFOLLOW and fstat keep symlinks and replacement files out of key loading.
	f, err := os.OpenFile(keyPath, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("CA key requires a regular 0600 file")
	}
	if info.Size() > 16384 {
		return nil, fmt.Errorf("CA key too large")
	}
	keyData := make([]byte, info.Size())
	if _, err := f.ReadAt(keyData, 0); err != nil {
		return nil, err
	}
	block, rest := pem.Decode(keyData)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, fmt.Errorf("invalid CA key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA key cannot sign")
	}
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, rest = pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, fmt.Errorf("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	if string(pubDER) != string(cert.RawSubjectPublicKeyInfo) || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("CA certificate and private key mismatch")
	}
	return &CA{certificate: cert, key: key, PEM: certData}, nil
}

func exclusiveFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		os.Remove(path)
		return err
	}
	return closeErr
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func ParseCSR(data []byte) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		return nil, fmt.Errorf("one CSR PEM required")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CSR")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature")
	}
	return csr, nil
}

func (c *CA) Issue(hostID string, data []byte, ttl time.Duration) (*IssuedCertificate, error) {
	csr, err := ParseCSR(data)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 || hostID == "" {
		return nil, fmt.Errorf("host ID and positive certificate TTL required")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expires := now.Add(ttl)
	if expires.After(c.certificate.NotAfter) || now.Before(c.certificate.NotBefore) {
		return nil, fmt.Errorf("CA validity does not cover certificate")
	}
	u := &url.URL{Scheme: "spiffe", Host: "allowops", Path: "/hosts/" + hostID}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: hostID}, URIs: []*url.URL{u}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, c.certificate, csr.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), c.PEM...)
	return &IssuedCertificate{PEM: chain, Serial: serial.Text(16), ExpiresAt: expires, RenewAfter: now.Add(ttl * 2 / 3)}, nil
}
