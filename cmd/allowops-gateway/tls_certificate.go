package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"
)

const certificateCheckInterval = time.Second

type certificateFiles struct {
	certPath, keyPath string
	mu                sync.Mutex
	current           *tls.Certificate
	files             [2]os.FileInfo
	nextCheck         time.Time
	lastError         string
}

func loadCertificateFiles(certPath, keyPath string) (*certificateFiles, error) {
	c := &certificateFiles{certPath: certPath, keyPath: keyPath}
	files, err := c.stat()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	c.current, c.files = &cert, files
	c.nextCheck = time.Now().Add(certificateCheckInterval)
	return c, nil
}

func (c *certificateFiles) stat() ([2]os.FileInfo, error) {
	cert, err := os.Stat(c.certPath)
	if err != nil {
		return [2]os.FileInfo{}, err
	}
	key, err := os.Stat(c.keyPath)
	return [2]os.FileInfo{cert, key}, err
}

func (c *certificateFiles) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if now.Before(c.nextCheck) {
		return c.current, nil
	}
	if err := c.reload(now); err != nil {
		if message := err.Error(); message != c.lastError {
			slog.Error("reload gateway TLS certificate failed", "error", message)
			c.lastError = message
		}
	} else {
		c.lastError = ""
	}
	c.nextCheck = time.Now().Add(certificateCheckInterval)
	return c.current, nil
}

func (c *certificateFiles) reload(now time.Time) error {
	files, err := c.stat()
	if err != nil {
		return err
	}
	if sameFile(files[0], c.files[0]) && sameFile(files[1], c.files[1]) {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
	if err != nil {
		return err
	}
	for i, der := range cert.Certificate {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		if i == 0 && (now.Before(parsed.NotBefore) || !now.Before(parsed.NotAfter)) {
			return errors.New("gateway TLS certificate outside validity period")
		}
	}
	c.current, c.files = &cert, files
	return nil
}

func sameFile(a, b os.FileInfo) bool {
	return a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size() && os.SameFile(a, b)
}
