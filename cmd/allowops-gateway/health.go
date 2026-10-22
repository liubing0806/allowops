package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

func runHealth(args []string) error {
	flags := flag.NewFlagSet("health", flag.ContinueOnError)
	address := flags.String("url", "https://localhost:8443/health/ready", "Gateway HTTPS health URL")
	caFile := flags.String("ca-file", "", "Trusted gateway TLS CA file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	u, err := url.Parse(*address)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || (u.Path != "/health/live" && u.Path != "/health/ready") || flags.NArg() != 0 {
		return errors.New("health requires an HTTPS /health/live or /health/ready URL")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			return errors.New("load health TLS CA")
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(*address)
	if err != nil {
		return errors.New("gateway health request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return errors.New("gateway health check failed")
	}
	return nil
}
