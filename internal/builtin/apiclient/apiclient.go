// Package apiclient implements the read-only HTTP client shared by the
// Prometheus and Alertmanager builtins.
package apiclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/params"
)

const (
	maxAddressBytes    = 4096
	maxCredentialBytes = 16 << 10
	maxCAFileBytes     = 1 << 20
)

// Config is trusted catalog configuration. Zero Timeout and MaxResponseBytes
// select the package defaults; callers apply their own defaults and upper
// limits with Tighten before constructing a Client. MaxResponseBytes limits
// response body bytes, independently of status and headers.
type Config struct {
	Address          string        `yaml:"address"`
	Credential       string        `yaml:"credential"`
	CAFile           string        `yaml:"ca_file"`
	Timeout          time.Duration `yaml:"timeout"`
	MaxResponseBytes int64         `yaml:"max_response_bytes"`
}

// Response is a completed GET exchange. Non-2xx statuses are not errors: the
// caller decodes the service's own error body.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

var (
	// ErrRedirect reports a 3xx response. Redirects are never followed.
	ErrRedirect = errors.New("apiclient: redirect response")
	// ErrResponseTooLarge reports a body above Config.MaxResponseBytes.
	ErrResponseTooLarge = errors.New("apiclient: response body exceeds max_response_bytes")
)

// Validate checks the address and file paths without touching the file system.
// The address is normalized by the shared URL parser and may carry a path prefix.
func (c Config) Validate() error {
	base, err := baseURL(c.Address)
	if err != nil {
		return err
	}
	if c.Credential != "" && !filepath.IsAbs(c.Credential) {
		return errors.New("credential path must be absolute")
	}
	if c.CAFile != "" {
		if !filepath.IsAbs(c.CAFile) {
			return errors.New("ca_file path must be absolute")
		}
		if base.Scheme != "https" {
			return errors.New("ca_file requires an https address")
		}
	}
	if c.Timeout < 0 || c.MaxResponseBytes < 0 {
		return errors.New("timeout and max_response_bytes must be nonnegative")
	}
	return nil
}

// baseURL returns the normalized base address. Credentials, query and fragment
// are rejected, so every request is origin + path prefix + fixed API path.
func baseURL(address string) (*url.URL, error) {
	if len(address) > maxAddressBytes {
		return nil, errors.New("invalid address")
	}
	u, err := params.NormalizeURL(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return nil, errors.New("address must not contain a query")
	}
	return u, nil
}

// Tighten applies the shared limit rule to a catalog value: zero selects def,
// and the result must lie in [1, max]. Configuration can only tighten limits.
func Tighten[T ~int | ~int64](name string, value, def, max T) (T, error) {
	if value == 0 {
		return def, nil
	}
	if value < 0 || value > max {
		return 0, fmt.Errorf("%s must be between 1 and %v", name, max)
	}
	return value, nil
}

type credential struct {
	BearerToken *string `json:"bearer_token"`
	Username    *string `json:"username"`
	Password    *string `json:"password"`
}

// readCredential applies the same file checks as the Redis and MySQL handlers.
// Error text never includes file content.
func readCredential(path string) (credential, error) {
	var c credential
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return c, errors.New("cannot open API credential file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return c, errors.New("cannot stat API credential file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return c, errors.New("API credential file must be owned by root")
	}
	if info.Mode() != 0600 {
		return c, errors.New("API credential file must be regular with mode 0600")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCredentialBytes+1))
	if err != nil || len(data) > maxCredentialBytes {
		return c, errors.New("cannot read API credential file or size exceeds 16KiB")
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return c, errors.New("API credential must contain one JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return credential{}, errors.New("invalid API credential JSON")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return credential{}, errors.New("API credential must contain one JSON object")
	}
	return c, nil
}

// authorize returns the Authorization header value: either bearer_token, or
// username with password, never both and never neither.
func (c credential) authorize() (func(*http.Request), error) {
	basic := c.Username != nil || c.Password != nil
	switch {
	case c.BearerToken != nil && basic:
		return nil, errors.New("API credential must use either bearer_token or username and password")
	case c.BearerToken != nil:
		token := *c.BearerToken
		if token == "" || strings.IndexFunc(token, func(r rune) bool { return r <= ' ' || r >= 127 }) >= 0 {
			return nil, errors.New("invalid API credential bearer_token")
		}
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }, nil
	case basic:
		if c.Username == nil || c.Password == nil || *c.Username == "" || *c.Password == "" ||
			strings.Contains(*c.Username, ":") ||
			strings.IndexFunc(*c.Username+*c.Password, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
			return nil, errors.New("invalid API credential username or password")
		}
		user, pass := *c.Username, *c.Password
		return func(r *http.Request) { r.SetBasicAuth(user, pass) }, nil
	}
	return nil, errors.New("API credential requires bearer_token or username and password")
}

// readCAFile returns a pool holding only the configured CA certificates.
func readCAFile(path string) (*x509.CertPool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open ca_file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("ca_file must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCAFileBytes+1))
	if err != nil || len(data) > maxCAFileBytes {
		return nil, errors.New("cannot read ca_file or size exceeds 1MiB")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("ca_file contains no PEM certificate")
	}
	return pool, nil
}

// Client issues GET requests to one configured service. It is safe for
// concurrent use; call Close when finished.
type Client struct {
	base      *url.URL
	authorize func(*http.Request)
	timeout   time.Duration
	maxBody   int64
	transport *http.Transport
	client    *http.Client
}

// New validates cfg, reads the credential and CA file, and returns a Client.
func New(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	base, err := baseURL(cfg.Address)
	if err != nil {
		return nil, err
	}
	c := &Client{base: base, timeout: cfg.Timeout, maxBody: cfg.MaxResponseBytes}
	if c.timeout == 0 {
		c.timeout = builtin.DefaultTimeout
	}
	if c.maxBody == 0 {
		c.maxBody = builtin.DefaultHTTPMaxResponseBytes
	}
	if cfg.Credential != "" {
		cred, err := readCredential(cfg.Credential)
		if err != nil {
			return nil, err
		}
		if c.authorize, err = cred.authorize(); err != nil {
			return nil, err
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		if tlsConfig.RootCAs, err = readCAFile(cfg.CAFile); err != nil {
			return nil, err
		}
	}
	c.transport = http.DefaultTransport.(*http.Transport).Clone()
	c.transport.Proxy = nil // Only the configured origin receives the credential.
	c.transport.DisableCompression = true
	c.transport.MaxResponseHeaderBytes = builtin.DefaultHTTPMaxHeaderBytes
	c.transport.TLSClientConfig = tlsConfig
	c.client = &http.Client{Transport: c.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c, nil
}

// Close releases idle connections.
func (c *Client) Close() { c.transport.CloseIdleConnections() }

// Get requests base path + apiPath with the given query parameters. apiPath is
// a fixed API path chosen by the handler, not user input: it must start with a
// single "/" and contain only letters, digits and "-._~/:" without "." or ".."
// segments. A 3xx status returns ErrRedirect, and a body above the configured
// limit returns ErrResponseTooLarge; neither returns partial data.
func (c *Client) Get(ctx context.Context, apiPath string, query url.Values) (Response, error) {
	if err := checkAPIPath(apiPath); err != nil {
		return Response{}, err
	}
	u := *c.base
	u.Path, u.RawPath = strings.TrimSuffix(c.base.Path, "/")+apiPath, ""
	u.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Response{}, errors.New("cannot construct GET request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header["User-Agent"] = nil
	if c.authorize != nil {
		c.authorize(req)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("GET request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return Response{}, fmt.Errorf("%w: HTTP %d", ErrRedirect, resp.StatusCode)
	}
	if resp.ContentLength > c.maxBody {
		return Response{}, ErrResponseTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return Response{}, fmt.Errorf("reading GET response failed: %w", err)
	}
	if int64(len(body)) > c.maxBody {
		return Response{}, ErrResponseTooLarge
	}
	return Response{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

func checkAPIPath(p string) error {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return errors.New("invalid API path")
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~/:", r)) {
			return errors.New("invalid API path")
		}
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." {
			return errors.New("invalid API path")
		}
	}
	return nil
}
