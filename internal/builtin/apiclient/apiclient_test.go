package apiclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The child sees the test user's files as root-owned without host privileges.
func inRootNamespace(t *testing.T) bool {
	t.Helper()
	if os.Geteuid() == 0 {
		return true
	}
	cmd := exec.Command("unshare", "-Ur", os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("root user-namespace test: %v\n%s", err, out)
	}
	t.Log(string(out))
	return false
}

func writeFile(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func credentialFile(t *testing.T, content string) string {
	t.Helper()
	return writeFile(t, "credential.json", content, 0600)
}

// echo reports the request line and Authorization header.
func echo(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(r.Method + " " + r.URL.RequestURI() + "\nauth=" + r.Header.Get("Authorization")))
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "apiclient test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca testCA) serve(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestGetBuildsPathAndQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(echo))
	defer srv.Close()
	for _, tc := range []struct{ base, want string }{
		{srv.URL, "GET /api/v1/query?query=up&step=15s"},
		{srv.URL + "/", "GET /api/v1/query?query=up&step=15s"},
		{srv.URL + "/prom", "GET /prom/api/v1/query?query=up&step=15s"},
		{srv.URL + "/prom/", "GET /prom/api/v1/query?query=up&step=15s"},
	} {
		c := newClient(t, Config{Address: tc.base})
		r, err := c.Get(context.Background(), "/api/v1/query", url.Values{"query": {"up"}, "step": {"15s"}})
		if err != nil || r.StatusCode != 200 || !strings.HasPrefix(string(r.Body), tc.want+"\n") {
			t.Fatalf("%s: %+v %v", tc.base, r, err)
		}
	}
	c := newClient(t, Config{Address: srv.URL})
	r, err := c.Get(context.Background(), "/api/v1/query", url.Values{"query": {`sum(rate(x{a="b c"}[5m])) & y`}})
	if err != nil || !strings.Contains(string(r.Body), "query=sum%28rate%28x%7Ba%3D%22b+c%22%7D%5B5m%5D%29%29+%26+y\n") {
		t.Fatalf("query encoding: %q %v", r.Body, err)
	}
	r, err = c.Get(context.Background(), "/api/v1/labels", nil)
	if err != nil || !strings.HasPrefix(string(r.Body), "GET /api/v1/labels\n") {
		t.Fatalf("no query: %q %v", r.Body, err)
	}
}

func TestGetRejectsBadAPIPath(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	c := newClient(t, Config{Address: srv.URL + "/prom"})
	for _, p := range []string{"", "api/v1/query", "/api/v1/query?x=1", "/api/../admin", "/api/./x", "/api/v1/x#f", "/api/%2e%2e/x", "/api\\x", "/api/\n", "//evil.example/x", "/api/v1/label/a b/values"} {
		if _, err := c.Get(context.Background(), p, nil); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("rejected paths reached the server %d times", hits.Load())
	}
}

func TestAuthHeaders(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	srv := httptest.NewServer(http.HandlerFunc(echo))
	defer srv.Close()
	for _, tc := range []struct{ name, content, want string }{
		{"none", "", "auth="},
		{"bearer", `{"bearer_token":"tok-123"}`, "auth=Bearer tok-123"},
		{"basic", `{"username":"alice","password":"s3cret"}`, "auth=Basic YWxpY2U6czNjcmV0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Address: srv.URL}
			if tc.content != "" {
				cfg.Credential = credentialFile(t, tc.content)
			}
			r, err := newClient(t, cfg).Get(context.Background(), "/x", nil)
			if err != nil || !strings.HasSuffix(string(r.Body), tc.want) {
				t.Fatalf("%q %v", r.Body, err)
			}
		})
	}
}

func TestStatusCodesAreNotErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"error"}`))
	}))
	defer srv.Close()
	r, err := newClient(t, Config{Address: srv.URL}).Get(context.Background(), "/x", nil)
	if err != nil || r.StatusCode != 400 || string(r.Body) != `{"status":"error"}` || r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var target atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { target.Add(1) }))
	defer other.Close()
	for _, code := range []int{301, 302, 303, 307, 308} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/landed", code)
		}))
		r, err := newClient(t, Config{Address: srv.URL}).Get(context.Background(), "/x", nil)
		srv.Close()
		if !errors.Is(err, ErrRedirect) || r.Body != nil {
			t.Fatalf("code %d: %+v %v", code, r, err)
		}
		if strings.Contains(err.Error(), other.URL) {
			t.Fatalf("error leaks Location: %v", err)
		}
	}
	if target.Load() != 0 {
		t.Fatalf("redirect target was requested %d times", target.Load())
	}
}

func TestProxyEnvironmentIsIgnored(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxied.Add(1) }))
	defer proxy.Close()
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"} {
		t.Setenv(name, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	srv := httptest.NewServer(http.HandlerFunc(echo))
	defer srv.Close()
	c := newClient(t, Config{Address: srv.URL})
	// ProxyFromEnvironment never proxies loopback destinations, so the
	// behavior check below cannot detect a regression by itself.
	if c.transport.Proxy != nil {
		t.Fatal("transport must not consult proxy environment variables")
	}
	if _, err := c.Get(context.Background(), "/x", nil); err != nil || proxied.Load() != 0 {
		t.Fatalf("proxied=%d err=%v", proxied.Load(), err)
	}
}

func TestResponseBodyLimit(t *testing.T) {
	const limit = 1024
	for _, tc := range []struct {
		name   string
		size   int
		length bool
		flush  bool
		ok     bool
	}{
		{"exact", limit, true, false, true},
		{"exact-chunked", limit, false, true, true},
		{"over-by-one", limit + 1, true, false, false},
		{"over-by-one-chunked", limit + 1, false, true, false},
		{"far-over-chunked", 64 * limit, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := []byte(strings.Repeat("a", tc.size))
				if tc.length {
					w.Header().Set("Content-Length", strconv.Itoa(tc.size))
				}
				if tc.flush {
					_, _ = w.Write(body[:1])
					w.(http.Flusher).Flush()
					body = body[1:]
				}
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			r, err := newClient(t, Config{Address: srv.URL, MaxResponseBytes: limit}).Get(context.Background(), "/x", nil)
			if tc.ok {
				if err != nil || len(r.Body) != tc.size {
					t.Fatalf("len=%d err=%v", len(r.Body), err)
				}
				return
			}
			if !errors.Is(err, ErrResponseTooLarge) || len(r.Body) != 0 {
				t.Fatalf("len=%d err=%v", len(r.Body), err)
			}
		})
	}
}

func TestResponseHeaderLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Big", strings.Repeat("a", 70<<10))
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	if r, err := newClient(t, Config{Address: srv.URL}).Get(context.Background(), "/x", nil); err == nil {
		t.Fatalf("oversized response header accepted: %+v", r)
	}
}

func TestCompressionIsNotNegotiated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "" {
			t.Errorf("Accept-Encoding = %q", r.Header.Get("Accept-Encoding"))
		}
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write([]byte("\x1f\x8bnot-decoded"))
	}))
	defer srv.Close()
	r, err := newClient(t, Config{Address: srv.URL}).Get(context.Background(), "/x", nil)
	if err != nil || !strings.HasPrefix(string(r.Body), "\x1f\x8b") {
		t.Fatalf("%q %v", r.Body, err)
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	start := time.Now()
	_, err := newClient(t, Config{Address: srv.URL, Timeout: 100 * time.Millisecond}).Get(context.Background(), "/x", nil)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("elapsed %v err %v", time.Since(start), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newClient(t, Config{Address: srv.URL}).Get(ctx, "/x", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
}

func TestTLS(t *testing.T) {
	ca, other := newCA(t), newCA(t)
	srv := ca.serve(t, http.HandlerFunc(echo))
	caFile := writeFile(t, "ca.pem", string(ca.pem), 0644)
	r, err := newClient(t, Config{Address: srv.URL + "/prom", CAFile: caFile}).Get(context.Background(), "/x", nil)
	if err != nil || !strings.HasPrefix(string(r.Body), "GET /prom/x\n") {
		t.Fatalf("trusted CA: %q %v", r.Body, err)
	}
	var unknown x509.UnknownAuthorityError
	if _, err := newClient(t, Config{Address: srv.URL}).Get(context.Background(), "/x", nil); !errors.As(err, &unknown) {
		t.Fatalf("no ca_file must fail verification: %v", err)
	}
	wrong := writeFile(t, "other.pem", string(other.pem), 0644)
	if _, err := newClient(t, Config{Address: srv.URL, CAFile: wrong}).Get(context.Background(), "/x", nil); !errors.As(err, &unknown) {
		t.Fatalf("untrusted CA must fail verification: %v", err)
	}
}

func TestCAFileRejections(t *testing.T) {
	ca := newCA(t)
	dir := t.TempDir()
	for name, cfg := range map[string]Config{
		"relative":  {Address: "https://127.0.0.1:1", CAFile: "ca.pem"},
		"missing":   {Address: "https://127.0.0.1:1", CAFile: filepath.Join(dir, "absent.pem")},
		"directory": {Address: "https://127.0.0.1:1", CAFile: dir},
		"not-pem":   {Address: "https://127.0.0.1:1", CAFile: writeFile(t, "bad.pem", "not a certificate", 0644)},
		"empty":     {Address: "https://127.0.0.1:1", CAFile: writeFile(t, "empty.pem", "", 0644)},
		"http-url":  {Address: "http://127.0.0.1:1", CAFile: writeFile(t, "ca.pem", string(ca.pem), 0644)},
		"oversize":  {Address: "https://127.0.0.1:1", CAFile: writeFile(t, "big.pem", string(ca.pem)+strings.Repeat("#", 2<<20), 0644)},
	} {
		if c, err := New(cfg); err == nil {
			c.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAddressValidation(t *testing.T) {
	for _, address := range []string{
		"http://127.0.0.1:9090", "https://prometheus.example.com", "https://example.com/", "https://example.com/prom", "http://example.com:9090/a/b/",
		"http://[::1]:9090", "HTTP://Example.COM:80/x",
	} {
		if err := (Config{Address: address}).Validate(); err != nil {
			t.Errorf("%q rejected: %v", address, err)
		}
	}
	for _, address := range []string{
		"", "127.0.0.1:9090", "ftp://example.com", "file:///etc/passwd", "unix:///run/x.sock", "http://", "http://:9090",
		"http://user@example.com", "http://user:pass@example.com", "http://example.com?x=1", "http://example.com/?", "http://example.com/p?x=1",
		"http://example.com#frag", "http://example.com/../x", "http://example.com/a/./b", "http://example.com/a%2fb", "http://example.com/a b",
		"http://example.com:0", "http://example.com:99999", "http://example.com/a\\b", "http://example.com/a//b", "http://example.com/a\nb",
	} {
		if err := (Config{Address: address}).Validate(); err == nil {
			t.Errorf("%q accepted", address)
		}
		if c, err := New(Config{Address: address}); err == nil {
			c.Close()
			t.Errorf("New(%q) accepted", address)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	good := Config{Address: "https://127.0.0.1:9090", Credential: "/etc/allowops/credentials/p.json", CAFile: "/etc/allowops/ca.pem", Timeout: time.Second, MaxResponseBytes: 1}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"relative credential": func(c *Config) { c.Credential = "p.json" },
		"relative ca_file":    func(c *Config) { c.CAFile = "ca.pem" },
		"negative timeout":    func(c *Config) { c.Timeout = -1 },
		"negative max bytes":  func(c *Config) { c.MaxResponseBytes = -1 },
	} {
		c := good
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestTighten(t *testing.T) {
	for _, tc := range []struct {
		value, want int
		ok          bool
	}{
		{0, 100, true}, {1, 1, true}, {100, 100, true}, {1000, 1000, true}, {1001, 0, false}, {-1, 0, false},
	} {
		got, err := Tighten("max_points", tc.value, 100, 1000)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("Tighten(%d) = %d, %v", tc.value, got, err)
		}
	}
	d, err := Tighten("timeout", 5*time.Second, 10*time.Second, 30*time.Second)
	if err != nil || d != 5*time.Second {
		t.Fatalf("%v %v", d, err)
	}
	if _, err := Tighten("timeout", 31*time.Second, 10*time.Second, 30*time.Second); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("over limit: %v", err)
	}
	if n, err := Tighten[int64]("max_response_bytes", 0, 4<<20, 16<<20); err != nil || n != 4<<20 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestCredentials(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	const secret = "TOP-SECRET-VALUE"
	for _, tc := range []struct {
		name    string
		content string
		mutate  func(path string) string
	}{
		{"missing", "", func(p string) string { return p + ".absent" }},
		{"wide", `{"bearer_token":"` + secret + `"}`, func(p string) string { _ = os.Chmod(p, 0644); return p }},
		{"group-readable", `{"bearer_token":"` + secret + `"}`, func(p string) string { _ = os.Chmod(p, 0640); return p }},
		{"read-only", `{"bearer_token":"` + secret + `"}`, func(p string) string { _ = os.Chmod(p, 0400); return p }},
		{"symlink", `{"bearer_token":"` + secret + `"}`, func(p string) string { _ = os.Symlink(p, p+".link"); return p + ".link" }},
		{"directory", "", func(p string) string { return filepath.Dir(p) }},
		{"relative", `{"bearer_token":"` + secret + `"}`, func(p string) string { return "credential.json" }},
		{"empty", "", nil},
		{"invalid-json", "invalid " + secret, nil},
		{"null", "null", nil},
		{"array", `["` + secret + `"]`, nil},
		{"string", `"` + secret + `"`, nil},
		{"two-objects", `{"bearer_token":"` + secret + `"} {"bearer_token":"x"}`, nil},
		{"trailing-garbage", `{"bearer_token":"` + secret + `"} ` + secret, nil},
		{"unknown-field", `{"bearer_token":"` + secret + `","address":"evil"}`, nil},
		{"wrong-type", `{"bearer_token":["` + secret + `"]}`, nil},
		{"oversize", `{"bearer_token":"` + strings.Repeat("x", 16385) + `"}`, nil},
		{"both-methods", `{"bearer_token":"` + secret + `","username":"u","password":"p"}`, nil},
		{"bearer-and-username", `{"bearer_token":"` + secret + `","username":"u"}`, nil},
		{"bearer-and-password", `{"bearer_token":"x","password":"` + secret + `"}`, nil},
		{"neither", `{}`, nil},
		{"empty-bearer", `{"bearer_token":""}`, nil},
		{"username-only", `{"username":"u"}`, nil},
		{"password-only", `{"password":"` + secret + `"}`, nil},
		{"empty-username", `{"username":"","password":"` + secret + `"}`, nil},
		{"empty-password", `{"username":"u","password":""}`, nil},
		{"colon-in-username", `{"username":"a:b","password":"` + secret + `"}`, nil},
		{"newline-in-token", `{"bearer_token":"a\nX-Injected: ` + secret + `"}`, nil},
		{"space-in-token", `{"bearer_token":"a b ` + secret + `"}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := credentialFile(t, tc.content)
			if tc.mutate != nil {
				path = tc.mutate(path)
			}
			c, err := New(Config{Address: "http://127.0.0.1:1", Credential: path})
			if err == nil {
				c.Close()
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaks credential content: %v", err)
			}
		})
	}
}

func TestCredentialAcceptedForms(t *testing.T) {
	if !inRootNamespace(t) {
		return
	}
	for name, content := range map[string]string{
		"bearer":      `{"bearer_token":"abc.DEF-123_~+/="}`,
		"basic":       `{"username":"alice","password":"p@ss word"}`,
		"surrounding": "\n  {\"bearer_token\":\"abc\"}\n\n",
	} {
		c, err := New(Config{Address: "http://127.0.0.1:1", Credential: credentialFile(t, content)})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		c.Close()
	}
}

func TestCredentialOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		return
	}
	path := credentialFile(t, `{"bearer_token":"abc"}`)
	c, err := New(Config{Address: "http://127.0.0.1:1", Credential: path})
	if err == nil || !strings.Contains(err.Error(), "root") {
		if c != nil {
			c.Close()
		}
		t.Fatalf("non-root owner: %v", err)
	}
}
