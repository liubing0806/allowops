package pluginhost

import (
	"context"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEgressEndpointValidation(t *testing.T) {
	p, err := egressConfig(Config{Egress: []string{"https://EXAMPLE.org:0443/api", "http://[::1]"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.endpoints[0]; got.host != "example.org" || got.port != "443" || got.pathPrefix != "/api" {
		t.Fatal(got)
	}
	if got := p.endpoints[1]; got.host != "::1" || got.port != "80" || !got.isIPLiteral {
		t.Fatal(got)
	}
	for _, addr := range []string{
		"https://example.org.", "https://*.example.org", "https://example.org?", "https://example.org?a=b",
		"https://example.org:65536", "https://user:opaque@x.example", "https://example.org/api/%2e%2e",
		"https://example.org/api%2fsibling", "https://[fe80::1%25eth0]",
	} {
		if _, err := egressConfig(Config{Egress: []string{addr}}, false); !errors.Is(err, errEgress) {
			t.Errorf("endpoint validation accepted %q: %v", addr, err)
		}
	}
	for _, cfg := range []Config{
		{CAFile: "/absolute", Egress: []string{"http://example.org"}},
		{CAFile: "relative", Egress: []string{"https://example.org"}},
	} {
		if _, err := egressConfig(cfg, false); !errors.Is(err, errCA) {
			t.Errorf("CA configuration accepted: %v", err)
		}
	}
}

func TestEgressIPPolicy(t *testing.T) {
	for _, raw := range []string{
		"0.0.0.0", "::", "224.0.0.1", "ff02::1", "169.254.169.254", "169.254.170.2", "169.254.169.253",
		"169.254.169.123", "fe80::1", "100.100.100.200", "fd00:ec2::254", "::ffff:169.254.169.254",
		"64:ff9b::169.254.169.254", "64:ff9b:1::10.0.0.1", "2002:7f00:0001::", "2001::1", "::10.0.0.1",
	} {
		if allowedIP(netip.MustParseAddr(raw), true, true, false) {
			t.Errorf("blocked address accepted: %s", raw)
		}
	}
	for _, raw := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		ip := netip.MustParseAddr(raw)
		if allowedIP(ip, false, true, false) || !allowedIP(ip, true, false, false) {
			t.Errorf("bad loopback handling: %s", raw)
		}
	}
	for _, raw := range []string{"10.0.0.1", "fd00::1", "100.64.0.1", "::ffff:10.0.0.1"} {
		ip := netip.MustParseAddr(raw)
		if allowedIP(ip, false, false, false) || !allowedIP(ip, true, false, false) || !allowedIP(ip, false, true, false) {
			t.Errorf("bad private handling: %s", raw)
		}
	}
	for _, raw := range []string{"93.184.216.34", "2606:4700::1111"} {
		if !allowedIP(netip.MustParseAddr(raw), false, false, false) {
			t.Errorf("public address denied: %s", raw)
		}
	}
}

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (r resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return r(ctx, network, host)
}

func TestEgressDialLocksResolvedIP(t *testing.T) {
	p, err := egressConfig(Config{Egress: []string{"https://plugin.example", "http://[::1]", "http://127.0.0.1"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	var lookups int
	resolve := resolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		lookups++
		if network != "ip" || host != "plugin.example" {
			t.Fatalf("lookup: %s %s", network, host)
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::ffff:93.184.216.34")}, nil
	})
	var addresses []string
	dial := p.dialContext(resolve, func(_ context.Context, _, addr string) (net.Conn, error) {
		addresses = append(addresses, addr)
		a, b := net.Pipe()
		b.Close()
		return a, nil
	})
	for _, target := range []string{"plugin.example:443", "[::1]:80", "127.0.0.1:80"} {
		c, err := dial(t.Context(), "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if lookups != 1 || !reflect.DeepEqual(addresses, []string{"93.184.216.34:443", "[::1]:80", "127.0.0.1:80"}) {
		t.Fatalf("lookups=%d, dials=%v", lookups, addresses)
	}
	if _, err := dial(t.Context(), "tcp", "plugin.example:80"); !errors.Is(err, errEgress) || lookups != 1 {
		t.Fatalf("unlisted port reached resolver: %v", err)
	}
}

func TestEgressRedirectsAndTLS(t *testing.T) {
	type request struct {
		path   string
		header http.Header
	}
	requests := make(chan request, 32)
	record := func(r *http.Request) { requests <- request{r.URL.Path, r.Header.Clone()} }
	var plaintextCalls atomic.Int32
	plaintext := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { plaintextCalls.Add(1) }))
	defer plaintext.Close()
	var a, b *httptest.Server
	a = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		switch r.URL.Path {
		case "/api/start":
			http.Redirect(w, r, b.URL+"/next", http.StatusFound)
		case "/api/downgrade":
			http.Redirect(w, r, plaintext.URL, http.StatusFound)
		case "/api/local":
			http.Redirect(w, r, "/api/done", http.StatusFound)
		}
	}))
	defer a.Close()
	b = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		http.Redirect(w, r, a.URL+"/api/done", http.StatusFound)
	}))
	defer b.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Egress: []string{a.URL + "/api", b.URL, plaintext.URL}, Timeout: time.Second}
	untrusted, err := newEgressClient(cfg, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := untrusted.Get(a.URL + "/api/local"); err == nil {
		resp.Body.Close()
		t.Fatal("accepted untrusted server")
	}
	untrusted.CloseIdleConnections()
	cfg.CAFile = ca
	for _, tc := range []struct {
		name, path string
		cross      bool
		want       []string
	}{
		{"default", "/api/start", false, []string{"/api/start"}},
		{"cross allowed", "/api/start", true, []string{"/api/start", "/next", "/api/done"}},
		{"local", "/api/local", false, []string{"/api/local", "/api/done"}},
		{"HTTPS downgrade", "/api/downgrade", true, []string{"/api/downgrade"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg.AllowCrossOriginRedirects = tc.cross
			client, err := newEgressClient(cfg, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			base := client.Transport.(egressTransport).base
			if base.Proxy != nil || !base.DisableCompression || base.MaxResponseHeaderBytes != 64<<10 || base.TLSClientConfig.InsecureSkipVerify {
				t.Fatal("transport hardening missing")
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, a.URL+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			init := http.Header{"Accept": {"private"}, "Authorization": {"Bearer private"}, "Cookie": {"session=private"}, "X-Api-Auth": {"private"}}
			req.Header = init.Clone()
			resp, err := client.Do(req)
			if resp != nil {
				resp.Body.Close()
			}
			if (err == nil) != (len(tc.want) > 1) {
				t.Fatalf("redirect error = %v", err)
			}
			for i, path := range tc.want {
				select {
				case got := <-requests:
					if got.path != path {
						t.Fatalf("path %q, want %q", got.path, path)
					}
					if i > 0 && tc.cross {
						got.header.Del("User-Agent") // implicit transport header
						if !reflect.DeepEqual(got.header, http.Header{"Accept": {"*/*"}}) {
							t.Fatalf("cross-hop headers: %v", got.header)
						}
					} else {
						for name, value := range init {
							if !reflect.DeepEqual(got.header.Values(name), value) {
								t.Errorf("same-origin header missing: %s", name)
							}
						}
					}
				default:
					t.Fatalf("missing request for %s", path)
				}
			}
			if len(requests) != 0 || plaintextCalls.Load() != 0 {
				t.Fatal("unexpected redirect reached destination")
			}
		})
	}
}

func TestEgressBlocksMethodsPathsAndRedirectTargets(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/allowed/downgrade":
			http.Redirect(w, r, target.URL, http.StatusFound)
		case "/allowed/unlisted":
			http.Redirect(w, r, "/outside", http.StatusFound)
		case "/allowed/loop":
			http.Redirect(w, r, "/allowed/loop", http.StatusFound)
		}
	}))
	defer origin.Close()
	client, err := newEgressClient(Config{Egress: []string{origin.URL + "/allowed", target.URL}, AllowCrossOriginRedirects: true}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	for _, tc := range []struct{ method, path string }{
		{"POST", "/allowed"}, {"GET", "/allowed-elsewhere"}, {"GET", "/allowed/%2e%2e"}, {"GET", "/allowed%2fpath"},
		{"GET", "/allowed/downgrade"}, {"GET", "/allowed/unlisted"}, {"GET", "/allowed/loop"},
	} {
		req, err := http.NewRequestWithContext(t.Context(), tc.method, origin.URL+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp, err := client.Do(req); !errors.Is(err, errEgress) {
			if resp != nil {
				resp.Body.Close()
			}
			t.Errorf("%+v: %v", tc, err)
		}
	}
	if hits.Load() != 6 { // two blocked redirects and four requests through the three-hop loop
		t.Errorf("requests = %d", hits.Load())
	}
	if resp, err := client.Head(origin.URL + "/allowed"); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	denied, err := newEgressClient(Config{}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Get(origin.URL); !errors.Is(err, errEgress) {
		t.Errorf("empty policy did not deny: %v", err)
	}
}

func TestEgressCAFileBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opaque-ca-name")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 1<<20+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path, dir, dir + "/missing"} {
		if _, err := loadCA(file); !errors.Is(err, errCA) {
			t.Errorf("unexpected CA error: %v", err)
		}
	}
}
