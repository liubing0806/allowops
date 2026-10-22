package httpget

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("X-Probe") != "fixed" {
			t.Errorf("request %s headers %v", r.Method, r.Header)
		}
		if len(r.Header) != 1 {
			t.Errorf("unconfigured request headers: %v", r.Header)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Set-Cookie", "secret")
		w.WriteHeader(201)
		_, _ = w.Write([]byte("hello"))
	}))
	defer s.Close()
	r, err := Run(context.Background(), Config{AllowedPrefixes: []string{s.URL + "/api"}, Headers: map[string]string{"X-Probe": "fixed"}}, Params{URL: s.URL + "/api/items?q=1"})
	if err != nil || r.StatusCode != 201 || r.Headers["Content-Type"] != "text/plain" || r.Headers["Set-Cookie"] != "" || r.Body != "hello" || !strings.Contains(r.Stdout, "hello") || r.Truncated || r.ExitCode != 0 {
		t.Fatalf("got %#v, %v", r, err)
	}
}

func TestURLValidation(t *testing.T) {
	prefix := "http://127.0.0.1:12001/api"
	for _, raw := range []string{prefix, prefix + "/", prefix + "/items?q=1", "http://127.0.0.1:012001/api"} {
		if err := ValidateURL(raw, []string{prefix}); err != nil {
			t.Errorf("rejected %q: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://127.0.0.1:12001@evil/api", "http://user:pass@127.0.0.1:12001/api", "http://127.0.0.1:120011/api",
		"http://127.0.0.1:12001.evil/api", "http://127.0.0.1:12002/api", "http://127.0.0.1:012002/api", "http://127.0.0.2:12001/api",
		"https://127.0.0.1:12001/api", "//127.0.0.1:12001/api", "http://127.0.0.1:12001/api../",
		"http://127.0.0.1:12001/apix", prefix + "/../secret", prefix + "/%2e%2e/secret", prefix + "/%252e%252e/secret",
		prefix + "%2f..%2fsecret", prefix + "/a%5cb", prefix + "/a\\b", prefix + "#fragment", prefix + "/\nsecret", "-test", "",
	} {
		t.Run(raw, func(t *testing.T) {
			if ValidateURL(raw, []string{prefix}) == nil {
				t.Fatalf("accepted %q", raw)
			}
		})
	}
	if ValidateURL(prefix, nil) == nil {
		t.Fatal("accepted empty allowlist")
	}
	if ValidateURL("http://LOCALHOST:80/api", []string{"http://localhost/api"}) != nil {
		t.Fatal("rejected equivalent default port and hostname case")
	}
	if ValidateURL("http://[::1]:12001/api/x", []string{"http://[::1]:12001/api"}) != nil {
		t.Fatal("rejected IPv6")
	}
}

func TestRejectBeforeRequest(t *testing.T) {
	var requests atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer s.Close()
	for _, raw := range []string{s.URL + "/api../", s.URL + "/api/../secret", strings.Replace(s.URL, "http://", "http://user@", 1) + "/api"} {
		r, err := Run(context.Background(), Config{AllowedPrefixes: []string{s.URL + "/api"}}, Params{URL: raw})
		if err == nil || r.ExitCode == 0 {
			t.Fatalf("accepted %q: %#v %v", raw, r, err)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("requests=%d", requests.Load())
	}
}

func TestRedirectAndStatus(t *testing.T) {
	var followed atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1) }))
	defer target.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, target.URL, http.StatusFound)
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer s.Close()
	r, err := Run(context.Background(), Config{AllowedPrefixes: []string{s.URL}}, Params{URL: s.URL + "/redirect"})
	if err != nil || r.StatusCode != 302 || r.ExitCode != 0 || followed.Load() != 0 {
		t.Fatalf("redirect %#v %v, followed %d", r, err, followed.Load())
	}
	r, err = Run(context.Background(), Config{AllowedPrefixes: []string{s.URL}}, Params{URL: s.URL + "/error"})
	if err != nil || r.StatusCode != 503 || r.ExitCode != 0 {
		t.Fatalf("status %#v %v", r, err)
	}
}

func TestLimitsAndTimeout(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("x", 1<<20)))
	}))
	defer s.Close()
	r, err := Run(context.Background(), Config{AllowedPrefixes: []string{s.URL}, MaxResponseBytes: 128}, Params{URL: s.URL})
	if err != nil || !r.Truncated || r.Body != "" || strings.Contains(r.Stdout, "xxx") {
		t.Fatalf("limit %#v %v", r, err)
	}
	r, err = Run(context.Background(), Config{AllowedPrefixes: []string{s.URL}, Timeout: 20 * time.Millisecond}, Params{URL: s.URL + "/slow"})
	if err == nil || r.ExitCode == 0 {
		t.Fatalf("timeout %#v %v", r, err)
	}
}

func TestResponseLimitIsIndependentOfOutput(t *testing.T) {
	begin, end := "-----BEGIN PRIVATE KEY-----\n", "\n-----END PRIVATE KEY-----"
	body := begin + strings.Repeat("x", (64<<10)-len(begin)-len(end)) + end
	if len(body) != 64<<10 {
		t.Fatalf("fixture size=%d", len(body))
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer s.Close()
	r, err := Run(context.Background(), Config{AllowedPrefixes: []string{s.URL}}, Params{URL: s.URL})
	if err != nil || r.Body != body || !strings.HasSuffix(r.Stdout, body) || r.Truncated || len(r.Stdout) <= 64<<10 {
		t.Fatalf("raw response: body=%d want=%d stdout=%d truncated=%v error=%v", len(r.Body), len(body), len(r.Stdout), r.Truncated, err)
	}
}

func TestConfigAndSchema(t *testing.T) {
	for _, cfg := range []Config{{}, {AllowedPrefixes: []string{"file:///tmp"}}, {AllowedPrefixes: []string{"http://localhost/api/../x"}}, {AllowedPrefixes: []string{"http://localhost/api?q=1"}}, {AllowedPrefixes: []string{"http://localhost"}, Headers: map[string]string{"Bad\nKey": "value"}}, {AllowedPrefixes: []string{"http://localhost"}, Headers: map[string]string{"X-Test": "value\nInjected: x"}}, {AllowedPrefixes: []string{"http://localhost"}, MaxResponseBytes: -1}} {
		if cfg.Validate() == nil {
			t.Fatalf("accepted %#v", cfg)
		}
	}
	s := ParamsSchema()
	if s["$schema"] != "https://json-schema.org/draft/2020-12/schema" || s["additionalProperties"] != false {
		t.Fatalf("schema %#v", s)
	}
}

func FuzzURL(f *testing.F) {
	for _, s := range []string{"http://127.0.0.1:12001/api", "http://127.0.0.1:12001@evil/api", "http://127.0.0.1:12001/api/%2e%2e", "http://127.0.0.1:12001/api?x=1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		err := ValidateURL(raw, []string{"http://127.0.0.1:12001/api"})
		if err == nil {
			u, parseErr := url.Parse(raw)
			if parseErr != nil {
				t.Fatalf("allowed invalid URL %q: %v", raw, parseErr)
			}
			// Compare numeric ports independently of the production canonical parser.
			port, portErr := strconv.Atoi(u.Port())
			if portErr != nil || u.User != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || port != 12001 || !(u.Path == "/api" || strings.HasPrefix(u.Path, "/api/")) {
				t.Fatalf("allowed unexpected URL: %q", raw)
			}
		}
	})
}

func TestCanonicalRequestURL(t *testing.T) {
	seen := make(chan string, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.Host + r.URL.RequestURI(); fmt.Fprint(w, "ok") }))
	defer s.Close()
	address := strings.TrimPrefix(s.URL, "http://127.0.0.1:")
	for _, tc := range []struct{ name, port string }{
		{"hostname case", address},
		{"zero-padded port", "0" + address},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "http://LOCALHOST:" + tc.port + "/api?q=x"
			prefix := "http://localhost:" + address + "/api"
			r, err := Run(context.Background(), Config{AllowedPrefixes: []string{prefix}}, Params{URL: raw})
			if err != nil || r.ExitCode != 0 {
				t.Fatalf("request: %+v %v", r, err)
			}
			if got := <-seen; got != "localhost:"+address+"/api?q=x" {
				t.Fatalf("actual request target=%q; want canonical host, port and path", got)
			}
		})
	}
}
