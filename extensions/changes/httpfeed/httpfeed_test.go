package httpfeed

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liubing0806/allowops/plugin/changes"
	"github.com/liubing0806/allowops/plugin/plugintest"
)

const changeRows = `[
  {"at":"2026-01-01T00:00:00.123Z","kind":"deploy","service":"web","summary":"first","actor":"alice","ref":"build:1"},
  {"at":"2025-12-31T23:59:59Z","kind":"deploy","summary":"too early"},
  {"at":"2026-01-02T00:00:00Z","kind":"deploy","service":"web","summary":"latest","ref":"build:2"},
  {"at":"2026-01-02T00:00:01Z","kind":"deploy","summary":"too late"}
]`

func feedServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		query := r.URL.Query()
		limit, limitErr := strconv.Atoi(query.Get("limit"))
		_, fromErr := time.Parse(time.RFC3339, query.Get("from"))
		_, toErr := time.Parse(time.RFC3339, query.Get("to"))
		if r.Method != http.MethodGet || len(query) != 3 || limitErr != nil || limit < 1 || fromErr != nil || toErr != nil ||
			r.Header.Get("Accept") != "application/json" || r.Header.Get("X-Feed-Token") != "Token fixture-token" {
			t.Errorf("unexpected feed request: %s %s", r.Method, r.URL)
		}
		switch r.URL.Path {
		case "/changes":
			_, _ = fmt.Fprintf(w, `{"changes":%s,"has_more":false}`, changeRows)
		case "/more":
			_, _ = io.WriteString(w, `{"changes":[],"has_more":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, &requests
}

func TestListerContract(t *testing.T) {
	server, _ := feedServer(t)
	config := fmt.Sprintf("url: %s/changes\ncredential_ref: feed\nauth_header: X-Feed-Token\nauth_scheme: Token\ncache_ttl: 1m\n", server.URL)
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	plugintest.RunListerContract(t, Module{}, config, plugintest.WithNow(now), plugintest.WithHTTPServer(server),
		plugintest.WithCredential("feed", []byte("fixture-token\n")), plugintest.WithExpectHTTP())
}

func TestListHTTPFeedChanges(t *testing.T) {
	server, requests := feedServer(t)
	host := plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithCredential("feed", []byte("fixture-token")))
	m := Module{URL: server.URL + "/changes?services=private&ignored=1", CredentialRef: "feed", AuthHeader: "X-Feed-Token", AuthScheme: "Token"}
	if err := m.Provision(t.Context(), host); err != nil {
		t.Fatal(err)
	}
	if m.CacheTTL != 30*time.Second || m.MaxResponseBytes != 4<<20 {
		t.Fatalf("defaults: ttl = %v, max bytes = %d", m.CacheTTL, m.MaxResponseBytes)
	}
	to := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	from := to.Add(-24*time.Hour + 123*time.Millisecond)
	q := changes.Query{From: from, To: to, MaxItems: 2}
	want := []changes.Change{
		{At: to, Kind: "deploy", Service: "web", Summary: "latest", Ref: "build:2"},
		{At: from, Kind: "deploy", Service: "web", Summary: "first", Actor: "alice", Ref: "build:1"},
	}
	for range 2 {
		result, err := m.List(t.Context(), q)
		if err != nil || result.HasMore || !reflect.DeepEqual(result.Changes, want) || requests.Load() != 1 {
			t.Fatalf("result = %+v, error = %v, requests = %d, want %+v", result, err, requests.Load(), want)
		}
		result.Changes[0].Summary = "mutated"
	}
	q.MaxItems = 1
	result, err := m.List(t.Context(), q)
	if err != nil || !result.HasMore || !reflect.DeepEqual(result.Changes, want[:1]) || requests.Load() != 2 {
		t.Fatalf("limited result = %+v, error = %v, requests = %d", result, err, requests.Load())
	}
	m.URL = server.URL + "/more"
	if err := m.Provision(t.Context(), plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithCredential("feed", []byte("fixture-token")))); err != nil {
		t.Fatal(err)
	}
	result, err = m.List(t.Context(), q)
	if err != nil || !result.HasMore || len(result.Changes) != 0 || requests.Load() != 3 {
		t.Fatalf("remote has_more result = %+v, error = %v, requests = %d", result, err, requests.Load())
	}
}

func TestValidateHTTPFeedConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Module)
	}{
		{"missing URL", func(m *Module) { m.URL = "" }},
		{"credential over plain HTTP", func(m *Module) { m.CredentialRef = "token" }},
		{"credentials in URL", func(m *Module) { m.URL = "https://user:password@example.test" }},
		{"reserved Accept", func(m *Module) { m.AuthHeader = "aCcEpT" }},
		{"reserved Host", func(m *Module) { m.AuthHeader = "Host" }},
		{"reserved Content-Length", func(m *Module) { m.AuthHeader = "Content-length" }},
		{"reserved Transfer-Encoding", func(m *Module) { m.AuthHeader = "transfer-encoding" }},
		{"malformed header", func(m *Module) { m.AuthHeader = "Authorization\r\nX-Other" }},
		{"malformed scheme", func(m *Module) { m.AuthScheme = "Token\n" }},
		{"cache TTL too long", func(m *Module) { m.CacheTTL += time.Second }},
		{"response limit too high", func(m *Module) { m.MaxResponseBytes++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Module{URL: "http://feed.example", CacheTTL: 10 * time.Minute, MaxResponseBytes: 16 << 20}
			if err := m.Validate(); err != nil {
				t.Fatal(err)
			}
			tc.edit(&m)
			if err := m.Validate(); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}

func TestHTTPFeedRejectsInvalidResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status           int
		maxBytes         int64
	}{
		{"unknown member", `{"changes":[],"has_more":false,"secret":"fixture-secret"}`, "invalid change feed response", 200, 0},
		{"unknown change member", `{"changes":[{"secret":"fixture-secret"}],"has_more":false}`, "invalid change feed response", 200, 0},
		{"duplicate member", `{"changes":[],"has_more":true,"has_more":false}`, "invalid change feed response", 200, 0},
		{"trailing JSON", `{"changes":[],"has_more":false}{}`, "invalid change feed response", 200, 0},
		{"missing has_more", `{"changes":[]}`, "invalid change feed response", 200, 0},
		{"null changes", `{"changes":null,"has_more":false}`, "invalid change feed response", 200, 0},
		{"invalid has_more", `{"changes":[],"has_more":"true"}`, "invalid change feed response", 200, 0},
		{"invalid timestamp", `{"changes":[{"at":"fixture-secret"}],"has_more":false}`, "invalid change feed response", 200, 0},
		{"HTTP error", "fixture-secret", "change feed returned an unsuccessful HTTP status", 502, 0},
		{"body limit", `{"changes":[],"has_more":false}`, "change feed response exceeds max_response_bytes", 200, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer fixture-secret" {
					t.Error("default authentication header missing")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			m := Module{URL: server.URL, CredentialRef: "feed", MaxResponseBytes: tc.maxBytes}
			host := plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithCredential("feed", []byte("fixture-secret")))
			if err := m.Provision(t.Context(), host); err != nil {
				t.Fatal(err)
			}
			if _, err := m.List(t.Context(), changes.Query{}); err == nil || err.Error() != tc.want || strings.Contains(err.Error(), "fixture-secret") {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestHTTPFeedCredentialAndNetworkErrors(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		opts       []plugintest.HostOption
	}{
		{"missing credential", "change feed credential unavailable", nil},
		{"invalid credential", "change feed credential unavailable", []plugintest.HostOption{plugintest.WithCredential("feed", []byte("fixture\r\nsecret"))}},
		{"network blocked", "change feed request failed", []plugintest.HostOption{plugintest.WithCredential("feed", []byte("fixture-secret"))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Module{URL: "https://feed.example", CredentialRef: "feed"}
			if err := m.Provision(t.Context(), plugintest.NewHost(t, tc.opts...)); err != nil {
				t.Fatal(err)
			}
			if _, err := m.List(t.Context(), changes.Query{}); err == nil || err.Error() != tc.want {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
