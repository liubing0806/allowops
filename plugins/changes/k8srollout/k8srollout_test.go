package k8srollout

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liubing0806/allowops/plugin/changes"
	"github.com/liubing0806/allowops/plugin/plugintest"
)

const replicas = `{"items":[
  {"metadata":{"name":"web-current","creationTimestamp":"2026-01-02T00:00:00Z",
    "ownerReferences":[{"kind":"Deployment","name":"web","controller":true}],
    "annotations":{"deployment.kubernetes.io/revision":"4","unrelated":"annotation-secret"}},
   "spec":{"template":{"spec":{"containers":[{"image":"web:4","env":[{"value":"env-secret"}]}],
    "initContainers":[{"image":"migrate:2"}]}}}},
  {"metadata":{"name":"unowned","creationTimestamp":"2026-01-01T12:00:00Z",
    "ownerReferences":[{"kind":"Job","name":"batch"}]}},
  {"metadata":{"name":"web-future","creationTimestamp":"2026-01-02T00:00:01Z",
    "ownerReferences":[{"kind":"Deployment","name":"web"}]}}
]}`

const revisions = `{"items":[
  {"metadata":{"name":"cache-old","creationTimestamp":"2025-12-31T23:59:59Z",
    "ownerReferences":[{"kind":"StatefulSet","name":"cache"}]}},
  {"metadata":{"name":"cache-revision","creationTimestamp":"2026-01-01T00:00:00Z",
    "ownerReferences":[{"kind":"Deployment","name":"other"},
      {"kind":"StatefulSet","name":"cache","controller":true}]},
   "data":{"spec":{"template":{"spec":{"containers":[{"image":"cache:2"}]}}}}},
  {"metadata":{"name":"logger-revision","creationTimestamp":"2026-01-01T14:00:00Z",
    "ownerReferences":[{"kind":"DaemonSet","name":"logger"}]},
   "data":{"spec":{"template":{"spec":{"containers":[{"image":"logger:1"}]}}}}}
]}`

func rolloutServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Header.Get("Accept") != "application/json" || r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Errorf("unexpected Kubernetes request: %s %s", r.Method, r.URL)
		}
		switch r.URL.Path {
		case "/apis/apps/v1/namespaces/apps/replicasets":
			_, _ = io.WriteString(w, replicas)
		case "/apis/apps/v1/namespaces/apps/controllerrevisions":
			_, _ = io.WriteString(w, revisions)
		case "/apis/apps/v1/namespaces/worker/replicasets", "/apis/apps/v1/namespaces/worker/controllerrevisions":
			_, _ = io.WriteString(w, `{"items":[]}`)
		default:
			t.Errorf("unexpected Kubernetes path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, &requests
}

func TestListerContract(t *testing.T) {
	server, _ := rolloutServer(t)
	config := fmt.Sprintf("api_server: %s\ncredential_ref: kube\nnamespaces: [apps]\ncache_ttl: 1m\n", server.URL)
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	plugintest.RunListerContract(t, Module{}, config, plugintest.WithNow(now), plugintest.WithHTTPServer(server),
		plugintest.WithCredential("kube", []byte("fixture-token\n")), plugintest.WithExpectHTTP())
}

func TestListKubernetesRollouts(t *testing.T) {
	server, requests := rolloutServer(t)
	host := plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithCredential("kube", []byte("fixture-token")))
	m := Module{APIServer: server.URL, CredentialRef: "kube", Namespaces: []string{"apps", "worker"}, Cluster: "east"}
	if err := m.Provision(t.Context(), host); err != nil {
		t.Fatal(err)
	}
	if m.CacheTTL != 30*time.Second || m.MaxResponseBytes != 4<<20 {
		t.Fatalf("defaults: ttl = %v, max bytes = %d", m.CacheTTL, m.MaxResponseBytes)
	}
	to := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	from := to.Add(-24 * time.Hour)
	q := changes.Query{From: from, To: to, MaxItems: 2}
	got, err := m.List(t.Context(), q)
	want := changes.ListResult{HasMore: true, Changes: []changes.Change{
		{At: to, Kind: "rollout", Service: "apps/web", Summary: "Deployment web rollout revision 4 (images: web:4, migrate:2)", Ref: "k8s:east/apps/ReplicaSet/web-current"},
		{At: from.Add(14 * time.Hour), Kind: "rollout", Service: "apps/logger", Summary: "DaemonSet logger rollout (images: logger:1)", Ref: "k8s:east/apps/ControllerRevision/logger-revision"},
	}}
	if err != nil || !reflect.DeepEqual(got, want) || requests.Load() != 4 {
		t.Fatalf("got %+v, error = %v, requests = %d, want %+v", got, err, requests.Load(), want)
	}
	got.Changes[0].Summary = "mutated"
	q.To = from
	got, err = m.List(t.Context(), q)
	want = changes.ListResult{Changes: []changes.Change{
		{At: from, Kind: "rollout", Service: "apps/cache", Summary: "StatefulSet cache rollout (images: cache:2)", Ref: "k8s:east/apps/ControllerRevision/cache-revision"},
	}}
	if err != nil || !reflect.DeepEqual(got, want) || requests.Load() != 4 {
		t.Fatalf("cached result = %+v, error = %v, requests = %d, want %+v", got, err, requests.Load(), want)
	}
}

func TestValidateKubernetesRolloutConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Module)
	}{
		{"missing api server", func(m *Module) { m.APIServer = "" }},
		{"credential over plain HTTP", func(m *Module) { m.CredentialRef = "token" }},
		{"no namespace", func(m *Module) { m.Namespaces = nil }},
		{"too many namespaces", func(m *Module) { m.Namespaces = make([]string, 65) }},
		{"invalid namespace", func(m *Module) { m.Namespaces = []string{"../apps"} }},
		{"cache TTL too long", func(m *Module) { m.CacheTTL += time.Second }},
		{"response limit too high", func(m *Module) { m.MaxResponseBytes++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Module{APIServer: "http://kubernetes.example", Namespaces: []string{"apps"}, CacheTTL: 10 * time.Minute, MaxResponseBytes: 16 << 20}
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

func TestKubernetesRolloutErrorsDoNotExposeRemoteData(t *testing.T) {
	const secret = "fixture-secret"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	}))
	defer server.Close()
	for _, tc := range []struct {
		name string
		opts []plugintest.HostOption
		want string
	}{
		{"missing credential", []plugintest.HostOption{plugintest.WithHTTPServer(server)}, "Kubernetes rollout credential unavailable"},
		{"network blocked", []plugintest.HostOption{plugintest.WithCredential("kube", []byte(secret))}, "Kubernetes rollout request failed"},
		{"HTTP error", []plugintest.HostOption{plugintest.WithHTTPServer(server), plugintest.WithCredential("kube", []byte(secret))}, "Kubernetes rollout returned an unsuccessful HTTP status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Module{APIServer: server.URL, CredentialRef: "kube", Namespaces: []string{"apps"}}
			if err := m.Provision(t.Context(), plugintest.NewHost(t, tc.opts...)); err != nil {
				t.Fatal(err)
			}
			if _, err := m.List(t.Context(), changes.Query{}); err == nil || err.Error() != tc.want || strings.Contains(err.Error(), secret) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
