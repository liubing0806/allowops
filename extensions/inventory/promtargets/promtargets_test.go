package promtargets

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liubing0806/allowops/plugin/inventory"
	"github.com/liubing0806/allowops/plugin/plugintest"
)

const targetList = `{"status":"success","data":{"activeTargets":[
	{"labels":{"job":"api","instance":"z.example:9090","node":"z.custom:123","region":"west","target_value":"hidden-only","team":"hidden"}},
	{"labels":{"job":"api","instance":"[2001:db8::1]:443","node":"ipv6.custom:123","region":"west","team":"visible"},"discoveredLabels":{"ignored":1}},
	{"labels":{"job":"api","instance":"z.example:9091","node":"z.custom:123","region":"west","team":"visible"}},
	{"labels":{"job":"worker","instance":"worker.example"}},
	{"labels":{"instance":"missing-job"}}
],"droppedTargets":[{"labels":{"job":"dropped"}}]}}`

func targetFixture(t *testing.T, wantAuth string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/proxy/api/v1/targets" || r.URL.RawQuery != "state=active" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != wantAuth {
			t.Error("incorrect authorization")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, targetList)
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func TestResolverContract(t *testing.T) {
	server, _ := targetFixture(t, "Basic bW9uaXRvcjpwYXNz")
	plugintest.RunResolverContract(t, Module{}, "address: "+server.URL+"/proxy\ncredential_ref: MONITOR",
		plugintest.WithHTTPServer(server), plugintest.WithCredential("MONITOR", []byte(`{"username":"monitor","password":"pass"}`)),
		plugintest.WithExpectHTTP())
}

func TestResolveTargets(t *testing.T) {
	server, calls := targetFixture(t, "Bearer test-token")
	host := plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithCredential("MONITOR", []byte("test-token\n")))
	module := Module{Address: server.URL + "/proxy", CredentialRef: "MONITOR", Cluster: "west"}
	if err := module.Provision(t.Context(), host); err != nil {
		t.Fatal(err)
	}
	rows, err := module.Resolve(t.Context(), inventory.Query{})
	want := []inventory.Entity{
		{Kind: "service", Name: "api", Hosts: []string{"2001:db8::1", "z.example"}, Attrs: map[string]string{"job": "api", "cluster": "west"}},
		{Kind: "service", Name: "worker", Hosts: []string{"worker.example"}, Attrs: map[string]string{"job": "worker", "cluster": "west"}},
	}
	if err != nil || !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows=%+v error=%v", rows, err)
	}
	rows[0].Attrs["job"] = "mutated"
	rows[0].Hosts[0] = "mutated"
	rows, err = module.Resolve(t.Context(), inventory.Query{Kind: "service"})
	if err != nil || !reflect.DeepEqual(rows, want) || calls.Load() != 1 {
		t.Fatalf("cache rows=%+v error=%v calls=%d", rows, err, calls.Load())
	}
	rows, err = module.Resolve(t.Context(), inventory.Query{Kind: "other"})
	if err != nil || len(rows) != 0 || calls.Load() != 1 {
		t.Fatalf("filtered rows=%+v error=%v calls=%d", rows, err, calls.Load())
	}
}

func TestResolveConfiguredLabels(t *testing.T) {
	server, _ := targetFixture(t, "Bearer test-token")
	host := plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithCredential("MONITOR", []byte(`{"bearer_token":"test-token"}`)))
	module := Module{
		Address: server.URL + "/proxy", CredentialRef: "MONITOR", Kind: "application",
		NameLabel: "region", HostLabel: "node", LabelAllowlist: []string{"job", "team"},
	}
	if err := module.Provision(t.Context(), host); err != nil {
		t.Fatal(err)
	}
	rows, err := module.Resolve(t.Context(), inventory.Query{Kind: "application"})
	want := []inventory.Entity{{Kind: "application", Name: "west", Hosts: []string{"ipv6.custom:123", "z.custom:123"}, Attrs: map[string]string{"region": "west", "job": "api"}}}
	if err != nil || !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows=%+v error=%v", rows, err)
	}
}

func TestValidate(t *testing.T) {
	for _, module := range []Module{
		{Address: "http://example.com", CredentialRef: "MONITOR"},
		{Address: "invalid"},
		{Address: "https://example.com", Kind: "invalid-kind"},
		{Address: "https://example.com", NameLabel: "invalid/key"},
		{Address: "https://example.com", CacheTTL: 11 * time.Minute},
		{Address: "https://example.com", MaxResponseBytes: 16<<20 + 1},
	} {
		if err := module.Validate(); err == nil {
			t.Errorf("invalid config accepted: %+v", module)
		}
	}
}

func TestResolveFixedErrors(t *testing.T) {
	const body = `{"status":"success","data":{"activeTargets":[]}}`
	for _, tc := range []struct {
		name   string
		status int
		body   string
		limit  int64
		token  string
		want   error
	}{
		{name: "invalid credential", token: `{"username":"secret-username"}`, want: errCredential},
		{name: "limit", body: body, limit: int64(len(body) - 1), want: errResponseSize},
		{name: "at limit", body: body, limit: int64(len(body))},
		{name: "invalid json", body: "private-response-data", want: errResponse},
		{name: "prometheus error", body: `{"status":"error","error":"private-response-data"}`, want: errResponse},
		{name: "http status", status: http.StatusUnauthorized, body: "private-response-data", want: errResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.want == errCredential {
					t.Error("network called with invalid credential")
				}
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			host := plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithCredential("MONITOR", []byte(tc.token)))
			module := Module{Address: server.URL, MaxResponseBytes: tc.limit}
			if tc.token != "" {
				module.CredentialRef = "MONITOR"
			}
			if err := module.Provision(t.Context(), host); err != nil {
				t.Fatal(err)
			}
			if _, err := module.Resolve(t.Context(), inventory.Query{}); err != tc.want {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
		})
	}
}
