package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liubing0806/allowops/plugin/inventory"
	"github.com/liubing0806/allowops/plugin/plugintest"
)

const deployment = `{"items":[
	{"metadata":{"name":"api","labels":{"app.kubernetes.io/name":"api","app.kubernetes.io_name":"second","bad@key":"invalid","private":"excluded"},"annotations":{"ignored":17}},
	 "spec":{"selector":{"matchLabels":{"app":"api","empty":""},"matchExpressions":[
		{"key":"tier","operator":"In","values":["frontend","backend"]},
		{"key":"skip","operator":"NotIn","values":["true"]},
		{"key":"ready","operator":"Exists"},
		{"key":"retired","operator":"DoesNotExist"}
	 ]},"template":{"spec":{"containers":[{"env":"ignored","args":12}]}}}},
	{"metadata":{"name":"no-selector"}},
	{"metadata":{"name":"unknown-selector"},"spec":{"selector":{"matchLabels":{"app":"api"},"matchExpressions":[{"operator":"Unknown"}]}}}
]}`

const podList = `{"items":[
	{"metadata":{"labels":{"app":"api","empty":"","tier":"backend","ready":""}},"spec":{"nodeName":"node-2"}},
	{"metadata":{"labels":{"app":"api","empty":"","tier":"frontend","skip":"false","ready":"yes"}},"spec":{"nodeName":"node-1"}},
	{"metadata":{"labels":{"app":"api","empty":"","tier":"backend","ready":"yes"}},"spec":{"nodeName":"node-1"}},
	{"metadata":{"labels":{"app":"api","empty":"","tier":"backend","ready":"yes"}},"spec":{}},
	{"metadata":{"labels":{"app":"api","tier":"backend","ready":"yes"}},"spec":{"nodeName":"no-empty-label"}},
	{"metadata":{"labels":{"app":"api","empty":"","tier":"other","ready":"yes"}},"spec":{"nodeName":"wrong-tier"}},
	{"metadata":{"labels":{"app":"api","empty":"","tier":"backend","skip":"true","ready":"yes"}},"spec":{"nodeName":"skip"}},
	{"metadata":{"labels":{"app":"api","empty":"","tier":"backend"}},"spec":{"nodeName":"not-ready"}},
	{"metadata":{"labels":{"app":"api","empty":"","tier":"backend","ready":"yes","retired":""}},"spec":{"nodeName":"retired"}}
]}`

func kubernetesFixture(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("unexpected method or authorization")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/proxy/api/v1/namespaces/prod/pods":
			if got := r.URL.Query().Get("fieldSelector"); got != "status.phase=Running" {
				t.Errorf("fieldSelector = %q", got)
			}
			fmt.Fprint(w, podList)
		case "/proxy/apis/apps/v1/namespaces/prod/deployments":
			fmt.Fprint(w, deployment)
		case "/proxy/apis/apps/v1/namespaces/prod/statefulsets":
			fmt.Fprint(w, `{"items":[{"metadata":{"name":"api"}}]}`)
		case "/proxy/apis/apps/v1/namespaces/prod/daemonsets":
			fmt.Fprint(w, `{"items":[]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func TestResolverContract(t *testing.T) {
	server, _ := kubernetesFixture(t)
	plugintest.RunResolverContract(t, Module{}, "api_server: "+server.URL+"/proxy\nnamespaces: [prod]\ncredential_ref: TOKEN",
		plugintest.WithHTTPServer(server), plugintest.WithCredential("TOKEN", []byte(`{"bearer_token":"test-token"}`)), plugintest.WithExpectHTTP())
}

func TestResolveWorkloads(t *testing.T) {
	server, calls := kubernetesFixture(t)
	host := plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithCredential("TOKEN", []byte("test-token\n")))
	module := Module{
		APIServer: server.URL + "/proxy", Namespaces: []string{"prod"}, CredentialRef: "TOKEN", Cluster: "west",
		EntityKind: "service", LabelAllowlist: []string{"app.kubernetes.io_name", "bad@key", "app.kubernetes.io/name"},
		SelectorLabel: "app.kubernetes.io/name",
	}
	if err := module.Provision(t.Context(), host); err != nil {
		t.Fatal(err)
	}
	rows, err := module.Resolve(t.Context(), inventory.Query{})
	if err != nil || len(rows) != 4 {
		t.Fatalf("rows=%+v error=%v", rows, err)
	}
	api := rows[0]
	if api.Kind != "service" || api.Name != "prod/api/deployment" || rows[1].Name != "prod/api/statefulset" ||
		rows[2].Name != "prod/no-selector" || rows[3].Name != "prod/unknown-selector" {
		t.Fatal(rows)
	}
	if !reflect.DeepEqual(api.Attrs, map[string]string{"cluster": "west", "app.kubernetes.io_name": "api"}) ||
		api.Selector != "app.kubernetes.io_name=api" || !reflect.DeepEqual(api.Hosts, []string{"node-1", "node-2"}) {
		t.Fatal(api)
	}
	for _, row := range rows[1:] {
		if len(row.Hosts) != 0 {
			t.Fatal(row)
		}
	}
	api.Attrs["cluster"] = "mutated"
	rows, err = module.Resolve(t.Context(), inventory.Query{Kind: "service"})
	if err != nil || rows[0].Attrs["cluster"] != "west" || calls.Load() != 4 {
		t.Fatalf("cache rows=%+v error=%v calls=%d", rows, err, calls.Load())
	}
}

func TestResolveWithoutPods(t *testing.T) {
	server, calls := kubernetesFixture(t)
	host := plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithCredential("TOKEN", []byte("test-token")))
	include := false
	module := Module{APIServer: server.URL + "/proxy", Namespaces: []string{"prod"}, CredentialRef: "TOKEN", Workloads: []string{"deployment"}, IncludePods: &include}
	if err := module.Provision(t.Context(), host); err != nil {
		t.Fatal(err)
	}
	rows, err := module.Resolve(t.Context(), inventory.Query{Kind: "deployment"})
	if err != nil || len(rows) != 3 || rows[0].Name != "prod/api" || len(rows[0].Hosts) != 0 || calls.Load() != 1 {
		t.Fatalf("rows=%+v error=%v calls=%d", rows, err, calls.Load())
	}
}

func TestSelectorRejectsMalformedExpressions(t *testing.T) {
	for _, expr := range []string{
		`{"key":"missing","operator":"NotIn"}`,
		`{"key":"present","operator":"Exists","values":["unexpected"]}`,
		`{"key":"missing","operator":"DoesNotExist","values":["unexpected"]}`,
	} {
		var selector labelSelector
		if err := json.Unmarshal([]byte(`{"matchExpressions":[`+expr+`]}`), &selector); err != nil {
			t.Fatal(err)
		}
		if selector.matches(map[string]string{"present": "yes"}) {
			t.Errorf("malformed expression matched: %s", expr)
		}
	}
}

func TestValidate(t *testing.T) {
	for _, module := range []Module{
		{APIServer: "http://example.com", CredentialRef: "TOKEN", Namespaces: []string{"prod"}},
		{APIServer: "https://example.com"},
		{APIServer: "https://example.com", Namespaces: []string{"not.a.label"}},
		{APIServer: "https://example.com", Namespaces: []string{"UPPER"}},
		{APIServer: "https://example.com", Namespaces: []string{strings.Repeat("a", 64)}},
		{APIServer: "https://example.com", Namespaces: make([]string, 65)},
		{APIServer: "https://example.com", Namespaces: []string{"prod"}, Workloads: []string{"service"}},
		{APIServer: "https://example.com", Namespaces: []string{"prod"}, CacheTTL: 11 * time.Minute},
		{APIServer: "https://example.com", Namespaces: []string{"prod"}, MaxResponseBytes: 16<<20 + 1},
	} {
		if err := module.Validate(); err == nil {
			t.Errorf("invalid config accepted: %+v", module)
		}
	}
}

func TestResolveFixedErrors(t *testing.T) {
	const body = `{"items":[]}`
	for _, tc := range []struct {
		name   string
		status int
		body   string
		limit  int64
		token  string
		want   error
	}{
		{name: "bad credential", token: `{"bearer_token":"secret value"}`, want: errCredential},
		{name: "limit", body: body, limit: int64(len(body) - 1), want: errResponseSize},
		{name: "at limit", body: body, limit: int64(len(body))},
		{name: "invalid json", body: "private-response-data", want: errResponse},
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
			host := plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithCredential("TOKEN", []byte(tc.token)))
			module := Module{APIServer: server.URL, Namespaces: []string{"prod"}, MaxResponseBytes: tc.limit}
			if tc.token != "" {
				module.CredentialRef = "TOKEN"
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
