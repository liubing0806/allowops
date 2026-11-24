package cmdbhttp

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

const entityList = `{"entities":[
	{"kind":"service","name":"api","attrs":{"owner":"platform"},"hosts":["api-1"],"selector":"app=api","depends_on":["database/store"]},
	{"kind":"database","name":"store","DependsOn":["storage/disk"]}
]}`

func TestResolverContract(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/entities" || r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("unexpected request")
		}
		fmt.Fprint(w, entityList)
	}))
	defer server.Close()
	plugintest.RunResolverContract(t, Module{}, "url: "+server.URL+"/entities\ncredential_ref: CMDB",
		plugintest.WithHTTPServer(server), plugintest.WithCredential("CMDB", []byte("fixture-token")),
		plugintest.WithExpectHTTP())
}

func TestResolveFiltersAndCachesByKind(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		query := r.URL.Query()
		wantKind := ""
		if n == 2 {
			wantKind = "service"
		}
		if r.URL.Path != "/entities" || r.Header.Get("X-Token") != "fixture-token" || r.Header.Get("Accept") != "application/json" ||
			query.Get("site") != "west" || query.Has("Name") || query.Has("name") || query.Get("kind") != wantKind ||
			query.Has("kind") != (wantKind != "") {
			t.Errorf("unexpected request %d query=%v", n, query)
		}
		fmt.Fprint(w, entityList)
	}))
	defer server.Close()
	host := plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithCredential("CMDB", []byte("fixture-token\n")))
	raw := ""
	module := Module{
		URL: server.URL + "/entities?site=west&Name=configured&kind=configured", CredentialRef: "CMDB",
		AuthHeader: "X-Token", AuthScheme: &raw,
	}
	if err := module.Provision(t.Context(), host); err != nil {
		t.Fatal(err)
	}
	rows, err := module.Resolve(t.Context(), inventory.Query{})
	if err != nil || len(rows) != 2 || rows[0].Name != "store" || rows[1].Name != "api" ||
		!reflect.DeepEqual(rows[0].DependsOn, []string{"storage/disk"}) {
		t.Fatalf("rows=%+v error=%v", rows, err)
	}
	service := inventory.Query{Kind: "service"}
	rows, err = module.Resolve(t.Context(), service)
	want := []inventory.Entity{{
		Kind: "service", Name: "api", Attrs: map[string]string{"owner": "platform"}, Hosts: []string{"api-1"},
		Selector: "app=api", DependsOn: []string{"database/store"},
	}}
	if err != nil || !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows=%+v error=%v", rows, err)
	}
	rows[0].DependsOn[0] = "mutated"
	rows, err = module.Resolve(t.Context(), service)
	if err != nil || !reflect.DeepEqual(rows, want) || calls.Load() != 2 {
		t.Fatalf("cache rows=%+v error=%v calls=%d", rows, err, calls.Load())
	}
}

func TestResolveBasic(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "monitor" || password != "pass" {
			t.Error("incorrect Basic authorization")
		}
		fmt.Fprint(w, `{"entities":[]}`)
	}))
	defer server.Close()
	host := plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithCredential("CMDB", []byte("bW9uaXRvcjpwYXNz")))
	scheme := "Basic"
	module := Module{URL: server.URL, CredentialRef: "CMDB", AuthScheme: &scheme}
	if err := module.Provision(t.Context(), host); err != nil {
		t.Fatal(err)
	}
	if _, err := module.Resolve(t.Context(), inventory.Query{}); err != nil {
		t.Fatal(err)
	}
}

func TestValidate(t *testing.T) {
	invalid := "Digest"
	for _, module := range []Module{
		{},
		{URL: "http://example.com", CredentialRef: "CMDB"},
		{URL: "https://example.com", AuthHeader: "aCCept"},
		{URL: "https://example.com", AuthHeader: "HOST"},
		{URL: "https://example.com", AuthHeader: "content-Length"},
		{URL: "https://example.com", AuthHeader: "Transfer-encoding"},
		{URL: "https://example.com", AuthHeader: "invalid header"},
		{URL: "https://example.com", AuthScheme: &invalid},
		{URL: "https://example.com", CacheTTL: 11 * time.Minute},
		{URL: "https://example.com", MaxResponseBytes: 16<<20 + 1},
	} {
		if err := module.Validate(); err == nil {
			t.Errorf("invalid config accepted: %+v", module)
		}
	}
}

func TestResolveFixedErrors(t *testing.T) {
	const body = `{"entities":[]}`
	for _, tc := range []struct {
		name  string
		body  string
		limit int64
		token string
		want  error
	}{
		{name: "invalid credential", token: "secret-a\r\nsecret-b", want: errCredential},
		{name: "limit", body: body, limit: int64(len(body) - 1), want: errResponseSize},
		{name: "at limit", body: body, limit: int64(len(body))},
		{name: "invalid json", body: "private-response-data", want: errResponse},
		{name: "unknown field", body: `{"entities":[],"secret-response-field":true}`, want: errResponse},
		{name: "unknown entity field", body: `{"entities":[{"kind":"service","name":"api","secret-response-field":true}]}`, want: errResponse},
		{name: "trailing data", body: body + body, want: errResponse},
		{name: "duplicate identity", body: `{"entities":[{"kind":"service","name":"secret-name"},{"kind":"service","name":"secret-name"}]}`, want: errDuplicate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.want == errCredential {
					t.Error("network called with invalid credential")
				}
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			host := plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithCredential("CMDB", []byte(tc.token)))
			module := Module{URL: server.URL, MaxResponseBytes: tc.limit}
			if tc.token != "" {
				module.CredentialRef = "CMDB"
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
