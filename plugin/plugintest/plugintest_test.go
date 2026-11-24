package plugintest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/changes"
	"github.com/liubing0806/allowops/plugin/inventory"
	"github.com/liubing0806/allowops/plugin/knowledge"
)

func TestHostFixtureCapabilities(t *testing.T) {
	now := time.Date(2026, time.November, 24, 10, 0, 0, 0, time.FixedZone("test", 8*60*60))
	h := NewHost(t, WithNow(now), WithCredential("api", []byte("credential")), WithHosts([]plugin.HostInfo{
		{Hostname: "one", Labels: map[string]string{"role": "db"}, ReportedLabels: map[string]string{"team": "ops"}},
	}), WithControlPlaneChanges(func(_ context.Context, _, _ time.Time, limit int) ([]plugin.ControlPlaneChange, bool, error) {
		return []plugin.ControlPlaneChange{{Kind: "policy", Version: int64(limit)}}, true, nil
	}))
	if h.Now() != now.UTC() || h.Logger() == nil || h.InstanceID() == "" {
		t.Fatal("host fixtures not initialized")
	}
	if _, err := h.HTTPClient().Get("http://example.invalid"); err == nil {
		t.Fatal("default host allowed network")
	}
	first, err := h.Credential("api")
	if err != nil {
		t.Fatal(err)
	}
	first[0] = 'x'
	second, _ := h.Credential("api")
	if string(second) != "credential" {
		t.Fatal("credential is shared")
	}
	hosts, _ := h.Hosts(t.Context())
	hosts[0].Labels["role"] = "changed"
	hosts[0].ReportedLabels["team"] = "changed"
	again, _ := h.Hosts(t.Context())
	if again[0].Labels["role"] != "db" || again[0].ReportedLabels["team"] != "ops" {
		t.Fatal("host labels are shared")
	}
	h.Cache().Set("key", []byte("entry"), time.Minute)
	entry, _ := h.Cache().Get("key")
	entry[0] = 'x'
	entry, _ = h.Cache().Get("key")
	if string(entry) != "entry" {
		t.Fatal("cache shares values")
	}
	h.Cache().Delete("key")
	if _, ok := h.Cache().Get("key"); ok {
		t.Fatal("cache did not delete")
	}
	if rows, more, err := h.ListControlPlaneChanges(t.Context(), now, now, 2); err != nil || !more || rows[0].Version != 2 {
		t.Fatalf("control plane fixture: %v %v %v", rows, more, err)
	}
}

type httpResolver struct {
	URL  string `yaml:"url"`
	host plugin.Host
}

func (httpResolver) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "inventory.contract_test", New: func() plugin.Module { return &httpResolver{} }}
}
func (m *httpResolver) Provision(_ context.Context, h plugin.Host) error { m.host = h; return nil }
func (m *httpResolver) Resolve(ctx context.Context, q inventory.Query) ([]inventory.Entity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if q.Kind != "" && q.Kind != "service" {
		return []inventory.Entity{}, nil
	}
	if _, ok := m.host.Cache().Get("response"); !ok {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.URL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := m.host.HTTPClient().Do(req)
		if err != nil {
			return nil, errors.New("fixture upstream unavailable")
		}
		resp.Body.Close()
		m.host.Cache().Set("response", []byte("ok"), time.Minute)
	}
	return []inventory.Entity{{Kind: "service", Name: "api", Attrs: map[string]string{"team": "ops"}, Hosts: []string{"one"}}}, nil
}

func TestResolverContractWithTLSAndHostCache(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	RunResolverContract(t, httpResolver{}, "url: "+server.URL, WithHTTPServer(server), WithExpectHTTP())
	if got := calls.Load(); got != 1 {
		t.Fatalf("fixture saw %d HTTP calls, want one cached response and no request after disabling HTTP", got)
	}
}

type testLister struct {
	host plugin.ControlPlaneChangeReader
}

func (testLister) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "changes.contract_test", New: func() plugin.Module { return &testLister{} }}
}
func (m *testLister) Provision(_ context.Context, host plugin.Host) error {
	m.host = host.(plugin.ControlPlaneChangeReader)
	return nil
}
func (m *testLister) List(ctx context.Context, q changes.Query) (changes.ListResult, error) {
	control, hasMore, err := m.host.ListControlPlaneChanges(ctx, q.From, q.To, q.MaxItems)
	rows := make([]changes.Change, len(control))
	for i, row := range control {
		rows[i] = changes.Change{At: row.At, Kind: row.Kind, Summary: row.Reason}
	}
	return changes.ListResult{Changes: rows, HasMore: hasMore}, err
}

func TestListerContractWithControlPlaneChanges(t *testing.T) {
	now := time.Date(2026, time.November, 24, 10, 0, 0, 0, time.UTC)
	RunListerContract(t, testLister{}, "{}", WithNow(now), WithControlPlaneChanges(func(ctx context.Context, from, to time.Time, limit int) ([]plugin.ControlPlaneChange, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		rows := []plugin.ControlPlaneChange{{At: to, Kind: "policy", Reason: "first"}, {At: from, Kind: "catalog", Reason: "second"}}
		return rows[:min(limit, len(rows))], len(rows) > limit, nil
	}))
}

type testStore struct {
	docs []knowledge.Doc
}

func (testStore) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "knowledge.contract_test", New: func() plugin.Module { return &testStore{} }}
}
func (m *testStore) Provision(context.Context, plugin.Host) error {
	m.docs = []knowledge.Doc{{ID: "a", Title: "A", Tags: []string{"ops"}, Headings: []string{"start"}}, {ID: "b", Title: "B"}}
	return nil
}
func (m *testStore) Search(ctx context.Context, q knowledge.SearchQuery) ([]knowledge.Doc, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return cloneDocs(m.docs[:min(len(m.docs), q.MaxDocs)]), nil
}
func (m *testStore) Read(ctx context.Context, id string) (knowledge.ReadResult, error) {
	if err := ctx.Err(); err != nil {
		return knowledge.ReadResult{}, err
	}
	pos := slices.IndexFunc(m.docs, func(doc knowledge.Doc) bool { return doc.ID == id })
	if pos < 0 {
		return knowledge.ReadResult{}, knowledge.ErrNotFound
	}
	return knowledge.ReadResult{Doc: cloneDoc(m.docs[pos]), Content: "# start"}, nil
}
func TestStoreContractWithFixture(t *testing.T) {
	RunStoreContract(t, testStore{}, "{}", WithCredential("api", []byte("fake-credential")))
}
