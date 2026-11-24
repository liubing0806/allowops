// Package plugintest provides reusable contract checks for gateway plugins.
package plugintest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/changes"
	"github.com/liubing0806/allowops/plugin/inventory"
	"github.com/liubing0806/allowops/plugin/knowledge"
	"github.com/liubing0806/allowops/plugin/notifier"
	"gopkg.in/yaml.v3"
)

type HostOption func(*TestHost)

func WithHTTPServer(server *httptest.Server) HostOption { return WithHTTPClient(server.Client()) }

func WithHTTPClient(client *http.Client) HostOption {
	return func(h *TestHost) {
		h.client = *client
		h.blockHTTP.Store(false)
	}
}

func WithCredential(ref string, value []byte) HostOption {
	return func(h *TestHost) { h.credentials[ref] = slices.Clone(value) }
}

func WithHosts(hosts []plugin.HostInfo) HostOption {
	return func(h *TestHost) { h.hosts = cloneHosts(hosts) }
}

func WithNow(now time.Time) HostOption {
	return func(h *TestHost) { h.now = now.UTC() }
}

func WithControlPlaneChanges(reader func(context.Context, time.Time, time.Time, int) ([]plugin.ControlPlaneChange, bool, error)) HostOption {
	return func(h *TestHost) { h.controlPlane = reader }
}

// WithExpectHTTP requires a call through the host client and requires a fresh
// plugin with an empty host cache to fail once that client is disabled.
func WithExpectHTTP() HostOption { return func(h *TestHost) { h.expectHTTP = true } }

type TestHost struct {
	client       http.Client
	transport    http.RoundTripper
	credentials  map[string][]byte
	hosts        []plugin.HostInfo
	now          time.Time
	logger       *slog.Logger
	cache        testCache
	controlPlane func(context.Context, time.Time, time.Time, int) ([]plugin.ControlPlaneChange, bool, error)
	expectHTTP   bool
	blockHTTP    atomic.Bool
	httpCalls    atomic.Int64
}

func NewHost(t testing.TB, opts ...HostOption) *TestHost {
	t.Helper()
	h := &TestHost{
		credentials: make(map[string][]byte),
		now:         time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	h.blockHTTP.Store(true)
	for _, opt := range opts {
		opt(h)
	}
	h.transport = h.client.Transport
	if h.transport == nil && !h.blockHTTP.Load() {
		h.transport = http.DefaultTransport
	}
	h.client.Transport = hostTransport{h}
	h.cache = testCache{now: h.Now, entries: make(map[string]cacheValue)}
	t.Cleanup(h.client.CloseIdleConnections)
	return h
}

func (h *TestHost) InstanceID() string       { return "plugintest" }
func (h *TestHost) Logger() *slog.Logger     { return h.logger }
func (h *TestHost) HTTPClient() *http.Client { return &h.client }
func (h *TestHost) Cache() plugin.Cache      { return &h.cache }
func (h *TestHost) Now() time.Time           { return h.now }

func (h *TestHost) Hosts(ctx context.Context) ([]plugin.HostInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return cloneHosts(h.hosts), nil
}

func cloneHosts(hosts []plugin.HostInfo) []plugin.HostInfo {
	out := slices.Clone(hosts)
	for i := range out {
		out[i].Labels = maps.Clone(out[i].Labels)
		out[i].ReportedLabels = maps.Clone(out[i].ReportedLabels)
	}
	return out
}

func (h *TestHost) Credential(ref string) ([]byte, error) {
	value, ok := h.credentials[ref]
	if !ok {
		return nil, errors.New("plugin credential: unavailable")
	}
	return slices.Clone(value), nil
}

func (h *TestHost) ListControlPlaneChanges(ctx context.Context, from, to time.Time, limit int) ([]plugin.ControlPlaneChange, bool, error) {
	if h.controlPlane == nil {
		return nil, false, errors.New("plugin control plane changes: unavailable")
	}
	return h.controlPlane(ctx, from, to, limit)
}

type hostTransport struct{ host *TestHost }

func (t hostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.host.httpCalls.Add(1)
	if t.host.blockHTTP.Load() {
		return nil, errors.New("plugintest: HTTP disabled")
	}
	return t.host.transport.RoundTrip(req)
}

func (t hostTransport) CloseIdleConnections() {
	if transport, ok := t.host.transport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
}

type cacheValue struct {
	data   []byte
	expiry time.Time
}

type testCache struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]cacheValue
}

func (c *testCache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, ok := c.entries[key]
	if !ok || !c.now().Before(value.expiry) {
		delete(c.entries, key)
		return nil, false
	}
	return slices.Clone(value.data), true
}

func (c *testCache) Set(key string, value []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl <= 0 {
		delete(c.entries, key)
		return
	}
	c.entries[key] = cacheValue{slices.Clone(value), c.now().Add(ttl)}
}

func (c *testCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func (c *testCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.entries)
}

// RunNotifierContract checks a notifier with a fixture that accepts
// approval.requested events.
func RunNotifierContract(t *testing.T, module plugin.Module, config string, opts ...HostOption) {
	t.Helper()
	h, create := contractSetup(t, module, config, "notifier", opts)
	event := notifier.Event{
		Type: notifier.EventApprovalRequested, EventID: "approval-fixture:1", At: h.Now(),
		ApprovalID: "approval-fixture", JobID: "job-fixture", Action: "report", Risk: "read",
		Requester: "requester-fixture", TargetCount: 1, MinApprovals: 1, ExpiresAt: h.Now().Add(time.Hour),
		ConsoleURL: "https://console.example/approvals/approval-fixture", Status: "pending",
	}
	call := func(m plugin.Module, ctx context.Context) (struct{}, error) {
		return struct{}{}, m.(notifier.Sender).Send(ctx, event)
	}
	m := readyModule(t, h, create)
	if _, ok := m.(notifier.Sender); !ok {
		t.Fatal("module must implement notifier.Sender")
	}
	checkCanceled(t, h, func(ctx context.Context) (struct{}, error) { return call(m, ctx) })
	before := h.httpCalls.Load()
	_, err := call(m, t.Context())
	requireNoError(t, h, err)
	if h.expectHTTP && h.httpCalls.Load() == before {
		t.Fatal("notifier Send did not use Host.HTTPClient")
	}
	checkHTTP(t, h, create, call)
}

// RunResolverContract checks an inventory module with a valid YAML fixture.
func RunResolverContract(t *testing.T, module plugin.Module, config string, opts ...HostOption) {
	t.Helper()
	h, create := contractSetup(t, module, config, "inventory", opts)
	resolve := func(m plugin.Module, ctx context.Context, q inventory.Query) ([]inventory.Entity, error) {
		resolver, ok := m.(inventory.Resolver)
		if !ok {
			t.Fatal("module must implement inventory.Resolver")
		}
		return resolver.Resolve(ctx, q)
	}
	m := readyModule(t, h, create)
	mainCall := func(m plugin.Module, ctx context.Context) ([]inventory.Entity, error) {
		return resolve(m, ctx, inventory.Query{})
	}
	checkCanceled(t, h, func(ctx context.Context) ([]inventory.Entity, error) { return mainCall(m, ctx) })
	values := checkStable(t, h, func() ([]inventory.Entity, error) { return mainCall(m, t.Context()) }, cloneEntities, mutateEntities)
	seen := make(map[[2]string]bool)
	for _, e := range values {
		key := [2]string{e.Kind, e.Name}
		if e.Kind == "" || e.Name == "" || seen[key] {
			t.Fatal("resolver returned an empty or duplicate identity")
		}
		seen[key] = true
	}
	if len(values) != 0 {
		kind := values[0].Kind
		filtered, err := resolve(m, t.Context(), inventory.Query{Kind: kind})
		requireNoError(t, h, err)
		var expected []inventory.Entity
		for _, value := range values {
			if value.Kind == kind {
				expected = append(expected, value)
			}
		}
		if !reflect.DeepEqual(filtered, expected) {
			t.Fatal("resolver did not honor Kind")
		}
	}
	checkHTTP(t, h, create, mainCall)
}

func cloneEntities(entities []inventory.Entity) []inventory.Entity {
	copy := slices.Clone(entities)
	for i := range copy {
		copy[i].Attrs = maps.Clone(copy[i].Attrs)
		copy[i].Hosts = slices.Clone(copy[i].Hosts)
		copy[i].DependsOn = slices.Clone(copy[i].DependsOn)
	}
	return copy
}

func mutateEntities(entities *[]inventory.Entity) {
	for i := range *entities {
		e := &(*entities)[i]
		e.Name = "plugintest-mutated"
		if e.Attrs != nil {
			e.Attrs["plugintest-mutated"] = "true"
		}
		if len(e.Hosts) > 0 {
			e.Hosts[0] = "plugintest-mutated"
		}
		if len(e.DependsOn) > 0 {
			e.DependsOn[0] = "plugintest-mutated"
		}
	}
}

// RunListerContract checks a Changes fixture in the seven days ending at
// Host.Now. Use WithNow to set the window for a dated fixture.
func RunListerContract(t *testing.T, module plugin.Module, config string, opts ...HostOption) {
	t.Helper()
	h, create := contractSetup(t, module, config, "changes", opts)
	query := changes.Query{From: h.Now().Add(-7 * 24 * time.Hour), To: h.Now(), MaxItems: 1000}
	list := func(m plugin.Module, ctx context.Context, q changes.Query) (changes.ListResult, error) {
		lister, ok := m.(changes.Lister)
		if !ok {
			t.Fatal("module must implement changes.Lister")
		}
		return lister.List(ctx, q)
	}
	m := readyModule(t, h, create)
	mainCall := func(m plugin.Module, ctx context.Context) (changes.ListResult, error) { return list(m, ctx, query) }
	checkCanceled(t, h, func(ctx context.Context) (changes.ListResult, error) { return mainCall(m, ctx) })
	all := checkStable(t, h, func() (changes.ListResult, error) { return mainCall(m, t.Context()) },
		func(r changes.ListResult) changes.ListResult {
			r.Changes = slices.Clone(r.Changes)
			return r
		}, func(r *changes.ListResult) {
			for i := range r.Changes {
				r.Changes[i].Summary = "plugintest-mutated"
			}
		})
	limited := query
	limited.MaxItems = 1
	result, err := list(m, t.Context(), limited)
	requireNoError(t, h, err)
	if len(all.Changes) > query.MaxItems || len(result.Changes) > limited.MaxItems || len(all.Changes) > limited.MaxItems && !result.HasMore {
		t.Fatal("lister did not honor MaxItems and HasMore")
	}
	for _, row := range all.Changes {
		if row.At.Before(query.From) || row.At.After(query.To) {
			t.Fatal("lister returned a change outside the requested window")
		}
	}
	checkHTTP(t, h, create, mainCall)
}

// RunStoreContract checks a Knowledge fixture. Include a document to exercise
// successful Read, including copies of its tags and headings.
func RunStoreContract(t *testing.T, module plugin.Module, config string, opts ...HostOption) {
	t.Helper()
	h, create := contractSetup(t, module, config, "knowledge", opts)
	query := knowledge.SearchQuery{MaxDocs: 1000}
	store := func(m plugin.Module) knowledge.Store {
		value, ok := m.(knowledge.Store)
		if !ok {
			t.Fatal("module must implement knowledge.Store")
		}
		return value
	}
	m := readyModule(t, h, create)
	mainCall := func(m plugin.Module, ctx context.Context) ([]knowledge.Doc, error) {
		return store(m).Search(ctx, query)
	}
	checkCanceled(t, h, func(ctx context.Context) ([]knowledge.Doc, error) { return mainCall(m, ctx) })
	docs := checkStable(t, h, func() ([]knowledge.Doc, error) { return mainCall(m, t.Context()) }, cloneDocs, func(docs *[]knowledge.Doc) {
		for i := range *docs {
			mutateDoc(&(*docs)[i])
		}
	})
	limited, err := store(m).Search(t.Context(), knowledge.SearchQuery{MaxDocs: 1})
	requireNoError(t, h, err)
	if len(docs) > query.MaxDocs || len(limited) > 1 {
		t.Fatal("store did not honor MaxDocs")
	}
	missing := "plugintest-not-found"
	for slices.ContainsFunc(docs, func(doc knowledge.Doc) bool { return doc.ID == missing }) {
		missing += "-x"
	}
	if _, err := store(m).Read(t.Context(), missing); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatal("missing document must return knowledge.ErrNotFound")
	} else {
		assertSafeError(t, h, err)
	}
	id := missing
	if len(docs) != 0 {
		id = docs[0].ID
		result := checkStable(t, h, func() (knowledge.ReadResult, error) { return store(m).Read(t.Context(), id) },
			func(r knowledge.ReadResult) knowledge.ReadResult { r.Doc = cloneDoc(r.Doc); return r },
			func(r *knowledge.ReadResult) { mutateDoc(&r.Doc); r.Content = "plugintest-mutated" })
		if !reflect.DeepEqual(result.Doc, docs[0]) {
			t.Fatal("Read metadata disagrees with Search on a fixed snapshot")
		}
	}
	checkCanceled(t, h, func(ctx context.Context) (knowledge.ReadResult, error) { return store(m).Read(ctx, id) })
	checkHTTP(t, h, create, mainCall)
}

func cloneDoc(doc knowledge.Doc) knowledge.Doc {
	doc.Tags = slices.Clone(doc.Tags)
	doc.Headings = slices.Clone(doc.Headings)
	return doc
}

func cloneDocs(docs []knowledge.Doc) []knowledge.Doc {
	out := slices.Clone(docs)
	for i := range out {
		out[i] = cloneDoc(out[i])
	}
	return out
}

func mutateDoc(doc *knowledge.Doc) {
	doc.Title = "plugintest-mutated"
	if len(doc.Tags) > 0 {
		doc.Tags[0] = "plugintest-mutated"
	}
	if len(doc.Headings) > 0 {
		doc.Headings[0] = "plugintest-mutated"
	}
}

var moduleName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$`)

func contractSetup(t *testing.T, module plugin.Module, config, namespace string, opts []HostOption) (*TestHost, func() plugin.Module) {
	t.Helper()
	host := NewHost(t, opts...)
	info := module.Module()
	id := string(info.ID)
	if !moduleName.MatchString(id) || !strings.HasPrefix(id, namespace+".") || info.New == nil {
		t.Fatal("invalid module ID or missing New factory")
	}
	a, b := info.New(), info.New()
	for _, m := range []plugin.Module{a, b} {
		v := reflect.ValueOf(m)
		if m == nil || v.Kind() == reflect.Pointer && v.IsNil() || m.Module().ID != info.ID {
			t.Fatal("New returned an invalid module")
		}
	}
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		t.Fatal("New returned different module types")
	}
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	if va.Kind() == reflect.Pointer && va.Type().Elem().Size() != 0 && va.Pointer() == vb.Pointer() {
		t.Fatal("New reused a module instance")
	}
	if strings.TrimSpace(config) == "" {
		config = "{}"
	}
	decode := func(input []byte, m plugin.Module) error {
		decoder := yaml.NewDecoder(bytes.NewReader(input))
		decoder.KnownFields(true)
		return decoder.Decode(m)
	}
	var configTree yaml.Node
	if err := yaml.Unmarshal([]byte(config), &configTree); err != nil || len(configTree.Content) != 1 || configTree.Content[0].Kind != yaml.MappingNode {
		t.Fatal("expected a valid YAML fixture mapping")
	}
	unknown := configTree.Content[0]
	unknown.Content = append(unknown.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: "plugintest_unknown_field"},
		&yaml.Node{Kind: yaml.ScalarNode, Value: "unknown"})
	invalid, err := yaml.Marshal(&configTree)
	if err != nil {
		t.Fatal("could not encode YAML fixture")
	}
	if err := decode(invalid, a); err == nil {
		t.Fatal("module accepted an unknown configuration field")
	}
	return host, func() plugin.Module {
		m := info.New()
		requireNoError(t, host, decode([]byte(config), m))
		if v, ok := m.(plugin.Validator); ok {
			requireNoError(t, host, v.Validate())
		}
		if c, ok := m.(plugin.Cleaner); ok {
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				requireNoError(t, host, c.Cleanup(ctx))
			})
		}
		return m
	}
}

func provision(ctx context.Context, h *TestHost, m plugin.Module) error {
	if p, ok := m.(plugin.Provisioner); ok {
		var capability plugin.Host = h
		if h.controlPlane == nil {
			// An embedded interface exposes only the unprivileged Host methods.
			capability = struct{ plugin.Host }{h}
		}
		return p.Provision(ctx, capability)
	}
	return nil
}

func readyModule(t *testing.T, h *TestHost, create func() plugin.Module) plugin.Module {
	t.Helper()
	m := create()
	requireNoError(t, h, provision(t.Context(), h, m))
	return m
}

func checkCanceled[T any](t *testing.T, h *TestHost, call func(context.Context) (T, error)) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan error, 1)
	go func() {
		_, err := call(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		assertSafeError(t, h, err)
	case <-time.After(time.Second):
		t.Fatal("call did not return within one second of context cancellation")
	}
}

func checkStable[T any](t *testing.T, h *TestHost, call func() (T, error), clone func(T) T, mutate func(*T)) T {
	t.Helper()
	first, err := call()
	requireNoError(t, h, err)
	expected := clone(first)
	second, err := call()
	requireNoError(t, h, err)
	if !reflect.DeepEqual(expected, second) {
		t.Fatal("identical calls returned different values or ordering")
	}
	mutate(&first)
	third, err := call()
	requireNoError(t, h, err)
	if !reflect.DeepEqual(expected, third) || !reflect.DeepEqual(expected, second) {
		t.Fatal("returned values share mutable state")
	}
	return expected
}

func checkHTTP[T any](t *testing.T, h *TestHost, create func() plugin.Module, call func(plugin.Module, context.Context) (T, error)) {
	t.Helper()
	if !h.expectHTTP {
		return
	}
	before := h.httpCalls.Load()
	if before == 0 {
		t.Fatal("plugin did not use Host.HTTPClient")
	}
	h.blockHTTP.Store(true)
	h.cache.clear()
	m := create()
	err := provision(t.Context(), h, m)
	if err == nil {
		_, err = call(m, t.Context())
	}
	if err == nil || h.httpCalls.Load() == before {
		t.Fatal("expected a host HTTP error after disabling the client and clearing the cache")
	}
	assertSafeError(t, h, err)
}

func requireNoError(t *testing.T, h *TestHost, err error) {
	t.Helper()
	if err != nil {
		assertSafeError(t, h, err)
		t.Fatalf("unexpected contract fixture error: %v", err)
	}
}

func assertSafeError(t *testing.T, h *TestHost, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, value := range h.credentials {
		if len(value) != 0 {
			secret := string(value)
			for _, candidate := range []string{secret, url.QueryEscape(secret), url.PathEscape(secret)} {
				if strings.Contains(err.Error(), candidate) {
					t.Fatal("plugin error exposes a configured credential")
				}
			}
		}
	}
}
