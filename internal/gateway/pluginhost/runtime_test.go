package pluginhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
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
	"golang.org/x/sys/unix"
)

type runtimeInventory struct {
	id        string
	callbacks inventoryCallbacks
}

type inventoryCallbacks struct {
	validate  func() error
	provision func(context.Context, plugin.Host) error
	resolve   func(context.Context, inventory.Query) ([]inventory.Entity, error)
	cleanup   func(context.Context, string) error
}

// Each fixture is set before New and remains immutable until workers finish.
var runtimeInventoryFixture inventoryCallbacks

func (runtimeInventory) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "inventory.runtime_test", New: func() plugin.Module { return &runtimeInventory{callbacks: runtimeInventoryFixture} }}
}
func (m *runtimeInventory) Validate() error {
	if m.callbacks.validate != nil {
		return m.callbacks.validate()
	}
	return nil
}
func (m *runtimeInventory) Provision(ctx context.Context, host plugin.Host) error {
	m.id = host.InstanceID()
	if m.callbacks.provision != nil {
		return m.callbacks.provision(ctx, host)
	}
	return nil
}
func (m *runtimeInventory) Resolve(ctx context.Context, q inventory.Query) ([]inventory.Entity, error) {
	if m.callbacks.resolve != nil {
		return m.callbacks.resolve(ctx, q)
	}
	return nil, nil
}
func (m *runtimeInventory) Cleanup(ctx context.Context) error {
	if m.callbacks.cleanup != nil {
		return m.callbacks.cleanup(ctx, m.id)
	}
	return nil
}

type runtimeChanges struct {
	internal bool
}

func (m runtimeChanges) Module() plugin.ModuleInfo {
	id := plugin.ModuleID("changes.runtime_test")
	if m.internal {
		id = "changes.allowops"
	}
	return plugin.ModuleInfo{ID: id, New: func() plugin.Module { return &runtimeChanges{internal: m.internal} }}
}

var changeQuery chan changes.Query
var controlPlaneCapability chan plugin.ControlPlaneChangeReader

func (m *runtimeChanges) Provision(_ context.Context, host plugin.Host) error {
	reader, _ := host.(plugin.ControlPlaneChangeReader)
	controlPlaneCapability <- reader
	return nil
}

func (m *runtimeChanges) List(_ context.Context, q changes.Query) (changes.ListResult, error) {
	changeQuery <- q
	return changes.ListResult{HasMore: true, Changes: []changes.Change{
		{At: q.To, Kind: "deploy", Service: "api", Summary: "first", Actor: "b", Ref: "a"},
		{At: q.To, Kind: "deploy", Service: "api", Summary: "second", Actor: "a", Ref: "b"},
		{At: q.From, Kind: "deploy", Service: "api", Summary: "password=opaque", Actor: "user-opaque", Ref: "opaque"},
		{At: q.To, Kind: "opaque", Service: "api", Summary: "password=opaque"},
		{At: q.To, Kind: "deploy", Service: "opaque", Summary: "password=opaque"},
		{At: q.To.Add(time.Second), Kind: "deploy", Service: "api", Summary: "after window"},
		{At: q.From.Add(-time.Second), Kind: "deploy", Service: "api", Summary: "before window"},
		{At: q.To, Kind: "bad-kind", Service: "api", Summary: "invalid"},
		{At: q.To, Kind: "deploy", Service: "api", Summary: "bad\nsummary"},
		{At: q.To, Kind: "deploy", Service: "api", Summary: strings.Repeat("x", 513)},
		{At: q.To, Kind: "deploy", Service: "api"},
	}}, nil
}

type runtimeKnowledge struct{}

var documents atomic.Pointer[knowledge.ReadResult]
var knowledgeSearches atomic.Int32
var knowledgeReads atomic.Int32

func (runtimeKnowledge) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "knowledge.runtime_test", New: func() plugin.Module { return &runtimeKnowledge{} }}
}
func (runtimeKnowledge) Search(_ context.Context, q knowledge.SearchQuery) ([]knowledge.Doc, error) {
	knowledgeSearches.Add(1)
	if q.MaxDocs != 1000 || q.Query != "" || len(q.Tags) != 0 {
		return nil, errors.New("unexpected query")
	}
	return []knowledge.Doc{documents.Load().Doc, {ID: "hidden-opaque", Title: "password=opaque"}}, nil
}
func (runtimeKnowledge) Read(_ context.Context, id string) (knowledge.ReadResult, error) {
	knowledgeReads.Add(1)
	result := documents.Load()
	if id == "missing" {
		return knowledge.ReadResult{}, fmt.Errorf("missing password=opaque: %w", knowledge.ErrNotFound)
	}
	return *result, nil
}

func init() {
	plugin.Register(runtimeInventory{})
	plugin.Register(runtimeChanges{})
	plugin.Register(runtimeChanges{internal: true})
	plugin.Register(runtimeKnowledge{})
}

func newTestHost(t *testing.T, cfg []Config, deps Deps) *Host {
	t.Helper()
	h, err := New(t.Context(), cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		h.Close(ctx)
	})
	return h
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for test callback")
		var zero T
		return zero
	}
}

func TestPluginNamespaceAndControlPlaneIsolation(t *testing.T) {
	controlPlaneCapability = make(chan plugin.ControlPlaneChangeReader, 2)
	now := time.Date(2026, time.November, 24, 10, 0, 0, 0, time.FixedZone("test", 8*60*60))
	var readCount int
	deps := testDeps()
	deps.Now = func() time.Time { return now }
	deps.ControlPlaneChanges = func(_ context.Context, from, to time.Time, limit int) ([]plugin.ControlPlaneChange, bool, error) {
		readCount++
		if from.Location() != time.UTC || to.Location() != time.UTC || limit != 1000 {
			t.Errorf("control-plane query: %v %v %d", from, to, limit)
		}
		return []plugin.ControlPlaneChange{{At: to, Kind: "policy"}}, true, nil
	}
	runtimeInventoryFixture = inventoryCallbacks{provision: func(_ context.Context, h plugin.Host) error {
		if _, ok := h.(plugin.ControlPlaneChangeReader); ok || h.Now() != now.UTC() || h.Cache() == nil || h.HTTPClient() == nil {
			t.Error("wrong inventory capability")
		}
		return nil
	}}
	t.Cleanup(func() { runtimeInventoryFixture = inventoryCallbacks{} })
	h := newTestHost(t, []Config{
		{ID: "inventory", Module: "inventory.runtime_test"},
		{ID: "ordinary", Module: "changes.runtime_test"},
		{ID: "allowops", Module: "changes.allowops"},
		{ID: "docs", Module: "knowledge.runtime_test"},
	}, deps)
	if !slices.Equal(h.InventorySources(), []string{"inventory"}) ||
		!slices.Equal(h.ChangesSources(), []string{"ordinary", "allowops"}) ||
		!slices.Equal(h.KnowledgeSources(), []string{"docs"}) {
		t.Fatalf("sources crossed namespaces: %+v", h.Health())
	}
	if reader := receive(t, controlPlaneCapability); reader != nil {
		t.Fatal("ordinary changes source has privileged capability")
	}
	reader := receive(t, controlPlaneCapability)
	if reader == nil {
		t.Fatal("missing allowops capability")
	}
	for _, q := range []struct {
		from, to time.Time
		limit    int
	}{{now, now.Add(7*24*time.Hour + time.Second), 1000}, {now, now, 1001}, {now, now, 0}, {now, now.Add(-time.Second), 1}} {
		if _, _, err := reader.ListControlPlaneChanges(t.Context(), q.from, q.to, q.limit); err == nil || readCount != 0 {
			t.Fatalf("invalid control-plane query reached dependencies: %v", err)
		}
	}
	items, more, err := reader.ListControlPlaneChanges(t.Context(), now, now.Add(7*24*time.Hour), 1000)
	if err != nil || !more || len(items) != 1 || readCount != 1 {
		t.Fatalf("control-plane read: %v %v %v %d", items, more, err, readCount)
	}
	if _, err := h.ReadKnowledge(t.Context(), "inventory", "id"); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("cross-namespace document read: %v", err)
	}
}

func TestListChangesRedactionFilteringAndOrdering(t *testing.T) {
	controlPlaneCapability = make(chan plugin.ControlPlaneChangeReader, 1)
	changeQuery = make(chan changes.Query, 4)
	h := newTestHost(t, []Config{
		{ID: "inventory", Module: "inventory.host_test"},
		{ID: "changes", Module: "changes.runtime_test"},
		{ID: "docs", Module: "knowledge.runtime_test"},
	}, testDeps())
	to := time.Date(2026, time.November, 24, 10, 0, 0, 0, time.UTC)
	q := ChangesQuery{From: to.Add(-time.Hour), To: to, Services: []string{"API"}}
	items, more, failed := h.ListChanges(t.Context(), q, nil)
	if len(items) != 3 || !more || len(failed) != 0 {
		t.Fatalf("unexpected changes: %+v, more=%v, errors=%v", items, more, failed)
	}
	if items[0].Actor != "a" || items[1].Actor != "b" || !items[0].At.Equal(q.To) || !items[2].At.Equal(q.From) {
		t.Fatalf("inclusive window or actor sort incorrect: %+v", items)
	}
	if got := items[2]; got.Actor != "user-[REDACTED]" || got.Ref != "[REDACTED]" || strings.Contains(got.Summary, "opaque") || got.Source != "changes" {
		t.Fatalf("cross-field redaction failed: %+v", got)
	}
	query := receive(t, changeQuery)
	if query.MaxItems != 1000 || query.From != q.From || query.To != q.To {
		t.Fatalf("unexpected list query: %+v", query)
	}
	q.Services = []string{"opaque"}
	items, more, failed = h.ListChanges(t.Context(), q, []string{"changes"})
	if len(items) != 0 || !more || len(failed) != 0 {
		t.Fatalf("filtered against unredacted service: %+v", items)
	}
	if items, more, failed := h.ListChanges(t.Context(), q, []string{"inventory", "docs"}); len(items) != 0 || more || len(failed) != 0 {
		t.Fatal("ListChanges used another namespace")
	}
}

func TestMergeVisibleInventoryPropagatesByRawIdentity(t *testing.T) {
	h := newTestHost(t, nil, testDeps())
	secret, other := "opaque-name", "clean"
	a := inventory.Entity{Kind: "service", Name: secret, Attrs: map[string]string{"password": secret}, Hosts: []string{"private"}}
	b := inventory.Entity{Kind: "service", Name: secret, Attrs: map[string]string{"memo": "tag-" + secret}, Selector: "name=" + secret, DependsOn: []string{"database/" + secret}, Hosts: []string{"public"}}
	aSecrets := h.redactEntity(&a)
	bSecrets := h.redactEntity(&b)
	visible := []Result{
		{Entity: a, Source: "a", rawKind: a.Kind, rawName: secret, secrets: aSecrets},
		{Entity: b, Source: "b", rawKind: b.Kind, rawName: secret, secrets: bSecrets},
		{Entity: inventory.Entity{Kind: "service", Name: other, Attrs: map[string]string{"memo": secret}}, Source: "c"},
	}
	merged := MergeVisibleInventory(visible[:2], "")
	text, _ := json.Marshal(merged)
	if len(merged) != 2 || strings.Contains(string(text), secret) || merged[1].Source != "b" || merged[1].Selector != "" {
		t.Fatalf("visible sources failed to share secret fragments: %s", text)
	}
	if filtered := MergeVisibleInventory(visible[:2], "OPAQUE"); len(filtered) != 0 {
		t.Fatalf("name filter saw the secret: %v", filtered)
	}
	bOnly := MergeVisibleInventory(visible[1:], "opaque")
	if len(bOnly) != 1 || bOnly[0].Name != secret || bOnly[0].Selector != b.Selector {
		t.Fatalf("hidden origin still affected visible source: %+v", bOnly)
	}
	independent := MergeVisibleInventory(visible, "CLEAN")
	if len(independent) != 1 || independent[0].Attrs["memo"] != secret {
		t.Fatalf("secret propagated to unrelated raw identity: %+v", independent)
	}
}

func TestMergeVisibleInventoryConflictsAndOwnership(t *testing.T) {
	a := Result{Source: "a", Entity: inventory.Entity{Kind: "service", Name: "api", Attrs: map[string]string{"team": "ops", "env": "test"}, Selector: "env=test", Hosts: []string{"two", "one"}, DependsOn: []string{"db/a"}}}
	b := Result{Source: "b", Entity: inventory.Entity{Kind: "service", Name: "api", Attrs: map[string]string{"team": "ops", "env": "prod", "tier": "api"}, Selector: "env=prod", Hosts: []string{"one"}, DependsOn: []string{"db/b"}}}
	results := MergeVisibleInventory([]Result{b, a}, "API")
	if len(results) != 1 {
		t.Fatalf("failed to merge: %v", results)
	}
	got := results[0]
	if got.Source != "" || !slices.Equal(got.Sources, []string{"a", "b"}) || !slices.Equal(got.Hosts, []string{"one", "two"}) || got.HostCount != 2 ||
		!slices.Equal(got.DependsOn, []string{"db/a", "db/b"}) || !reflect.DeepEqual(got.Attrs, map[string]string{"team": "ops", "tier": "api"}) ||
		!reflect.DeepEqual(got.Conflicts, map[string]map[string]string{"env": {"a": "test", "b": "prod"}}) ||
		got.Selector != "" || !reflect.DeepEqual(got.SelectorConflicts, map[string]string{"a": "env=test", "b": "env=prod"}) {
		t.Fatalf("bad merged result: %+v", got)
	}
	got.Attrs["team"] = "modified"
	got.Conflicts["env"]["a"] = "modified"
	if a.Attrs["team"] != "ops" || a.Attrs["env"] != "test" {
		t.Fatal("merged result mutated source")
	}
}

func TestKnowledgeSearchReadSnapshotAndRedaction(t *testing.T) {
	knowledgeSearches.Store(0)
	knowledgeReads.Store(0)
	original := knowledge.ReadResult{
		Doc: knowledge.Doc{ID: "guide.md", Title: "Restart", Summary: "password=opaque", Tags: []string{"Ops", "opaque"}, Headings: []string{"Steps"}},
		Content: "# Steps (#3)\n# Steps\n## Steps\n# Steps (2)\nopaque follows this heading\n" +
			"```sh\n# not a heading\n```\nAuthorization: Bearer inline-secret\n",
	}
	documents.Store(&original)
	h := newTestHost(t, []Config{{ID: "docs", Module: "knowledge.runtime_test"}}, testDeps())
	found, rev, failed := h.SearchKnowledge(t.Context(), KnowledgeQuery{Query: "steps", Tags: []string{"ops"}}, nil)
	if len(found) != 1 || len(failed) != 0 || len(rev) != 16 || found[0].Tags[1] != "[REDACTED]" ||
		found[0].Summary == original.Doc.Summary || original.Doc.Tags[1] != "opaque" {
		t.Fatalf("metadata redaction/revision failed: %+v %q %v", found, rev, failed)
	}
	if filtered, other, _ := h.SearchKnowledge(t.Context(), KnowledgeQuery{Query: "opaque"}, nil); len(filtered) != 0 || other != rev {
		t.Fatalf("searched unredacted fields or revision changed: %+v %q %q", filtered, other, rev)
	}
	read, err := h.ReadKnowledge(t.Context(), "docs", "guide.md")
	if err != nil || read.Revision != contentRevision([]byte(read.Content)) || strings.Contains(read.Content, "opaque") || strings.Contains(read.Content, "inline-secret") {
		t.Fatalf("read: %+v %v", read, err)
	}
	wantSections := []string{"Steps (#3)", "Steps", "Steps (#3) (#3)", "Steps (2)"}
	if len(read.Sections) != len(wantSections) {
		t.Fatalf("sections: %+v", read.Sections)
	}
	for i, section := range read.Sections {
		if section.Title != wantSections[i] || read.Content[section.Offset] != '#' {
			t.Errorf("section %d: %+v", i, section)
		}
	}

	updated := original
	updated.Doc.Summary = "password=guide"
	updated.Content = "metadata now identifies the ID as sensitive"
	documents.Store(&updated)
	for _, id := range []string{"guide.md", "missing", "../guide.md", "other.md"} {
		read, err := h.ReadKnowledge(t.Context(), "docs", id)
		if !errors.Is(err, knowledge.ErrNotFound) || read.Content != "" || read.Doc.ID != "" {
			t.Fatalf("hidden/missing id %q: %+v %v", id, read, err)
		}
	}
	if knowledgeSearches.Load() != 2 || knowledgeReads.Load() != 4 {
		t.Fatalf("expected one snapshot per read, searches=%d reads=%d", knowledgeSearches.Load(), knowledgeReads.Load())
	}
	documents.Store(&original)
	h.maxLine = 20
	if read, err := h.ReadKnowledge(t.Context(), "docs", "guide.md"); err == nil || read.Content != "" || read.Revision != "" {
		t.Fatalf("redaction exposed a partial document: %+v %v", read, err)
	}
	changed := original
	changed.Doc.Title = "Updated"
	changed.Content = "updated"
	documents.Store(&changed)
	if _, other, _ := h.SearchKnowledge(t.Context(), KnowledgeQuery{}, nil); other == rev {
		t.Fatal("changed metadata kept old index revision")
	}
	if got, err := h.ReadKnowledge(t.Context(), "docs", "guide.md"); err != nil || got.Revision == read.Revision {
		t.Fatalf("changed content kept old revision: %+v %v", got, err)
	}
}

func TestPluginLoggerRedactsAttributesAndNewlines(t *testing.T) {
	var out bytes.Buffer
	runtimeInventoryFixture = inventoryCallbacks{provision: func(ctx context.Context, h plugin.Host) error {
		h.Logger().WithGroup("nested\nname").With("password", "bare-credential").LogAttrs(ctx, slog.LevelInfo, "line\npassword=hidden",
			slog.Group("g", "header", "Authorization: Bearer hidden"), slog.Any("error", errors.New("joined\rsecret=hidden")))
		return nil
	}}
	t.Cleanup(func() { runtimeInventoryFixture = inventoryCallbacks{} })
	newTestHost(t, []Config{{ID: "runtime", Module: "inventory.runtime_test"}}, Deps{Logger: slog.New(slog.NewJSONHandler(&out, nil))})
	if strings.Contains(out.String(), "hidden") || strings.Contains(out.String(), "bare-credential") ||
		strings.Count(out.String(), "\n") != 1 || strings.ContainsAny(strings.TrimSpace(out.String()), "\r\n") ||
		!strings.Contains(out.String(), "nested name") {
		t.Fatalf("log was not sanitized: %s", out.String())
	}
}

func TestPluginProvisionTimeoutLeavesResourcesForLateCleanup(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	writeCredential(t, token, "credential", 0o600)
	allowFinish := make(chan struct{})
	finish := sync.OnceFunc(func() { close(allowFinish) })
	defer finish()
	readAfterTimeout := make(chan error, 1)
	cleaned := make(chan error, 1)
	var capability plugin.Host
	runtimeInventoryFixture = inventoryCallbacks{
		provision: func(ctx context.Context, h plugin.Host) error {
			capability = h
			<-ctx.Done()
			<-allowFinish
			got, err := h.Credential("token")
			if err == nil && string(got) != "credential" {
				err = errors.New("wrong credential")
			}
			readAfterTimeout <- err
			return ctx.Err()
		},
		cleanup: func(ctx context.Context, _ string) error {
			got, err := capability.Credential("token")
			if err == nil && (string(got) != "credential" || ctx.Err() != nil) {
				err = errors.New("cleanup lacks working credentials or context")
			}
			cleaned <- err
			return err
		},
	}
	t.Cleanup(func() { runtimeInventoryFixture = inventoryCallbacks{} })
	start := time.Now()
	h := newTestHost(t, []Config{{
		ID: "late", Module: "inventory.runtime_test", Timeout: 100 * time.Millisecond, Credentials: map[string]string{"token": token},
	}}, testDeps())
	if time.Since(start) > time.Second || len(h.InventorySources()) != 0 || h.Health()[0].OK {
		t.Fatal("startup waited for an abandoned provision or exposed unhealthy source")
	}
	inst := h.instances[0]
	fd := inst.credentials.files["token"].dir
	if inst.refs.Load() != 1 {
		t.Fatalf("wanted only provision reference, got %d", inst.refs.Load())
	}
	h.Close(t.Context())
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		t.Fatalf("Close released descriptor still used by Provision: %v", err)
	}
	finish()
	if err := receive(t, readAfterTimeout); err != nil {
		t.Fatal(err)
	}
	if err := receive(t, cleaned); err != nil {
		t.Fatal(err)
	}
	waitForRelease(t, inst, fd)
}

func waitForRelease(t *testing.T, inst *instance, fd int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if inst.refs.Load() == 0 && errors.Is(err, unix.EBADF) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("resources not released, refs=%d", inst.refs.Load())
}

func TestPluginQueueTimeoutAndCloseHoldWorkerReferences(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	writeCredential(t, token, "credential", 0o600)
	started := make(chan struct{})
	cancelled := make(chan struct{})
	allowFinish := make(chan struct{})
	finish := sync.OnceFunc(func() { close(allowFinish) })
	defer finish()
	workerResult := make(chan error, 1)
	cleanups := make(chan string, 1)
	var calls atomic.Int32
	var capability plugin.Host
	runtimeInventoryFixture = inventoryCallbacks{
		provision: func(_ context.Context, h plugin.Host) error { capability = h; return nil },
		resolve: func(ctx context.Context, _ inventory.Query) ([]inventory.Entity, error) {
			if calls.Add(1) > 1 {
				return nil, errors.New("unexpected concurrent call")
			}
			close(started)
			<-ctx.Done()
			close(cancelled)
			<-allowFinish
			_, err := capability.Credential("token")
			workerResult <- err
			return nil, err
		},
		cleanup: func(_ context.Context, id string) error { cleanups <- id; return nil },
	}
	t.Cleanup(func() { runtimeInventoryFixture = inventoryCallbacks{} })
	h := newTestHost(t, []Config{{
		ID: "runtime", Module: "inventory.runtime_test", Timeout: time.Second, MaxConcurrency: 1,
		Credentials: map[string]string{"token": token},
	}}, testDeps())
	inst := h.instances[0]
	fd := inst.credentials.files["token"].dir
	first := make(chan []SourceError, 1)
	go func() {
		_, errs := h.SearchInventory(context.Background(), Query{}, nil)
		first <- errs
	}()
	receive(t, started)
	short, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if _, errs := h.SearchInventory(short, Query{}, nil); !slices.Equal(errs, []SourceError{{"runtime", "timeout"}}) || calls.Load() != 1 {
		t.Fatalf("queued call executed or ignored deadline: %v", errs)
	}
	closeCtx, closeCancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer closeCancel()
	h.Close(closeCtx)
	receive(t, cancelled)
	if !slices.Equal(receive(t, first), []SourceError{{"runtime", "timeout"}}) {
		t.Fatal("in-flight caller did not return on shutdown")
	}
	if _, errs := h.SearchInventory(t.Context(), Query{}, nil); !slices.Equal(errs, []SourceError{{"runtime", "closed"}}) || calls.Load() != 1 {
		t.Fatalf("shutdown accepted a new call: %v", errs)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		t.Fatalf("shutdown closed an in-flight descriptor: %v", err)
	}
	if got := receive(t, cleanups); got != "runtime" {
		t.Fatalf("unexpected cleanup %s", got)
	}
	finish()
	if err := receive(t, workerResult); err != nil {
		t.Fatal(err)
	}
	waitForRelease(t, inst, fd)
	if len(inst.sem) != 0 {
		t.Fatal("worker did not release concurrency slot")
	}
}

func TestPluginCleanupOrderAndStartupFailure(t *testing.T) {
	cleanups := make(chan string, 8)
	runtimeInventoryFixture = inventoryCallbacks{
		provision: func(_ context.Context, h plugin.Host) error {
			if h.InstanceID() == "required" {
				panic("password=do-not-log")
			}
			return nil
		},
		cleanup: func(_ context.Context, id string) error { cleanups <- id; return nil },
	}
	t.Cleanup(func() { runtimeInventoryFixture = inventoryCallbacks{} })
	configs := []Config{
		{ID: "first", Module: "inventory.runtime_test"},
		{ID: "second", Module: "inventory.runtime_test"},
		{ID: "required", Module: "inventory.runtime_test", Required: true},
	}
	h, err := New(t.Context(), configs, testDeps())
	if h != nil || err == nil || !strings.Contains(err.Error(), "plugin panic") || strings.Contains(err.Error(), "do-not-log") {
		t.Fatalf("required provision returned %v", err)
	}
	for _, want := range []string{"required", "second", "first"} {
		if got := receive(t, cleanups); got != want {
			t.Fatalf("cleanup order got %s, wanted %s", got, want)
		}
	}
	h = newTestHost(t, configs[:2], testDeps())
	h.Close(t.Context())
	h.Close(t.Context())
	for _, want := range []string{"second", "first"} {
		if got := receive(t, cleanups); got != want {
			t.Fatalf("cleanup order got %s, wanted %s", got, want)
		}
	}
	if len(cleanups) != 0 {
		t.Fatal("repeated Close invoked cleanup again")
	}
	runtimeInventoryFixture = inventoryCallbacks{validate: func() error { return errors.New("password=do-not-log") }}
	if _, err := New(t.Context(), configs[:1], testDeps()); err == nil || strings.Contains(err.Error(), "do-not-log") {
		t.Fatalf("invalid optional plugin config accepted or exposed: %v", err)
	}
}

func TestPluginStartupRejectsInvalidHostSettings(t *testing.T) {
	for _, cfg := range []Config{
		{MaxConcurrency: -1}, {MaxConcurrency: 33}, {Egress: []string{"https://example.org?"}},
		{Credentials: map[string]string{"invalid-token!": "/tmp/token"}},
		{Credentials: map[string]string{"token": "relative-file"}},
	} {
		cfg.ID, cfg.Module = "valid", "inventory.host_test"
		if _, err := New(t.Context(), []Config{cfg}, testDeps()); err == nil || strings.Contains(err.Error(), "invalid-token!") {
			t.Fatalf("invalid config or leaked value: %v", err)
		}
	}
}
