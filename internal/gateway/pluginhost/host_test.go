package pluginhost

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/inventory"
	_ "github.com/liubing0806/allowops/plugins/inventory/hostlabels"
	"gopkg.in/yaml.v3"
)

type testInventory struct {
	Mode string `yaml:"mode"`
}

func (testInventory) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "inventory.host_test", New: func() plugin.Module { return &testInventory{} }}
}
func (m *testInventory) Provision(ctx context.Context, h plugin.Host) error {
	if h.InstanceID() == "" || h.Logger() == nil {
		return errors.New("missing host capabilities")
	}
	if m.Mode == "provision" {
		return errors.New("private provision error password=hunter2")
	}
	return nil
}

var sharedEntity = inventory.Entity{Kind: "service", Name: "Shared", Attrs: map[string]string{"password": "x", "team": "ops"}, Hosts: []string{"host"}, DependsOn: []string{"database/db"}, Selector: "service=Shared"}

func (m *testInventory) Resolve(ctx context.Context, q inventory.Query) ([]inventory.Entity, error) {
	switch m.Mode {
	case "timeout":
		<-ctx.Done()
		<-releaseTimeout
		return []inventory.Entity{sharedEntity}, nil
	case "failed":
		return nil, errors.New("private source error password=hunter2")
	case "panic":
		panic("private panic password=hunter2")
	case "secret":
		return []inventory.Entity{{Kind: "service", Name: "password=hunter2", Selector: "service=https://u:hunter2@x.example",
			Attrs: map[string]string{jwtKey: "v", "team": "ops"}, Hosts: []string{"host"}}}, nil
	case "invalid":
		return []inventory.Entity{
			{Kind: "bad-kind", Name: "a"}, {Kind: "service", Name: ""}, {Kind: "service", Name: strings.Repeat("x", 129)},
			{Kind: "service", Name: "n\n"}, {Kind: "service", Name: "a", Attrs: map[string]string{"bad key": "x"}},
			{Kind: "service", Name: "a", Attrs: map[string]string{"ok": "x\r"}}, {Kind: "service", Name: "a", Selector: strings.Repeat("s", 513)},
			{Kind: "service", Name: "a", Hosts: []string{"x\n"}}, {Kind: "service", Name: "a", DependsOn: []string{"x\n"}},
			{Kind: "database", Name: "z"}, {Kind: "service", Name: "B"}, {Kind: "service", Name: "A", Selector: "password=x", DependsOn: []string{"password=x"}},
		}, nil
	}
	return []inventory.Entity{sharedEntity}, nil
}

var releaseTimeout chan struct{}

const jwtKey = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"

type wrongModule struct{}

func (wrongModule) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "inventory.wrong_test", New: func() plugin.Module { return &wrongModule{} }}
}

type wrongNamespace struct{ testInventory }

func (wrongNamespace) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "changes.host_test", New: func() plugin.Module { return &wrongNamespace{} }}
}
func init() {
	plugin.Register(testInventory{})
	plugin.Register(wrongModule{})
	plugin.Register(wrongNamespace{})
}
func config(t *testing.T, raw string) Config {
	t.Helper()
	var c Config
	d := yaml.NewDecoder(strings.NewReader(raw))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		t.Fatal(err)
	}
	return c
}
func testDeps() Deps { return Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))} }
func TestConfigErrors(t *testing.T) {
	base := Config{ID: "test", Module: "inventory.host_test"}
	tests := map[string][]Config{
		"id": {{ID: "Bad", Module: base.Module}}, "duplicate": {base, base}, "count": make([]Config, 33),
		"unknown module": {{ID: "test", Module: "inventory.absent"}}, "interface": {{ID: "test", Module: "inventory.wrong_test"}},
		"namespace":      {{ID: "test", Module: "changes.host_test"}},
		"unknown field":  {config(t, "id: test\nmodule: inventory.host_test\nconfig: {unknown: true}")},
		"alias":          {config(t, "id: test\nmodule: inventory.host_test\nconfig: {mode: &mode normal, other: *mode}")},
		"external alias": {config(t, "id: &id test\nmodule: inventory.host_test\nconfig: {mode: *id}")},
		"timeout low":    {{ID: "test", Module: base.Module, Timeout: 99 * time.Millisecond}},
		"timeout high":   {{ID: "test", Module: base.Module, Timeout: 31 * time.Second}},
	}
	for name, configs := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(context.Background(), configs, testDeps()); err == nil {
				t.Fatal("configuration accepted")
			} else if strings.Contains(name, "alias") && !strings.Contains(err.Error(), "plugin test: config contains YAML alias") {
				t.Fatal(err)
			}
		})
	}
}
func TestProvisionHealthAndDisabled(t *testing.T) {
	failed := config(t, "id: failed\nmodule: inventory.host_test\nconfig: {mode: provision}")
	h, err := New(context.Background(), []Config{failed, {ID: "disabled", Module: "absent", Disabled: true}, {ID: "ok", Module: "inventory.host_test"}}, testDeps())
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Health(); !reflect.DeepEqual(got, []Health{{ID: "failed", Module: failed.Module, OK: false}, {ID: "ok", Module: failed.Module, OK: true}}) {
		t.Fatal(got)
	}
	if !reflect.DeepEqual(h.InventorySources(), []string{"ok"}) {
		t.Fatal(h.InventorySources())
	}
	got := h.Health()
	got[0].OK = true
	if h.Health()[0].OK {
		t.Fatal("health aliases internal state")
	}
	failed.Required = true
	if _, err := New(context.Background(), []Config{failed}, testDeps()); err == nil {
		t.Fatal("required failure accepted")
	}
}
func TestResolveFailures(t *testing.T) {
	releaseTimeout = make(chan struct{})
	defer close(releaseTimeout)
	var configs []Config
	for _, mode := range []string{"timeout", "failed", "panic"} {
		configs = append(configs, config(t, "id: "+mode+"\nmodule: inventory.host_test\ntimeout: 100ms\nconfig: {mode: "+mode+"}"))
	}
	configs = append(configs, Config{ID: "ok", Module: "inventory.host_test"})
	h, err := New(context.Background(), configs, testDeps())
	if err != nil {
		t.Fatal(err)
	}
	results, errs := h.SearchInventory(context.Background(), Query{}, nil)
	if len(results) != 1 || !reflect.DeepEqual(errs, []SourceError{{"timeout", "timeout"}, {"failed", "failed"}, {"panic", "panic"}}) {
		t.Fatalf("results=%+v errors=%+v", results, errs)
	}
	for _, health := range h.Health() {
		if !health.OK {
			t.Fatal("query changed health")
		}
	}
	results, errs = h.SearchInventory(context.Background(), Query{}, []string{"ok"})
	if len(results) != 1 || len(errs) != 0 {
		t.Fatalf("source selection: %v %v", results, errs)
	}
}
func TestValidationFilteringSortingAndRedaction(t *testing.T) {
	c := config(t, "id: z\nmodule: inventory.host_test\nconfig: {mode: invalid}")
	c2 := c
	c2.ID = "a"
	h, err := New(context.Background(), []Config{c, c2}, testDeps())
	if err != nil {
		t.Fatal(err)
	}
	results, errs := h.SearchInventory(context.Background(), Query{}, nil)
	if len(errs) != 0 || len(results) != 6 {
		t.Fatalf("results=%+v errors=%+v", results, errs)
	}
	if results[0].Kind != "database" || results[0].Source != "a" || results[2].Name != "A" || results[4].Name != "B" {
		t.Fatal(results)
	}
	if results[2].Selector == "password=x" || results[2].DependsOn[0] == "password=x" {
		t.Fatal("secret not redacted")
	}
	results, _ = h.SearchInventory(context.Background(), Query{Kind: "service", Name: "b"}, nil)
	if len(results) != 2 || results[0].Name != "B" {
		t.Fatal(results)
	}
}
func TestConcurrentSearchOwnsResults(t *testing.T) {
	h, err := New(context.Background(), []Config{{ID: "test", Module: "inventory.host_test"}}, testDeps())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			for range 20 {
				results, errs := h.SearchInventory(context.Background(), Query{}, nil)
				if len(errs) != 0 || len(results) != 1 {
					t.Errorf("results=%v errors=%v", results, errs)
					return
				}
				e := results[0]
				if e.Attrs["password"] != "[REDACTED]" || e.Attrs["team"] != "ops" || e.Hosts[0] != "host" || e.DependsOn[0] != "database/db" {
					t.Error(e)
				}
				e.Attrs["team"] = "changed"
				e.Hosts[0] = "changed"
				e.DependsOn[0] = "changed"
			}
		})
	}
	wg.Wait()
	if sharedEntity.Attrs["password"] != "x" || sharedEntity.Attrs["team"] != "ops" || sharedEntity.Hosts[0] != "host" || sharedEntity.DependsOn[0] != "database/db" {
		t.Fatal(sharedEntity)
	}
}

func TestSecretsDoNotLeak(t *testing.T) {
	var logs bytes.Buffer
	deps := Deps{Logger: slog.New(slog.NewTextHandler(&logs, nil)), Hosts: func(context.Context) ([]plugin.HostInfo, error) {
		return []plugin.HostInfo{{Hostname: "h1", Labels: map[string]string{"service": "https://u:hunter2@x.example"}}}, nil
	}}
	var configs []Config
	for _, mode := range []string{"secret", "failed", "panic", "provision"} {
		configs = append(configs, config(t, "id: "+mode+"\nmodule: inventory.host_test\nconfig: {mode: "+mode+"}"))
	}
	configs = append(configs, config(t, "id: labels\nmodule: inventory.host_labels\nconfig: {label: service}"))
	h, err := New(context.Background(), configs, deps)
	if err != nil {
		t.Fatal(err)
	}
	results, errs := h.SearchInventory(context.Background(), Query{}, nil)
	if len(results) != 2 || len(errs) != 2 {
		t.Fatalf("results=%+v errors=%+v", results, errs)
	}
	for _, e := range results {
		if e.Selector != "" || len(e.Hosts) != 1 || strings.Contains(e.Name, "hunter2") {
			t.Errorf("redaction changed selector or kept secret: %+v", e)
		}
		if e.Source == "secret" && (len(e.Attrs) != 1 || e.Attrs["team"] != "ops") {
			t.Errorf("secret attribute key kept: %+v", e.Attrs)
		}
	}
	for _, probe := range []string{"password=h", "password=hunter2", "u:h"} {
		if results, _ := h.SearchInventory(context.Background(), Query{Name: probe}, []string{"secret", "labels"}); len(results) != 0 {
			t.Errorf("name probe %q matched %+v", probe, results)
		}
	}
	configs[3].Required = true
	if _, err := New(context.Background(), configs[3:4], deps); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("required provision error: %v", err)
	}
	if strings.Contains(logs.String(), "hunter2") {
		t.Errorf("logs contain secret: %s", logs.String())
	}
}
