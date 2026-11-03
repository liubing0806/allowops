package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
)

func TestInventoryPluginConfiguration(t *testing.T) {
	cfg, err := decodeConfig(strings.NewReader(`plugins:
  - id: static
    module: inventory.static
    required: true
    timeout: 100ms
    config:
      file: ../../examples/topology.yaml
  - id: labels
    module: inventory.host_labels
    disabled: true
    config:
      label: service
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Plugins) != 2 || cfg.Plugins[0].Timeout != 100*time.Millisecond || !cfg.Plugins[0].Required || !cfg.Plugins[1].Disabled {
		t.Fatal(cfg.Plugins)
	}
	h, err := pluginhost.New(context.Background(), cfg.Plugins, pluginhost.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	sources := h.InventorySources()
	if len(sources) != 1 || sources[0] != "static" {
		t.Fatal(sources)
	}
	results, errors := h.SearchInventory(context.Background(), pluginhost.Query{Kind: "service"}, nil)
	if len(errors) != 0 || len(results) != 1 || results[0].Name != "order-api" {
		t.Fatalf("%v %v", results, errors)
	}
	for _, raw := range []string{
		"plugins: [{id: a, module: inventory.static, unknown: true}]",
		"plugins: [{id: a, module: inventory.static, max_concurrency: 4}]",
	} {
		if _, err := decodeConfig(strings.NewReader(raw)); err == nil {
			t.Fatalf("unknown plugin field accepted: %s", raw)
		}
	}
	cfg, err = decodeConfig(strings.NewReader("plugins: [{id: static, module: inventory.static, config: {unknown: true}}]"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pluginhost.New(context.Background(), cfg.Plugins, pluginhost.Deps{}); err == nil {
		t.Fatal("unknown module config field accepted")
	}
}
