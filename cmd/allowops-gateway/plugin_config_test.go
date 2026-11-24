package main

import (
	"strings"
	"testing"
)

func TestPluginConfigErrorsOmitValues(t *testing.T) {
	const value = "opaque-config-value"
	for _, input := range []string{
		"plugins: " + value,
		"plugins: {" + value + ": true}",
		"plugins:\n  - " + value,
		"plugins:\n  - timeout: " + value,
		"plugins:\n  - max_concurrency: " + value,
		"plugins:\n  - allow_private_egress: " + value,
		"plugins:\n  - egress: " + value,
		"plugins:\n  - " + value + ": true",
		"plugins:\n  - id: &name " + value + "\n    config: {mode: *name}",
	} {
		_, err := decodeConfig(strings.NewReader(input))
		if err == nil || strings.Contains(err.Error(), value) || !strings.Contains(err.Error(), "at line ") {
			t.Errorf("unexpected config error: %v", err)
		}
	}
}

func TestPluginConfigEmptyAndValid(t *testing.T) {
	for _, input := range []string{"plugins: null", "plugins: []", "{}"} {
		c, err := decodeConfig(strings.NewReader(input))
		if err != nil || len(c.Plugins) != 0 {
			t.Fatalf("%q: %v", input, err)
		}
	}
	c, err := decodeConfig(strings.NewReader("plugins:\n  - id: one\n    module: inventory.static\n    max_concurrency: 2\n    egress: [https://example.com]\n    credentials: {api: /safe/token}"))
	if err != nil || len(c.Plugins) != 1 || c.Plugins[0].MaxConcurrency != 2 || len(c.Plugins[0].Egress) != 1 || c.Plugins[0].Credentials["api"] != "/safe/token" {
		t.Fatalf("unexpected decoded plugins: %v, %v", c.Plugins, err)
	}
}
