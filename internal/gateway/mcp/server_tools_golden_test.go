package mcp

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// TestServerToolsGolden pins the initialize result and tools/list output that
// serverFor builds in the default flat mode for an admin and a viewer identity.
func TestServerToolsGolden(t *testing.T) {
	f := newTransportFixture(t)
	checkToolsGolden(t, f, map[string]string{"admin": f.admin, "viewer": f.viewer}, "testdata/server_tools_golden.json")
}

// TestServerToolsProgressiveGolden pins progressive tools/list output: admin
// sees read, write and dangerous actions, readonly only read actions, and
// viewer none.
func TestServerToolsProgressiveGolden(t *testing.T) {
	f := newProgressiveFixture(t, func(c *Config) { c.Mode = modeProgressive })
	checkToolsGolden(t, f.transportFixture, map[string]string{"admin": f.admin, "readonly": f.reader, "viewer": f.viewer}, "testdata/server_tools_progressive_golden.json")
}

func checkToolsGolden(t *testing.T, f *transportFixture, tokens map[string]string, path string) {
	t.Helper()
	out := map[string]any{}
	for name, token := range tokens {
		c, _ := f.client(t, token, nil)
		list, err := c.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		init := c.InitializeResult()
		out[name] = map[string]any{"instructions": init.Instructions, "capabilities": init.Capabilities, "serverInfo": init.ServerInfo, "tools": list.Tools}
	}
	got, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("tools/list output differs from %s; set UPDATE_GOLDEN=1 only for an intended behavior change", path)
	}
}
