package mcp

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// TestServerToolsGolden pins the initialize result and tools/list output that
// serverFor builds for an admin and a viewer identity.
func TestServerToolsGolden(t *testing.T) {
	f := newTransportFixture(t)
	out := map[string]any{}
	for name, token := range map[string]string{"admin": f.admin, "viewer": f.viewer} {
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
	path := "testdata/server_tools_golden.json"
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
