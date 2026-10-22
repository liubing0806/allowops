package params

import "testing"

func TestGatewayPathsCheckRootsWithoutLocalFilesystem(t *testing.T) {
	defs := map[string]Definition{"path": {Type: Path, Description: "remote file", AllowedRoots: []string{"/remote"}}}
	if _, err := ParseGateway(defs, map[string]any{"path": "/remote/exists-only-on-agent"}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/outside", "/remote-other/file", "/remote/../outside"} {
		if _, err := ParseGateway(defs, map[string]any{"path": path}); err == nil {
			t.Fatalf("accepted path outside signed roots: %s", path)
		}
	}
}
