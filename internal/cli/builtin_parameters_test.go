package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
)

type nativeParameterBuiltin struct{}

func (nativeParameterBuiltin) Parameters(map[string]any) (map[string]params.Definition, error) {
	return map[string]params.Definition{
		"fixed": {Type: params.Bool, Description: "fixed", Default: false},
		"args":  {Type: params.StringArray, Description: "arguments", MaxLen: 8, MaxItems: 2},
	}, nil
}

func (nativeParameterBuiltin) ValidateConfig(map[string]any) error { return nil }

func (nativeParameterBuiltin) Run(_ context.Context, _ map[string]any, values map[string]any) (catalog.BuiltinResult, error) {
	return catalog.BuiltinResult{Stdout: fmt.Sprintf("%t %s\n", values["fixed"].(bool), strings.Join(values["args"].([]string), " "))}, nil
}

func TestCatalogTryNativeBuiltinInputs(t *testing.T) {
	const name = "cli_native_fixture"
	catalog.Builtins[name] = nativeParameterBuiltin{}
	defer delete(catalog.Builtins, name)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "actions"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte("schema_version: 1\ncatalog_id: native\ndefaults: {timeout: 1s, max_output: 1KB}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "actions/native.yaml"), []byte("name: native\ndescription: native parameters\nrisk: read\nbuiltin: cli_native_fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, _, err := runCommand("try", "native", "--dir", dir, "--param", "fixed=true", "--param", `args=["key","field"]`)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Stdout string `json:"stdout"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil || result.Stdout != "true key field\n" {
		t.Fatalf("out=%s err=%v", out, err)
	}
	for _, bad := range []string{`null`, `[1]`, `["-option"]`, `["a","b","c"]`} {
		if _, _, err := runCommand("try", "native", "--dir", dir, "--param", "args="+bad); err == nil {
			t.Errorf("accepted args=%s", bad)
		}
	}
}
