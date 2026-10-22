package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCatalogTryPrefersActionParameterType(t *testing.T) {
	for _, name := range []string{"count", "head", "tail"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "actions"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte("catalog_id: filters\nschema_version: 1\ndefaults: {timeout: 1s, max_output: 1KB}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			action := fmt.Sprintf("name: named_param\ndescription: named parameter\nrisk: read\nparams:\n  %s: {type: string, description: action parameter}\nfilters: [%s]\nexec: [/bin/echo, '{%s}']\n", name, name, name)
			if err := os.WriteFile(filepath.Join(dir, "actions/named_param.yaml"), []byte(action), 0600); err != nil {
				t.Fatal(err)
			}
			out, _, err := runCommand("try", "named_param", "--dir", dir, "--param", name+"=123")
			if err != nil {
				t.Fatal(err)
			}
			var r struct {
				Stdout string `json:"stdout"`
			}
			if err := json.Unmarshal([]byte(out), &r); err != nil {
				t.Fatal(err)
			}
			if r.Stdout != "123\n" {
				t.Fatalf("stdout=%q; want action string argument", r.Stdout)
			}
		})
	}
}
