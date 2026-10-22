package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCatalogTryScanContract(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "actions"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte("schema_version: 1\ncatalog_id: scan\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "actions/scan.yaml"), []byte("name: scan\ndescription: scan\nrisk: read\ntimeout: 1s\nmax_output: 1KB\nmax_scan: 8\nexec: [/usr/bin/printf, 'one\\ntwo\\nthree\\n']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, _, err := runCommand("try", "scan", "--dir", dir)
	var r struct {
		OK   bool `json:"ok"`
		Exit int  `json:"exit_code"`
		Scan bool `json:"scan_limit_reached"`
	}
	decodeErr := json.Unmarshal([]byte(out), &r)
	if err != nil || decodeErr != nil || !r.OK || r.Exit != 0 || !r.Scan {
		t.Errorf("catalog try result=%s err=%v decode=%v; want ok/exit0/scan_limit", out, err, decodeErr)
	}
}
