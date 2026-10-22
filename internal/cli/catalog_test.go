package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/catalog"
)

func runCommand(args ...string) (string, string, error) {
	c := NewCatalogCmd()
	var out, stderr bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&stderr)
	c.SetArgs(args)
	err := c.Execute()
	return out.String(), stderr.String(), err
}

func TestCatalogCommands(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "actions"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte("catalog_id: cli_test\nschema_version: 1\ndefaults: {timeout: 1s, max_output: 1KB}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	yaml := "name: echo_value\ndescription: echo\nrisk: read\nrun_as: root\nparams:\n  value: {type: string, max_len: 128, description: value}\n  n: {type: int, description: number, default: 1}\nexec: [/bin/echo, '{value}', '{n}']\n"
	if err := os.WriteFile(filepath.Join(dir, "actions", "echo_value.yaml"), []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(dir, "key.pem")
	public := filepath.Join(dir, "key.pub.pem")
	if _, _, err := runCommand("keygen", "--private-key", private, "--public-key", public); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(private); info.Mode().Perm() != 0600 {
		t.Fatalf("private key mode %v", info.Mode())
	}
	if _, _, err := runCommand("keygen", "--private-key", private, "--public-key", public); err == nil {
		t.Fatal("overwrote key")
	}
	if _, _, err := runCommand("validate", "--dir", dir); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCommand("validate", dir); err != nil {
		t.Fatal(err)
	}
	unsigned := filepath.Join(dir, "catalog.json")
	signed := filepath.Join(dir, "catalog.dsse.json")
	if _, _, err := runCommand("build", "--dir", dir, "--out", unsigned, "--git-commit", "ae79ac7"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCommand("sign", "--in", unsigned, "--out", signed, "--key", private); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(signed)
	e, err := catalog.ParseEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	publicData, _ := os.ReadFile(public)
	pub, err := catalog.ParsePublicKey(publicData)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Verify(e, map[string]ed25519.PublicKey{catalog.KeyID(pub): pub}, catalog.VerifyOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCommand("sign", "--in", signed, "--out", signed, "--key", private); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(signed)
	e, err = catalog.ParseEnvelope(data)
	if err != nil || len(e.Signatures) != 2 {
		t.Fatalf("append signature: %#v %v", e, err)
	}
	output, warnings, err := runCommand("try", "echo_value", "--dir", dir, "--param", "value=$(id)", "--param", "n=-2")
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		OK       bool   `json:"ok"`
		Action   string `json:"action"`
		Stdout   string `json:"stdout"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Action != "echo_value" || result.Stdout != "$(id) -2\n" || result.ExitCode != 0 || !strings.Contains(warnings, "run_as") {
		t.Fatalf("%#v stderr=%q", result, warnings)
	}
	for _, args := range [][]string{{"try", "echo_value", "--dir", dir, "--param", "value=a", "--param", "value=b"}, {"try", "echo_value", "--dir", dir, "--param", "value=a", "--param", "unknown=b"}, {"try", "echo_value", "--dir", dir, "--param", "n=1"}} {
		if _, _, err := runCommand(args...); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
}
