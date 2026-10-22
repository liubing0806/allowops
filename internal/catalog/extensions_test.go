package catalog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtensionModes(t *testing.T) {
	base, _ := ParseAction([]byte(validAction))
	for _, mode := range []string{"filters", "steps", "fallback", "builtin"} {
		a := base
		switch mode {
		case "filters":
			a.Filters = []string{"match", "exclude", "tail", "head", "count"}
			a.MaxScan = 1024
		case "steps":
			a.Exec = nil
			a.Steps = []Step{{Name: "one", Exec: base.Exec}, {Name: "two", Exec: base.Exec}}
		case "fallback":
			a.ExecFallbacks = []string{"/bin/echo"}
		case "builtin":
			a.Exec = nil
			a.Params = nil
			a.Builtin = "mysql_query"
			a.BuiltinConfig = map[string]any{"credential": "/etc/allowops/credentials/test.json", "address": "tcp://127.0.0.1:3306"}
		}
		if _, err := ValidateAction(a); err != nil {
			t.Errorf("%s: %v", mode, err)
		}
	}
}

func TestWrapperCommands(t *testing.T) {
	for _, argv := range [][]any{
		{"/usr/bin/docker", "--context", "local", "exec", "-e", "X=x", "container", "echo"},
		{"/usr/bin/kubectl", "--namespace=local", "exec", "pod", "-c", "main", "--", "echo"},
		{"/usr/bin/env", "-i", "LANG=C", "echo"},
		{"/usr/bin/timeout", "--signal", "TERM", "5", "echo"},
		{"/usr/bin/nice", "-n", "5", "echo"},
		{"/usr/bin/ionice", "-c2", "echo"},
		{"/usr/bin/stdbuf", "-oL", "echo"},
		{"/usr/bin/xargs", "-n1", "echo"},
		{"/usr/bin/nsenter", "-t", "1", "--", "echo"},
		{"/usr/sbin/chroot", "/root", "echo"},
	} {
		a, _ := ParseAction([]byte(validAction))
		a.Exec = argv
		if _, err := ValidateAction(a); err != nil {
			t.Errorf("%q: %v", argv, err)
		}
	}
}

func TestScriptContentInDigest(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{"actions", "scripts"} {
		if err := os.Mkdir(filepath.Join(dir, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte("schema_version: 1\ncatalog_id: scripts\n"), 0600); err != nil {
		t.Fatal(err)
	}
	action := "name: script_test\ndescription: script\nrisk: read\ntimeout: 1s\nmax_output: 1KB\nscript: {file: scripts/test.py, interpreter: /usr/bin/python3}\n"
	if err := os.WriteFile(filepath.Join(dir, "actions/script_test.yaml"), []byte(action), 0600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "scripts/test.py")
	if err := os.WriteFile(script, []byte("print(1)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := ActionDigest(first.Actions["script_test"])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("print(2)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ActionDigest(second.Actions["script_test"])
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d2 {
		t.Fatal("script content did not change action digest")
	}
}

func TestInvalidExtensionCombinations(t *testing.T) {
	base, _ := ParseAction([]byte(validAction))
	for _, change := range []func(*Action){
		func(a *Action) { a.Steps = []Step{{Name: "one", Exec: a.Exec}} },
		func(a *Action) { a.OnError = "stop" },
		func(a *Action) { a.Args = []any{"arg"} },
		func(a *Action) { a.BuiltinConfig = map[string]any{} },
		func(a *Action) { a.Filters = []string{"match", "match"} },
		func(a *Action) { a.Filters = []string{"unknown"} },
		func(a *Action) { a.MaxScan = -1 },
		func(a *Action) { a.ExecFallbacks = []string{"/bin/sh"} },
		func(a *Action) {
			a.Exec = nil
			a.Steps = []Step{{Name: "same", Exec: base.Exec}, {Name: "same", Exec: base.Exec}}
		},
	} {
		a := base
		change(&a)
		if _, err := ValidateAction(a); err == nil {
			t.Fatalf("accepted %#v", a)
		}
	}
}

func TestFallbackHostSafety(t *testing.T) {
	a, _ := ParseAction([]byte(validAction))
	a.Exec[0] = filepath.Join(t.TempDir(), "missing")
	script := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	a.ExecFallbacks = []string{script, "/bin/echo"}
	if status := CheckHost(a); status.Supported {
		t.Fatal("skipped unsafe existing fallback", status)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink("/bin/sh", alias); err != nil {
		t.Fatal(err)
	}
	a.ExecFallbacks = []string{alias}
	if status := CheckHost(a); status.Supported {
		t.Fatal("accepted interpreter alias", status)
	}
}
