package attack

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/executor"
	"github.com/liubing0806/allowops/internal/params"
)

func attackAction(argv []any) catalog.Action {
	return catalog.Action{Name: "attack", Description: "attack", Risk: "read", Exec: argv, Timeout: "1s", MaxOutput: 1024}
}

func TestWrappedInterpreterAttacks(t *testing.T) {
	for _, argv := range [][]any{
		{"/usr/bin/docker", "exec", "-e", "X=echo", "container", "sh"},
		{"/usr/bin/docker", "--context=local", "exec", "--", "container", "bash"},
		{"/usr/bin/kubectl", "-n", "default", "exec", "pod", "-c", "container", "--", "awk"},
		{"/usr/bin/kubectl", "exec", "-ccontainer", "pod", "--", "sed"},
		{"/usr/bin/env", "-i", "sh"}, {"/usr/bin/env", "--", "sh"},
		{"/usr/bin/env", "-S", "echo sh"},
		{"/usr/bin/timeout", "5", "bash"}, {"/usr/bin/timeout", "-sTERM", "--", "5", "bash"},
		{"/usr/bin/xargs", "sh"}, {"/usr/bin/xargs", "-I{}", "--", "sh"},
		{"/usr/bin/nsenter", "-t", "1", "--", "sh"},
		{"/usr/bin/nsenter", "--mount=/proc/1/ns/mnt", "--target=1", "--", "sh"},
		{"/usr/sbin/chroot", "--userspec=0:0", "/", "sh"},
		{"/usr/bin/nice", "-n5", "/usr/bin/env", "-i", "sh"},
		{"/usr/bin/ionice", "-c", "2", "mawk"}, {"/usr/bin/stdbuf", "-oL", "gawk"},
	} {
		a := attackAction(argv)
		if _, err := catalog.ValidateAction(a); err == nil {
			t.Errorf("accepted %q", argv)
		}
		if _, err := executor.Run(context.Background(), a, nil, nil); err == nil {
			t.Errorf("executed %q", argv)
		}
		a.AllowInterpreter = true
		if strings.Contains(strings.Join(catalogWords(argv), " "), "-S") {
			continue
		}
		warnings, err := catalog.ValidateAction(a)
		if err != nil || len(warnings) == 0 {
			t.Errorf("override %q: warnings=%v err=%v", argv, warnings, err)
		}
	}
}

func catalogWords(argv []any) []string {
	out := []string{}
	for _, value := range argv {
		out = append(out, value.(string))
	}
	return out
}

func TestTTYAlwaysRejected(t *testing.T) {
	for _, name := range []string{"docker", "kubectl"} {
		for _, option := range []string{"-t", "-it", "-ti", "--tty", "--tty=true", "--tty=false"} {
			argv := []any{"/usr/bin/" + name, "exec", option, "target"}
			if name == "kubectl" {
				argv = append(argv, "--")
			}
			argv = append(argv, "echo")
			a := attackAction(argv)
			a.AllowInterpreter = true
			if _, err := catalog.ValidateAction(a); err == nil {
				t.Errorf("accepted %q", argv)
			}
		}
	}
	// kubectl permits options after the pod, including combined stdin/tty flags.
	a := attackAction([]any{"/usr/bin/kubectl", "exec", "pod", "-it", "--", "echo"})
	if _, err := catalog.ValidateAction(a); err == nil {
		t.Fatal("accepted tty after pod")
	}
}

func TestRenderedWrapperAttack(t *testing.T) {
	a := attackAction([]any{"/usr/bin/env", "{mode}", "sh"})
	a.Params = map[string]params.Definition{"mode": {Type: params.Enum, Description: "mode", Values: []string{"-i", "LANG=C"}}}
	if _, err := executor.Run(context.Background(), a, map[string]any{"mode": "-i"}, nil); err == nil {
		t.Fatal("rendered interpreter accepted")
	}
}

func TestURLBypassAttacks(t *testing.T) {
	for _, value := range []string{
		"https://example.com.evil/api", "https://example.com@evil/api", "https://evil@example.com/api",
		"https://example.com/api/..%2fsecret", "https://example.com/api/%2E%2E/secret", "https://example.com/api/%252fsecret",
		"https://example.com/api%5csecret", "https://example.com/api/%09secret", "https://example.com:4430/api", "https://example.com/api-other",
	} {
		if _, err := params.ParseURL(value, []string{"https://example.com/api"}); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}

func TestScriptCatalogSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "script.py")
	if err := os.WriteFile(outside, []byte("print(1)"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "actions"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "script.py")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte("catalog_id: attack\nschema_version: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "actions/attack.yaml"), []byte("name: attack\ndescription: attack\nrisk: read\nscript: {file: script.py, interpreter: /usr/bin/python3}\ntimeout: 1s\nmax_output: 1KB\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Load(dir); err == nil {
		t.Fatal("accepted source symlink")
	}
}

func TestScriptConcurrentExecution(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "actions"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte("catalog_id: script_race\nschema_version: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source := `import os, sys
print(oct(os.stat(os.path.dirname(__file__)).st_mode & 0o777))
print(__file__)
print(sys.flags.isolated)
`
	if err := os.WriteFile(filepath.Join(dir, "script.py"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "actions/script_race.yaml"), []byte("name: script_race\ndescription: script\nrisk: read\nscript: {file: script.py, interpreter: /usr/bin/python3}\ntimeout: 2s\nmax_output: 1KB\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := c.Actions["script_race"]
	// Mutation after loading cannot alter the embedded, signed source.
	if err := os.WriteFile(filepath.Join(dir, "script.py"), []byte("raise Exception('changed')"), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan executor.Result, 8)
	for i := 0; i < 8; i++ {
		go func() {
			r, err := executor.Run(context.Background(), a, nil, nil)
			if err != nil {
				t.Error(err)
			}
			done <- r
		}()
	}
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		r := <-done
		lines := strings.Split(strings.TrimSpace(r.Stdout), "\n")
		if r.ExitCode != 0 || len(lines) != 3 || lines[0] != "0o700" || lines[2] != "1" {
			t.Fatalf("script: %#v", r)
		}
		if seen[lines[1]] {
			t.Fatal("shared script path")
		}
		seen[lines[1]] = true
		if _, err := os.Stat(filepath.Dir(lines[1])); !os.IsNotExist(err) {
			t.Fatalf("directory retained: %s %v", lines[1], err)
		}
	}
}

func TestFilterRegexLengthAttack(t *testing.T) {
	a := attackAction([]any{"/bin/echo", "safe"})
	a.Filters = []string{"match"}
	r, err := executor.Run(context.Background(), a, map[string]any{"match": strings.Repeat("x", 201)}, nil)
	if err == nil || r.Stdout != "" {
		t.Fatalf("long regex: %#v %v", r, err)
	}
}
func TestInterpreterProgramTextAttack(t *testing.T) {
	for _, argv := range [][]any{{"/bin/sh", "-c", "{cmd}"}, {"/usr/bin/env", "watch", "-n1", "{cmd}"}} {
		a := attackAction(argv)
		a.AllowInterpreter = true
		a.Params = map[string]params.Definition{"cmd": {Type: params.String, Description: "cmd", MaxLen: 64}}
		r, err := executor.Run(context.Background(), a, map[string]any{"cmd": "echo injected"}, nil)
		if err == nil || strings.Contains(r.Stdout, "injected") {
			t.Errorf("%q ran caller program text: %#v %v", argv, r, err)
		}
	}
}
