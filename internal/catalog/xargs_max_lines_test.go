package catalog

import (
	"os"
	"path/filepath"
	"testing"
)

// RR-c-03: GNU xargs takes the --max-lines argument only as --max-lines=N.
// A following word is the command to run, as with -l.
func TestHostXargsMaxLinesOptionalArgument(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	text := filepath.Join(dir, "text")
	if err := os.WriteFile(text, []byte("echo no shebang\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		argv []any
		want bool
	}{
		{"script as command", []any{"/usr/bin/xargs", "--max-lines", script, "/usr/bin/true"}, false},
		{"interpreter as command", []any{"/usr/bin/xargs", "--max-lines", "/bin/sh", text}, false},
		{"interpreter and ELF operand", []any{"/usr/bin/xargs", "--max-lines", "/bin/sh", "/usr/bin/true"}, false},
		{"short -l script", []any{"/usr/bin/xargs", "-l", script, "/usr/bin/true"}, false},
		{"attached value script", []any{"/usr/bin/xargs", "--max-lines=1", script}, false},
		{"separate -L value script", []any{"/usr/bin/xargs", "-L", "1", script}, false},
		{"ELF command", []any{"/usr/bin/xargs", "--max-lines", "/usr/bin/true", script}, true},
		{"attached value ELF", []any{"/usr/bin/xargs", "--max-lines=1", "/usr/bin/true", script}, true},
		{"separate -L value ELF", []any{"/usr/bin/xargs", "-L", "1", "/usr/bin/true", script}, true},
	}
	for _, tc := range cases {
		a := Action{Name: "xargs_lines", Description: "xargs lines", Risk: "read", Timeout: "1s", MaxOutput: 1024, Exec: tc.argv}
		if got := CheckHost(a); got.Supported != tc.want {
			t.Errorf("%s: %v supported=%t; want %t (%s)", tc.name, tc.argv, got.Supported, tc.want, got.Reason)
		}
		// CheckCommand sees names only, so it must pick /bin/sh as the program.
		strs := make([]string, len(tc.argv))
		for i, v := range tc.argv {
			strs[i] = v.(string)
		}
		if err := CheckCommand(strs, false); (err != nil) != (tc.argv[2] == "/bin/sh") {
			t.Errorf("%s: CheckCommand err=%v; interpreter command=%t", tc.name, err, tc.argv[2] == "/bin/sh")
		}
	}
}
