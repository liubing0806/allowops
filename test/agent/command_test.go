package agenttest

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the installed command boundary, rather than just the JSON decoder.
func TestExecRejectsInvalidRequests(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "allowops-exec")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/allowops-exec")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for _, input := range []string{"", "not json", "{}", strings.Repeat("x", 128*1024+1)} {
		t.Run(strings.TrimSpace(input[:min(len(input), 12)]), func(t *testing.T) {
			command := exec.Command(binary)
			command.Stdin = strings.NewReader(input)
			if out, err := command.CombinedOutput(); err == nil {
				t.Fatalf("invalid stdin accepted: exit=0 output=%q", out)
			}
		})
	}
	for _, args := range [][]string{{""}, {"--version"}, {"--catalog", "/tmp/untrusted"}} {
		command := exec.Command(binary, args...)
		command.Stdin = bytes.NewBufferString("{}")
		if out, err := command.CombinedOutput(); err == nil {
			t.Errorf("argv %q accepted: exit=0 output=%q", args, out)
		}
	}
}
