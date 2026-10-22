package executor

import (
	"github.com/liubing0806/allowops/internal/redact"
	"strings"
	"testing"
)

func TestEmptyExcludePattern(t *testing.T) {
	options, err := ParseFilters([]string{"exclude"}, map[string]any{"exclude": ""})
	if err != nil {
		t.Fatal(err)
	}
	output := &limitedOutput{limit: 32}
	r, _ := redact.New(nil)
	if err := streamStdout(strings.NewReader("visible\n"), output, r, options, 1024); err != nil {
		t.Fatal(err)
	}
	if got := output.buffer.String(); got != "" {
		t.Fatalf("empty RE2 matches every line; got %q, want empty", got)
	}
}
