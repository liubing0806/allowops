package catalog

import (
	"testing"

	"github.com/liubing0806/allowops/internal/params"
)

// Security 8: global-option operands and omitted argv lists cannot conceal a dynamic exec subcommand.
func TestSecurity8DynamicWrapperRejection(t *testing.T) {
	for _, argv := range [][]any{
		{"/usr/bin/docker", "--context", "local", "{command}", "target", "echo"},
		{"/usr/bin/kubectl", "--context", "local", "{command}", "pod", "--", "echo"},
		{"/usr/bin/docker", []any{"ps", "{optional}"}, "{command}", "target", "echo"},
	} {
		a, _ := ParseAction([]byte(validAction))
		a.Exec = argv
		a.Params = map[string]params.Definition{
			"command":  {Type: params.String, Description: "command", MaxLen: 16},
			"optional": {Type: params.String, Description: "optional", Optional: true, MaxLen: 16},
		}
		if _, err := ValidateAction(a); err == nil {
			t.Fatalf("accepted dynamic wrapper %q: %v", argv, err)
		}
	}
}
