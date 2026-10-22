package params

import "testing"

func TestRejectTypeInapplicableConstraints(t *testing.T) {
	min := int64(1)
	for _, def := range []Definition{
		{Type: String, Description: "text", Max: 16},
		{Type: String, Description: "text", Min: &min},
		{Type: Int, Description: "number", Regex: `^[0-9]+$`},
		{Type: Enum, Description: "choice", Values: []string{"a"}, MaxLen: 10},
		{Type: Duration, Description: "delay", Max: "1h", AllowedRoots: []string{"/tmp"}},
		{Type: Path, Description: "path", AllowedRoots: []string{"/tmp"}, Format: "go"},
	} {
		if err := ValidateDefinitions(map[string]Definition{"value": def}); err == nil {
			t.Fatalf("accepted ignored constraint: %#v", def)
		}
	}
}
