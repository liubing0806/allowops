package mcp

import (
	"encoding/json"
	"testing"
)

func TestFixedToolOmittedArgumentsUseEmptyObject(t *testing.T) {
	args, err := fixedArguments(nil, "hostname", "selector", "next_cursor")
	if err != nil || len(args) != 0 {
		t.Fatalf("omitted arguments=%v error=%v", args, err)
	}
}

func TestFixedToolEmptyStringsRespectSchema(t *testing.T) {
	for _, field := range []string{"hostname", "selector", "host", "next_cursor"} {
		data, _ := json.Marshal(map[string]any{field: ""})
		if _, err := fixedArguments(data, field); err == nil {
			t.Fatalf("accepted empty %s despite minLength=1", field)
		}
	}
}
