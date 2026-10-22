package params

import (
	"encoding/json"
	"testing"
)

func TestReaderFutureDefinitionCommonValidation(t *testing.T) {
	negative := int64(-1)
	for _, tc := range []struct {
		name string
		def  Definition
	}{
		{"negative-length", Definition{MaxLen: -1}},
		{"negative-items", Definition{MaxItems: -1}},
		{"negative-min", Definition{Min: &negative}},
		{"negative-max", Definition{Max: -1}},
		{"negative-fraction", Definition{Max: json.Number("-0.5")}},
		{"invalid-regex", Definition{Regex: "["}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := tc.def
			d.Type = "future_type"
			d.Description = "future"
			if err := ValidateDefinitionsForReader(map[string]Definition{"future": d}); err == nil {
				t.Error("reader accepted malformed future constraint")
			}
		})
	}
	for _, tc := range []struct {
		name string
		def  Definition
	}{
		{"bad-name", Definition{Type: "future_type", Description: "future"}},
		{"future", Definition{Type: "bad\ntype", Description: "future"}},
		{"future", Definition{Type: "future_type"}},
		{"future", Definition{Description: "future"}},
	} {
		name := tc.name
		if name == "bad-name" {
			name = "BadName"
		}
		if err := ValidateDefinitionsForReader(map[string]Definition{name: tc.def}); err == nil {
			t.Errorf("reader accepted malformed definition %s", tc.name)
		}
	}
	for _, known := range []Definition{{Type: Enum, Description: "enum"}, {Type: String, Description: "string", Regex: "["}, {Type: Int, Description: "int", Default: "not-a-number"}} {
		defs := map[string]Definition{"a_future": {Type: "future_type", Description: "future"}, "z_known": known}
		if err := ValidateDefinitionsForReader(defs); err == nil {
			t.Error("future definition bypassed malformed known definition")
		}
	}
}
