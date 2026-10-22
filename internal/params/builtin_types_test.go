package params

import (
	"encoding/json"
	"testing"
)

func TestBuiltinBooleanAndArrayParameters(t *testing.T) {
	var defs map[string]Definition
	if err := json.Unmarshal([]byte(`{"fixed":{"type":"bool","description":"fixed","default":false},"args":{"type":"string_array","description":"args","max_items":2,"max_len":8,"optional":true}}`), &defs); err != nil {
		t.Fatal(err)
	}
	for _, input := range []map[string]any{{}, {"fixed": true, "args": []any{"key", "field"}}, {"args": []string{}}} {
		parsed, err := Parse(defs, input)
		if err != nil {
			t.Errorf("%v: %v", input, err)
			continue
		}
		if _, ok := parsed["fixed"].(bool); !ok {
			t.Error("fixed is not boolean")
		}
	}
	for _, input := range []map[string]any{{"fixed": "true"}, {"args": "key"}, {"args": nil}, {"args": []any{1}}, {"args": []string{"-option"}}, {"args": []string{"123456789"}}, {"args": []string{"a", "b", "c"}}} {
		if _, err := Parse(defs, input); err == nil {
			t.Errorf("accepted %v", input)
		}
	}
	schema, err := JSONSchema(defs)
	if err != nil {
		t.Fatal(err)
	}
	properties := schema["properties"].(map[string]any)
	if properties["fixed"].(map[string]any)["type"] != "boolean" || properties["args"].(map[string]any)["type"] != "array" {
		t.Fatal(properties)
	}
}
