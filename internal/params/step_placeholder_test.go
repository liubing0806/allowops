package params

import (
	"reflect"
	"strings"
	"testing"
)

func TestStepPlaceholder(t *testing.T) {
	long := "a" + strings.Repeat("b", 63)
	for _, name := range []string{"a", "a0_b", long} {
		word := "{steps." + name + ".value}"
		step, variable, ok := StepPlaceholder(word)
		if !ok || step != name || variable != "value" {
			t.Fatalf("StepPlaceholder(%q) = (%q, %q, %t)", word, step, variable, ok)
		}
		if key, ok := Placeholder(word); !ok || key != "steps."+name+".value" {
			t.Fatalf("Placeholder(%q) = (%q, %t)", word, key, ok)
		}
	}
	for _, word := range []string{
		"{steps.a}", "{steps.a.b.c}", "{steps.1a.b}", "{steps.a.B}", "{steps.a.a-b}",
		"{steps." + long + "b.x}", "{steps.a." + long + "b}", "prefix-{steps.a.b}",
		"{steps.a.b}-suffix", " {steps.a.b}", "{steps.a.b}\n",
	} {
		if _, _, ok := StepPlaceholder(word); ok {
			t.Errorf("accepted %q as a step placeholder", word)
		}
		if _, ok := Placeholder(word); ok {
			t.Errorf("accepted %q as a placeholder", word)
		}
	}
	if key, ok := Placeholder("{param}"); !ok || key != "param" {
		t.Fatalf("ordinary placeholder = (%q, %t)", key, ok)
	}
	if _, _, ok := StepPlaceholder("{param}"); ok {
		t.Fatal("ordinary placeholder recognized as a step placeholder")
	}
}

func TestRenderStepPlaceholder(t *testing.T) {
	defs := map[string]Definition{
		"prefix": {Type: String}, "steps.a.pid": {Type: Int},
		"steps.a.active": {Type: Bool}, "steps.a.label": {Type: String},
	}
	template := []any{"/bin/echo", "{prefix}", "{steps.a.pid}", "{steps.a.active}",
		[]any{"--label", "{steps.a.label}"}, "prefix-{steps.a.pid}"}
	values := map[string]any{"prefix": "process", "steps.a.pid": int64(0), "steps.a.active": false, "steps.a.label": ""}
	want := []string{"/bin/echo", "process", "0", "false", "--label", "", "prefix-{steps.a.pid}"}
	argv, err := Render(template, defs, values)
	if err != nil || !reflect.DeepEqual(argv, want) {
		t.Fatalf("Render = %q, %v, want %q", argv, err, want)
	}
	delete(values, "steps.a.label")
	argv, err = Render(template, defs, values)
	want = []string{"/bin/echo", "process", "0", "false", "prefix-{steps.a.pid}"}
	if err != nil || !reflect.DeepEqual(argv, want) {
		t.Fatalf("Render without optional value = %q, %v, want %q", argv, err, want)
	}
	if err := ValidateTemplate(template, map[string]Definition{"prefix": {Type: String}}); err == nil ||
		!strings.Contains(err.Error(), "unknown placeholder steps.a.pid") {
		t.Fatalf("ValidateTemplate with ordinary definitions = %v", err)
	}
}
