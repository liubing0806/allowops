package params

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func definitions() map[string]Definition {
	min := int64(-5)
	return map[string]Definition{
		"service": {Type: Enum, Values: []string{"api", "nginx"}, Description: "service"},
		"n":       {Type: Int, Min: &min, Max: 500, Default: 100, Description: "number"},
		"since":   {Type: String, Regex: `^[0-9]+ (min|hour) ago$`, MaxLen: 16, Optional: true, Description: "since"},
		"delay":   {Type: Duration, Max: "2h", Default: "1h", Description: "delay"},
	}
}

// Security 2: only complete argv elements are substituted; optional lists are atomic.
func TestSecurity2Render(t *testing.T) {
	d := definitions()
	v, err := Parse(d, map[string]any{"service": "api", "n": json.Number("-2")})
	if err != nil {
		t.Fatal(err)
	}
	argv, err := Render([]any{"/bin/echo", "{service}", "{n}", "{delay}", "prefix{service}", "{{json .}}", []any{"--since", "{since}"}}, d, v)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/bin/echo", "api", "-2", "1h0m0s", "prefix{service}", "{{json .}}"}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("got %q, want %q", argv, want)
	}
	delay := d["delay"]
	delay.Format = "seconds"
	d["delay"] = delay
	argv, err = Render([]any{"/bin/echo", "{delay}"}, d, v)
	if err != nil || argv[1] != "3600" {
		t.Fatalf("got %q, err %v", argv, err)
	}
	v, err = Parse(d, map[string]any{"service": "api", "since": "1 min ago", "delay": "1.25s"})
	if err != nil {
		t.Fatal(err)
	}
	argv, err = Render([]any{"/bin/echo", []any{"--since", "{since}"}, "{delay}"}, d, v)
	if err != nil || !reflect.DeepEqual(argv, []string{"/bin/echo", "--since", "1 min ago", "1.25"}) {
		t.Fatalf("%q %v", argv, err)
	}
	argv, err = Render([]any{"/bin/echo", []any{"{service}", "{since}"}}, d, map[string]any{"service": "api"})
	if err != nil || len(argv) != 1 {
		t.Fatalf("optional list not omitted atomically: %q %v", argv, err)
	}
}

// Security 3 and 9: reject options, unknown names, missing inputs, wrong types and bounds.
func TestSecurity3And9RejectParameters(t *testing.T) {
	d := definitions()
	for _, input := range []map[string]any{
		{}, {"service": "bad"}, {"service": 42}, {"service": "api", "unknown": 1},
		{"service": "api", "n": "1"}, {"service": "api", "n": 1.5}, {"service": "api", "n": 501},
		{"service": "api", "since": "--output=/etc/passwd"}, {"service": "api", "delay": "3h"},
		{"service": "api", "since": strings.Repeat("a", 10000)}, {"service": "api", "since": "1 min ago\x00"},
	} {
		if _, err := Parse(d, input); err == nil || !strings.Contains(err.Error(), "allowed") {
			t.Fatalf("input %#v: expected allowed values error, got %v", input, err)
		}
	}
}

// Security 4: resolve symlinks before checking path-component boundaries.
func TestSecurity4Path(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	d := map[string]Definition{"path": {Type: Path, AllowedRoots: []string{root}, Description: "path"}}
	for _, p := range []string{link, filepath.Join(root, "..", filepath.Base(outside)), root + "-suffix", "../../etc/shadow", "-bad", filepath.Join(root, "missing")} {
		if _, err := Parse(d, map[string]any{"path": p}); err == nil {
			t.Fatalf("accepted %q", p)
		}
	}
	v, err := Parse(d, map[string]any{"path": file})
	if err != nil || v["path"] != file {
		t.Fatalf("%#v %v", v, err)
	}
}

func TestDefinitionsAndJSONSchema(t *testing.T) {
	d := definitions()
	schema, err := JSONSchema(d)
	if err != nil {
		t.Fatal(err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" || schema["additionalProperties"] != false {
		t.Fatal(schema)
	}
	if !reflect.DeepEqual(schema["required"], []string{"service"}) {
		t.Fatal(schema["required"])
	}
	for _, def := range []Definition{
		{Type: Enum, Description: "x"}, {Type: String, Regex: "[", Description: "x"},
		{Type: Duration, Max: "bad", Description: "x"}, {Type: Path, Description: "x"},
		{Type: "url", Description: "x"}, {Type: Int, Description: "x", Default: "bad"},
	} {
		if err := ValidateDefinitions(map[string]Definition{"x": def}); err == nil {
			t.Fatalf("accepted %#v", def)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{`{"service":"api"}`, `{"service":"api","n":5}`, `{"service":"$(id)"}`, `{"n":null}`, `[]`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var input map[string]any
		decoder := json.NewDecoder(strings.NewReader(s))
		decoder.UseNumber()
		if decoder.Decode(&input) != nil {
			return
		}
		v, err := Parse(definitions(), input)
		if err == nil {
			if _, err := Render([]any{"/bin/echo", "{service}", "{n}", "{delay}"}, definitions(), v); err != nil {
				t.Fatal(err)
			}
		}
	})
}
