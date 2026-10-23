package params

import (
	"encoding/json"
	"math"
	"testing"
)

// Characterizes the exact error (and its precedence) for every rejection branch
// of validateDefinitions so that refactoring cannot change what is reported.
func TestValidateDefinitionsErrorBranches(t *testing.T) {
	neg := int64(-1)
	one := int64(1)
	for _, tc := range []struct {
		name   string
		defs   map[string]Definition
		reader bool
		want   string
	}{
		{name: "bad name", defs: map[string]Definition{"Bad": {Type: String, Description: "d"}}, want: `parameter "Bad": valid name and description required`},
		{name: "blank description", defs: map[string]Definition{"x": {Type: String, Description: "  "}}, want: `parameter "x": valid name and description required`},
		{name: "name before constraints", defs: map[string]Definition{"X": {Type: String, Description: "d", Min: &one}}, want: `parameter "X": valid name and description required`},
		{name: "constraint min on string", defs: map[string]Definition{"x": {Type: String, Description: "d", Min: &one}}, want: "parameter x: constraints do not apply to type string; allowed: enum(values), int(min,max), string(regex,max_len), duration(max,format), path(allowed_roots)"},
		{name: "constraint values on int", defs: map[string]Definition{"x": {Type: Int, Description: "d", Values: []string{"a"}}}, want: "parameter x: constraints do not apply to type int; allowed: enum(values), int(min,max), string(regex,max_len), duration(max,format), path(allowed_roots)"},
		{name: "constraint max on bool", defs: map[string]Definition{"x": {Type: Bool, Description: "d", Max: 1}}, want: "parameter x: constraints do not apply to type bool; allowed: enum(values), int(min,max), string(regex,max_len), duration(max,format), path(allowed_roots)"},
		{name: "constraint max_items on string", defs: map[string]Definition{"x": {Type: String, Description: "d", MaxItems: 2}}, want: "parameter x: constraints do not apply to type string; allowed: enum(values), int(min,max), string(regex,max_len), duration(max,format), path(allowed_roots)"},
		{name: "constraint format on path", defs: map[string]Definition{"x": {Type: Path, Description: "d", Format: "go"}}, want: "parameter x: constraints do not apply to type path; allowed: enum(values), int(min,max), string(regex,max_len), duration(max,format), path(allowed_roots)"},
		{name: "constraint prefixes on path", defs: map[string]Definition{"x": {Type: Path, Description: "d", AllowedPrefixes: []string{"http://a/"}}}, want: "parameter x: constraints do not apply to type path; allowed: enum(values), int(min,max), string(regex,max_len), duration(max,format), path(allowed_roots)"},
		{name: "constraint roots on url", defs: map[string]Definition{"x": {Type: URL, Description: "d", AllowedRoots: []string{"/a"}}}, want: "parameter x: constraints do not apply to type url; allowed: enum(values), int(min,max), string(regex,max_len), duration(max,format), path(allowed_roots)"},
		{name: "enum empty", defs: map[string]Definition{"x": {Type: Enum, Description: "d"}}, want: "parameter x: enum values required"},
		{name: "enum duplicate", defs: map[string]Definition{"x": {Type: Enum, Description: "d", Values: []string{"a", "a"}}}, want: "parameter x: invalid or duplicate enum value"},
		{name: "enum invalid text", defs: map[string]Definition{"x": {Type: Enum, Description: "d", Values: []string{"a\nb"}}}, want: "parameter x: invalid or duplicate enum value"},
		{name: "int max not integer", defs: map[string]Definition{"x": {Type: Int, Description: "d", Max: "five"}}, want: "parameter x: invalid integer bounds"},
		{name: "int min above max", defs: map[string]Definition{"x": {Type: Int, Description: "d", Min: &one, Max: 0}}, want: "parameter x: invalid integer bounds"},
		{name: "string negative max_items", defs: map[string]Definition{"x": {Type: String, Description: "d", MaxItems: -1}}, want: "parameter x: constraints do not apply to type string; allowed: enum(values), int(min,max), string(regex,max_len), duration(max,format), path(allowed_roots)"},
		{name: "string array negative max_items", defs: map[string]Definition{"x": {Type: StringArray, Description: "d", MaxItems: -1}}, want: "parameter x: max_items must be nonnegative"},
		{name: "string negative max_len", defs: map[string]Definition{"x": {Type: String, Description: "d", MaxLen: -1}}, want: "parameter x: max_len must be nonnegative"},
		{name: "string array negative max_len", defs: map[string]Definition{"x": {Type: StringArray, Description: "d", MaxLen: -1}}, want: "parameter x: max_len must be nonnegative"},
		{name: "string bad regex", defs: map[string]Definition{"x": {Type: String, Description: "d", Regex: "["}}, want: "parameter x: error parsing regexp: missing closing ]: `[`"},
		{name: "duration max missing", defs: map[string]Definition{"x": {Type: Duration, Description: "d"}}, want: "parameter x: duration max required (Go duration)"},
		{name: "duration max not string", defs: map[string]Definition{"x": {Type: Duration, Description: "d", Max: 5}}, want: "parameter x: duration max required (Go duration)"},
		{name: "duration max unparsable", defs: map[string]Definition{"x": {Type: Duration, Description: "d", Max: "bad"}}, want: "parameter x: duration max required (Go duration)"},
		{name: "duration max negative", defs: map[string]Definition{"x": {Type: Duration, Description: "d", Max: "-1s"}}, want: "parameter x: duration max required (Go duration)"},
		{name: "duration bad format", defs: map[string]Definition{"x": {Type: Duration, Description: "d", Max: "1s", Format: "hex"}}, want: "parameter x: format allowed: go, seconds"},
		{name: "url prefixes missing", defs: map[string]Definition{"x": {Type: URL, Description: "d"}}, want: "parameter x: allowed_prefixes required"},
		{name: "path roots missing", defs: map[string]Definition{"x": {Type: Path, Description: "d"}}, want: "parameter x: allowed_roots required"},
		{name: "path root relative", defs: map[string]Definition{"x": {Type: Path, Description: "d", AllowedRoots: []string{"rel"}}}, want: "parameter x: allowed_roots must be absolute paths"},
		{name: "path root invalid text", defs: map[string]Definition{"x": {Type: Path, Description: "d", AllowedRoots: []string{"/a\nb"}}}, want: "parameter x: allowed_roots must be absolute paths"},
		{name: "unsupported type", defs: map[string]Definition{"x": {Type: "future", Description: "d"}}, want: `parameter x: type "future" unsupported; allowed: enum, int, string, duration, path, url, bool, string_array`},
		{name: "empty type", defs: map[string]Definition{"x": {Description: "d"}}, want: `parameter x: type "" unsupported; allowed: enum, int, string, duration, path, url, bool, string_array`},
		{name: "reader empty type", reader: true, defs: map[string]Definition{"x": {Description: "d"}}, want: "parameter x: invalid type or description"},
		{name: "reader invalid type text", reader: true, defs: map[string]Definition{"x": {Type: "a\nb", Description: "d"}}, want: "parameter x: invalid type or description"},
		{name: "reader invalid description text", reader: true, defs: map[string]Definition{"x": {Type: "future", Description: "d\x00"}}, want: "parameter x: invalid type or description"},
		{name: "reader negative max_len", reader: true, defs: map[string]Definition{"x": {Type: "future", Description: "d", MaxLen: -1}}, want: "parameter x: constraints must be nonnegative"},
		{name: "reader negative max_items", reader: true, defs: map[string]Definition{"x": {Type: "future", Description: "d", MaxItems: -1}}, want: "parameter x: constraints must be nonnegative"},
		{name: "reader negative min", reader: true, defs: map[string]Definition{"x": {Type: "future", Description: "d", Min: &neg}}, want: "parameter x: constraints must be nonnegative"},
		{name: "reader bad json number", reader: true, defs: map[string]Definition{"x": {Type: "future", Description: "d", Max: json.Number("nope")}}, want: "parameter x: invalid numeric maximum"},
		{name: "reader negative max int", reader: true, defs: map[string]Definition{"x": {Type: "future", Description: "d", Max: -1}}, want: "parameter x: numeric maximum must be nonnegative and finite"},
		{name: "reader negative max int64", reader: true, defs: map[string]Definition{"x": {Type: "future", Description: "d", Max: int64(-1)}}, want: "parameter x: numeric maximum must be nonnegative and finite"},
		{name: "reader nan max", reader: true, defs: map[string]Definition{"x": {Type: "future", Description: "d", Max: math.NaN()}}, want: "parameter x: numeric maximum must be nonnegative and finite"},
		{name: "reader inf max", reader: true, defs: map[string]Definition{"x": {Type: "future", Description: "d", Max: math.Inf(1)}}, want: "parameter x: numeric maximum must be nonnegative and finite"},
		{name: "reader bad regex", reader: true, defs: map[string]Definition{"x": {Type: "future", Description: "d", Regex: "["}}, want: "parameter x: error parsing regexp: missing closing ]: `[`"},
		{name: "default invalid", defs: map[string]Definition{"x": {Type: Int, Description: "d", Default: "bad"}}, want: "parameter x default: expected integer"},
		{name: "sorted order reports first name", defs: map[string]Definition{"b_x": {Type: Enum, Description: "d"}, "a_x": {Type: Path, Description: "d"}}, want: "parameter a_x: allowed_roots required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			validate := ValidateDefinitions
			if tc.reader {
				validate = ValidateDefinitionsForReader
			}
			err := validate(tc.defs)
			if err == nil {
				t.Fatal("accepted")
			}
			if err.Error() != tc.want {
				t.Fatalf("got  %q\nwant %q", err.Error(), tc.want)
			}
		})
	}
}

// Pins the full text of the two messages whose suffix comes from a parser.
func TestValidateDefinitionsWrappedMessages(t *testing.T) {
	err := ValidateDefinitions(map[string]Definition{"x": {Type: Int, Description: "d", Default: "bad"}})
	if err == nil || err.Error()[:len("parameter x default: ")] != "parameter x default: " {
		t.Fatalf("%v", err)
	}
	err = ValidateDefinitions(map[string]Definition{"x": {Type: URL, Description: "d", AllowedPrefixes: []string{"ftp://bad/"}}})
	if err == nil || err.Error()[:len("parameter x: ")] != "parameter x: " {
		t.Fatalf("%v", err)
	}
}

func TestValidateDefinitionsAcceptsAndSkipsFutureDefault(t *testing.T) {
	// Understood types are accepted, and a reader-mode future type returns
	// before its default would be parsed.
	defs := map[string]Definition{
		"e": {Type: Enum, Description: "d", Values: []string{"a", "b"}, Default: "a"},
		"i": {Type: Int, Description: "d", Max: 5, Default: 3},
		"b": {Type: Bool, Description: "d"},
		"s": {Type: StringArray, Description: "d", MaxItems: 2, MaxLen: 4, Regex: "^a"},
		"t": {Type: Duration, Description: "d", Max: "1h", Format: "seconds"},
		"u": {Type: URL, Description: "d", AllowedPrefixes: []string{"https://example.com/"}},
		"p": {Type: Path, Description: "d", AllowedRoots: []string{"/tmp"}},
	}
	if err := ValidateDefinitions(defs); err != nil {
		t.Fatal(err)
	}
	defs["f"] = Definition{Type: "future", Description: "d", Default: struct{}{}, Max: int64(3)}
	if err := ValidateDefinitionsForReader(defs); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDefinitions(defs); err == nil {
		t.Fatal("authoring accepted future type")
	}
	// A reader accepts a known-type default error only through the known path.
	defs["f"] = Definition{Type: "future", Description: "d", Max: float64(1.5), Regex: "^a"}
	if err := ValidateDefinitionsForReader(defs); err != nil {
		t.Fatal(err)
	}
}
