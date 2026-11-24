package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/params"
	"gopkg.in/yaml.v3"
)

const stepDataflowAction = `
name: probe
description: Inspect process
risk: read
timeout: 1s
max_output: 1KB
steps:
  - name: collect
    exec: [/bin/echo, '0']
    extract:
      pid:
        tsv: {line: 1, column: 1, delimiter: whitespace}
        max_bytes: 64KB
        as: {type: int, min: 0, max: 0}
      state:
        regex: '^state=(.*)$'
        match: exactly_one
        optional: true
        as: {type: enum, values: [ready, stopped]}
      alive:
        json_path: '$[0].State["healthy/ready"]'
        as: {type: bool}
      label:
        json_path: "$['service.label']"
        as: {type: string, regex: '[a-z]*', max_len: 16}
      file:
        json_path: $.path
        as: {type: path, allowed_roots: [/var/log]}
  - name: inspect
    exec: [/bin/echo, '{steps.collect.pid}', ['--state', '{steps.collect.state}']]
    when:
      all:
        - {ref: steps.collect.pid, eq: 0}
        - {ref: steps.collect.alive, eq: false}
        - {ref: steps.collect.label, eq: ""}
        - {ref: steps.collect.file, exists: false}
        - {ref: prev.exit_code, gte: 0}
        - {ref: steps.collect.exit_code, in: [-1, 0, 9223372036854775807]}
        - {ref: prev.skipped, ne: true}
        - {ref: steps.collect.skipped, eq: false}
        - any:
            - {ref: steps.collect.state, ne: stopped}
            - not: {ref: steps.collect.state, in: [ready]}
`

func parsedStepDataflowAction(t *testing.T) Action {
	t.Helper()
	a, err := ParseAction([]byte(stepDataflowAction))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestStepDataflowCanonicalPackage(t *testing.T) {
	a := parsedStepDataflowAction(t)
	now := time.Date(2026, 10, 13, 1, 2, 3, 0, time.UTC)
	p, err := Build(&Catalog{Config: Config{SchemaVersion: 1, CatalogID: "test"}, Actions: map[string]Action{a.Name: a}}, BuildOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, word := range []string{`"eq":0`, `"eq":false`, `"eq":""`, `"exists":false`, `"min":0`, `"max":0`, `"gte":0`, `"in":[-1,0,9223372036854775807]`, `"max_bytes":65536`} {
		if !bytes.Contains(canonical, []byte(word)) {
			t.Errorf("canonical package omitted %s: %s", word, canonical)
		}
	}
	if bytes.Contains(canonical, []byte("null")) {
		t.Errorf("canonical package contains null: %s", canonical)
	}
	roundTrip, err := ParsePackage(canonical)
	if err != nil {
		t.Fatal(err)
	}
	again, err := CanonicalJSON(roundTrip)
	if err != nil || !bytes.Equal(canonical, again) {
		t.Fatalf("round trip = %s, %v, want %s", again, err, canonical)
	}
	digest, err := ActionDigest(roundTrip.Actions[a.Name])
	if err != nil || digest != p.Digests[a.Name] {
		t.Fatalf("round trip digest = %q, %v, want %s", digest, err, p.Digests[a.Name])
	}
	for _, field := range []string{"extract", "when"} {
		step := p.Actions[a.Name].Steps[0]
		if field == "when" {
			step = p.Actions[a.Name].Steps[1]
		}
		stepJSON, err := CanonicalJSON(step)
		if err != nil {
			t.Fatal(err)
		}
		var oldStep struct {
			Name string `json:"name"`
			Exec []any  `json:"exec"`
		}
		d := json.NewDecoder(bytes.NewReader(stepJSON))
		d.DisallowUnknownFields()
		if err := d.Decode(&oldStep); err == nil || !strings.Contains(err.Error(), `unknown field "`+field+`"`) {
			t.Errorf("old schema decoding step with %s = %v", field, err)
		}
	}
	for _, literal := range []string{`0`, `-1`, `false`, `""`, `"abc"`, `-9223372036854775808`} {
		var value ConditionValue
		if err := json.Unmarshal([]byte(literal), &value); err != nil {
			t.Fatal(err)
		}
		data, err := CanonicalJSON(value)
		if err != nil || string(data) != literal {
			t.Errorf("condition operand round trip = %s, %v, want %s", data, err, literal)
		}
	}
}

func TestStepDataflowLegacyActionDigest(t *testing.T) {
	const legacy = `{"description":"Inspect process","max_output":1024,"name":"probe","risk":"read","steps":[{"exec":["/bin/echo","0"],"name":"collect"}],"timeout":"1s"}`
	const legacyDigest = "34fb76e25d3be3cdf76f58f9dd3d84943cd02a3d3b27cd65f782a6cfc951fd8a"
	a := parsedStepDataflowAction(t)
	a.Steps = a.Steps[:1]
	a.Steps[0].Extract = nil
	data, err := CanonicalJSON(a)
	if err != nil || string(data) != legacy {
		t.Fatalf("canonical = %s, %v, want %s", data, err, legacy)
	}
	digest, err := ActionDigest(a)
	if err != nil || digest != legacyDigest {
		t.Fatalf("digest = %s, %v, want %s", digest, err, legacyDigest)
	}
}

func TestStepDataflowYAMLAliases(t *testing.T) {
	const source = `
steps:
  - &source
    name: collect
    exec: [/bin/echo]
    extract:
      one: {tsv: {column: &column 1}, as: {type: bool}}
      two: {tsv: {column: *column}, as: {type: bool}}
  - name: inspect
    <<: *source
    when: {ref: prev.exit_code, eq: 0}
`
	a, err := ParseAction([]byte(source))
	if err != nil || len(a.Steps) != 2 || a.Steps[1].Name != "inspect" {
		t.Fatalf("YAML merge and alias decoded as %+v, %v", a.Steps, err)
	}
	if got := a.Steps[1].Extract["two"].TSV; got == nil || got.Column != 1 {
		t.Fatalf("YAML merged extractor TSV = %+v", got)
	}
	if _, err := ParseAction([]byte(strings.Replace(source, "&column 1", "&column 1.5", 1))); err == nil {
		t.Fatal("accepted aliased YAML float for integer field")
	}
	if _, err := ParseAction([]byte(strings.Replace(source, "exec: [/bin/echo]", "exec: [/bin/echo]\n    when: null", 1))); err == nil {
		t.Fatal("accepted explicit null in YAML step anchor")
	}
}

func TestStepDataflowStrictDecode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target func() any
		source string
		fields []string
	}{
		{"tsv", func() any { return new(TSVExtractor) }, `{"%s":%s}`, []string{"line", "column"}},
		{"as", func() any { return new(ExtractType) }, `{"type":"int","%s":%s}`, []string{"min", "max"}},
		{"as_string", func() any { return new(ExtractType) }, `{"type":"string","%s":%s}`, []string{"max_len"}},
		{"when", func() any { return new(StepCondition) }, `{"ref":"prev.exit_code","%s":%s}`, []string{"gt", "gte", "lt", "lte"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, field := range tc.fields {
				for _, value := range []string{`1.5`, `1.0`, `1e0`, `"2"`, `true`, `null`, `9223372036854775808`} {
					assertDataflowDecodeFails(t, tc.target, fmt.Sprintf(tc.source, field, value))
				}
			}
		})
	}
	for _, tc := range []struct {
		target func() any
		bad    []string
	}{
		{func() any { return new(TSVExtractor) }, []string{
			`{"line":0,"column":1}`, `{"line":-1,"column":1}`, `{"line":10001,"column":1}`,
			`{"column":1,"column":2}`, `{"column":1,"Column":2}`, `{"column":1,"typo":0}`,
		}},
		{func() any { return new(ExtractType) }, []string{
			`{"type":"int","min":0,"min":1}`, `{"type":"int","typo":0}`,
			`{"type":"enum","values":[null]}`, `{"type":"bool","max_len":0}`,
			`{"type":"bool","regex":""}`, `{"type":"bool","values":[]}`,
		}},
		{func() any { return new(StepExtractor) }, []string{
			`{"regex":"(x)","tsv":null}`, `{"regex":"(x)","as":null}`,
			`{"tsv":{"column":1},"match":""}`, `{"regex":"","tsv":{"column":1}}`,
			`{"regex":"(x)","regex":"(y)"}`, `{"regex":"(x)","typo":0}`,
		}},
		{func() any { return new(StepCondition) }, []string{
			`{"eq":null}`, `{"ne":null}`, `{"exists":null}`, `{"in":null}`, `{"not":null}`,
			`{"all":[null]}`, `{"any":[null]}`, `{"in":[null]}`, `{"in":[1.5]}`,
			`{"eq":9223372036854775808}`, `{"eq":1.5}`, `{"eq":1e0}`, `{"eq":"bad\rvalue"}`,
			`{"eq":"bad\nvalue"}`, `{"eq":"bad\u0000value"}`, `{"eq":"` + string([]byte{0xff}) + `"}`,
			`{"eq":0,"eq":1}`, `{"eq":0,"typo":false}`, `{"eq":{"x":1}}`,
			`{"ref":"","not":{"ref":"prev.exit_code","eq":0}}`,
		}},
		{func() any { return new(Step) }, []string{
			`{"when":null}`, `{"extract":null}`, `{"extract":{"pid":null}}`,
			`{"extract":{"pid":{},"pid":{}}}`, `{"extract":{},"extract":{}}`,
			`{"when":{"typo":true}}`, `{"when":{},"When":{}}`, `{"unknown":1}`,
		}},
	} {
		for _, invalid := range tc.bad {
			assertDataflowDecodeFails(t, tc.target, invalid)
		}
	}
	for _, scalar := range []string{"!!int 1.5", "!!str 2", "!!bool true", "!!null null", "!!binary Mg=="} {
		var tsv TSVExtractor
		if err := yaml.Unmarshal([]byte("line: "+scalar+"\ncolumn: 1\n"), &tsv); err == nil {
			t.Errorf("accepted YAML line %q", scalar)
		}
	}
}

func assertDataflowDecodeFails(t *testing.T, target func() any, data string) {
	t.Helper()
	if err := json.Unmarshal([]byte(data), target()); err == nil {
		t.Errorf("JSON accepted %s", data)
	}
	if err := yaml.Unmarshal([]byte(data), target()); err == nil {
		t.Errorf("YAML accepted %s", data)
	}
}

func TestParseStepJSONPath(t *testing.T) {
	segments, err := ParseJSONPath(`$.metadata.labels["app.kubernetes.io/name"]['value:key'][0][9999].foo-bar_2`)
	want := []JSONPathSegment{
		{Field: "metadata"}, {Field: "labels"}, {Field: "app.kubernetes.io/name"}, {Field: "value:key"},
		{IsIndex: true}, {IsIndex: true, Index: 9999}, {Field: "foo-bar_2"},
	}
	if err != nil || !reflect.DeepEqual(segments, want) {
		t.Fatalf("ParseJSONPath = %+v, %v, want %+v", segments, err, want)
	}
	for _, path := range []string{"", "$", "foo", "$.", "$..foo", "$[*]", "$[-1]", "$[00]", "$[10000]", "$.foo bar", `$[""]`,
		`$["a\u002eb"]`, "$." + strings.Repeat("a", 65), "$['" + strings.Repeat("a", 129) + "']", "$" + strings.Repeat(".x", 17)} {
		if _, err := ParseJSONPath(path); err == nil {
			t.Errorf("accepted json_path %q", path)
		}
	}
	for _, path := range []string{"$." + strings.Repeat("a", 64), "$['" + strings.Repeat("a", 128) + "']", "$" + strings.Repeat(".x", 16)} {
		if _, err := ParseJSONPath(path); err != nil {
			t.Errorf("rejected json_path %q: %v", path, err)
		}
	}
}

func TestStepPlaceholderExecutionPositions(t *testing.T) {
	const ref = "{steps.collect.pid}"
	for _, argv := range [][]any{
		{ref}, {"/usr/bin/nsenter", "-t", ref, "-m", "/usr/bin/id"},
		{"/usr/bin/env", ref, "/usr/bin/id"}, {"/usr/bin/env", "-u", ref, "/usr/bin/id"},
		{"/usr/bin/timeout", ref, "/usr/bin/id"}, {"/usr/bin/timeout", "3", ref},
		{"/usr/bin/nice", "-n", ref, "/usr/bin/id"}, {"/usr/bin/ionice", "-n", ref, "/usr/bin/id"},
		{"/usr/bin/stdbuf", "-o", ref, "/usr/bin/id"}, {"/usr/bin/xargs", "-I", ref, "/usr/bin/id"},
		{"/usr/bin/xargs", "-n", ref}, {"/usr/bin/chroot", ref, "/usr/bin/id"},
		{"/usr/bin/docker", "-H", ref, "logs", "container"}, {"/usr/bin/docker", ref},
		{"/usr/bin/kubectl", "--server", ref, "logs", "pod"}, {"/usr/bin/kubectl", "logs", "pod", "--kubeconfig", ref},
		{"/usr/bin/kubectl", "logs", "pod", "-s", ref}, {"/usr/bin/docker", "logs", "-H", ref, "container"},
		{"/usr/bin/docker", "exec", ref, "ps"}, {"/usr/bin/docker", "exec", "container", ref},
		{"/usr/bin/docker", "exec", "-u", ref, "container", "ps"},
		{"/usr/bin/kubectl", "exec", ref, "--", "ps"}, {"/usr/bin/kubectl", "exec", "pod", "--", ref},
		{"/usr/bin/kubectl", "exec", "pod", "-c", ref, "--", "ps"},
		{"/usr/bin/kubectl", "exec", "pod", "-n", ref, "--", "ps"},
		{"/usr/bin/env", "/usr/bin/timeout", ref, "/usr/bin/id"},
		{"/usr/bin/timeout", []any{"-k", ref}, "3", "/usr/bin/id"},
	} {
		a := parsedStepDataflowAction(t)
		a.Steps[1].Exec = argv
		if _, err := ValidateAction(a); err == nil {
			t.Errorf("accepted execution position: %v", argv)
		}
	}
	for _, argv := range [][]any{
		{"/usr/bin/docker", "logs", "--tail", ref, "container"}, {"/usr/bin/kubectl", "logs", "pod", "--tail", ref},
		{"/usr/bin/env", "/usr/bin/timeout", "3", "/bin/echo", ref},
		{"/usr/bin/docker", "exec", "container", "/bin/echo", ref},
		{"/usr/bin/kubectl", "exec", "pod", "--", "/bin/echo", ref},
	} {
		a := parsedStepDataflowAction(t)
		a.Steps[1].Exec = argv
		if _, err := ValidateAction(a); err != nil {
			t.Errorf("rejected ordinary argument: %v: %v", argv, err)
		}
	}
}

func TestStepPlaceholderRequiresStepDefinitions(t *testing.T) {
	const ref = "{steps.collect.pid}"
	a, err := ParseAction([]byte(validAction))
	if err != nil {
		t.Fatal(err)
	}
	a.Exec = []any{"/bin/echo", ref}
	if _, err := ValidateAction(a); err == nil || !strings.Contains(err.Error(), "unknown placeholder steps.collect.pid") {
		t.Fatalf("ordinary exec validation = %v", err)
	}
	script := Script{File: "check.sh", Interpreter: "/bin/sh", Content: []byte("echo ok\n")}
	script.SHA256 = scriptDigest(script.Content)
	a.Exec, a.Script, a.Args = nil, &script, []any{ref}
	if _, err := ValidateAction(a); err == nil || !strings.Contains(err.Error(), "unknown placeholder steps.collect.pid") {
		t.Fatalf("script argument validation = %v", err)
	}
}

func TestStepDataflowStaticValidation(t *testing.T) {
	setPID := func(a *Action, change func(*StepExtractor)) {
		e := a.Steps[0].Extract["pid"]
		change(&e)
		a.Steps[0].Extract["pid"] = e
	}
	noForward := []any{"/bin/echo", "{steps.inspect.pid}"}
	for _, tc := range []struct {
		name   string
		change func(*Action)
		want   string
	}{
		{"first when", func(a *Action) { a.Steps[0].When = a.Steps[1].When }, "first step"},
		{"forward exec", func(a *Action) { a.Steps[0].Exec = noForward }, "unknown placeholder"},
		{"self exec", func(a *Action) { a.Steps[1].Exec = noForward }, "unknown placeholder"},
		{"exec status", func(a *Action) { a.Steps[1].Exec = []any{"/bin/echo", "{steps.collect.exit_code}"} }, "unknown placeholder"},
		{"allow interpreter", func(a *Action) { a.AllowInterpreter = true }, "step placeholders forbidden with allow_interpreter"},
		{"missing min", func(a *Action) { setPID(a, func(e *StepExtractor) { e.As.Min = nil }) }, "requires min and max"},
		{"missing max", func(a *Action) { setPID(a, func(e *StepExtractor) { e.As.Max = nil }) }, "requires min and max"},
		{"negative min", func(a *Action) { setPID(a, func(e *StepExtractor) { min := int64(-1); e.As.Min = &min }) }, "min >= 0"},
		{"unbounded string", func(a *Action) {
			setPID(a, func(e *StepExtractor) { e.As = ExtractType{Type: params.String, Regex: "."} })
		}, "max_len"},
		{"unbalanced string regex", func(a *Action) {
			setPID(a, func(e *StepExtractor) { e.As = ExtractType{Type: params.String, Regex: "allow)|b|(?:safe", MaxLen: 24} })
		}, "invalid extract string regex"},
		{"relative path root", func(a *Action) {
			setPID(a, func(e *StepExtractor) { e.As = ExtractType{Type: params.Path, AllowedRoots: []string{"relative"}} })
		}, "absolute paths"},
		{"unsupported type", func(a *Action) { setPID(a, func(e *StepExtractor) { e.As = ExtractType{Type: params.URL} }) }, "unsupported extract type"},
		{"enum dash", func(a *Action) {
			setPID(a, func(e *StepExtractor) { e.As = ExtractType{Type: params.Enum, Values: []string{"-bad"}} })
		}, "must not start with '-'"},
		{"enum duplicate", func(a *Action) {
			setPID(a, func(e *StepExtractor) { e.As = ExtractType{Type: params.Enum, Values: []string{"yes", "yes"}} })
		}, "duplicate enum"},
		{"enum invalid", func(a *Action) {
			setPID(a, func(e *StepExtractor) { e.As = ExtractType{Type: params.Enum, Values: []string{"bad\nvalue"}} })
		}, "invalid or duplicate enum"},
		{"inapplicable constraint", func(a *Action) {
			setPID(a, func(e *StepExtractor) { e.As = ExtractType{Type: params.Bool, Values: []string{"x"}} })
		}, "constraints do not apply"},
		{"reserved exit code", func(a *Action) { a.Steps[0].Extract["exit_code"] = a.Steps[0].Extract["pid"] }, "reserved extract variable"},
		{"reserved skipped", func(a *Action) { a.Steps[0].Extract["skipped"] = a.Steps[0].Extract["pid"] }, "reserved extract variable"},
		{"invalid name", func(a *Action) { a.Steps[0].Extract["Bad"] = a.Steps[0].Extract["pid"] }, "invalid or reserved extract variable"},
		{"multiple extractors", func(a *Action) { setPID(a, func(e *StepExtractor) { e.Regex = "." }) }, "exactly one of"},
		{"match on tsv", func(a *Action) { setPID(a, func(e *StepExtractor) { e.Match = "first" }) }, "match requires regex"},
		{"invalid match", func(a *Action) { setPID(a, func(e *StepExtractor) { e.TSV = nil; e.Regex = "(a)"; e.Match = "last" }) }, "must be first or exactly_one"},
		{"regex no capture", func(a *Action) { setPID(a, func(e *StepExtractor) { e.TSV = nil; e.Regex = "x" }) }, "exactly one capture"},
		{"regex two captures", func(a *Action) { setPID(a, func(e *StepExtractor) { e.TSV = nil; e.Regex = "(x)(y)" }) }, "exactly one capture"},
		{"regex over limit", func(a *Action) {
			setPID(a, func(e *StepExtractor) { e.TSV = nil; e.Regex = "(" + strings.Repeat("x", 255) + ")" })
		}, "up to 256"},
		{"regex invalid", func(a *Action) { setPID(a, func(e *StepExtractor) { e.TSV = nil; e.Regex = "(" }) }, "invalid extractor regex"},
		{"invalid json_path", func(a *Action) { setPID(a, func(e *StepExtractor) { e.TSV = nil; e.JSONPath = "$[*]" }) }, "invalid json_path"},
		{"column over limit", func(a *Action) { setPID(a, func(e *StepExtractor) { e.TSV.Column = 65 }) }, "tsv column"},
		{"delimiter invalid", func(a *Action) { setPID(a, func(e *StepExtractor) { e.TSV.Delimiter = "," }) }, "tsv delimiter"},
		{"max_bytes over limit", func(a *Action) { setPID(a, func(e *StepExtractor) { e.MaxBytes = MaxExtractMaxBytes + 1 }) }, "max_bytes"},
		{"max_bytes negative", func(a *Action) { setPID(a, func(e *StepExtractor) { e.MaxBytes = -1 }) }, "max_bytes"},
		{"step extractor count", func(a *Action) { maps.Copy(a.Steps[0].Extract, repeatedStepExtractors(a.Steps[0].Extract["pid"])) }, "per step"},
		{"action extractor count", func(a *Action) {
			var steps []Step
			for i := range 5 {
				steps = append(steps, Step{Name: fmt.Sprintf("step%d", i), Exec: []any{"/bin/echo"}, Extract: repeatedStepExtractors(a.Steps[0].Extract["pid"])})
			}
			a.Steps = steps
		}, "per action"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := parsedStepDataflowAction(t)
			tc.change(&a)
			if _, err := ValidateAction(a); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateAction = %v, want error containing %q", err, tc.want)
			}
		})
	}
	a := parsedStepDataflowAction(t)
	a.Steps[1].Exec = []any{"/bin/echo"}
	setPID(&a, func(e *StepExtractor) { min := int64(-1); e.As.Min = &min })
	if _, err := ValidateAction(a); err != nil {
		t.Fatalf("negative minimum used only in a condition: %v", err)
	}
}

func repeatedStepExtractors(e StepExtractor) map[string]StepExtractor {
	extract := map[string]StepExtractor{}
	for i := range MaxExtractorsPerStep {
		extract[fmt.Sprintf("v%d", i)] = e
	}
	return extract
}

func TestStepConditionValidation(t *testing.T) {
	a := parsedStepDataflowAction(t)
	leaf := StepCondition{Ref: "prev.exit_code", Eq: &ConditionValue{Value: int64(0)}}
	deep := leaf
	for range MaxConditionDepth {
		child := deep
		deep = StepCondition{Not: &child}
	}
	var many []StepCondition
	for range MaxConditionChildren {
		many = append(many, StepCondition{Any: []StepCondition{leaf, leaf}})
	}
	if err := ValidateStepCondition(&leaf, a.Steps[:1]); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		source string
		want   string
	}{
		{`{ref: steps.inspect.exit_code, eq: 0}`, "earlier step"},
		{`{ref: steps.future.exit_code, eq: 0}`, "earlier step"},
		{`{ref: steps.collect.missing, eq: 0}`, "earlier step"},
		{`{ref: prev.pid, eq: 0}`, "earlier step"},
		{`{ref: steps.collect.state, eq: unknown}`, "allowed values"},
		{`{ref: steps.collect.state, in: [ready, unknown]}`, "allowed values"},
		{`{ref: steps.collect.file, eq: /var/log/app}`, "does not match type path"},
		{`{ref: steps.collect.file, in: [/var/log/app]}`, "forbidden for type path"},
		{`{ref: steps.collect.alive, in: [true]}`, "forbidden for type bool"},
		{`{ref: steps.collect.alive, eq: 1}`, "does not match type bool"},
		{`{ref: steps.collect.label, lt: 1}`, "requires an int ref"},
		{`{ref: steps.collect.label, in: [yes, 1]}`, "does not match type string"},
		{`{ref: prev.exit_code, eq: "0"}`, "does not match type int"},
		{`{ref: prev.exit_code, eq: 0, ne: 1}`, "exactly one"},
		{`{ref: prev.exit_code, any: [{ref: prev.exit_code, eq: 0}]}`, "exactly one"},
		{`{all: [], any: []}`, "exactly one"},
		{`{all: []}`, "children"},
		{`{ref: prev.exit_code, in: []}`, "operands"},
		{`{eq: 0}`, "exactly one"},
	} {
		var c StepCondition
		if err := yaml.Unmarshal([]byte(tc.source), &c); err != nil {
			t.Fatalf("%s: %v", tc.source, err)
		}
		if err := ValidateStepCondition(&c, a.Steps[:1]); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want error containing %q", tc.source, err, tc.want)
		}
	}
	for _, tc := range []struct {
		c    StepCondition
		want string
	}{
		{deep, "maximum depth"},
		{StepCondition{All: many}, "node count"},
		{StepCondition{Any: make([]StepCondition, MaxConditionChildren+1)}, "children"},
		{StepCondition{Ref: leaf.Ref, In: make([]ConditionValue, MaxConditionInItems+1)}, "operands"},
	} {
		if err := ValidateStepCondition(&tc.c, a.Steps[:1]); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ValidateStepCondition = %v, want error containing %q", err, tc.want)
		}
	}
}

func TestStepDataflowWarningsAndHost(t *testing.T) {
	a := parsedStepDataflowAction(t)
	if warnings, err := ValidateAction(a); err != nil || len(warnings) != 0 {
		t.Fatalf("read action: warnings %q, error %v", warnings, err)
	}
	a.Risk = "write"
	const warning = "action probe: step extract/when uses untrusted host output; every step of a non-read action must be safe if executed unconditionally"
	if warnings, err := ValidateAction(a); err != nil || !reflect.DeepEqual(warnings, []string{warning}) {
		t.Fatalf("write action: warnings %q, error %v", warnings, err)
	}
	if support := CheckHost(a); !support.Supported || !reflect.DeepEqual(support.Warnings, []string{warning}) {
		t.Fatalf("host support = %+v", support)
	}
	dir := t.TempDir()
	alias := filepath.Join(dir, "wrapper")
	if err := os.Symlink("/usr/bin/timeout", alias); err != nil {
		t.Fatal(err)
	}
	for _, argv := range [][]any{
		{alias, "{steps.collect.pid}", "/bin/echo"},
		{"/usr/bin/env", alias, "{steps.collect.pid}", "/bin/echo"},
	} {
		a.Steps[1].Exec = argv
		if _, err := ValidateAction(a); err != nil {
			t.Fatalf("validate before host resolution: %v", err)
		}
		if support := CheckHost(a); support.Supported || !strings.Contains(support.Reason, "step placeholder forbidden") {
			t.Errorf("accepted symlink to wrapper with dynamic operand: %+v", support)
		}
	}
	interpreter := filepath.Join(dir, "interpreter")
	if err := os.Symlink("/bin/sh", interpreter); err != nil {
		t.Fatal(err)
	}
	exec := []any{interpreter, "-c", ":", "{arg}"}
	a = Action{Name: "ordinary", Description: "Ordinary argument", Risk: "read", Timeout: "1s", MaxOutput: 1024,
		AllowInterpreter: true, Exec: exec, Params: map[string]params.Definition{
			"arg": {Type: params.Enum, Description: "Argument", Values: []string{"-x"}},
		}}
	if _, err := ResolveExecutable(exec, nil, true); err != nil {
		t.Fatalf("legacy resolver with synthesized definitions: %v", err)
	}
	if support := CheckHost(a); support.Supported || !strings.Contains(support.Reason, "may render an option") {
		t.Errorf("host used synthesized definitions: %+v", support)
	}
	a.Exec, a.Steps = nil, []Step{{Name: "one", Exec: exec}}
	if support := CheckHost(a); support.Supported || !strings.Contains(support.Reason, "may render an option") {
		t.Errorf("host steps used synthesized definitions: %+v", support)
	}
	a.Steps[0].Exec = append([]any{"/usr/bin/env"}, exec...)
	if support := CheckHost(a); support.Supported || !strings.Contains(support.Reason, "may render an option") {
		t.Errorf("host skipped real definitions for a nested symlink: %+v", support)
	}
}
