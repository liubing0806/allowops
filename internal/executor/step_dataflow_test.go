package executor

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/liubing0806/allowops/internal/redact"
)

func TestStepDataflowStreamingExtractors(t *testing.T) {
	text := catalog.ExtractType{Type: params.String, Regex: "[a-z]*", MaxLen: 16}
	number := catalog.ExtractType{Type: params.Int, Min: new(int64(-10)), Max: new(int64(9007199254740993))}
	boolean := catalog.ExtractType{Type: params.Bool}
	for _, tc := range []struct {
		name, stdout string
		spec         catalog.StepExtractor
		want         any
		err          error
	}{
		{name: "first", stdout: "v=first\nv=next", spec: catalog.StepExtractor{Regex: "^v=([a-z]+)$", As: text}, want: "first"},
		{name: "first before overflow", stdout: "v=first\nv=next", spec: catalog.StepExtractor{Regex: "^v=([a-z]+)$", As: text, MaxBytes: 8}, want: "first"},
		{name: "no partial line", stdout: "v=first\n", spec: catalog.StepExtractor{Regex: "^v=([a-z]+)$", As: text, MaxBytes: 7}, err: ErrExtractFailed},
		{name: "exactly one", stdout: "skip\nv=first\nskip", spec: catalog.StepExtractor{Regex: "^v=([a-z]+)$", Match: "exactly_one", As: text}, want: "first"},
		{name: "duplicate", stdout: "v=first\nv=next", spec: catalog.StepExtractor{Regex: "^v=([a-z]+)$", Match: "exactly_one", As: text, Optional: true}, err: ErrExtractFailed},
		{name: "uniqueness unknown", stdout: "v=first\nlonger\n", spec: catalog.StepExtractor{Regex: "^v=([a-z]+)$", Match: "exactly_one", As: text, MaxBytes: 8}, err: ErrExtractFailed},
		{name: "required absent", stdout: "other", spec: catalog.StepExtractor{Regex: "^v=([a-z]+)$", As: text}, err: ErrExtractFailed},
		{name: "optional absent", stdout: "other", spec: catalog.StepExtractor{Regex: "^v=([a-z]+)$", As: text, Optional: true}},
		{name: "optional overflow", stdout: "other", spec: catalog.StepExtractor{Regex: "^v=([a-z]+)$", As: text, Optional: true, MaxBytes: 4}, err: ErrExtractFailed},
		{name: "tab with empty column", stdout: "row\t\tlast", spec: catalog.StepExtractor{TSV: &catalog.TSVExtractor{Column: 2}, As: text}, want: ""},
		{name: "whitespace line two", stdout: "first  1\n second \t -2 ", spec: catalog.StepExtractor{TSV: &catalog.TSVExtractor{Line: new(2), Column: 2, Delimiter: "whitespace"}, As: number}, want: int64(-2)},
		{name: "TSV output exceeds limit after match", stdout: "row\ttrue\nextra", spec: catalog.StepExtractor{TSV: &catalog.TSVExtractor{Column: 2}, As: boolean, MaxBytes: 9}, want: true},
		{name: "TSV target after limit", stdout: "first\nsecond\ttrue", spec: catalog.StepExtractor{TSV: &catalog.TSVExtractor{Line: new(2), Column: 2}, As: boolean, Optional: true, MaxBytes: 7}, err: ErrExtractFailed},
		{name: "optional missing column", stdout: "row", spec: catalog.StepExtractor{TSV: &catalog.TSVExtractor{Column: 2}, As: text, Optional: true}},
		{name: "optional missing line", stdout: "row", spec: catalog.StepExtractor{TSV: &catalog.TSVExtractor{Line: new(2), Column: 1}, As: text, Optional: true}},
		{name: "strict integer whitespace", stdout: " 2 ", spec: catalog.StepExtractor{Regex: "^(.*)$", As: number, Optional: true}, err: ErrExtractTypeInvalid},
		{name: "strict integer plus", stdout: "+2", spec: catalog.StepExtractor{Regex: "^(.*)$", As: number}, err: ErrExtractTypeInvalid},
		{name: "integer overflow", stdout: "9223372036854775808", spec: catalog.StepExtractor{Regex: "^(.*)$", As: number}, err: ErrExtractTypeInvalid},
		{name: "strict boolean", stdout: "TRUE", spec: catalog.StepExtractor{Regex: "^(.*)$", As: boolean}, err: ErrExtractTypeInvalid},
		{name: "anchored string regex", stdout: "accept-me", spec: catalog.StepExtractor{Regex: "^(.*)$", As: text}, err: ErrExtractTypeInvalid},
		{name: "redaction marker", stdout: "v=[REDACTED:fixture]", spec: catalog.StepExtractor{Regex: "^v=(.*)$", As: text}, err: ErrExtractFailed},
		{name: "partially redacted match", stdout: "app-password=fixture", spec: catalog.StepExtractor{Regex: "^(app)", As: text}, err: ErrExtractFailed},
		{name: "tainted TSV with absent column", stdout: "password=fixture", spec: catalog.StepExtractor{TSV: &catalog.TSVExtractor{Column: 2}, As: text, Optional: true}, err: ErrExtractFailed},
		{name: "PEM-tainted empty line", stdout: "-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----", spec: catalog.StepExtractor{Regex: "^()$", As: text}, err: ErrExtractFailed},
		{name: "unrelated tainted line", stdout: "password=fixture\nv=next", spec: catalog.StepExtractor{Regex: "^v=([a-z]+)$", As: text}, want: "next"},
		{name: "exactly one tainted before match", stdout: "password=fixture\nv=next\n", spec: catalog.StepExtractor{Regex: "^v=([a-z]+)$", Match: "exactly_one", As: text}, err: ErrExtractFailed},
		{name: "exactly one tainted after match", stdout: "v=next\npassword=fixture\n", spec: catalog.StepExtractor{Regex: "^v=([a-z]+)$", Match: "exactly_one", As: text}, err: ErrExtractFailed},
		{name: "NDJSON quoted keys", stdout: "{\"a.b/c\":[{\"label\":\"first\"}]}\n{\"a.b/c\":false}", spec: catalog.StepExtractor{JSONPath: `$["a.b/c"][0].label`, As: text}, want: "first"},
		{name: "NDJSON clean first document before redacted second line", stdout: "{\"v\":\"first\"}\n{\"password\":\"fixture\"}\n", spec: catalog.StepExtractor{JSONPath: "$.v", As: text}, want: "first"},
		{name: "JSON same-line trailing redaction still taints", stdout: "{\"v\":\"first\"} {\"password\":\"fixture\"}\n", spec: catalog.StepExtractor{JSONPath: "$.v", As: text}, err: ErrExtractFailed},
		{name: "multiline JSON integer fidelity", stdout: "{\n  \"n\":9007199254740993\n}", spec: catalog.StepExtractor{JSONPath: "$.n", As: number}, want: int64(9007199254740993)},
		{name: "JSON boolean", stdout: `{"flag":false}`, spec: catalog.StepExtractor{JSONPath: "$.flag", As: boolean}, want: false},
		{name: "JSON Number is not a string", stdout: `{"n":1}`, spec: catalog.StepExtractor{JSONPath: "$.n", As: text}, err: ErrExtractTypeInvalid},
		{name: "JSON fractional number", stdout: `{"n":1.0}`, spec: catalog.StepExtractor{JSONPath: "$.n", As: number}, err: ErrExtractTypeInvalid},
		{name: "JSON duplicate key", stdout: `{"v":"first","v":"next"}`, spec: catalog.StepExtractor{JSONPath: "$.v", As: text}, err: ErrExtractFailed},
		{name: "JSON duplicate escaped key", stdout: `{"v":"first","\u0076":"next"}`, spec: catalog.StepExtractor{JSONPath: "$.v", As: text}, err: ErrExtractFailed},
		{name: "JSON syntax", stdout: `{"v":"first",}`, spec: catalog.StepExtractor{JSONPath: "$.v", As: text, Optional: true}, err: ErrExtractFailed},
		{name: "JSON invalid UTF8", stdout: "{\"v\":\"first\",\"x\":\"\xff\"}", spec: catalog.StepExtractor{JSONPath: "$.v", As: text}, err: ErrExtractFailed},
		{name: "JSON depth limit", stdout: `{"v":"first","x":` + strings.Repeat("[", 32) + strings.Repeat("]", 32) + "}", spec: catalog.StepExtractor{JSONPath: "$.v", As: text}, err: ErrExtractFailed},
		{name: "JSON at depth limit", stdout: `{"v":"first","x":` + strings.Repeat("[", 31) + strings.Repeat("]", 31) + "}", spec: catalog.StepExtractor{JSONPath: "$.v", As: text}, want: "first"},
		{name: "JSON null", stdout: `{"v":null}`, spec: catalog.StepExtractor{JSONPath: "$.v", As: text, Optional: true}},
		{name: "JSON missing field", stdout: `{"v":null}`, spec: catalog.StepExtractor{JSONPath: "$.absent", As: text, Optional: true}},
		{name: "JSON index beyond array", stdout: `{"v":[]}`, spec: catalog.StepExtractor{JSONPath: "$.v[0]", As: text, Optional: true}},
		{name: "JSON wrong container", stdout: `{"v":true}`, spec: catalog.StepExtractor{JSONPath: "$.v[0]", As: text, Optional: true}, err: ErrExtractFailed},
		{name: "JSON object target", stdout: `{"v":{}}`, spec: catalog.StepExtractor{JSONPath: "$.v", As: text, Optional: true}, err: ErrExtractTypeInvalid},
		{name: "JSON array target", stdout: `{"v":[]}`, spec: catalog.StepExtractor{JSONPath: "$.v", As: text, Optional: true}, err: ErrExtractTypeInvalid},
		{name: "JSON first document fits prefix", stdout: "{\"v\":\"first\"}\n{\"v\":\"next\"}", spec: catalog.StepExtractor{JSONPath: "$.v", As: text, MaxBytes: 13}, want: "first"},
		{name: "JSON truncated document", stdout: `{"v":"first"}`, spec: catalog.StepExtractor{JSONPath: "$.v", As: text, MaxBytes: 12, Optional: true}, err: ErrExtractFailed},
		{name: "JSON optional absent over limit", stdout: "{\"v\":null}\n{}", spec: catalog.StepExtractor{JSONPath: "$.v", As: text, MaxBytes: 10, Optional: true}, err: ErrExtractFailed},
		{name: "JSON line taint", stdout: "{\"v\":\"first\",\n\"password\": \"fixture\"}", spec: catalog.StepExtractor{JSONPath: "$.v", As: text}, err: ErrExtractFailed},
		{name: "JSON escaped key redaction", stdout: `{"\u0070assword":"fixture"}`, spec: catalog.StepExtractor{JSONPath: "$.password", As: text}, err: ErrExtractFailed},
		{name: "JSON escaped value redaction", stdout: `{"v":"\u0070assword=fixture"}`, spec: catalog.StepExtractor{JSONPath: "$.v", As: text}, err: ErrExtractFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := redact.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			step := catalog.Step{Name: "producer", Extract: map[string]catalog.StepExtractor{"value": tc.spec}}
			sink := newStepExtractSink(t.Context(), step, r)
			if err := r.StreamTracked(strings.NewReader(tc.stdout), redact.DefaultMaxLine, sink.Write); err != nil {
				t.Fatal(err)
			}
			values, err := sink.Finalize(false)
			if !errors.Is(err, tc.err) {
				t.Fatalf("error=%v, want %v", err, tc.err)
			}
			if got := values["value"]; got != tc.want {
				t.Fatalf("value=%#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestStepDataflowSharedJSONBuffer(t *testing.T) {
	text := catalog.ExtractType{Type: params.String, Regex: "[a-z]+", MaxLen: 16}
	step := catalog.Step{Name: "producer", Extract: map[string]catalog.StepExtractor{
		"second": {JSONPath: "$.second", MaxBytes: catalog.MaxExtractMaxBytes, As: text},
		"first":  {JSONPath: "$.first", MaxBytes: 19, As: text},
	}}
	sink := newStepExtractSink(t.Context(), step, &redact.Redactor{})
	if err := sink.Write("{\"first\":\"ok\",\"second\":\"ok\"}\n", false); err != nil {
		t.Fatal(err)
	}
	for range 9 {
		if err := sink.Write(strings.Repeat(" ", 128*1024)+"\n", false); err != nil {
			t.Fatal(err)
		}
	}
	if sink.json.Len() != catalog.MaxExtractMaxBytes || sink.json.Cap() > catalog.MaxExtractMaxBytes {
		t.Fatalf("shared JSON len=%d cap=%d, want at most %d bytes", sink.json.Len(), sink.json.Cap(), catalog.MaxExtractMaxBytes)
	}
	// The second extractor can decode the document, while the first must
	// validate it using its own smaller prefix. Errors follow variable order.
	if _, err := sink.Finalize(false); err == nil || err.Error() != "step producer variable first: EXTRACT_FAILED" {
		t.Fatalf("error=%v, want first variable's extraction failure", err)
	}
	step.Extract["first"] = catalog.StepExtractor{JSONPath: "$.second", MaxBytes: 16, As: text}
	sink = newStepExtractSink(t.Context(), step, &redact.Redactor{})
	if err := sink.Write("{\"second\":\"ok\"}\n", false); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write("{\"password\":\"[REDACTED:credential]\"}\n", true); err != nil {
		t.Fatal(err)
	}
	values, err := sink.Finalize(false)
	if err != nil || !maps.Equal(values, map[string]any{"first": "ok", "second": "ok"}) {
		t.Fatalf("values=%v, err=%v", values, err)
	}
	if _, err := sink.Finalize(true); !errors.Is(err, ErrExtractFailed) {
		t.Fatalf("error=%v, want incomplete-output failure", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	sink = newStepExtractSink(ctx, step, &redact.Redactor{})
	if err := sink.Write("unused", false); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want cancellation", err)
	}
}

func TestStepDataflowJSONRechecksQuotedKeyValue(t *testing.T) {
	r, err := redact.New(&redact.Config{Custom: []redact.Rule{{Name: "fixture", Regex: `"tag":"fixture"`}}})
	if err != nil {
		t.Fatal(err)
	}
	step := catalog.Step{Name: "producer", Extract: map[string]catalog.StepExtractor{
		"value": {JSONPath: "$.tag", As: catalog.ExtractType{Type: params.Enum, Values: []string{"fixture"}}},
	}}
	sink := newStepExtractSink(t.Context(), step, r)
	if err := r.StreamTracked(strings.NewReader(`{"ta\u0067":"fixture"}`), redact.DefaultMaxLine, sink.Write); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Finalize(false); !errors.Is(err, ErrExtractFailed) {
		t.Fatalf("error=%v, want extraction failure from quoted key and value", err)
	}
}

func TestStepDataflowKleeneTruthTable(t *testing.T) {
	states := []stepRuntimeState{
		{name: "producer", exitCode: new(0), cleanSuccess: true, values: map[string]any{"value": int64(4)}},
		{name: "omitted", skipped: true},
		{name: "consumer"},
	}
	tests := []catalog.StepCondition{
		{Ref: "prev.skipped", Eq: &catalog.ConditionValue{Value: false}},
		{Ref: "steps.producer.value", Eq: &catalog.ConditionValue{Value: int64(4)}},
		{Ref: "prev.exit_code", Eq: &catalog.ConditionValue{Value: int64(0)}},
	}
	all := [3][3]tribool{{triFalse, triFalse, triFalse}, {triFalse, triTrue, triUnknown}, {triFalse, triUnknown, triUnknown}}
	any := [3][3]tribool{{triFalse, triTrue, triUnknown}, {triTrue, triTrue, triTrue}, {triUnknown, triTrue, triUnknown}}
	not := [3]tribool{triTrue, triFalse, triUnknown}
	for i := range tests {
		if got := evalCondition(&catalog.StepCondition{Not: &tests[i]}, 2, states); got != not[i] {
			t.Errorf("not(%d)=%d, want %d", i, got, not[i])
		}
		for j := range tests {
			children := []catalog.StepCondition{tests[i], tests[j]}
			if got := evalCondition(&catalog.StepCondition{All: children}, 2, states); got != all[i][j] {
				t.Errorf("all(%d,%d)=%d, want %d", i, j, got, all[i][j])
			}
			if got := evalCondition(&catalog.StepCondition{Any: children}, 2, states); got != any[i][j] {
				t.Errorf("any(%d,%d)=%d, want %d", i, j, got, any[i][j])
			}
		}
	}
	for _, tc := range []struct {
		condition catalog.StepCondition
		want      tribool
	}{
		{catalog.StepCondition{Ref: "prev.exit_code", Exists: new(false)}, triTrue},
		{catalog.StepCondition{Ref: "prev.exit_code", Exists: new(true)}, triFalse},
		{catalog.StepCondition{Ref: "prev.skipped", Exists: new(true)}, triTrue},
		{catalog.StepCondition{Ref: "steps.producer.skipped", Exists: new(false)}, triFalse},
		{catalog.StepCondition{Ref: "steps.producer.exit_code", Eq: &catalog.ConditionValue{Value: int64(0)}}, triTrue},
		{catalog.StepCondition{Ref: "steps.producer.value", Ne: &catalog.ConditionValue{Value: int64(5)}}, triTrue},
		{catalog.StepCondition{Ref: "steps.producer.value", Gt: new(int64(3))}, triTrue},
		{catalog.StepCondition{Ref: "steps.producer.value", Gte: new(int64(4))}, triTrue},
		{catalog.StepCondition{Ref: "steps.producer.value", Lt: new(int64(5))}, triTrue},
		{catalog.StepCondition{Ref: "steps.producer.value", Lte: new(int64(4))}, triTrue},
		{catalog.StepCondition{Ref: "steps.producer.value", In: []catalog.ConditionValue{{Value: int64(4)}}}, triTrue},
		{catalog.StepCondition{Ref: "steps.omitted.value", Ne: &catalog.ConditionValue{Value: int64(4)}}, triUnknown},
		{catalog.StepCondition{Ref: "steps.omitted.value", In: []catalog.ConditionValue{{Value: int64(4)}}}, triUnknown},
		{catalog.StepCondition{Ref: "steps.omitted.value", Exists: new(false)}, triUnknown},
		{catalog.StepCondition{Ref: "steps.omitted.value", Exists: new(true)}, triUnknown},
		{catalog.StepCondition{Ref: "steps.producer.absent", Exists: new(false)}, triTrue},
		{catalog.StepCondition{Ref: "steps.producer.absent", Exists: new(true)}, triFalse},
	} {
		if got := evalCondition(&tc.condition, 2, states); got != tc.want {
			t.Errorf("%+v=%d, want %d", tc.condition, got, tc.want)
		}
	}
}

func stepFlowAction(steps ...catalog.Step) catalog.Action {
	return catalog.Action{Name: "step_flow", Description: "step flow", Risk: "read", OnError: "continue", Steps: steps, Timeout: "5s", MaxOutput: 1024}
}

func idExtractor(optional bool) catalog.StepExtractor {
	return catalog.StepExtractor{
		Regex: "^id=(.*)$", Optional: optional,
		As: catalog.ExtractType{Type: params.Int, Min: new(int64(0)), Max: new(int64(100))},
	}
}

func TestStepDataflowFiltersAndSharedBudget(t *testing.T) {
	a := stepFlowAction(
		catalog.Step{Name: "producer", Exec: []any{"/usr/bin/printf", `%s\n`, "id=42"}, Extract: map[string]catalog.StepExtractor{"id": idExtractor(false)}},
		catalog.Step{Name: "consumer", Exec: []any{"/usr/bin/printf", `id:%s\n`, "{steps.producer.id}"}, When: &catalog.StepCondition{Ref: "steps.producer.id", Gte: new(int64(42))}},
	)
	a.Filters = []string{"exclude", "count"}
	for _, tc := range []struct {
		name, first, second string
		filter              map[string]any
		limit               catalog.Size
		truncated           bool
	}{
		{"exclude", "", "id:42\n", map[string]any{"exclude": "^id="}, 1024, false},
		{"count", "1\n", "1\n", map[string]any{"count": true}, 1024, false},
		{"shared budget", "id", "", nil, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a.MaxOutput = tc.limit
			r, err := RunWithFilters(t.Context(), a, nil, tc.filter, nil)
			if err != nil || r.ExitCode != 0 || r.Truncated != tc.truncated || len(r.Steps) != 2 ||
				r.Steps[0].Stdout != tc.first || r.Steps[1].Stdout != tc.second || r.Steps[1].Skipped {
				t.Fatalf("result=%+v, err=%v", r, err)
			}
		})
	}
}

func TestStepDataflowOptionalReferenceAndSkips(t *testing.T) {
	missing := catalog.StepCondition{Ref: "steps.producer.id", Eq: &catalog.ConditionValue{Value: int64(1)}}
	for _, tc := range []struct {
		name, onError string
		producer      []any
		optionalGroup bool
		skipProducer  bool
		wantReason    string
		wantError     error
		wantStdout    string
	}{
		{name: "omit optional group after clean miss", producer: []any{"/usr/bin/true"}, optionalGroup: true, wantStdout: "consumer\n"},
		{name: "mandatory reference after clean miss", producer: []any{"/usr/bin/true"}, wantError: ErrExtractMissing},
		{name: "failed process cannot omit group", producer: []any{"/usr/bin/false"}, optionalGroup: true, wantError: ErrExtractMissing},
		{name: "failed extraction cannot omit group", producer: []any{"/usr/bin/printf", "id=invalid"}, optionalGroup: true, wantError: ErrExtractTypeInvalid},
		{name: "skipped producer cannot omit group", producer: []any{"/usr/bin/true"}, optionalGroup: true, skipProducer: true, wantError: ErrExtractMissing},
		{name: "stop after failure", producer: []any{"/usr/bin/false"}, optionalGroup: true, onError: "stop", wantReason: ReasonSkipStopped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			producer := catalog.Step{Name: "producer", Exec: tc.producer, Extract: map[string]catalog.StepExtractor{"id": idExtractor(true)}}
			if tc.skipProducer {
				producer.When = &catalog.StepCondition{Ref: "prev.exit_code", Ne: &catalog.ConditionValue{Value: int64(0)}}
			}
			consumer := []any{"/usr/bin/printf", `consumer\n`, "{steps.producer.id}"}
			if tc.optionalGroup {
				consumer[2] = []any{"{steps.producer.id}"}
			}
			a := stepFlowAction(catalog.Step{Name: "prepare", Exec: []any{"/usr/bin/true"}}, producer,
				catalog.Step{Name: "condition", Exec: []any{"/usr/bin/false"}, When: &catalog.StepCondition{Not: &missing}},
				catalog.Step{Name: "consumer", Exec: consumer, When: &catalog.StepCondition{Ref: "prev.skipped", Eq: &catalog.ConditionValue{Value: true}}},
			)
			if tc.onError != "" {
				a.OnError = tc.onError
			}
			var stepErrors []error
			r, err := RunWithCallbacks(t.Context(), a, nil, nil, nil, Callbacks{StepCompleted: func(_ StepResult, err error) error {
				stepErrors = append(stepErrors, err)
				return nil
			}})
			if !errors.Is(err, tc.wantError) || len(r.Steps) != 4 || len(stepErrors) != 4 {
				t.Fatalf("result=%+v, err=%v, step errors=%v", r, err, stepErrors)
			}
			wantCondition := ReasonSkipConditionFalse
			if tc.wantReason == ReasonSkipStopped {
				wantCondition = ReasonSkipStopped
			} else if tc.wantError != nil && !errors.Is(stepErrors[3], ErrExtractMissing) {
				t.Fatalf("consumer error=%v, want %v", stepErrors[3], ErrExtractMissing)
			}
			condition, consumerResult := r.Steps[2], r.Steps[3]
			if !condition.Skipped || condition.SkipReason != wantCondition || condition.ExitCode != nil ||
				consumerResult.SkipReason != tc.wantReason || consumerResult.Stdout != tc.wantStdout {
				t.Fatalf("condition=%+v, consumer=%+v, error=%v", condition, consumerResult, err)
			}
		})
	}
}

func TestStepDataflowRejectsIncompleteOutput(t *testing.T) {
	for _, mode := range []string{"max_scan", "wait_delay"} {
		t.Run(mode, func(t *testing.T) {
			step := catalog.Step{Name: "producer", Exec: []any{"/usr/bin/printf", `id=42\nmore\n`}, Extract: map[string]catalog.StepExtractor{"id": idExtractor(true)}}
			a := stepFlowAction(step)
			if mode == "max_scan" {
				a.MaxScan = 6
			} else {
				pidFile := filepath.Join(t.TempDir(), "child.pid")
				t.Cleanup(func() {
					if data, err := os.ReadFile(pidFile); err == nil {
						if pid, err := strconv.Atoi(string(data)); err == nil {
							_ = syscall.Kill(pid, syscall.SIGKILL)
						}
					}
				})
				a.Steps[0].Exec = append(helperAction("detach").Exec, pidFile)
				a.Timeout = "30s"
			}
			r, err := Run(t.Context(), a, nil, nil)
			if !errors.Is(err, ErrExtractFailed) || r.ExitCode != -1 || len(r.Steps) != 1 || r.Steps[0].ExitCode != nil ||
				r.ScanLimitReached != (mode == "max_scan") || (mode == "wait_delay" && !r.Truncated) {
				t.Fatalf("result=%+v, error=%v, want EXTRACT_FAILED on incomplete stdout", r, err)
			}
		})
	}
}

func TestStepDataflowSharedTimeout(t *testing.T) {
	a := stepFlowAction(
		catalog.Step{Name: "first", Exec: []any{"/usr/bin/sleep", "0.4"}},
		catalog.Step{Name: "second", Exec: []any{"/usr/bin/sleep", "0.7"}, Extract: map[string]catalog.StepExtractor{"id": idExtractor(true)}},
		catalog.Step{Name: "last", Exec: []any{"/usr/bin/true"}},
	)
	a.Timeout = "900ms"
	r, err := Run(t.Context(), a, nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) || len(r.Steps) != 3 || r.Steps[0].ExitCode == nil ||
		*r.Steps[0].ExitCode != 0 || r.Steps[1].ExitCode != nil || r.Steps[2].SkipReason != ReasonSkipStopped {
		t.Fatalf("result=%+v, error=%v, want shared deadline and STOPPED", r, err)
	}
}

func TestStepDataflowExtractedPathErrorsOmitValues(t *testing.T) {
	root, untrusted := pathFixture(t, 0o775, 0o644)
	absent := filepath.Join(root, "absent")
	for _, tc := range []struct {
		path string
		want error
	}{
		{untrusted, params.ErrPathNotTrusted},
		{absent, ErrExtractTypeInvalid},
	} {
		t.Run(tc.want.Error(), func(t *testing.T) {
			a := stepFlowAction(
				catalog.Step{Name: "producer", Exec: []any{"/usr/bin/printf", "%s", tc.path}, Extract: map[string]catalog.StepExtractor{
					"file": {Regex: "^(.*)$", As: catalog.ExtractType{Type: params.Path, AllowedRoots: []string{root}}},
				}},
				catalog.Step{Name: "consumer", Exec: []any{"/usr/bin/cat", "{steps.producer.file}"}},
			)
			r, err := Run(t.Context(), a, nil, nil)
			var pathError *os.PathError
			if !errors.Is(err, tc.want) || strings.Contains(err.Error(), tc.path) || errors.As(err, &pathError) ||
				len(r.Steps) != 2 || r.Steps[1].Stdout != "" || r.ExitCode != -1 {
				t.Fatalf("result=%+v, error=%v, want classified error with no path and no consumer output", r, err)
			}
		})
	}
}

func TestStepDataflowRejectsLeadingDashBeforeRendering(t *testing.T) {
	steps := []catalog.Step{
		{Name: "producer", Extract: map[string]catalog.StepExtractor{"id": idExtractor(false)}},
		{Name: "consumer", Exec: []any{"/usr/bin/printf", "%s", "{steps.producer.id}"}},
	}
	states := []stepRuntimeState{{name: "producer", cleanSuccess: true, values: map[string]any{"id": int64(-123)}}}
	_, err := checkStepReferences(1, steps, states)
	if !errors.Is(err, ErrExtractTypeInvalid) || strings.Contains(err.Error(), "-123") {
		t.Fatalf("error=%v, want type failure with no extracted value", err)
	}
}
