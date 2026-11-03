package catalog

import (
	"reflect"
	"testing"

	"github.com/liubing0806/allowops/internal/params"
	"github.com/liubing0806/allowops/internal/redact"
)

// Characterizes the exact error, its precedence among simultaneous errors and
// the warning order of validateAction.
func TestValidateActionErrorBranches(t *testing.T) {
	base := func() Action {
		return Action{Name: "a_b", Description: "d", Risk: "read", Exec: []any{"/bin/echo", "x"}, Timeout: "1s", MaxOutput: 1024}
	}
	script := func() *Script {
		content := []byte("echo hi\n")
		return &Script{File: "s.sh", Interpreter: "/bin/sh", Content: content, SHA256: scriptDigest(content)}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Action)
		want   string
	}{
		{"bad name", func(a *Action) { a.Name = "Bad" }, `invalid or reserved action name "Bad"`},
		{"reserved name", func(a *Action) { a.Name = "jobs_get" }, `invalid or reserved action name "jobs_get"`},
		{"description blank", func(a *Action) { a.Description = " " }, "description required"},
		{"risk", func(a *Action) { a.Risk = "high" }, "risk allowed: read, write, dangerous"},
		{"name before description and risk", func(a *Action) { a.Name = "Bad"; a.Description = ""; a.Risk = "" }, `invalid or reserved action name "Bad"`},
		{"description before risk", func(a *Action) { a.Description = ""; a.Risk = "" }, "description required"},
		{"unknown builtin", func(a *Action) { a.Exec = nil; a.Builtin = "future" }, `unsupported builtin "future"`},
		{"unknown builtin parameter", func(a *Action) {
			*a = registeredBuiltinAction("redis_command")
			a.Params = map[string]params.Definition{"nope": {Type: params.String, Description: "d"}}
		}, `unknown builtin parameter "nope"`},
		{"parameter definitions before modes", func(a *Action) {
			a.Exec = nil
			a.Params = map[string]params.Definition{"X": {Type: params.String, Description: "d"}}
		}, `parameter "X": valid name and description required`},
		{"parameter definitions before exec", func(a *Action) {
			a.Exec = []any{"relative"}
			a.Params = map[string]params.Definition{"x": {Type: params.Enum, Description: "d"}}
		}, "parameter x: enum values required"},
		{"no mode", func(a *Action) { a.Exec = nil }, "exactly one of exec, steps, script, builtin required"},
		{"two modes", func(a *Action) { a.Steps = []Step{{Name: "s1", Exec: []any{"/bin/echo"}}} }, "exactly one of exec, steps, script, builtin required"},
		{"modes before on_error", func(a *Action) { a.Exec = nil; a.OnError = "bad" }, "exactly one of exec, steps, script, builtin required"},
		{"on_error without steps", func(a *Action) { a.OnError = "continue" }, "on_error allowed for steps: continue, stop"},
		{"on_error value", func(a *Action) {
			a.Exec = nil
			a.Steps = []Step{{Name: "s1", Exec: []any{"/bin/echo"}}}
			a.OnError = "retry"
		}, "on_error allowed for steps: continue, stop"},
		{"exec_fallbacks without exec", func(a *Action) {
			a.Exec = nil
			a.Steps = []Step{{Name: "s1", Exec: []any{"/bin/echo"}}}
			a.ExecFallbacks = []string{"/bin/true"}
		}, "exec_fallbacks requires exec"},
		{"args without script", func(a *Action) { a.Args = []any{"x"} }, "args requires script"},
		{"builtin_config without builtin", func(a *Action) { a.BuiltinConfig = map[string]any{"k": 1} }, "builtin_config requires builtin"},
		{"negative max_scan", func(a *Action) { a.MaxScan = -1 }, "max_scan must be nonnegative"},
		{"invalid filter", func(a *Action) { a.Filters = []string{"bogus"} }, `invalid or duplicate filter "bogus"`},
		{"duplicate filter", func(a *Action) { a.Filters = []string{"head", "tail", "head"} }, `invalid or duplicate filter "head"`},
		{"filters before exec", func(a *Action) { a.Exec = []any{"relative"}; a.Filters = []string{"bogus"} }, `invalid or duplicate filter "bogus"`},
		{"on_error before exec_fallbacks", func(a *Action) { a.OnError = "stop"; a.ExecFallbacks = []string{"/bin/true"} }, "on_error allowed for steps: continue, stop"},
		{"exec relative", func(a *Action) { a.Exec = []any{"echo"} }, "exec[0] must be a fixed absolute path"},
		{"exec sudo", func(a *Action) { a.Exec = []any{"/bin/echo", "sudo"} }, "sudo forbidden in exec; use run_as"},
		{"exec fallback relative", func(a *Action) { a.ExecFallbacks = []string{"relative"} }, "exec[0] must be a fixed absolute path"},
		{"exec before timeout", func(a *Action) { a.Exec = []any{"echo"}; a.Timeout = "" }, "exec[0] must be a fixed absolute path"},
		{"steps empty", func(a *Action) { a.Exec = nil; a.Steps = []Step{} }, "steps must not be empty"},
		{"step name", func(a *Action) { a.Exec = nil; a.Steps = []Step{{Name: "Bad", Exec: []any{"/bin/echo"}}} }, `invalid or duplicate step name "Bad"`},
		{"step duplicate", func(a *Action) {
			a.Exec = nil
			a.Steps = []Step{{Name: "s1", Exec: []any{"/bin/echo"}}, {Name: "s1", Exec: []any{"/bin/echo"}}}
		}, `invalid or duplicate step name "s1"`},
		{"step exec", func(a *Action) {
			a.Exec = nil
			a.Steps = []Step{{Name: "s1", Exec: []any{"/bin/echo"}}, {Name: "s2", Exec: []any{"echo"}}}
		}, "step s2: exec[0] must be a fixed absolute path"},
		{"step name before step exec", func(a *Action) {
			a.Exec = nil
			a.Steps = []Step{{Name: "s1", Exec: []any{"echo"}}, {Name: "Bad", Exec: []any{"/bin/echo"}}}
		}, "step s1: exec[0] must be a fixed absolute path"},
		{"script file", func(a *Action) { a.Exec = nil; a.Script = script(); a.Script.File = "/abs" }, "script.file must be a relative catalog path"},
		{"script traversal", func(a *Action) { a.Exec = nil; a.Script = script(); a.Script.File = "a/../b" }, "script.file traversal forbidden"},
		{"script interpreter", func(a *Action) { a.Exec = nil; a.Script = script(); a.Script.Interpreter = "/bin/cat" }, "script.interpreter must be an absolute interpreter path"},
		{"script digest", func(a *Action) { a.Exec = nil; a.Script = script(); a.Script.SHA256 = "00" }, "script content digest mismatch"},
		{"script args template", func(a *Action) { a.Exec = nil; a.Script = script(); a.Args = []any{"{missing}"} }, "unknown placeholder missing; allowed: []"},
		{"builtin config", func(a *Action) {
			*a = registeredBuiltinAction("redis_command")
			a.BuiltinConfig["commands"] = []string{"KEYS"}
		}, "commands may only contain: GET, MGET, HGET, HLEN, TTL, TYPE, EXISTS, STRLEN, LLEN, SCARD, ZCARD, SCAN, INFO, CONFIG, SLOWLOG"},
		{"timeout empty", func(a *Action) { a.Timeout = "" }, "timeout required: positive Go duration"},
		{"timeout zero", func(a *Action) { a.Timeout = "0s" }, "timeout required: positive Go duration"},
		{"timeout negative", func(a *Action) { a.Timeout = "-1s" }, "timeout required: positive Go duration"},
		{"timeout unparsable", func(a *Action) { a.Timeout = "soon" }, "timeout required: positive Go duration"},
		{"max_output", func(a *Action) { a.MaxOutput = 0 }, "max_output must be positive integer bytes"},
		{"timeout before max_output", func(a *Action) { a.Timeout = ""; a.MaxOutput = 0 }, "timeout required: positive Go duration"},
		{"batch_size", func(a *Action) { a.BatchSize = -1 }, "batch_size and max_failures must be nonnegative"},
		{"max_failures", func(a *Action) { n := -1; a.MaxFailures = &n }, "batch_size and max_failures must be nonnegative"},
		{"max_output before batch_size", func(a *Action) { a.MaxOutput = 0; a.BatchSize = -1 }, "max_output must be positive integer bytes"},
		{"run_as newline", func(a *Action) { a.RunAs = "a\nb" }, "invalid run_as"},
		{"run_as nul", func(a *Action) { a.RunAs = "a\x00b" }, "invalid run_as"},
		{"run_as dash", func(a *Action) { a.RunAs = "-u" }, "invalid run_as"},
		{"batch_size before run_as", func(a *Action) { a.BatchSize = -1; a.RunAs = "-u" }, "batch_size and max_failures must be nonnegative"},
		{"redact", func(a *Action) { a.Redact = &redact.Config{Builtin: []string{"bogus"}} }, `unknown redaction builtin "bogus"; allowed: secrets, pii`},
		{"run_as before redact", func(a *Action) { a.RunAs = "-u"; a.Redact = &redact.Config{Builtin: []string{"bogus"}} }, "invalid run_as"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := base()
			tc.mutate(&a)
			warnings, err := ValidateAction(a)
			if err == nil {
				t.Fatalf("accepted; warnings %q", warnings)
			}
			if warnings != nil {
				t.Fatalf("warnings with error: %q", warnings)
			}
			if err.Error() != tc.want {
				t.Fatalf("got  %q\nwant %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidateActionWarningsOrder(t *testing.T) {
	content := []byte("echo hi\n")
	a := Action{Name: "a_b", Description: "d", Risk: "read", Script: &Script{File: "s.sh", Interpreter: "/bin/sh", Content: content, SHA256: scriptDigest(content)}, Timeout: "1s", MaxOutput: 1024, AllowInterpreter: true}
	got, err := ValidateAction(a)
	want := []string{"action a_b: signed script permits arbitrary execution", "action a_b: allow_interpreter permits arbitrary interpreter/script execution"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%q %v", got, err)
	}
	a.Script = nil
	a.Exec = []any{"/bin/echo", "x"}
	got, err = ValidateAction(a)
	if err != nil || !reflect.DeepEqual(got, want[1:]) {
		t.Fatalf("%q %v", got, err)
	}
	a.AllowInterpreter = false
	got, err = ValidateAction(a)
	if err != nil || got != nil {
		t.Fatalf("%q %v", got, err)
	}
}

// Reader mode keeps unknown handlers and types but still validates what it understands.
func TestValidateActionReaderMode(t *testing.T) {
	future := Action{Name: "a_b", Description: "d", Risk: "read", Builtin: "future", BuiltinConfig: map[string]any{"k": 1}, Timeout: "1s", MaxOutput: 1024,
		Params: map[string]params.Definition{"v": {Type: "future_type", Description: "d"}}}
	if warnings, err := validateAction(future, true); err != nil || warnings != nil {
		t.Fatalf("%q %v", warnings, err)
	}
	if _, err := validateAction(future, false); err == nil || err.Error() != `unsupported builtin "future"` {
		t.Fatalf("%v", err)
	}
	future.Params = map[string]params.Definition{"v": {Type: "future_type", Description: "d", MaxLen: -1}}
	if _, err := validateAction(future, true); err == nil || err.Error() != "parameter v: constraints must be nonnegative" {
		t.Fatalf("%v", err)
	}
	future.Params = nil
	future.Exec = []any{"/bin/echo"}
	if _, err := validateAction(future, true); err == nil || err.Error() != "exactly one of exec, steps, script, builtin required" {
		t.Fatalf("%v", err)
	}
	future.Exec = nil
	future.Timeout = ""
	if _, err := validateAction(future, true); err == nil || err.Error() != "timeout required: positive Go duration" {
		t.Fatalf("%v", err)
	}
	// A known builtin with a bad config is rejected even in reader mode.
	known := Action{Name: "a_b", Description: "d", Risk: "read", Builtin: "redis_command", BuiltinConfig: map[string]any{"commands": []string{"KEYS"}}, Timeout: "1s", MaxOutput: 1024}
	if _, err := validateAction(known, true); err == nil {
		t.Fatal("accepted")
	}
}
