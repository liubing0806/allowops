package attack

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/executor"
	"github.com/liubing0806/allowops/internal/params"
)

const (
	stepCommandDir = "step-command-fixture"
	stepValueRef   = "steps.s1.value"
	stepValueArg   = "{" + stepValueRef + "}"
)

// Run the test binary under the command name the catalog checks. The child
// records its actual argv before producing fixed output, regardless of its args.
func TestMain(m *testing.M) {
	dir := filepath.Dir(os.Args[0])
	if filepath.Base(dir) == stepCommandDir {
		argv, err := json.Marshal(os.Args[1:])
		if err != nil || os.WriteFile(filepath.Join(dir, "started"), argv, 0o600) != nil {
			os.Exit(2)
		}
		_, _ = os.Stdout.WriteString("consumer\n")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func stepCommandFixture(t *testing.T, name string) (command, marker string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), stepCommandDir)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command = filepath.Join(dir, name)
	if err := os.Symlink(self, command); err != nil {
		t.Fatal(err)
	}
	return command, filepath.Join(dir, "started")
}

func stepOutput(stdout string) []any {
	// printf receives one static format and writes the fixture as data.
	encoded := strings.NewReplacer(`\`, `\\`, "\n", `\n`, "\x00", `\0000`).Replace(stdout)
	return []any{"/usr/bin/printf", "%b", encoded}
}

func stepTextExtractor(pattern string) catalog.StepExtractor {
	return catalog.StepExtractor{
		Regex: "^(.*)$",
		As:    catalog.ExtractType{Type: params.String, Regex: pattern, MaxLen: 256},
	}
}

func stepDataflowAction(producer []any, spec catalog.StepExtractor, consumer ...any) catalog.Action {
	return catalog.Action{
		Name: "step_dataflow", Description: "Step dataflow boundary test", Risk: "read",
		Timeout: "10s", MaxOutput: 1024, OnError: "stop",
		Steps: []catalog.Step{
			{Name: "s1", Exec: producer, Extract: map[string]catalog.StepExtractor{"value": spec}},
			{Name: "s2", Exec: consumer},
		},
	}
}

func assertStepCommandAbsent(t *testing.T, marker string) {
	t.Helper()
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no consumer process marker, stat error = %v", err)
	}
}

func assertStepCommandArgs(t *testing.T, marker string, want ...string) {
	t.Helper()
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := json.Unmarshal(data, &got); err != nil || !slices.Equal(got, want) {
		t.Fatalf("consumer argv = %q, want %q, decode error = %v", got, want, err)
	}
}

func assertInvalidStepAction(t *testing.T, a catalog.Action, marker, reason string) {
	t.Helper()
	if _, err := catalog.ValidateAction(a); err == nil || !strings.Contains(err.Error(), reason) {
		t.Errorf("validation error = %v, want %q", err, reason)
	}
	result, err := executor.Run(t.Context(), a, nil, nil)
	assertStepCommandAbsent(t, marker)
	if err == nil || !strings.Contains(err.Error(), reason) || len(result.Steps) != 0 {
		t.Fatalf("run result = %+v, error = %v, want preflight rejection %q", result, err, reason)
	}
}

func assertProducerRejected(t *testing.T, result executor.Result, err, want error, marker string) {
	t.Helper()
	assertStepCommandAbsent(t, marker)
	if !errors.Is(err, want) || result.ExitCode != -1 || len(result.Steps) != 2 {
		t.Fatalf("run result = %+v, error = %v, want %v from producer", result, err, want)
	}
	if result.Steps[0].Skipped || result.Steps[0].ExitCode != nil ||
		!result.Steps[1].Skipped || result.Steps[1].SkipReason != executor.ReasonSkipStopped {
		t.Fatalf("steps = %+v, want producer failure followed by STOPPED", result.Steps)
	}
}

func TestStepDataflowRejectsExecutionContextReferences(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		args          []any
		reason        string
	}{
		{"namespace target", "nsenter", []any{"-t", stepValueArg, "-m", "/usr/bin/cat", "/proc/self/status"}, "step placeholder forbidden"},
		{"docker host", "docker", []any{"-H", stepValueArg, "ps"}, "global options or subcommand"},
		{"docker context", "docker", []any{"-c", stepValueArg, "ps"}, "global options or subcommand"},
		{"kubectl server", "kubectl", []any{"--server", stepValueArg, "get", "pods"}, "global options or subcommand"},
		{"kubectl configuration", "kubectl", []any{"logs", "fixture-pod", "--kubeconfig", stepValueArg}, "forbidden as the value of --kubeconfig"},
		{"docker exec target", "docker", []any{"exec", stepValueArg, "/usr/bin/ps"}, "execution options or operands"},
		{"kubectl exec target", "kubectl", []any{"exec", stepValueArg, "--", "/usr/bin/ps"}, "execution options or operands"},
		{"environment operand", "env", []any{stepValueArg, "/usr/bin/id"}, "step placeholder forbidden as a command"},
		{"timeout operand", "timeout", []any{stepValueArg, "/usr/bin/id"}, "execution options or operands"},
		{"xargs replacement", "xargs", []any{"-I", stepValueArg, "/bin/echo"}, "fixed xargs replacement required"},
		{"chroot operand", "chroot", []any{stepValueArg, "/usr/bin/id"}, "execution options or operands"},
		{"executable", "fixture", nil, "exec[0] must be a fixed absolute path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, marker := stepCommandFixture(t, tc.command)
			argv := append([]any{command}, tc.args...)
			if tc.command == "fixture" {
				argv[0] = stepValueArg
			}
			a := stepDataflowAction(stepOutput(command+"\n"), stepTextExtractor(".+"), argv...)
			assertInvalidStepAction(t, a, marker, tc.reason)
		})
	}
}

func TestStepDataflowRejectsUnsafeIntegerBounds(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		min, max     *int64
	}{
		{"missing minimum", "extract int requires min and max", nil, new(int64(100))},
		{"missing maximum", "extract int requires min and max", new(int64(0)), nil},
		{"negative minimum", "requires min >= 0", new(int64(-1)), new(int64(100))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, marker := stepCommandFixture(t, "consumer")
			spec := catalog.StepExtractor{Regex: "^(.*)$", As: catalog.ExtractType{Type: params.Int, Min: tc.min, Max: tc.max}}
			a := stepDataflowAction(stepOutput("1\n"), spec, command, stepValueArg)
			assertInvalidStepAction(t, a, marker, tc.reason)
		})
	}
}

func TestStepDataflowRejectsInvalidExtractedArguments(t *testing.T) {
	anyText := catalog.ExtractType{Type: params.String, Regex: ".+", MaxLen: 256}
	for _, tc := range []struct {
		name, stdout, jsonPath string
		as                     catalog.ExtractType
	}{
		{name: "long option", stdout: "--output=fixture\n", as: anyText},
		{name: "short options", stdout: "-rf\n", as: anyText},
		{name: "negative integer", stdout: "-1\n", as: catalog.ExtractType{Type: params.Int, Min: new(int64(0)), Max: new(int64(100))}},
		{name: "unanchored type pattern with command separator", stdout: "ok; fixture\n"},
		{name: "substitution delimiters", stdout: "$( )\n"},
		{name: "backtick delimiters", stdout: "` `\n"},
		{name: "embedded newline", stdout: `{"value":"a\nb"}`, jsonPath: "$.value"},
		{name: "embedded NUL", stdout: "a\x00b\n", as: anyText},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, marker := stepCommandFixture(t, "consumer")
			spec := stepTextExtractor("[a-z0-9]+")
			spec.Optional = true
			if tc.as.Type != "" {
				spec.As = tc.as
			}
			if tc.jsonPath != "" {
				spec.Regex = ""
				spec.JSONPath = tc.jsonPath
				spec.As.Regex = "(?s:.*)"
			}
			a := stepDataflowAction(stepOutput(tc.stdout), spec, command, []any{"-u", stepValueArg})
			result, err := executor.Run(t.Context(), a, nil, nil)
			assertProducerRejected(t, result, err, executor.ErrExtractTypeInvalid, marker)
		})
	}
}

func TestStepDataflowPreservesLiteralArgument(t *testing.T) {
	command, marker := stepCommandFixture(t, "consumer")
	const literal = "fixture; $( ) ` `"
	a := stepDataflowAction(stepOutput(literal+"\n"), stepTextExtractor(".+"), command, stepValueArg)
	result, err := executor.Run(t.Context(), a, nil, nil)
	if err != nil || result.ExitCode != 0 || len(result.Steps) != 2 {
		t.Fatalf("result = %+v, error = %v, want successful execution", result, err)
	}
	assertStepCommandArgs(t, marker, literal)
}

func TestStepDataflowRedactedConditionStaysUnknown(t *testing.T) {
	for _, tc := range []struct {
		name, stdout string
		optional     bool
		want         error
	}{
		{"required", "-----BEGIN PRIVATE KEY-----\nstate=inactive\n", false, executor.ErrExtractFailed},
		{"optional", "-----BEGIN PRIVATE KEY-----\nstate=inactive\n", true, nil},
		{"visible inactive state", "state=inactive\n", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, marker := stepCommandFixture(t, "consumer")
			spec := stepTextExtractor("[a-z]+")
			spec.Regex = "^state=([a-z]+)$"
			spec.Optional = tc.optional
			a := stepDataflowAction(stepOutput(tc.stdout), spec, command)
			a.OnError = "continue"
			a.Steps[1].When = &catalog.StepCondition{Not: &catalog.StepCondition{
				Ref: stepValueRef, Eq: &catalog.ConditionValue{Value: "active"},
			}}
			result, err := executor.Run(t.Context(), a, nil, nil)
			if !errors.Is(err, tc.want) || len(result.Steps) != 2 {
				t.Fatalf("result = %+v, error = %v, want %v and two steps", result, err, tc.want)
			}
			consumer := result.Steps[1]
			if tc.stdout == "state=inactive\n" {
				assertStepCommandArgs(t, marker)
				if consumer.Skipped || consumer.ExitCode == nil || *consumer.ExitCode != 0 {
					t.Fatalf("consumer = %+v, want successful execution", consumer)
				}
				return
			}
			assertStepCommandAbsent(t, marker)
			if !consumer.Skipped || consumer.SkipReason != executor.ReasonSkipConditionFalse || consumer.ExitCode != nil {
				t.Fatalf("consumer = %+v, want CONDITION_FALSE", consumer)
			}
			if strings.Contains(result.Steps[0].Stdout, "inactive") {
				t.Fatal("state inside the PEM block reached producer stdout")
			}
		})
	}
}

func TestStepDataflowFailedProducerCannotOmitOptionalGroup(t *testing.T) {
	for _, tc := range []struct {
		name     string
		producer []any
		exitCode *int
		want     error
	}{
		{"nonzero exit", []any{"/usr/bin/false"}, new(1), nil},
		{"extract failure", stepOutput("unit=123\n"), nil, executor.ErrExtractTypeInvalid},
		{"clean miss", stepOutput("other\n"), new(0), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, marker := stepCommandFixture(t, "consumer")
			spec := stepTextExtractor("[a-z]+")
			spec.Regex = "^unit=(.*)$"
			spec.Optional = true
			a := stepDataflowAction(tc.producer, spec, command, []any{"-u", stepValueArg})
			a.OnError = "continue"
			var stepErrs []error
			result, err := executor.RunWithCallbacks(t.Context(), a, nil, nil, nil, executor.Callbacks{
				StepCompleted: func(_ executor.StepResult, err error) error {
					stepErrs = append(stepErrs, err)
					return nil
				},
			})
			if len(stepErrs) != 2 || len(result.Steps) != 2 || !errors.Is(stepErrs[0], tc.want) {
				t.Fatalf("result = %+v, step errors = %v, want producer error %v", result, stepErrs, tc.want)
			}
			gotExit := result.Steps[0].ExitCode
			if (gotExit == nil) != (tc.exitCode == nil) || (gotExit != nil && *gotExit != *tc.exitCode) {
				t.Fatalf("producer exit code = %v, want %v", gotExit, tc.exitCode)
			}
			if tc.name == "clean miss" {
				assertStepCommandArgs(t, marker)
				if err != nil || result.ExitCode != 0 {
					t.Fatalf("result = %+v, error = %v, want clean omission", result, err)
				}
				return
			}
			assertStepCommandAbsent(t, marker)
			if !errors.Is(err, executor.ErrExtractMissing) || !errors.Is(stepErrs[1], executor.ErrExtractMissing) || result.Steps[1].Skipped {
				t.Fatalf("result = %+v, run error = %v, consumer error = %v, want EXTRACT_MISSING", result, err, stepErrs[1])
			}
		})
	}
}

func TestStepDataflowRejectsInterpreterOverride(t *testing.T) {
	command, marker := stepCommandFixture(t, "consumer")
	a := stepDataflowAction(stepOutput("fixture\n"), stepTextExtractor("[a-z]+"), command, stepValueArg)
	a.AllowInterpreter = true
	assertInvalidStepAction(t, a, marker, "step placeholders forbidden with allow_interpreter")
}

func TestStepDataflowRechecksRenderedCommand(t *testing.T) {
	for _, tc := range []struct {
		command, value string
		args           []any
	}{
		{"tar", "xIf", []any{stepValueArg, "fixture.tar"}},
		{"ip", "exec", []any{stepValueArg}},
	} {
		t.Run(tc.command, func(t *testing.T) {
			command, marker := stepCommandFixture(t, tc.command)
			a := stepDataflowAction(stepOutput(tc.value+"\n"), stepTextExtractor("[a-zA-Z]+"), append([]any{command}, tc.args...)...)
			if _, err := catalog.ValidateAction(a); err != nil {
				t.Fatalf("template validation error = %v, want rendered-command rejection only", err)
			}
			result, err := executor.Run(t.Context(), a, nil, nil)
			assertStepCommandAbsent(t, marker)
			if err == nil || !strings.Contains(err.Error(), tc.command+" runs commands from its arguments") || len(result.Steps) != 2 {
				t.Fatalf("result = %+v, error = %v, want rendered-command rejection", result, err)
			}
			producer, consumer := result.Steps[0], result.Steps[1]
			if producer.ExitCode == nil || *producer.ExitCode != 0 || consumer.Skipped || consumer.ExitCode != nil {
				t.Fatalf("producer = %+v, consumer = %+v, want successful producer and pre-exec consumer failure", producer, consumer)
			}
		})
	}
}

func TestStepDataflowRejectsDuplicateRegexMatches(t *testing.T) {
	command, marker := stepCommandFixture(t, "consumer")
	spec := stepTextExtractor("[a-z]+")
	spec.Regex = "^id=([a-z]+)$"
	spec.Match = "exactly_one"
	a := stepDataflowAction(stepOutput("id=first\nid=second\n"), spec, command, stepValueArg)
	result, err := executor.Run(t.Context(), a, nil, nil)
	assertProducerRejected(t, result, err, executor.ErrExtractFailed, marker)
}

func TestStepDataflowRejectsRedactedValues(t *testing.T) {
	const credential = "testcredential"
	for _, tc := range []struct {
		name, stdout, regex, jsonPath string
	}{
		{"redacted prefix", "app-password=" + credential + "\n", "^([a-z-]+)", ""},
		{"decoded JSON field", "{\"\\u0070assword\":\"" + credential + "\"}", "", "$.password"},
		{"decoded JSON array element", "{\"\\u0070assword\":[\"" + credential + "\"]}", "", "$.password[0]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, marker := stepCommandFixture(t, "consumer")
			spec := stepTextExtractor("[a-z-]+")
			spec.Regex, spec.JSONPath = tc.regex, tc.jsonPath
			a := stepDataflowAction(stepOutput(tc.stdout), spec, command, stepValueArg)
			result, err := executor.Run(t.Context(), a, nil, nil)
			assertProducerRejected(t, result, err, executor.ErrExtractFailed, marker)
			if strings.Contains(err.Error(), credential) {
				t.Fatal("diagnostic contains the extracted credential")
			}
			if tc.regex != "" && result.Steps[0].Stdout != "app-[REDACTED:credential]\n" {
				t.Fatalf("producer stdout = %q, want redacted line with an otherwise extractable prefix", result.Steps[0].Stdout)
			}
		})
	}
}

func TestStepDataflowConditionCannotDistinguishRedactedCredentials(t *testing.T) {
	for _, credential := range []string{"supersecret", "other"} {
		command, marker := stepCommandFixture(t, "consumer")
		spec := stepTextExtractor("[a-z]+")
		spec.Regex = "^token=([a-z]+)$"
		spec.Optional = true
		a := stepDataflowAction(stepOutput("token="+credential+"\n"), spec, command)
		a.Steps[1].When = &catalog.StepCondition{Ref: stepValueRef, Eq: &catalog.ConditionValue{Value: "supersecret"}}
		result, err := executor.Run(t.Context(), a, nil, nil)
		assertStepCommandAbsent(t, marker)
		if err != nil || result.ExitCode != 0 || len(result.Steps) != 2 ||
			result.Steps[0].Stdout != "[REDACTED:credential]\n" ||
			!result.Steps[1].Skipped || result.Steps[1].SkipReason != executor.ReasonSkipConditionFalse {
			t.Fatalf("result = %+v, error = %v, want redacted stdout and CONDITION_FALSE", result, err)
		}
	}
}

func TestStepDataflowRejectsOversizedOutput(t *testing.T) {
	const lineBytes, lineCount = 4096, 1025
	path := filepath.Join(t.TempDir(), "producer-output")
	contents := make([]byte, 0, lineBytes*lineCount)
	contents = append(contents, strings.Repeat("a", lineBytes-1)+"\n"...)
	line := strings.Repeat("b", lineBytes-1) + "\n"
	for range lineCount - 1 {
		contents = append(contents, line...)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	producer := []any{"/usr/bin/cat", path}
	t.Run("max_scan discards an otherwise complete match", func(t *testing.T) {
		command, marker := stepCommandFixture(t, "consumer")
		spec := stepTextExtractor("a")
		spec.Regex = "^(a)a+$"
		spec.Optional = true
		a := stepDataflowAction(producer, spec, command, []any{"-u", stepValueArg})
		a.MaxScan = 2 * lineBytes
		a.MaxOutput = a.MaxScan
		result, err := executor.Run(t.Context(), a, nil, nil)
		assertProducerRejected(t, result, err, executor.ErrExtractFailed, marker)
		if !result.ScanLimitReached || !result.Steps[0].ScanLimitReached {
			t.Fatalf("result = %+v, want max_scan reached", result)
		}
	})
	t.Run("max_bytes bounds uniqueness check during a flood", func(t *testing.T) {
		command, marker := stepCommandFixture(t, "consumer")
		spec := stepTextExtractor("a")
		spec.Regex = "^(a)a+$"
		spec.Match = "exactly_one"
		spec.MaxBytes = lineBytes
		a := stepDataflowAction(producer, spec, command, stepValueArg)
		a.MaxScan = catalog.Size(len(contents) + 1)
		a.Filters = []string{"count"}
		result, err := executor.Run(t.Context(), a, map[string]any{"count": true}, nil)
		assertProducerRejected(t, result, err, executor.ErrExtractFailed, marker)
		if result.ScanLimitReached || result.Steps[0].Truncated || result.Steps[0].Stdout != strconv.Itoa(lineCount)+"\n" {
			t.Fatalf("result = %+v, want all %d lines scanned with bounded output", result, lineCount)
		}
	})
}

func TestStepDataflowRejectsUntrustedPathsWithoutEchoingValues(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "allowed")
	sibling := root + "-sibling"
	writable := filepath.Join(root, "group-writable")
	for _, dir := range []string{root, sibling, writable} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(sibling, "fixture")
	inside := filepath.Join(writable, "fixture")
	for _, path := range []string{outside, inside} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := params.CheckPathTrusted(inside, os.Geteuid()); err != nil {
		t.Fatalf("path fixture must start trusted: %v", err)
	}
	if err := os.Chmod(writable, 0o770); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	traversal, err := filepath.Rel(cwd, outside)
	if err != nil || !strings.HasPrefix(traversal, "../") {
		t.Fatalf("relative path = %q, error = %v, want a traversal to the outside fixture", traversal, err)
	}

	for _, tc := range []struct {
		name, path string
		want       error
	}{
		{"traversal", traversal, executor.ErrExtractTypeInvalid},
		{"sibling prefix", outside, executor.ErrExtractTypeInvalid},
		{"symlink escape", link, executor.ErrExtractTypeInvalid},
		{"group writable directory", inside, params.ErrPathNotTrusted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, marker := stepCommandFixture(t, "consumer")
			spec := catalog.StepExtractor{Regex: "^(.*)$", As: catalog.ExtractType{Type: params.Path, AllowedRoots: []string{root}}}
			a := stepDataflowAction(stepOutput(tc.path+"\n"), spec, command, stepValueArg)
			result, err := executor.Run(t.Context(), a, nil, nil)
			if tc.want == params.ErrPathNotTrusted {
				assertStepCommandAbsent(t, marker)
				if !errors.Is(err, tc.want) || len(result.Steps) != 2 {
					t.Fatalf("result = %+v, error = %v, want PATH_NOT_TRUSTED", result, err)
				}
				producer, consumer := result.Steps[0], result.Steps[1]
				if producer.ExitCode == nil || *producer.ExitCode != 0 || consumer.Skipped || consumer.ExitCode != nil {
					t.Fatalf("producer = %+v, consumer = %+v, want successful producer and pre-exec consumer failure", producer, consumer)
				}
			} else {
				assertProducerRejected(t, result, err, tc.want, marker)
			}
			var pathError *os.PathError
			if strings.Contains(err.Error(), tc.path) || strings.Contains(err.Error(), base) || errors.As(err, &pathError) {
				t.Fatal("diagnostic contains a source or resolved path")
			}
		})
	}
}

func TestStepDataflowExtractionPrecedesCallerFilters(t *testing.T) {
	for _, tc := range []struct {
		name string
		arg  any
		want string
	}{
		{"count", true, "1\n"},
		{"exclude", ".*", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, marker := stepCommandFixture(t, "consumer")
			a := stepDataflowAction(stepOutput("fixture\n"), stepTextExtractor("[a-z]+"), command, stepValueArg)
			a.Filters = []string{"count", "exclude"}
			result, err := executor.Run(t.Context(), a, map[string]any{tc.name: tc.arg}, nil)
			if err != nil || result.ExitCode != 0 || len(result.Steps) != 2 {
				t.Fatalf("result = %+v, error = %v, want both steps to run", result, err)
			}
			for _, step := range result.Steps {
				if step.Skipped || step.ExitCode == nil || *step.ExitCode != 0 || step.Stdout != tc.want {
					t.Fatalf("step = %+v, want successful execution and filtered stdout %q", step, tc.want)
				}
			}
			assertStepCommandArgs(t, marker, "fixture")
		})
	}
}

func TestStepDataflowRejectsUnboundedOrAmbiguousJSON(t *testing.T) {
	for _, tc := range []struct{ name, stdout string }{
		{"nested JSON", "{\"id\":\"safe\",\"nested\":" + strings.Repeat("[", 64) + "0" + strings.Repeat("]", 64) + "}"},
		{"duplicate key", "{\"id\":\"safe\",\"id\":\"other\"}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, marker := stepCommandFixture(t, "consumer")
			spec := stepTextExtractor("[a-z]+")
			spec.Regex, spec.JSONPath = "", "$.id"
			a := stepDataflowAction(stepOutput(tc.stdout), spec, command, stepValueArg)
			result, err := executor.Run(t.Context(), a, nil, nil)
			assertProducerRejected(t, result, err, executor.ErrExtractFailed, marker)
		})
	}
}

func TestStepDataflowOldAgentStrictCatalogDecoding(t *testing.T) {
	type oldStep struct {
		Name string `json:"name"`
		Exec []any  `json:"exec"`
	}
	type oldAction struct {
		catalog.Action
		Steps []oldStep `json:"steps"`
	}
	type oldPackage struct {
		catalog.Package
		Actions map[string]oldAction `json:"actions"`
	}
	for _, tc := range []struct {
		name          string
		extract, when bool
		unknownField  string
	}{
		{"old action", false, false, ""},
		{"extract only", true, false, "extract"},
		{"when only", false, true, "when"},
		{"extract and when", true, true, "extract"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := stepDataflowAction(stepOutput("fixture\n"), stepTextExtractor("[a-z]+"), "/usr/bin/true")
			if !tc.extract {
				a.Steps[0].Extract = nil
			}
			if tc.when {
				a.Steps[1].When = &catalog.StepCondition{Ref: "prev.exit_code", Eq: &catalog.ConditionValue{Value: int64(0)}}
			}
			pkg, err := catalog.Build(&catalog.Catalog{
				Config:  catalog.Config{SchemaVersion: 1, CatalogID: "step-dataflow"},
				Actions: map[string]catalog.Action{a.Name: a},
			}, catalog.BuildOptions{Now: time.Unix(0, 0)})
			if err != nil {
				t.Fatal(err)
			}
			data, err := catalog.CanonicalJSON(pkg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := catalog.ParsePackage(data); err != nil {
				t.Fatalf("current schema rejected the package: %v", err)
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			var old oldPackage
			err = decoder.Decode(&old)
			if tc.unknownField == "" {
				if err != nil || len(old.Actions[a.Name].Steps) != 2 {
					t.Fatalf("legacy package decode error = %v, want two decoded steps", err)
				}
				return
			}
			want := "json: unknown field \"" + tc.unknownField + "\""
			if err == nil || err.Error() != want {
				t.Fatalf("legacy package decode error = %v, want %s", err, want)
			}
		})
	}
}
