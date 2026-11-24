package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/liubing0806/allowops/internal/redact"
)

const (
	ReasonExtractFailed      = "EXTRACT_FAILED"
	ReasonExtractTypeInvalid = "EXTRACT_TYPE_INVALID"
	ReasonExtractMissing     = "EXTRACT_MISSING"
	ReasonSkipConditionFalse = "CONDITION_FALSE"
	ReasonSkipStopped        = "STOPPED"
)

var (
	ErrExtractFailed      = NewReasonError(ReasonExtractFailed, "")
	ErrExtractTypeInvalid = NewReasonError(ReasonExtractTypeInvalid, "")
	ErrExtractMissing     = NewReasonError(ReasonExtractMissing, "")
)

type reasonError struct {
	code, message string
}

func (e *reasonError) Error() string  { return e.message }
func (e *reasonError) Reason() string { return e.code }

func (e *reasonError) Is(target error) bool {
	other, ok := target.(*reasonError)
	return ok && e.code == other.code
}

// KnownReason reports whether code is a step dataflow failure reason.
func KnownReason(code string) bool {
	switch code {
	case ReasonExtractFailed, ReasonExtractTypeInvalid, ReasonExtractMissing:
		return true
	default:
		return false
	}
}

// ReasonOf returns the first step dataflow failure reason carried by err.
func ReasonOf(err error) string {
	var reason *reasonError
	if errors.As(err, &reason) && KnownReason(reason.code) {
		return reason.code
	}
	return ""
}

// NewReasonError reconstructs a reason received from the execution helper.
func NewReasonError(code, message string) error {
	if message == "" {
		message = code
	}
	return &reasonError{code: code, message: message}
}

func stepVariableError(step, variable string, err error) error {
	return fmt.Errorf("step %s variable %s: %w", step, variable, err)
}

type stepExtractor struct {
	name       string
	spec       catalog.StepExtractor
	limit      int
	regex      *regexp.Regexp
	targetLine int
	value      string
	matched    bool
	tainted    bool
	duplicate  bool
}

type stepExtractSink struct {
	ctx         context.Context
	step        string
	redactor    *redact.Redactor
	extractors  []stepExtractor
	bytesSeen   int
	linesSeen   int
	maxBytes    int
	json        bytes.Buffer
	jsonLimit   int
	jsonTainted bool
}

// newStepExtractSink receives a step already validated by catalog.CheckHost.
func newStepExtractSink(ctx context.Context, step catalog.Step, redactor *redact.Redactor) *stepExtractSink {
	s := &stepExtractSink{ctx: ctx, step: step.Name, redactor: redactor}
	for _, name := range slices.Sorted(maps.Keys(step.Extract)) {
		spec := step.Extract[name]
		limit := catalog.DefaultExtractMaxBytes
		if spec.MaxBytes > 0 {
			limit = int(min(spec.MaxBytes, catalog.MaxExtractMaxBytes))
		}
		e := stepExtractor{name: name, spec: spec, limit: limit, targetLine: 1}
		switch {
		case spec.Regex != "":
			e.regex = regexp.MustCompile(spec.Regex)
		case spec.JSONPath != "":
			s.jsonLimit = max(s.jsonLimit, limit)
		case spec.TSV.Line != nil:
			e.targetLine = *spec.TSV.Line
		}
		s.maxBytes = max(s.maxBytes, limit)
		s.extractors = append(s.extractors, e)
	}
	return s
}

// Write receives a complete redacted line before filters or output budgeting.
func (s *stepExtractSink) Write(line string, modified bool) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if s.bytesSeen > s.maxBytes {
		return nil
	}
	s.bytesSeen += len(line)
	s.linesSeen++
	if n := min(s.jsonLimit-s.json.Len(), len(line)); n > 0 {
		if s.json.Len() == 0 {
			s.json.Grow(s.jsonLimit)
		}
		s.json.WriteString(line[:n])
		s.jsonTainted = s.jsonTainted || modified
	}
	text := strings.TrimSuffix(line, "\n")
	for i := range s.extractors {
		e := &s.extractors[i]
		if s.bytesSeen > e.limit {
			continue
		}
		switch {
		case e.regex != nil && !e.duplicate && (!e.matched || e.spec.Match == "exactly_one"):
			if match := e.regex.FindStringSubmatch(text); match != nil {
				if e.matched {
					e.duplicate = true
				} else {
					e.capture(match[1], modified)
				}
			}
		case e.spec.TSV != nil && s.linesSeen == e.targetLine:
			e.tainted = modified
			fields := strings.SplitSeq(text, "\t")
			if e.spec.TSV.Delimiter == "whitespace" {
				fields = strings.FieldsSeq(text)
			}
			column := 0
			for field := range fields {
				column++
				if column == e.spec.TSV.Column {
					e.capture(field, modified)
					break
				}
			}
		}
	}
	return nil
}

func (e *stepExtractor) capture(value string, modified bool) {
	e.value, e.matched, e.tainted = strings.Clone(value), true, modified
}

func (s *stepExtractSink) Finalize(incompleteOutput bool) (map[string]any, error) {
	values := make(map[string]any, len(s.extractors))
	for _, e := range s.extractors {
		if err := s.ctx.Err(); err != nil {
			return nil, err
		}
		value, err := s.extractValue(e, incompleteOutput)
		if err != nil {
			return nil, stepVariableError(s.step, e.name, err)
		}
		if value != nil {
			values[e.name] = value
		}
	}
	return values, nil
}

func (s *stepExtractSink) extractValue(e stepExtractor, incompleteOutput bool) (any, error) {
	overflowed := s.bytesSeen > e.limit
	if incompleteOutput || e.tainted || e.duplicate || (overflowed && e.spec.Match == "exactly_one") {
		return nil, ErrExtractFailed
	}
	var candidate any
	switch {
	case e.spec.JSONPath != "":
		value, err := s.jsonValue(e)
		if err != nil {
			return nil, err
		}
		candidate = value
	case e.matched:
		candidate = e.value
	}
	if candidate == nil {
		if overflowed || !e.spec.Optional {
			return nil, ErrExtractFailed
		}
		return nil, nil
	}
	if text, ok := candidate.(string); ok && strings.Contains(text, "[REDACTED:") {
		return nil, ErrExtractFailed
	}
	return parseExtractedValue(e, candidate)
}

var exactDecimal = regexp.MustCompile(`^-?[0-9]+$`)

func parseExtractedValue(e stepExtractor, candidate any) (any, error) {
	switch e.spec.As.Type {
	case params.Int:
		if text, ok := candidate.(string); ok {
			if !exactDecimal.MatchString(text) {
				return nil, ErrExtractTypeInvalid
			}
			// Parse checks Int64 conversion and the signed bounds.
			candidate = json.Number(text)
		}
	case params.Bool:
		if text, ok := candidate.(string); ok {
			switch text {
			case "true":
				candidate = true
			case "false":
				candidate = false
			}
		}
	}
	def := e.spec.As.AsParamDefinition(e.name)
	values, err := params.Parse(map[string]params.Definition{e.name: def}, map[string]any{e.name: candidate})
	if err != nil {
		// Parse can wrap a filesystem error containing the extracted path.
		return nil, ErrExtractTypeInvalid
	}
	return values[e.name], nil
}

func (s *stepExtractSink) jsonValue(e stepExtractor) (any, error) {
	if s.jsonTainted {
		return nil, ErrExtractFailed
	}
	prefix := s.json.Bytes()[:min(s.json.Len(), e.limit)]
	decoder := json.NewDecoder(bytes.NewReader(prefix))
	decoder.UseNumber()
	value, err := readExtractJSON(decoder, 0)
	if err != nil || !utf8.Valid(prefix[:decoder.InputOffset()]) {
		return nil, ErrExtractFailed
	}
	segments, err := catalog.ParseJSONPath(e.spec.JSONPath)
	if err != nil {
		return nil, ErrExtractFailed
	}
	for _, segment := range segments {
		if segment.IsIndex {
			items, ok := value.([]any)
			if !ok {
				return nil, ErrExtractFailed
			}
			if segment.Index >= len(items) {
				return nil, nil
			}
			value = items[segment.Index]
		} else {
			fields, ok := value.(map[string]any)
			if !ok {
				return nil, ErrExtractFailed
			}
			var exists bool
			value, exists = fields[segment.Field]
			if !exists {
				return nil, nil
			}
		}
	}
	switch value.(type) {
	case nil:
		return nil, nil
	case map[string]any, []any:
		return nil, ErrExtractTypeInvalid
	}

	text := fmt.Sprint(value)
	if _, modified := s.redactor.LineTracked(text); modified {
		return nil, ErrExtractFailed
	}
	for _, segment := range segments {
		if segment.Field == "" {
			continue
		}
		_, assignmentModified := s.redactor.LineTracked(segment.Field + "=" + text)
		_, jsonModified := s.redactor.LineTracked(strconv.Quote(segment.Field) + ":" + strconv.Quote(text))
		if assignmentModified || jsonModified {
			return nil, ErrExtractFailed
		}
	}
	return value, nil
}

const maxExtractJSONDepth = 32

// readExtractJSON consumes the first value only. Building objects from tokens
// lets it reject duplicate keys before a value can overwrite an earlier one.
func readExtractJSON(d *json.Decoder, depth int) (any, error) {
	token, err := d.Token()
	if err != nil {
		return nil, ErrExtractFailed
	}
	delim, container := token.(json.Delim)
	if !container {
		return token, nil
	}
	if depth >= maxExtractJSONDepth {
		return nil, ErrExtractFailed
	}
	var value any
	switch delim {
	case '{':
		fields := map[string]any{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return nil, ErrExtractFailed
			}
			if _, exists := fields[name]; exists {
				return nil, ErrExtractFailed
			}
			item, err := readExtractJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			fields[name] = item
		}
		value = fields
	case '[':
		var items []any
		for d.More() {
			item, err := readExtractJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		value = items
	default:
		return nil, ErrExtractFailed
	}
	if _, err := d.Token(); err != nil {
		return nil, ErrExtractFailed
	}
	return value, nil
}

type stepRuntimeState struct {
	name         string
	skipped      bool
	exitCode     *int
	cleanSuccess bool
	values       map[string]any
}

func priorStepIndex(name string, states []stepRuntimeState) int {
	return slices.IndexFunc(states, func(state stepRuntimeState) bool { return state.name == name })
}

type tribool uint8

const (
	triFalse tribool = iota
	triTrue
	triUnknown
)

func truth(value bool) tribool {
	if value {
		return triTrue
	}
	return triFalse
}

func evalCondition(c *catalog.StepCondition, stepIndex int, states []stepRuntimeState) tribool {
	switch {
	case c.Not != nil:
		switch evalCondition(c.Not, stepIndex, states) {
		case triFalse:
			return triTrue
		case triTrue:
			return triFalse
		default:
			return triUnknown
		}
	case c.All != nil:
		return evalConditions(c.All, stepIndex, states, triFalse, triTrue)
	case c.Any != nil:
		return evalConditions(c.Any, stepIndex, states, triTrue, triFalse)
	}

	value, exists := conditionRef(c.Ref, stepIndex, states)
	if c.Exists != nil {
		return truth(exists == *c.Exists)
	}
	if !exists {
		return triUnknown
	}
	switch {
	case c.Eq != nil:
		return truth(value == c.Eq.Value)
	case c.Ne != nil:
		return truth(value != c.Ne.Value)
	case c.Gt != nil:
		return truth(value.(int64) > *c.Gt)
	case c.Gte != nil:
		return truth(value.(int64) >= *c.Gte)
	case c.Lt != nil:
		return truth(value.(int64) < *c.Lt)
	case c.Lte != nil:
		return truth(value.(int64) <= *c.Lte)
	case c.In != nil:
		return truth(slices.ContainsFunc(c.In, func(item catalog.ConditionValue) bool { return value == item.Value }))
	default:
		return triUnknown
	}
}

func evalConditions(children []catalog.StepCondition, stepIndex int, states []stepRuntimeState, decisive, otherwise tribool) tribool {
	result := otherwise
	for i := range children {
		value := evalCondition(&children[i], stepIndex, states)
		if value == decisive {
			return decisive
		}
		if value == triUnknown {
			result = triUnknown
		}
	}
	return result
}

func conditionRef(ref string, stepIndex int, states []stepRuntimeState) (any, bool) {
	index := stepIndex - 1
	field, previous := strings.CutPrefix(ref, "prev.")
	if !previous {
		name, variable, _ := params.StepPlaceholder("{" + ref + "}")
		index = priorStepIndex(name, states[:stepIndex])
		field = variable
	}
	if index < 0 {
		return nil, false
	}
	state := states[index]
	switch field {
	case "skipped":
		return state.skipped, true
	case "exit_code":
		if state.exitCode != nil {
			return int64(*state.exitCode), true
		}
		return nil, false
	default:
		value, present := state.values[field]
		return value, present
	}
}

type stepPath struct {
	variable string
	path     string
}

// checkStepReferences runs before params.Render so an optional argv group can
// only disappear for an optional extraction from a cleanly successful step.
func checkStepReferences(stepIndex int, steps []catalog.Step, states []stepRuntimeState) ([]stepPath, error) {
	step := steps[stepIndex]
	var paths []stepPath
	for _, element := range step.Exec {
		words, optional := element.([]any)
		if !optional {
			words = []any{element}
		}
		for _, word := range words {
			from, name, ok := params.StepPlaceholder(word.(string))
			if !ok {
				continue
			}
			variable := from + "." + name
			producer := priorStepIndex(from, states[:stepIndex])
			if producer < 0 {
				return nil, stepVariableError(step.Name, variable, ErrExtractMissing)
			}
			extractor := steps[producer].Extract[name]
			state := states[producer]
			value, present := state.values[name]
			if !present {
				if optional && state.cleanSuccess && extractor.Optional {
					continue
				}
				return nil, stepVariableError(step.Name, variable, ErrExtractMissing)
			}
			if strings.HasPrefix(fmt.Sprint(value), "-") {
				return nil, stepVariableError(step.Name, variable, ErrExtractTypeInvalid)
			}
			if extractor.As.Type == params.Path {
				paths = append(paths, stepPath{variable: variable, path: value.(string)})
			}
		}
	}
	return paths, nil
}

func trustStepPaths(step string, paths []stepPath) error {
	for _, path := range paths {
		if err := params.CheckPathTrusted(path.path, os.Geteuid()); err != nil {
			return stepVariableError(step, path.variable, params.ErrPathNotTrusted)
		}
	}
	return nil
}
