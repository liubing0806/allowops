package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/liubing0806/allowops/internal/params"
	"gopkg.in/yaml.v3"
)

const (
	DefaultExtractMaxBytes = 64 * 1024
	MaxExtractMaxBytes     = 1024 * 1024
	MaxExtractorsPerStep   = 16
	MaxExtractorsPerAction = 64
	MaxConditionDepth      = 4
	MaxConditionNodes      = 32
	MaxConditionChildren   = 16
	MaxConditionInItems    = 32
	MaxExtractRegexLen     = 256
	MaxExtractStringLen    = 1024
	MaxTSVLine             = 10000
	MaxTSVColumn           = 64
	MaxJSONPathSegments    = 16
	MaxJSONPathIndex       = 9999
)

type TSVExtractor struct {
	Line      *int   `json:"line,omitempty" yaml:"line,omitempty"`
	Column    int    `json:"column" yaml:"column"`
	Delimiter string `json:"delimiter,omitempty" yaml:"delimiter,omitempty"`
}

type ExtractType struct {
	Type         params.Type `json:"type" yaml:"type"`
	Values       []string    `json:"values,omitempty" yaml:"values,omitempty"`
	Min          *int64      `json:"min,omitempty" yaml:"min,omitempty"`
	Max          *int64      `json:"max,omitempty" yaml:"max,omitempty"`
	Regex        string      `json:"regex,omitempty" yaml:"regex,omitempty"`
	MaxLen       int         `json:"max_len,omitempty" yaml:"max_len,omitempty"`
	AllowedRoots []string    `json:"allowed_roots,omitempty" yaml:"allowed_roots,omitempty"`
}

type StepExtractor struct {
	Regex    string        `json:"regex,omitempty" yaml:"regex,omitempty"`
	Match    string        `json:"match,omitempty" yaml:"match,omitempty"`
	JSONPath string        `json:"json_path,omitempty" yaml:"json_path,omitempty"`
	TSV      *TSVExtractor `json:"tsv,omitempty" yaml:"tsv,omitempty"`
	MaxBytes Size          `json:"max_bytes,omitempty" yaml:"max_bytes,omitempty"`
	Optional bool          `json:"optional,omitempty" yaml:"optional,omitempty"`
	As       ExtractType   `json:"as" yaml:"as"`
}

// ConditionValue holds an exact int64, string, or bool operand.
type ConditionValue struct {
	Value any
}

type StepCondition struct {
	All    []StepCondition  `json:"all,omitempty" yaml:"all,omitempty"`
	Any    []StepCondition  `json:"any,omitempty" yaml:"any,omitempty"`
	Not    *StepCondition   `json:"not,omitempty" yaml:"not,omitempty"`
	Ref    string           `json:"ref,omitempty" yaml:"ref,omitempty"`
	Exists *bool            `json:"exists,omitempty" yaml:"exists,omitempty"`
	Eq     *ConditionValue  `json:"eq,omitempty" yaml:"eq,omitempty"`
	Ne     *ConditionValue  `json:"ne,omitempty" yaml:"ne,omitempty"`
	Gt     *int64           `json:"gt,omitempty" yaml:"gt,omitempty"`
	Gte    *int64           `json:"gte,omitempty" yaml:"gte,omitempty"`
	Lt     *int64           `json:"lt,omitempty" yaml:"lt,omitempty"`
	Lte    *int64           `json:"lte,omitempty" yaml:"lte,omitempty"`
	In     []ConditionValue `json:"in,omitempty" yaml:"in,omitempty"`
}

var (
	tsvFields         = map[string]string{"line": "!!int", "column": "!!int", "delimiter": "!!str"}
	extractTypeFields = map[string]string{
		"type": "!!str", "values": "!!seq:!!str", "min": "!!int", "max": "!!int",
		"regex": "!!str", "max_len": "!!int", "allowed_roots": "!!seq:!!str",
	}
	extractorFields = map[string]string{
		"regex": "!!str", "match": "!!str", "json_path": "!!str", "tsv": "!!map",
		"max_bytes": "!!int|!!str", "optional": "!!bool", "as": "!!map",
	}
	conditionFields = map[string]string{
		"all": "!!seq:!!map", "any": "!!seq:!!map", "not": "!!map", "ref": "!!str", "exists": "!!bool",
		"eq": conditionScalarTags, "ne": conditionScalarTags, "in": "!!seq:" + conditionScalarTags,
		"gt": "!!int", "gte": "!!int", "lt": "!!int", "lte": "!!int",
	}
	stepFields = map[string]string{"name": "", "exec": "", "when": "!!map", "extract": "!!map:!!map"}
)

const conditionScalarTags = "!!int|!!str|!!bool"

// yaml.Node.Decode does not inherit KnownFields and may coerce scalars or
// skip nulls. Check keys and tags before handing the mapping to it.
func decodeDataflowYAML(node *yaml.Node, out any, fields map[string]string) (map[string]bool, error) {
	seen, err := checkDataflowYAML(node, fields, nil)
	if err != nil {
		return nil, err
	}
	return seen, node.Decode(out)
}

func checkDataflowYAML(node *yaml.Node, fields map[string]string, checkMerge func(*yaml.Node) error) (map[string]bool, error) {
	if node.Kind != yaml.MappingNode || node.ShortTag() != "!!map" {
		return nil, fmt.Errorf("expected YAML mapping")
	}
	seen := map[string]bool{}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		tags, known := fields[key.Value]
		if seen[key.Value] {
			return nil, fmt.Errorf("line %d: duplicate YAML field %q", key.Line, key.Value)
		}
		seen[key.Value] = true
		if checkMerge != nil && key.ShortTag() == "!!merge" && key.Value == "<<" {
			if err := checkMerge(value); err != nil {
				return nil, err
			}
			continue
		}
		if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || !known {
			return nil, fmt.Errorf("line %d: unknown YAML field %q", key.Line, key.Value)
		}
		if tags != "" && !matchesDataflowYAML(value, tags) {
			return nil, fmt.Errorf("line %d: invalid YAML type for %q", value.Line, key.Value)
		}
	}
	return seen, nil
}

func matchesDataflowYAML(node *yaml.Node, tags string) bool {
	if node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	tag, itemTags, collection := strings.Cut(tags, ":")
	if !slices.Contains(strings.Split(tag, "|"), node.ShortTag()) {
		return false
	}
	if !collection {
		return true
	}
	switch node.Kind {
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if !matchesDataflowYAML(item, itemTags) {
				return false
			}
		}
	case yaml.MappingNode:
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || seen[key.Value] || !matchesDataflowYAML(node.Content[i+1], itemTags) {
				return false
			}
			seen[key.Value] = true
		}
	default:
		return false
	}
	return true
}

// JSON struct decoding silently accepts null and matches field names without
// regard to case. Check exact keys and explicit nulls before assigning fields.
func decodeDataflowJSON(data []byte, out any, fields map[string]string) (map[string]bool, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("invalid UTF-8 in JSON")
	}
	var raw map[string]json.RawMessage
	if err := strictJSON(data, &raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("expected JSON object")
	}
	seen := map[string]bool{}
	for _, key := range slices.Sorted(maps.Keys(raw)) {
		value := raw[key]
		tags, known := fields[key]
		if !known {
			return nil, fmt.Errorf("unknown JSON field %q", key)
		}
		if tags != "" && bytes.Equal(value, []byte("null")) {
			return nil, fmt.Errorf("JSON field %q cannot be null", key)
		}
		if strings.HasPrefix(tags, "!!seq:") {
			var items []json.RawMessage
			if err := json.Unmarshal(value, &items); err != nil {
				return nil, fmt.Errorf("JSON field %q: %w", key, err)
			}
			for _, item := range items {
				if bytes.Equal(item, []byte("null")) {
					return nil, fmt.Errorf("JSON field %q cannot contain null", key)
				}
			}
		}
		seen[key] = true
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	return seen, decoder.Decode(out)
}

func (s *Step) UnmarshalYAML(node *yaml.Node) error {
	if err := checkStepYAML(node, map[*yaml.Node]bool{}); err != nil {
		return err
	}
	type plain Step
	return node.Decode((*plain)(s))
}

// Steps already supported YAML merges. Inspect the merged mappings as well so
// they cannot bypass field and null checks when Node.Decode applies the merge.
func checkStepYAML(node *yaml.Node, seen map[*yaml.Node]bool) error {
	if seen[node] {
		return nil
	}
	seen[node] = true
	switch node.Kind {
	case yaml.AliasNode:
		return checkStepYAML(node.Alias, seen)
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if err := checkStepYAML(item, seen); err != nil {
				return err
			}
		}
		return nil
	default:
		_, err := checkDataflowYAML(node, stepFields, func(merged *yaml.Node) error {
			return checkStepYAML(merged, seen)
		})
		return err
	}
}

func (s *Step) UnmarshalJSON(data []byte) error {
	type plain Step
	_, err := decodeDataflowJSON(data, (*plain)(s), stepFields)
	return err
}

func (t *TSVExtractor) UnmarshalYAML(node *yaml.Node) error {
	type plain TSVExtractor
	if _, err := decodeDataflowYAML(node, (*plain)(t), tsvFields); err != nil {
		return err
	}
	return t.validateLine()
}

func (t *TSVExtractor) UnmarshalJSON(data []byte) error {
	type plain TSVExtractor
	if _, err := decodeDataflowJSON(data, (*plain)(t), tsvFields); err != nil {
		return err
	}
	return t.validateLine()
}

func (t TSVExtractor) validateLine() error {
	if t.Line != nil && (*t.Line < 1 || *t.Line > MaxTSVLine) {
		return fmt.Errorf("tsv line must be between 1 and %d", MaxTSVLine)
	}
	return nil
}

func (t *ExtractType) UnmarshalYAML(node *yaml.Node) error {
	type plain ExtractType
	fields, err := decodeDataflowYAML(node, (*plain)(t), extractTypeFields)
	if err != nil {
		return err
	}
	return t.validateFields(fields)
}

func (t *ExtractType) UnmarshalJSON(data []byte) error {
	type plain ExtractType
	fields, err := decodeDataflowJSON(data, (*plain)(t), extractTypeFields)
	if err != nil {
		return err
	}
	return t.validateFields(fields)
}

func (e *StepExtractor) UnmarshalYAML(node *yaml.Node) error {
	type plain StepExtractor
	fields, err := decodeDataflowYAML(node, (*plain)(e), extractorFields)
	if err != nil {
		return err
	}
	return e.validateSelectorFields(fields)
}

func (e *StepExtractor) UnmarshalJSON(data []byte) error {
	type plain StepExtractor
	fields, err := decodeDataflowJSON(data, (*plain)(e), extractorFields)
	if err != nil {
		return err
	}
	return e.validateSelectorFields(fields)
}

func (e StepExtractor) validateSelectorFields(fields map[string]bool) error {
	if (fields["regex"] && e.Regex == "") || (fields["json_path"] && e.JSONPath == "") {
		return fmt.Errorf("regex and json_path must be non-empty when specified")
	}
	if fields["match"] && !fields["regex"] {
		return fmt.Errorf("match requires regex")
	}
	return nil
}

func (c *StepCondition) UnmarshalYAML(node *yaml.Node) error {
	nodes := 0
	if err := checkConditionYAMLBounds(node, 1, &nodes); err != nil {
		return err
	}
	type plain StepCondition
	fields, err := decodeDataflowYAML(node, (*plain)(c), conditionFields)
	if err != nil {
		return err
	}
	return c.validateRefField(fields)
}

// Bound recursion before Node.Decode invokes child unmarshaling methods.
func checkConditionYAMLBounds(node *yaml.Node, depth int, nodes *int) error {
	if err := checkConditionBounds(depth, nodes); err != nil {
		return err
	}
	if node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		child := node.Content[i+1]
		switch node.Content[i].Value {
		case "not":
			if err := checkConditionYAMLBounds(child, depth+1, nodes); err != nil {
				return err
			}
		case "all", "any":
			if child.Kind == yaml.AliasNode {
				child = child.Alias
			}
			if child.Kind == yaml.SequenceNode {
				for _, item := range child.Content {
					if err := checkConditionYAMLBounds(item, depth+1, nodes); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func (c *StepCondition) UnmarshalJSON(data []byte) error {
	// A level may have one condition object and one list of child conditions
	// or operands. Limit nesting before recursively decoding typed children.
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	depth, nodes := 0, 0
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if token == json.Delim('{') {
			nodes++
			if nodes > MaxConditionNodes {
				return fmt.Errorf("when exceeds maximum node count %d", MaxConditionNodes)
			}
		}
		switch token {
		case json.Delim('{'), json.Delim('['):
			depth++
			if depth > 2*MaxConditionDepth {
				return fmt.Errorf("when exceeds maximum JSON nesting %d", 2*MaxConditionDepth)
			}
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth == 0 {
			break
		}
	}
	type plain StepCondition
	fields, err := decodeDataflowJSON(data, (*plain)(c), conditionFields)
	if err != nil {
		return err
	}
	return c.validateRefField(fields)
}

func (c StepCondition) validateRefField(fields map[string]bool) error {
	if fields["ref"] && c.Ref == "" {
		return fmt.Errorf("when ref cannot be empty")
	}
	return nil
}

func (v *ConditionValue) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("condition operand must be an integer, string or boolean")
	}
	switch node.ShortTag() {
	case "!!int":
		var n int64
		if err := node.Decode(&n); err != nil {
			return err
		}
		v.Value = n
	case "!!str":
		var s string
		if err := node.Decode(&s); err != nil {
			return err
		}
		v.Value = s
	case "!!bool":
		var b bool
		if err := node.Decode(&b); err != nil {
			return err
		}
		v.Value = b
	default:
		return fmt.Errorf("condition operand must be an integer, string or boolean")
	}
	return v.validate()
}

func (v *ConditionValue) UnmarshalJSON(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid UTF-8 in condition operand")
	}
	var value any
	if err := strictJSON(data, &value); err != nil {
		return err
	}
	if n, ok := value.(json.Number); ok {
		exact, err := n.Int64()
		if err != nil {
			return fmt.Errorf("condition operand must be an exact int64: %w", err)
		}
		value = exact
	}
	v.Value = value
	return v.validate()
}

func (v ConditionValue) MarshalJSON() ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(v.Value)
}

func (v ConditionValue) MarshalYAML() (any, error) {
	return v.Value, v.validate()
}

func (v ConditionValue) validate() error {
	switch value := v.Value.(type) {
	case int64, bool:
		return nil
	case string:
		if !invalidDataflowText(value) {
			return nil
		}
		return fmt.Errorf("condition operand must be valid text without CR/LF/NUL")
	default:
		return fmt.Errorf("condition operand must be an integer, string or boolean")
	}
}

func invalidDataflowText(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsAny(s, "\x00\r\n")
}

// AsParamDefinition returns the constraints used to validate a captured value.
func (t ExtractType) AsParamDefinition(name string) params.Definition {
	def := params.Definition{
		Type: t.Type, Description: name, Values: t.Values, Min: t.Min,
		MaxLen: t.MaxLen, AllowedRoots: t.AllowedRoots,
	}
	if t.Max != nil {
		def.Max = *t.Max
	}
	if t.Regex != "" {
		def.Regex = "^(?:" + t.Regex + ")$"
	}
	return def
}

func (t ExtractType) validateFields(fields map[string]bool) error {
	if (t.Type != params.Enum && fields["values"]) ||
		(t.Type != params.Int && (fields["min"] || fields["max"])) ||
		(t.Type != params.String && (fields["regex"] || fields["max_len"])) ||
		(t.Type != params.Path && fields["allowed_roots"]) {
		return fmt.Errorf("extract constraints do not apply to type %s", t.Type)
	}
	return nil
}

func (t ExtractType) Validate(name string) error {
	switch t.Type {
	case params.Int:
		if t.Min == nil || t.Max == nil {
			return fmt.Errorf("parameter %s: extract int requires min and max", name)
		}
	case params.Enum:
		for _, value := range t.Values {
			if strings.HasPrefix(value, "-") {
				return fmt.Errorf("parameter %s: extract enum value must not start with '-'", name)
			}
		}
	case params.String:
		if t.Regex == "" || invalidDataflowText(t.Regex) {
			return fmt.Errorf("parameter %s: extract string requires a valid regex", name)
		}
		if t.MaxLen < 1 || t.MaxLen > MaxExtractStringLen {
			return fmt.Errorf("parameter %s: extract max_len must be between 1 and %d", name, MaxExtractStringLen)
		}
		// The pattern must be valid on its own so it cannot close the group
		// in the anchored pattern and place an alternative outside the anchors.
		if _, err := regexp.Compile(t.Regex); err != nil {
			return fmt.Errorf("parameter %s: invalid extract string regex: %w", name, err)
		}
	case params.Path, params.Bool:
	default:
		return fmt.Errorf("parameter %s: unsupported extract type %q", name, t.Type)
	}
	return params.ValidateDefinitions(map[string]params.Definition{name: t.AsParamDefinition(name)})
}

type JSONPathSegment struct {
	Field   string
	Index   int
	IsIndex bool
}

var jsonPathSegment = regexp.MustCompile(`^(?:\.([A-Za-z0-9_-]{1,64})|\[(?:(0|[1-9][0-9]{0,3})|"([A-Za-z0-9_./:-]{1,128})"|'([A-Za-z0-9_./:-]{1,128})')\])`)

// ParseJSONPath parses a field/index path rooted at $.
func ParseJSONPath(expr string) ([]JSONPathSegment, error) {
	remaining, ok := strings.CutPrefix(expr, "$")
	if !ok || remaining == "" {
		return nil, fmt.Errorf("json_path must start with $ and contain a segment")
	}
	var segments []JSONPathSegment
	for remaining != "" {
		if len(segments) == MaxJSONPathSegments {
			return nil, fmt.Errorf("json_path exceeds %d segments", MaxJSONPathSegments)
		}
		match := jsonPathSegment.FindStringSubmatch(remaining)
		if match == nil {
			return nil, fmt.Errorf("invalid json_path segment")
		}
		if match[2] != "" {
			index, err := strconv.Atoi(match[2])
			if err != nil || index > MaxJSONPathIndex {
				return nil, fmt.Errorf("invalid json_path index")
			}
			segments = append(segments, JSONPathSegment{Index: index, IsIndex: true})
		} else {
			segments = append(segments, JSONPathSegment{Field: match[1] + match[3] + match[4]})
		}
		remaining = remaining[len(match[0]):]
	}
	return segments, nil
}

// ValidateStepExtract validates a step's extractors. The caller supplies
// the number of extractors already declared by earlier steps in the action.
func ValidateStepExtract(extract map[string]StepExtractor, priorCount int) error {
	if len(extract) > MaxExtractorsPerStep {
		return fmt.Errorf("extract exceeds %d variables per step", MaxExtractorsPerStep)
	}
	if priorCount+len(extract) > MaxExtractorsPerAction {
		return fmt.Errorf("extract exceeds %d variables per action", MaxExtractorsPerAction)
	}
	for _, name := range slices.Sorted(maps.Keys(extract)) {
		if !actionName.MatchString(name) || name == "exit_code" || name == "skipped" {
			return fmt.Errorf("invalid or reserved extract variable %q", name)
		}
		if err := extract[name].validate(name); err != nil {
			return fmt.Errorf("extract %s: %w", name, err)
		}
	}
	return nil
}

func (e StepExtractor) validate(name string) error {
	if e.MaxBytes < 0 || e.MaxBytes > MaxExtractMaxBytes {
		return fmt.Errorf("max_bytes must be between 0 and %d", MaxExtractMaxBytes)
	}
	if countSet(e.Regex != "", e.JSONPath != "", e.TSV != nil) != 1 {
		return fmt.Errorf("exactly one of regex, json_path or tsv required")
	}
	if e.Match != "" && (e.Regex == "" || (e.Match != "first" && e.Match != "exactly_one")) {
		return fmt.Errorf("match requires regex and must be first or exactly_one")
	}
	switch {
	case e.Regex != "":
		if invalidDataflowText(e.Regex) || utf8.RuneCountInString(e.Regex) > MaxExtractRegexLen {
			return fmt.Errorf("regex requires valid text up to %d characters", MaxExtractRegexLen)
		}
		re, err := regexp.Compile(e.Regex)
		if err != nil {
			return fmt.Errorf("invalid extractor regex: %w", err)
		}
		if re.NumSubexp() != 1 {
			return fmt.Errorf("regex requires exactly one capture group")
		}
	case e.JSONPath != "":
		if _, err := ParseJSONPath(e.JSONPath); err != nil {
			return err
		}
	case e.TSV != nil:
		if err := e.TSV.validateLine(); err != nil {
			return err
		}
		if e.TSV.Column < 1 || e.TSV.Column > MaxTSVColumn {
			return fmt.Errorf("tsv column must be between 1 and %d", MaxTSVColumn)
		}
		if e.TSV.Delimiter != "" && e.TSV.Delimiter != "tab" && e.TSV.Delimiter != "whitespace" {
			return fmt.Errorf("tsv delimiter must be tab or whitespace")
		}
	}
	return e.As.Validate(name)
}

func countSet(fields ...bool) int {
	count := 0
	for _, set := range fields {
		if set {
			count++
		}
	}
	return count
}

// ValidateStepCondition resolves references against the steps in declaration order
// before the current step. A nil condition is valid for any step.
func ValidateStepCondition(c *StepCondition, priorSteps []Step) error {
	if c == nil {
		return nil
	}
	if len(priorSteps) == 0 {
		return fmt.Errorf("when is forbidden on the first step")
	}
	nodes := 0
	return c.validate(priorSteps, 1, &nodes)
}

func (c StepCondition) validate(priorSteps []Step, depth int, nodes *int) error {
	if err := checkConditionBounds(depth, nodes); err != nil {
		return err
	}
	combinators := countSet(c.All != nil, c.Any != nil, c.Not != nil)
	integerOps := countSet(c.Gt != nil, c.Gte != nil, c.Lt != nil, c.Lte != nil)
	operators := integerOps + countSet(c.Exists != nil, c.Eq != nil, c.Ne != nil, c.In != nil)
	if combinators > 0 {
		if combinators != 1 || c.Ref != "" || operators != 0 {
			return fmt.Errorf("when requires exactly one combinator or one ref and operator")
		}
		if c.Not != nil {
			return c.Not.validate(priorSteps, depth+1, nodes)
		}
		children := c.All
		if children == nil {
			children = c.Any
		}
		if len(children) == 0 || len(children) > MaxConditionChildren {
			return fmt.Errorf("when all/any requires between 1 and %d children", MaxConditionChildren)
		}
		for _, child := range children {
			if err := child.validate(priorSteps, depth+1, nodes); err != nil {
				return err
			}
		}
		return nil
	}
	if c.Ref == "" || operators != 1 {
		return fmt.Errorf("when requires exactly one combinator or one ref and operator")
	}
	ref, err := conditionRefType(c.Ref, priorSteps)
	if err != nil {
		return err
	}
	switch {
	case c.Exists != nil:
		return nil
	case integerOps != 0:
		if ref.Type != params.Int {
			return fmt.Errorf("when numeric comparison requires an int ref")
		}
	case c.In != nil:
		if ref.Type != params.Int && ref.Type != params.String && ref.Type != params.Enum {
			return fmt.Errorf("when in is forbidden for type %s", ref.Type)
		}
		if len(c.In) == 0 || len(c.In) > MaxConditionInItems {
			return fmt.Errorf("when in requires between 1 and %d operands", MaxConditionInItems)
		}
		for _, value := range c.In {
			if err := value.validateType(ref); err != nil {
				return err
			}
		}
	case c.Eq != nil:
		return c.Eq.validateType(ref)
	case c.Ne != nil:
		return c.Ne.validateType(ref)
	}
	return nil
}

func checkConditionBounds(depth int, nodes *int) error {
	*nodes = *nodes + 1
	if depth > MaxConditionDepth || *nodes > MaxConditionNodes {
		return fmt.Errorf("when exceeds maximum depth %d or node count %d", MaxConditionDepth, MaxConditionNodes)
	}
	return nil
}

func conditionRefType(ref string, priorSteps []Step) (ExtractType, error) {
	switch ref {
	case "prev.exit_code":
		return ExtractType{Type: params.Int}, nil
	case "prev.skipped":
		return ExtractType{Type: params.Bool}, nil
	}
	name, variable, ok := params.StepPlaceholder("{" + ref + "}")
	if ok {
		for _, step := range priorSteps {
			if step.Name != name {
				continue
			}
			switch variable {
			case "exit_code":
				return ExtractType{Type: params.Int}, nil
			case "skipped":
				return ExtractType{Type: params.Bool}, nil
			}
			if extractor, ok := step.Extract[variable]; ok {
				return extractor.As, nil
			}
			break
		}
	}
	return ExtractType{}, fmt.Errorf("when ref %q must reference a declared value from an earlier step", ref)
}

func (v ConditionValue) validateType(t ExtractType) error {
	if err := v.validate(); err != nil {
		return err
	}
	switch value := v.Value.(type) {
	case int64:
		if t.Type == params.Int {
			return nil
		}
	case bool:
		if t.Type == params.Bool {
			return nil
		}
	case string:
		if t.Type == params.String || (t.Type == params.Enum && slices.Contains(t.Values, value)) {
			return nil
		}
	}
	return fmt.Errorf("when operand does not match type %s or its allowed values", t.Type)
}
