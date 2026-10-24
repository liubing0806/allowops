package params

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Type string

const (
	Enum        Type = "enum"
	Int         Type = "int"
	String      Type = "string"
	Duration    Type = "duration"
	Path        Type = "path"
	URL         Type = "url"
	Bool        Type = "bool"
	StringArray Type = "string_array"
)

type Definition struct {
	Type        Type     `json:"type" yaml:"type"`
	Description string   `json:"description" yaml:"description"`
	Values      []string `json:"values,omitempty" yaml:"values,omitempty"`
	Min         *int64   `json:"min,omitempty" yaml:"min,omitempty"`
	// Max is an integer bound for int, or a Go duration string for duration.
	Max             any      `json:"max,omitempty" yaml:"max,omitempty"`
	Regex           string   `json:"regex,omitempty" yaml:"regex,omitempty"`
	MaxItems        int      `json:"max_items,omitempty" yaml:"max_items,omitempty"`
	MaxLen          int      `json:"max_len,omitempty" yaml:"max_len,omitempty"`
	Format          string   `json:"format,omitempty" yaml:"format,omitempty"`
	AllowedPrefixes []string `json:"allowed_prefixes,omitempty" yaml:"allowed_prefixes,omitempty"`
	AllowedRoots    []string `json:"allowed_roots,omitempty" yaml:"allowed_roots,omitempty"`
	Default         any      `json:"default,omitempty" yaml:"default,omitempty"`
	Optional        bool     `json:"optional,omitempty" yaml:"optional,omitempty"`
}

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func names(defs map[string]Definition) []string {
	result := make([]string, 0, len(defs))
	for name := range defs {
		result = append(result, name)
	}
	slices.Sort(result)
	return result
}

func ValidateDefinitions(defs map[string]Definition) error {
	return validateDefinitions(defs, false)
}

// ValidateDefinitionsForReader preserves unsupported types in a known signed
// schema. Common constraints and every understood definition remain validated;
// authoring and parameter parsing continue to use ValidateDefinitions.
func ValidateDefinitionsForReader(defs map[string]Definition) error {
	return validateDefinitions(defs, true)
}

func SupportedType(t Type) bool {
	switch t {
	case Enum, Int, String, Duration, Path, URL, Bool, StringArray:
		return true
	default:
		return false
	}
}

func validateDefinitions(defs map[string]Definition, allowUnknownTypes bool) error {
	for _, name := range names(defs) {
		if err := validateDefinition(name, defs[name], allowUnknownTypes); err != nil {
			return err
		}
	}
	return nil
}

// validateDefinition checks one parameter in a fixed order: name and
// description, constraint applicability, type-specific rules, then the default.
func validateDefinition(name string, d Definition, allowUnknownTypes bool) error {
	if !namePattern.MatchString(name) || strings.TrimSpace(d.Description) == "" {
		return fmt.Errorf("parameter %q: valid name and description required", name)
	}
	if allowUnknownTypes && !SupportedType(d.Type) {
		// Applicability and default parsing depend on the unsupported type.
		// The signed definition is retained, but authoring/execution stay strict.
		return validateFutureDefinition(name, d)
	}
	if (d.Type != Enum && d.Values != nil) || (d.Type != Int && d.Min != nil) ||
		(d.Type != Int && d.Type != Duration && d.Max != nil) ||
		((d.Type != String && d.Type != StringArray) && (d.Regex != "" || d.MaxLen != 0)) || (d.Type != StringArray && d.MaxItems != 0) ||
		(d.Type != Duration && d.Format != "") || (d.Type != Path && d.AllowedRoots != nil) || (d.Type != URL && d.AllowedPrefixes != nil) {
		return fmt.Errorf("parameter %s: constraints do not apply to type %s; allowed: enum(values), int(min,max), string(regex,max_len), duration(max,format), path(allowed_roots)", name, d.Type)
	}
	if err := validateTypeRules(name, d, allowUnknownTypes); err != nil {
		return err
	}
	if d.Default != nil {
		if _, err := parseValue(d, d.Default, false); err != nil {
			return fmt.Errorf("parameter %s default: %w", name, err)
		}
	}
	return nil
}

// validateFutureDefinition applies only the common constraints to a type this
// build does not understand.
func validateFutureDefinition(name string, d Definition) error {
	if d.Type == "" || invalidText(string(d.Type)) || invalidText(d.Description) {
		return fmt.Errorf("parameter %s: invalid type or description", name)
	}
	if d.MaxLen < 0 || d.MaxItems < 0 || (d.Min != nil && *d.Min < 0) {
		return fmt.Errorf("parameter %s: constraints must be nonnegative", name)
	}
	var numericMax float64
	switch max := d.Max.(type) {
	case int:
		numericMax = float64(max)
	case int64:
		numericMax = float64(max)
	case float64:
		numericMax = max
	case json.Number:
		var err error
		numericMax, err = max.Float64()
		if err != nil {
			return fmt.Errorf("parameter %s: invalid numeric maximum", name)
		}
	}
	if numericMax < 0 || math.IsNaN(numericMax) || math.IsInf(numericMax, 0) {
		return fmt.Errorf("parameter %s: numeric maximum must be nonnegative and finite", name)
	}
	if d.Regex != "" {
		if _, err := regexp.Compile(d.Regex); err != nil {
			return fmt.Errorf("parameter %s: %w", name, err)
		}
	}
	return nil
}

func validateTypeRules(name string, d Definition, allowUnknownTypes bool) error {
	switch d.Type {
	case Enum:
		return validateEnumValues(name, d)
	case Int:
		return validateIntBounds(name, d)
	case Bool:
		return nil
	case String, StringArray:
		return validateStringLimits(name, d)
	case Duration:
		return validateDurationBounds(name, d)
	case URL:
		return validateURLPrefixes(name, d)
	case Path:
		return validatePathRoots(name, d)
	default:
		if !allowUnknownTypes || d.Type == "" || invalidText(string(d.Type)) {
			return fmt.Errorf("parameter %s: type %q unsupported; allowed: enum, int, string, duration, path, url, bool, string_array", name, d.Type)
		}
		return nil
	}
}

func validateEnumValues(name string, d Definition) error {
	if len(d.Values) == 0 {
		return fmt.Errorf("parameter %s: enum values required", name)
	}
	seen := map[string]bool{}
	for _, value := range d.Values {
		if invalidText(value) || seen[value] {
			return fmt.Errorf("parameter %s: invalid or duplicate enum value", name)
		}
		seen[value] = true
	}
	return nil
}

func validateIntBounds(name string, d Definition) error {
	if d.Max != nil {
		max, ok := integer(d.Max)
		if !ok || (d.Min != nil && *d.Min > max) {
			return fmt.Errorf("parameter %s: invalid integer bounds", name)
		}
	}
	return nil
}

func validateStringLimits(name string, d Definition) error {
	if d.MaxItems < 0 {
		return fmt.Errorf("parameter %s: max_items must be nonnegative", name)
	}
	if d.MaxLen < 0 {
		return fmt.Errorf("parameter %s: max_len must be nonnegative", name)
	}
	if d.Regex != "" {
		if _, err := regexp.Compile(d.Regex); err != nil {
			return fmt.Errorf("parameter %s: %w", name, err)
		}
	}
	return nil
}

func validateDurationBounds(name string, d Definition) error {
	max, ok := d.Max.(string)
	parsed, err := time.ParseDuration(max)
	if !ok || err != nil || parsed < 0 {
		return fmt.Errorf("parameter %s: duration max required (Go duration)", name)
	}
	if d.Format != "" && d.Format != "go" && d.Format != "seconds" {
		return fmt.Errorf("parameter %s: format allowed: go, seconds", name)
	}
	return nil
}

func validateURLPrefixes(name string, d Definition) error {
	if len(d.AllowedPrefixes) == 0 {
		return fmt.Errorf("parameter %s: allowed_prefixes required", name)
	}
	for _, prefix := range d.AllowedPrefixes {
		if _, err := ParseURL(prefix, []string{prefix}); err != nil {
			return fmt.Errorf("parameter %s: %w", name, err)
		}
	}
	return nil
}

func validatePathRoots(name string, d Definition) error {
	if len(d.AllowedRoots) == 0 {
		return fmt.Errorf("parameter %s: allowed_roots required", name)
	}
	for _, root := range d.AllowedRoots {
		if !filepath.IsAbs(root) || invalidText(root) {
			return fmt.Errorf("parameter %s: allowed_roots must be absolute paths", name)
		}
	}
	return nil
}

func allowed(d Definition) string {
	switch d.Type {
	case Enum:
		return fmt.Sprintf("enum %q", d.Values)
	case Int:
		min, max := "unbounded", "unbounded"
		if d.Min != nil {
			min = strconv.FormatInt(*d.Min, 10)
		}
		if d.Max != nil {
			max = fmt.Sprint(d.Max)
		}
		return "integer min=" + min + " max=" + max
	case String:
		return fmt.Sprintf("string without leading '-' or CR/LF/NUL, max_len=%d (0=unbounded), regex=%q", d.MaxLen, d.Regex)
	case Duration:
		return fmt.Sprintf("Go duration between 0s and %v", d.Max)
	case URL:
		return fmt.Sprintf("http(s) URL within %q", d.AllowedPrefixes)
	case Bool:
		return "boolean"
	case StringArray:
		return fmt.Sprintf("string array with max_items=%d, item max_len=%d", d.MaxItems, d.MaxLen)
	case Path:
		return fmt.Sprintf("existing path within %q without leading '-' or CR/LF/NUL", d.AllowedRoots)
	default:
		return "enum, int, string, duration, path, url, bool, string_array"
	}
}

// Parse rejects unknown inputs and returns normalized values, including resolved paths.
// Path resolution is execution-host validation. The gateway must only precheck path
// syntax and allowed_roots prefixes, without calling local EvalSymlinks through Parse.
func Parse(defs map[string]Definition, input map[string]any) (map[string]any, error) {
	return parse(defs, input, true)
}

// ParseGateway checks schema values without resolving paths on the gateway.
// The agent remains responsible for symlink and allowed-root enforcement.
func ParseGateway(defs map[string]Definition, input map[string]any) (map[string]any, error) {
	return parse(defs, input, false)
}

func parse(defs map[string]Definition, input map[string]any, resolve bool) (map[string]any, error) {
	if err := ValidateDefinitions(defs); err != nil {
		return nil, err
	}
	for name := range input {
		if _, ok := defs[name]; !ok {
			return nil, fmt.Errorf("unknown parameter %q; allowed names: %v", name, names(defs))
		}
	}
	result := make(map[string]any, len(defs))
	for _, name := range names(defs) {
		d := defs[name]
		value, present := input[name]
		if !present {
			if d.Default != nil {
				value = d.Default
			} else if d.Optional {
				continue
			} else {
				return nil, fmt.Errorf("missing parameter %s; allowed: %s", name, allowed(d))
			}
		}
		parsed, err := parseValue(d, value, resolve)
		if err != nil {
			return nil, fmt.Errorf("parameter %s: %w; allowed: %s", name, err, allowed(d))
		}
		result[name] = parsed
	}
	return result, nil
}

func invalidText(value string) bool {
	return !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n")
}

func integer(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v >= 9223372036854775808.0 || v < -9223372036854775808.0 || math.Trunc(v) != v {
			return 0, false
		}
		return int64(v), true
	default:
		return 0, false
	}
}

func parseValue(d Definition, value any, resolve bool) (any, error) {
	switch d.Type {
	case Bool:
		b, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("expected boolean")
		}
		return b, nil
	case StringArray:
		var items []any
		switch v := value.(type) {
		case []string:
			if d.MaxItems > 0 && len(v) > d.MaxItems {
				return nil, fmt.Errorf("exceeds max_items")
			}
			for _, item := range v {
				items = append(items, item)
			}
		case []any:
			items = v
		default:
			return nil, fmt.Errorf("expected string array")
		}
		if d.MaxItems > 0 && len(items) > d.MaxItems {
			return nil, fmt.Errorf("exceeds max_items")
		}
		result := make([]string, 0, len(items))
		for _, item := range items {
			parsed, err := parseValue(Definition{Type: String, Regex: d.Regex, MaxLen: d.MaxLen}, item, false)
			if err != nil {
				return nil, err
			}
			result = append(result, parsed.(string))
		}
		return result, nil
	case Int:
		n, ok := integer(value)
		if !ok {
			return nil, fmt.Errorf("expected integer")
		}
		if d.Min != nil && n < *d.Min {
			return nil, fmt.Errorf("below min")
		}
		if d.Max != nil {
			max, _ := integer(d.Max)
			if n > max {
				return nil, fmt.Errorf("above max")
			}
		}
		return n, nil
	case Enum, String, Duration, Path, URL:
		s, ok := value.(string)
		if !ok || invalidText(s) {
			return nil, fmt.Errorf("expected string without CR/LF/NUL")
		}
		switch d.Type {
		case Enum:
			if !slices.Contains(d.Values, s) {
				return nil, fmt.Errorf("not an enum value")
			}
		case String:
			if strings.HasPrefix(s, "-") {
				return nil, fmt.Errorf("leading '-' rejected")
			}
			if d.MaxLen > 0 && utf8.RuneCountInString(s) > d.MaxLen {
				return nil, fmt.Errorf("exceeds max_len")
			}
			if d.Regex != "" {
				re, err := regexp.Compile(d.Regex)
				if err != nil {
					return nil, err
				}
				if !re.MatchString(s) {
					return nil, fmt.Errorf("does not match regex")
				}
			}
		case Duration:
			n, err := time.ParseDuration(s)
			if err != nil {
				return nil, fmt.Errorf("invalid Go duration")
			}
			max, _ := time.ParseDuration(d.Max.(string))
			if n < 0 || n > max {
				return nil, fmt.Errorf("duration out of range")
			}
			return n, nil
		case URL:
			u, err := ParseURL(s, d.AllowedPrefixes)
			if err != nil {
				return nil, err
			}
			return u.String(), nil
		case Path:
			if strings.HasPrefix(s, "-") {
				return nil, fmt.Errorf("leading '-' rejected")
			}
			if resolve {
				return ResolvePath(s, d.AllowedRoots)
			}
			if !filepath.IsAbs(s) {
				return nil, fmt.Errorf("path must be absolute")
			}
			clean := filepath.Clean(s)
			for _, root := range d.AllowedRoots {
				rel, err := filepath.Rel(filepath.Clean(root), clean)
				if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return clean, nil
				}
			}
			return nil, fmt.Errorf("path outside allowed_roots")
		}
		return s, nil
	default:
		return nil, fmt.Errorf("unsupported parameter type")
	}
}

// ResolvePath is execution-host validation: it checks component boundaries after
// resolving symlinks. Gateway prechecks must not inspect the gateway's filesystem.
func ResolvePath(path string, roots []string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("path must exist: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	for _, root := range roots {
		realRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		realRoot, err = filepath.Abs(realRoot)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(realRoot, resolved)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("path outside allowed_roots %q", roots)
}

var placeholder = regexp.MustCompile(`^\{([a-z][a-z0-9_]{0,63})\}$`)

func Placeholder(s string) (string, bool) {
	m := placeholder.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ValidateTemplate allows strings and one level of optional string lists.
func ValidateTemplate(template []any, defs map[string]Definition) error {
	for _, element := range template {
		var words []any
		switch v := element.(type) {
		case string:
			words = []any{v}
		case []any:
			if len(v) == 0 {
				return fmt.Errorf("empty optional argv list")
			}
			words = v
		default:
			return fmt.Errorf("argv elements must be strings or optional lists")
		}
		for _, word := range words {
			s, ok := word.(string)
			if !ok || invalidText(s) {
				return fmt.Errorf("argv contains invalid string")
			}
			if name, ok := Placeholder(s); ok {
				if defs[name].Type == StringArray {
					return fmt.Errorf("array parameters cannot be rendered into argv")
				}
				if _, exists := defs[name]; !exists {
					return fmt.Errorf("unknown placeholder %s; allowed: %v", name, names(defs))
				}
			}
		}
	}
	return nil
}

func Render(template []any, defs map[string]Definition, values map[string]any) ([]string, error) {
	if err := ValidateTemplate(template, defs); err != nil {
		return nil, err
	}
	var argv []string
	for _, element := range template {
		words, optional := element.([]any)
		if !optional {
			words = []any{element}
		}
		missing := false
		for _, word := range words {
			if name, ok := Placeholder(word.(string)); ok {
				if _, present := values[name]; !present {
					missing = true
				}
			}
		}
		if missing && optional {
			continue
		}
		if missing {
			return nil, fmt.Errorf("missing argv parameter; allowed: provided parameter values")
		}
		for _, word := range words {
			s := word.(string)
			name, ok := Placeholder(s)
			if !ok {
				argv = append(argv, s)
				continue
			}
			value := values[name]
			switch defs[name].Type {
			case Bool:
				b, ok := value.(bool)
				if !ok {
					return nil, fmt.Errorf("parameter %s: expected parsed boolean", name)
				}
				s = strconv.FormatBool(b)
			case Int:
				n, ok := value.(int64)
				if !ok {
					return nil, fmt.Errorf("parameter %s: expected parsed integer", name)
				}
				s = strconv.FormatInt(n, 10)
			case Duration:
				n, ok := value.(time.Duration)
				if !ok {
					return nil, fmt.Errorf("parameter %s: expected parsed duration", name)
				}
				s = n.String()
				if defs[name].Format == "seconds" {
					whole, fraction := n/time.Second, n%time.Second
					s = strconv.FormatInt(int64(whole), 10)
					if fraction != 0 {
						s += "." + strings.TrimRight(fmt.Sprintf("%09d", fraction), "0")
					}
				}
			default:
				var ok bool
				s, ok = value.(string)
				if !ok {
					return nil, fmt.Errorf("parameter %s: expected parsed string", name)
				}
			}
			argv = append(argv, s)
		}
	}
	return argv, nil
}
