package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/executor"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/params"
)

// actionRequest validates in a fixed order, which decides which error a caller
// sees first: argument object and names, reason, targets, expected_count,
// run limits, response_format, params, then output filters.
func actionRequest(a catalog.Action, raw json.RawMessage, cfg job.Config) (*v1.RunJobRequest, string, error) {
	args, err := argumentObject(raw)
	if err != nil {
		return nil, "", err
	}
	allowed := []string{"params", "targets", "expected_count", "reason", "wait_seconds", "batch_size", "max_failures", "response_format"}
	allowed = append(allowed, a.Filters...)
	for name := range args {
		if !slices.Contains(allowed, name) {
			return nil, "", fmt.Errorf("unknown argument; allowed names: %v", allowed)
		}
	}
	req := &v1.RunJobRequest{Action: a.Name}
	if err := decodeField(args, "reason", &req.Reason, true); err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(req.Reason) == "" {
		return nil, "", errors.New("reason required; allowed: non-whitespace string")
	}
	if err := parseTargets(args, req); err != nil {
		return nil, "", err
	}
	if err := parseExpectedCount(args, req); err != nil {
		return nil, "", err
	}
	if err := parseRunLimits(a, args, req, cfg); err != nil {
		return nil, "", err
	}
	format, err := parseResponseFormat(args)
	if err != nil {
		return nil, "", err
	}
	if err := parseActionParams(a, args, req); err != nil {
		return nil, "", err
	}
	if err := parseOutputFilters(a, args, req); err != nil {
		return nil, "", err
	}
	return req, format, nil
}

// parseTargets selects hosts or selector. A selector also requires expected_count.
func parseTargets(args map[string]json.RawMessage, req *v1.RunJobRequest) error {
	targets, err := argumentObject(args["targets"])
	if err != nil {
		return errors.New("targets required; allowed: hosts or selector")
	}
	if len(targets) != 1 {
		return errors.New("targets requires exactly one of hosts or selector")
	}
	switch {
	case targets["hosts"] != nil:
		names, err := parseHostNames(targets)
		if err != nil {
			return err
		}
		req.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: names}}}
	case targets["selector"] != nil:
		var selector string
		if err := decodeField(targets, "selector", &selector, true); err != nil {
			return err
		}
		if err := validateSelector(selector); err != nil {
			return err
		}
		req.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: selector}}
		if args["expected_count"] == nil {
			return errors.New("expected_count required with selector; allowed: nonnegative integer")
		}
	default:
		return errors.New("targets allowed: hosts or selector")
	}
	return nil
}

func parseHostNames(targets map[string]json.RawMessage) ([]string, error) {
	var names []string
	if err := decodeField(targets, "hosts", &names, true); err != nil || len(names) == 0 {
		return nil, errors.New("targets.hosts required; allowed: nonempty hostname array")
	}
	for _, name := range names {
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\x00\r\n") {
			return nil, errors.New("targets.hosts allowed: nonempty hostnames without CR/LF/NUL")
		}
	}
	sorted := slices.Clone(names)
	slices.Sort(sorted)
	if len(slices.Compact(sorted)) != len(names) {
		return nil, errors.New("targets.hosts allowed: unique hostnames")
	}
	return names, nil
}

func parseExpectedCount(args map[string]json.RawMessage, req *v1.RunJobRequest) error {
	if args["expected_count"] == nil {
		return nil
	}
	var n uint64
	if err := decodeField(args, "expected_count", &n, false); err != nil {
		return err
	}
	req.ExpectedCount = &n
	return nil
}

// parseRunLimits fills wait_seconds, batch_size and max_failures. The caller
// may lower batch_size and max_failures from the effective limits (gateway job
// configuration and catalog) but not raise them. Absent options stay nil so the
// job layer applies its own defaults; only explicit values are checked here,
// against the same effective limits.
func parseRunLimits(a catalog.Action, args map[string]json.RawMessage, req *v1.RunJobRequest, cfg job.Config) error {
	batch, failures, err := batchLimits(a, cfg)
	if err != nil {
		return err
	}
	wait, size, stops := cfg.WaitSeconds, batch, failures
	for _, field := range []struct {
		name     string
		value    *uint32
		min, max uint32
		target   **uint32
	}{{"wait_seconds", &wait, 0, cfg.MaxWaitSeconds, &req.WaitSeconds}, {"batch_size", &size, 1, batch, &req.BatchSize}, {"max_failures", &stops, 0, failures, &req.MaxFailures}} {
		if err := decodeField(args, field.name, field.value, false); err != nil {
			return err
		}
		if *field.value < field.min || *field.value > field.max {
			return fmt.Errorf("%s allowed: integer in [%d,%d]", field.name, field.min, field.max)
		}
		if _, present := args[field.name]; present {
			*field.target = field.value
		}
	}
	return nil
}

func parseResponseFormat(args map[string]json.RawMessage) (string, error) {
	format := "concise"
	if err := decodeField(args, "response_format", &format, false); err != nil {
		return "", err
	}
	if format != "concise" && format != "detailed" {
		return "", errors.New("response_format allowed: concise, detailed")
	}
	return format, nil
}

func parseActionParams(a catalog.Action, args map[string]json.RawMessage, req *v1.RunJobRequest) error {
	defs, err := catalog.ParameterDefinitions(a)
	if err != nil {
		return err
	}
	values := map[string]any{}
	if data := args["params"]; data != nil {
		if _, err := argumentObject(data); err != nil {
			return errors.New("params allowed: JSON object")
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&values); err != nil {
			return errors.New("params allowed: JSON object")
		}
	}
	values, err = gatewayParams(a, defs, values)
	if err != nil {
		return err
	}
	data, err := json.Marshal(values)
	if err != nil {
		return err
	}
	req.Params = &v1.Parameters{Json: data}
	return nil
}

// parseOutputFilters decodes the filters the action declares, then lets the
// executor validate the combination.
func parseOutputFilters(a catalog.Action, args map[string]json.RawMessage, req *v1.RunJobRequest) error {
	filters := map[string]any{}
	req.Filters = &v1.OutputFilters{}
	selected := 0
	for _, name := range a.Filters {
		data, present := args[name]
		if !present {
			continue
		}
		if name == "tail" || name == "head" || name == "count" {
			selected++
		}
		if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
			return fmt.Errorf("filter %s must not be null", name)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("filter %s has invalid type", name)
		}
		filters[name] = value
		if err := setOutputFilter(req.Filters, name, data); err != nil {
			return err
		}
	}
	if selected > 1 {
		return errors.New("tail, head and count are mutually exclusive; allowed: match/exclude with at most one of tail, head, count")
	}
	if _, err := executor.ParseFilters(a.Filters, filters); err != nil {
		return err
	}
	return nil
}

func setOutputFilter(filters *v1.OutputFilters, name string, data json.RawMessage) error {
	switch name {
	case "match", "exclude":
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("%s allowed: RE2 string", name)
		}
		if name == "match" {
			filters.Match = &s
		} else {
			filters.Exclude = &s
		}
	case "tail", "head":
		var n uint32
		if err := json.Unmarshal(data, &n); err != nil {
			return fmt.Errorf("%s allowed: integer in [1,%d]", name, uint64(^uint32(0)))
		}
		if name == "tail" {
			filters.Tail = &n
		} else {
			filters.Head = &n
		}
	case "count":
		var b bool
		if err := json.Unmarshal(data, &b); err != nil {
			return errors.New("count allowed: boolean")
		}
		filters.Count = &b
	}
	return nil
}

func decodeField(args map[string]json.RawMessage, name string, out any, required bool) error {
	data, present := args[name]
	if !present {
		if required {
			return fmt.Errorf("%s required", name)
		}
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) || json.Unmarshal(data, out) != nil {
		return fmt.Errorf("%s has invalid type; allowed: declared inputSchema type, without null", name)
	}
	return nil
}

func validateSelector(selector string) error {
	seen := map[string]string{}
	for _, term := range strings.Split(selector, ",") {
		pair := strings.Split(term, "=")
		if len(pair) != 2 || strings.TrimSpace(pair[0]) == "" || strings.TrimSpace(pair[1]) == "" || strings.ContainsAny(term, "\x00\r\n") {
			return errors.New("selector allowed: comma-separated key=value conjunctions")
		}
		key, value := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		if old, ok := seen[key]; ok && old != value {
			return errors.New("selector has conflicting conditions; allowed: one value per key")
		}
		seen[key] = value
	}
	return nil
}

func gatewayParams(a catalog.Action, defs map[string]params.Definition, input map[string]any) (map[string]any, error) {
	if err := params.ValidateDefinitions(defs); err != nil {
		return nil, err
	}
	gatewayDefs := make(map[string]params.Definition, len(defs))
	for name, d := range defs {
		if d.Type == params.Path {
			value, present := input[name]
			if !present {
				value = d.Default
			}
			if value != nil {
				path, ok := value.(string)
				if !ok || !utf8.ValidString(path) || !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
					return nil, fmt.Errorf("parameter %s allowed: absolute host path within %v", name, d.AllowedRoots)
				}
				inside := false
				for _, root := range d.AllowedRoots {
					rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
					if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
						inside = true
					}
				}
				if !inside {
					return nil, fmt.Errorf("parameter %s allowed_roots: %v", name, d.AllowedRoots)
				}
			}
			// Only host execution may resolve symlinks or check path existence.
			d.Type = params.String
			d.AllowedRoots = nil
		}
		gatewayDefs[name] = d
	}
	parsed, err := params.Parse(gatewayDefs, input)
	if err != nil {
		return nil, err
	}
	for name, override := range a.Params {
		if a.Builtin != "" && override.Regex != "" {
			re, err := regexp.Compile(override.Regex)
			if err != nil {
				return nil, fmt.Errorf("parameter %s has invalid signed regex", name)
			}
			var values []string
			switch value := parsed[name].(type) {
			case string:
				values = []string{value}
			case []string:
				values = value
			}
			for _, value := range values {
				if !re.MatchString(value) {
					return nil, fmt.Errorf("parameter %s allowed: regex %s", name, override.Regex)
				}
			}
		}
	}
	for name, value := range parsed {
		if duration, ok := value.(time.Duration); ok {
			parsed[name] = duration.String()
		}
	}
	return parsed, nil
}

// Preserve integer precision and reject duplicate members before typed decoding.
func argumentObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := checkArgumentJSON(d, 0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("arguments allowed: one JSON object")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, errors.New("arguments allowed: JSON object")
	}
	return object, nil
}

func checkArgumentJSON(d *json.Decoder, depth int) error {
	if depth > 1000 {
		return errors.New("arguments exceed maximum JSON depth")
	}
	token, err := d.Token()
	if err != nil {
		return errors.New("invalid JSON arguments")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return errors.New("invalid JSON object")
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate JSON member; allowed: unique member names")
			}
			seen[name] = true
			if err := checkArgumentJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := checkArgumentJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON arguments")
	}
	_, err = d.Token()
	if err != nil {
		return errors.New("invalid JSON arguments")
	}
	return nil
}
