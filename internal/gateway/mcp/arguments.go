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
	targets, err := argumentObject(args["targets"])
	if err != nil {
		return nil, "", errors.New("targets required; allowed: hosts or selector")
	}
	if len(targets) != 1 {
		return nil, "", errors.New("targets requires exactly one of hosts or selector")
	}
	switch {
	case targets["hosts"] != nil:
		var names []string
		if err := decodeField(targets, "hosts", &names, true); err != nil || len(names) == 0 {
			return nil, "", errors.New("targets.hosts required; allowed: nonempty hostname array")
		}
		for _, name := range names {
			if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\x00\r\n") {
				return nil, "", errors.New("targets.hosts allowed: nonempty hostnames without CR/LF/NUL")
			}
		}
		sorted := slices.Clone(names)
		slices.Sort(sorted)
		if len(slices.Compact(sorted)) != len(names) {
			return nil, "", errors.New("targets.hosts allowed: unique hostnames")
		}
		req.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: names}}}
	case targets["selector"] != nil:
		var selector string
		if err := decodeField(targets, "selector", &selector, true); err != nil {
			return nil, "", err
		}
		if err := validateSelector(selector); err != nil {
			return nil, "", err
		}
		req.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: selector}}
		if args["expected_count"] == nil {
			return nil, "", errors.New("expected_count required with selector; allowed: nonnegative integer")
		}
	default:
		return nil, "", errors.New("targets allowed: hosts or selector")
	}
	if args["expected_count"] != nil {
		var n uint64
		if err := decodeField(args, "expected_count", &n, false); err != nil {
			return nil, "", err
		}
		req.ExpectedCount = &n
	}
	batch, failures, err := batchLimits(a, cfg)
	if err != nil {
		return nil, "", err
	}
	// Absent options stay nil so the job layer applies its own defaults; only
	// explicit values are checked here, against the same effective limits.
	wait, size, stops := cfg.WaitSeconds, batch, failures
	for _, field := range []struct {
		name     string
		value    *uint32
		min, max uint32
		target   **uint32
	}{{"wait_seconds", &wait, 0, cfg.MaxWaitSeconds, &req.WaitSeconds}, {"batch_size", &size, 1, batch, &req.BatchSize}, {"max_failures", &stops, 0, failures, &req.MaxFailures}} {
		if err := decodeField(args, field.name, field.value, false); err != nil {
			return nil, "", err
		}
		if *field.value < field.min || *field.value > field.max {
			return nil, "", fmt.Errorf("%s allowed: integer in [%d,%d]", field.name, field.min, field.max)
		}
		if _, present := args[field.name]; present {
			*field.target = field.value
		}
	}
	format := "concise"
	if err := decodeField(args, "response_format", &format, false); err != nil {
		return nil, "", err
	}
	if format != "concise" && format != "detailed" {
		return nil, "", errors.New("response_format allowed: concise, detailed")
	}
	defs, err := catalog.ParameterDefinitions(a)
	if err != nil {
		return nil, "", err
	}
	values := map[string]any{}
	if data := args["params"]; data != nil {
		if _, err := argumentObject(data); err != nil {
			return nil, "", errors.New("params allowed: JSON object")
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&values); err != nil {
			return nil, "", errors.New("params allowed: JSON object")
		}
	}
	values, err = gatewayParams(a, defs, values)
	if err != nil {
		return nil, "", err
	}
	data, err := json.Marshal(values)
	if err != nil {
		return nil, "", err
	}
	req.Params = &v1.Parameters{Json: data}
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
			return nil, "", fmt.Errorf("filter %s must not be null", name)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, "", fmt.Errorf("filter %s has invalid type", name)
		}
		filters[name] = value
		switch name {
		case "match", "exclude":
			var s string
			if err := json.Unmarshal(data, &s); err != nil {
				return nil, "", fmt.Errorf("%s allowed: RE2 string", name)
			}
			if name == "match" {
				req.Filters.Match = &s
			} else {
				req.Filters.Exclude = &s
			}
		case "tail", "head":
			var n uint32
			if err := json.Unmarshal(data, &n); err != nil {
				return nil, "", fmt.Errorf("%s allowed: integer in [1,%d]", name, uint64(^uint32(0)))
			}
			if name == "tail" {
				req.Filters.Tail = &n
			} else {
				req.Filters.Head = &n
			}
		case "count":
			var b bool
			if err := json.Unmarshal(data, &b); err != nil {
				return nil, "", errors.New("count allowed: boolean")
			}
			req.Filters.Count = &b
		}
	}
	if selected > 1 {
		return nil, "", errors.New("tail, head and count are mutually exclusive; allowed: match/exclude with at most one of tail, head, count")
	}
	if _, err := executor.ParseFilters(a.Filters, filters); err != nil {
		return nil, "", err
	}
	return req, format, nil
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
