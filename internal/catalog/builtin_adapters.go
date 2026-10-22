package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/builtin/httpget"
	"github.com/liubing0806/allowops/internal/builtin/logsearch"
	redisbuiltin "github.com/liubing0806/allowops/internal/builtin/redis"
	"github.com/liubing0806/allowops/internal/params"
)

func decodeBuiltinConfig(input map[string]any, out any) error {
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if input == nil {
		data = []byte("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

func builtinStringList(value any, name string) ([]string, error) {
	var values []string
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &values); err != nil || values == nil {
		return nil, fmt.Errorf("builtin_config.%s requires a nonempty list of strings", name)
	}
	return values, nil
}
func builtinTimeout(text string) (time.Duration, error) {
	if text == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(text)
	if err != nil || d < 0 || d > builtin.DefaultTimeout {
		return 0, fmt.Errorf("builtin timeout must be between 0s and %s", builtin.DefaultTimeout)
	}
	return d, nil
}
func positiveBound(n, defaultValue int) int {
	if n == 0 {
		return defaultValue
	}
	return n
}
func integerDefinition(description string, min, max int, defaultValue any) params.Definition {
	lower := int64(min)
	return params.Definition{Type: params.Int, Description: description, Min: &lower, Max: max, Default: defaultValue}
}
func adaptBuiltinResult(r builtin.Result) BuiltinResult {
	return BuiltinResult{Stdout: r.Stdout, ExitCode: r.ExitCode, ResourceLimited: r.Truncated}
}

type logSearchHandler struct{}

func logSearchConfig(input map[string]any) (logsearch.Config, error) {
	var fields struct {
		AllowedRoots []string `json:"allowed_roots"`
		MaxFiles     int      `json:"max_files"`
		MaxScan      Size     `json:"max_scan"`
		MaxMatches   int      `json:"max_matches"`
		MaxContext   int      `json:"max_context"`
		Timeout      string   `json:"timeout"`
	}
	if err := decodeBuiltinConfig(input, &fields); err != nil {
		return logsearch.Config{}, err
	}
	timeout, err := builtinTimeout(fields.Timeout)
	if err != nil {
		return logsearch.Config{}, err
	}
	if len(fields.AllowedRoots) == 0 {
		return logsearch.Config{}, fmt.Errorf("allowed_roots required")
	}
	for _, root := range fields.AllowedRoots {
		if !filepath.IsAbs(root) || strings.ContainsAny(root, "\x00\r\n") {
			return logsearch.Config{}, fmt.Errorf("allowed_roots must be absolute paths without NUL/newlines")
		}
	}
	if fields.MaxFiles < 0 || fields.MaxFiles > builtin.DefaultLogMaxFiles || fields.MaxScan < 0 || int64(fields.MaxScan) > builtin.DefaultLogMaxScan || fields.MaxMatches < 0 || fields.MaxMatches > builtin.DefaultLogMaxMatches || fields.MaxContext < 0 || fields.MaxContext > builtin.DefaultLogMaxContext {
		return logsearch.Config{}, fmt.Errorf("log_search builtin_config may only tighten default resource limits")
	}
	return logsearch.Config{AllowedRoots: fields.AllowedRoots, MaxFiles: fields.MaxFiles, MaxScan: int64(fields.MaxScan), MaxMatches: fields.MaxMatches, MaxContext: fields.MaxContext, Timeout: timeout}, nil
}
func (logSearchHandler) ValidateConfig(input map[string]any) error {
	_, err := logSearchConfig(input)
	return err
}
func (logSearchHandler) Parameters(input map[string]any) (map[string]params.Definition, error) {
	cfg, err := logSearchConfig(input)
	if err != nil {
		return nil, err
	}
	maxMatches := positiveBound(cfg.MaxMatches, builtin.DefaultLogMaxMatches)
	return map[string]params.Definition{
		"path_glob":   {Type: params.String, Description: "Absolute log path glob", Regex: `^.+$`, MaxLen: 4096},
		"pattern":     {Type: params.String, Description: "Search pattern", Regex: `^.+$`, MaxLen: 200},
		"fixed":       {Type: params.Bool, Description: "Treat pattern and exclude as literal text", Default: false},
		"exclude":     {Type: params.String, Description: "Handler exclusion pattern", MaxLen: 200, Optional: true},
		"context":     integerDefinition("Context lines", 0, positiveBound(cfg.MaxContext, builtin.DefaultLogMaxContext), 0),
		"max_matches": integerDefinition("Maximum matches", 1, maxMatches, maxMatches),
	}, nil
}
func (logSearchHandler) Run(ctx context.Context, input, values map[string]any) (BuiltinResult, error) {
	cfg, err := logSearchConfig(input)
	if err != nil {
		return BuiltinResult{ExitCode: builtin.ExitFailure}, err
	}
	exclude, _ := values["exclude"].(string)
	r, err := logsearch.Run(ctx, cfg, logsearch.Params{PathGlob: values["path_glob"].(string), Pattern: values["pattern"].(string), Fixed: values["fixed"].(bool), Exclude: exclude, Context: int(values["context"].(int64)), MaxMatches: int(values["max_matches"].(int64))})
	return adaptBuiltinResult(r), err
}

type httpGetHandler struct{}

func httpGetConfig(input map[string]any) (httpget.Config, error) {
	var fields struct {
		AllowedPrefixes  []string          `json:"allowed_prefixes"`
		Headers          map[string]string `json:"headers"`
		Timeout          string            `json:"timeout"`
		MaxResponseBytes Size              `json:"max_response_bytes"`
	}
	if err := decodeBuiltinConfig(input, &fields); err != nil {
		return httpget.Config{}, err
	}
	timeout, err := builtinTimeout(fields.Timeout)
	if err != nil {
		return httpget.Config{}, err
	}
	if fields.MaxResponseBytes < 0 || int64(fields.MaxResponseBytes) > builtin.DefaultHTTPMaxResponseBytes {
		return httpget.Config{}, fmt.Errorf("http_get max_response_bytes may only tighten default %d", builtin.DefaultHTTPMaxResponseBytes)
	}
	cfg := httpget.Config{AllowedPrefixes: fields.AllowedPrefixes, Headers: fields.Headers, Timeout: timeout, MaxResponseBytes: int64(fields.MaxResponseBytes)}
	return cfg, cfg.Validate()
}
func (httpGetHandler) ValidateConfig(input map[string]any) error {
	_, err := httpGetConfig(input)
	return err
}
func (httpGetHandler) Parameters(input map[string]any) (map[string]params.Definition, error) {
	cfg, err := httpGetConfig(input)
	if err != nil {
		return nil, err
	}
	return map[string]params.Definition{"url": {Type: params.URL, Description: "GET URL", AllowedPrefixes: cfg.AllowedPrefixes}}, nil
}
func (httpGetHandler) Run(ctx context.Context, input, values map[string]any) (BuiltinResult, error) {
	cfg, err := httpGetConfig(input)
	if err != nil {
		return BuiltinResult{ExitCode: builtin.ExitFailure}, err
	}
	r, err := httpget.Run(ctx, cfg, httpget.Params{URL: values["url"].(string)})
	out := adaptBuiltinResult(r.Result)
	out.StatusCode = r.StatusCode
	return out, err
}

type redisHandler struct{}

func redisConfig(input map[string]any) (redisbuiltin.Config, error) {
	var fields struct {
		Address          string   `json:"address"`
		Credential       string   `json:"credential"`
		DB               int      `json:"db"`
		Timeout          string   `json:"timeout"`
		MaxResponseBytes Size     `json:"max_response_bytes"`
		MaxScanCount     int      `json:"max_scan_count"`
		Commands         []string `json:"commands"`
		KeyPrefixes      []string `json:"key_prefixes"`
		InfoSections     []string `json:"info_sections"`
	}
	if err := decodeBuiltinConfig(input, &fields); err != nil {
		return redisbuiltin.Config{}, err
	}
	for _, list := range []struct {
		name   string
		values []string
	}{{"commands", fields.Commands}, {"key_prefixes", fields.KeyPrefixes}, {"info_sections", fields.InfoSections}} {
		if _, present := input[list.name]; present && list.values == nil {
			return redisbuiltin.Config{}, fmt.Errorf("builtin_config.%s requires a nonempty list of strings", list.name)
		}
	}
	timeout, err := builtinTimeout(fields.Timeout)
	if err != nil {
		return redisbuiltin.Config{}, err
	}
	if fields.MaxResponseBytes < 0 || int64(fields.MaxResponseBytes) > builtin.DefaultRedisMaxResponseBytes {
		return redisbuiltin.Config{}, fmt.Errorf("redis_command max_response_bytes may only tighten default %d", builtin.DefaultRedisMaxResponseBytes)
	}
	cfg := redisbuiltin.Config{Address: fields.Address, Credential: fields.Credential, DB: fields.DB, Timeout: timeout, MaxResponseBytes: int64(fields.MaxResponseBytes), MaxScanCount: fields.MaxScanCount, Commands: fields.Commands, KeyPrefixes: fields.KeyPrefixes, InfoSections: fields.InfoSections}
	return cfg, cfg.Validate()
}
func (redisHandler) ValidateConfig(input map[string]any) error {
	_, err := redisConfig(input)
	return err
}
func (redisHandler) Parameters(input map[string]any) (map[string]params.Definition, error) {
	cfg, err := redisConfig(input)
	if err != nil {
		return nil, err
	}
	schema := redisbuiltin.ParamsSchema()["properties"].(map[string]any)
	commands := schema["command"].(map[string]any)["enum"].([]string)
	if cfg.Commands != nil {
		commands = make([]string, len(cfg.Commands))
		for i, command := range cfg.Commands {
			commands[i] = strings.ToUpper(command)
		}
	}
	return map[string]params.Definition{
		"command": {Type: params.Enum, Description: "Read-only Redis command", Values: commands},
		"args":    {Type: params.StringArray, Description: "Redis command arguments", MaxLen: 4096, MaxItems: 128, Optional: true},
	}, nil
}
func (redisHandler) Run(ctx context.Context, input, values map[string]any) (BuiltinResult, error) {
	return (redisHandler{}).RunRedacted(ctx, input, values, nil)
}

func (redisHandler) RunRedacted(ctx context.Context, input, values map[string]any, mask func(string) string) (BuiltinResult, error) {
	cfg, err := redisConfig(input)
	if err != nil {
		return BuiltinResult{ExitCode: builtin.ExitFailure}, err
	}
	args, _ := values["args"].([]string)
	r, err := redisbuiltin.RunRedacted(ctx, cfg, redisbuiltin.Params{Command: values["command"].(string), Args: args}, mask)
	return adaptBuiltinResult(r), err
}
