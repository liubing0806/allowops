package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/builtin/mysql"
	"github.com/liubing0806/allowops/internal/params"
)

// BuiltinResult contains raw host-local output. The executor owns redaction,
// filters and max_output. ResourceLimited is separate from output truncation.
type BuiltinResult struct {
	Stdout, Stderr  string
	ExitCode        int
	ResourceLimited bool
	StatusCode      int
}

// BuiltinHandler is the registration boundary for builtin handlers (design
// P12B). Size fields in catalog adapters must use Size/ParseSize before passing
// byte limits to handlers.
type BuiltinHandler interface {
	Parameters(map[string]any) (map[string]params.Definition, error)
	ValidateConfig(map[string]any) error
	Run(context.Context, map[string]any, map[string]any) (BuiltinResult, error)
}

// RedactingBuiltinHandler encodes structured output only after applying the
// executor-selected policy to its original strings. Final filters and output
// budgets remain in the executor. Run remains the raw internal handler API.
type RedactingBuiltinHandler interface {
	RunRedacted(context.Context, map[string]any, map[string]any, func(string) string) (BuiltinResult, error)
}

// Builtins is the process-local registration table; registration occurs at startup.
var Builtins = map[string]BuiltinHandler{"mysql_query": mysqlHandler{}, "log_search": logSearchHandler{}, "http_get": httpGetHandler{}, "redis_command": redisHandler{}, "alertmanager_alerts": alertmanagerHandler{}}

type mysqlHandler struct{}

func (mysqlHandler) Parameters(map[string]any) (map[string]params.Definition, error) {
	return map[string]params.Definition{
		"database": {Type: params.String, Description: "Database name", Regex: `^[a-zA-Z0-9_]{1,64}$`, MaxLen: 64},
		"sql":      {Type: params.String, Description: "Read-only SQL", MaxLen: 4000},
	}, nil
}

func MySQLConfig(config map[string]any) (mysql.Config, error) {
	c := mysql.Config{}
	for key, value := range config {
		switch key {
		case "credential", "address":
			s, ok := value.(string)
			if !ok {
				return c, fmt.Errorf("builtin_config.%s requires string", key)
			}
			if key == "credential" {
				c.Credential = s
			} else {
				c.Address = s
			}
		case "max_rows":
			text := fmt.Sprint(value)
			n, err := strconv.Atoi(text)
			if err != nil {
				return c, fmt.Errorf("max_rows requires integer")
			}
			c.MaxRows = n
		case "max_response_bytes":
			// Same size syntax and tighten-only rule as redis_command.
			var size Size
			data, err := json.Marshal(value)
			if err == nil {
				err = json.Unmarshal(data, &size)
			}
			if err != nil {
				return c, fmt.Errorf("builtin_config.max_response_bytes requires a byte size: %w", err)
			}
			if int64(size) > builtin.DefaultMySQLMaxResponseBytes {
				return c, fmt.Errorf("mysql_query max_response_bytes may only tighten default %d", builtin.DefaultMySQLMaxResponseBytes)
			}
			c.MaxResponseBytes = int64(size)
		case "databases", "statement_types", "show_types":
			values, err := builtinStringList(value, key)
			if err != nil {
				return c, err
			}
			switch key {
			case "databases":
				c.Databases = values
			case "statement_types":
				c.StatementTypes = values
			case "show_types":
				c.ShowTypes = values
			}
		case "timeout":
			s, ok := value.(string)
			if !ok {
				return c, fmt.Errorf("builtin_config.timeout requires duration string")
			}
			d, err := time.ParseDuration(s)
			if err != nil {
				return c, err
			}
			c.Timeout = d
		default:
			return c, fmt.Errorf("unknown mysql_query builtin_config field %s", key)
		}
	}
	return c, c.Validate()
}

func (mysqlHandler) ValidateConfig(config map[string]any) error {
	_, err := MySQLConfig(config)
	return err
}

func (mysqlHandler) Run(ctx context.Context, config map[string]any, values map[string]any) (BuiltinResult, error) {
	return (mysqlHandler{}).RunRedacted(ctx, config, values, nil)
}

func (mysqlHandler) RunRedacted(ctx context.Context, config map[string]any, values map[string]any, mask func(string) string) (BuiltinResult, error) {
	c, err := MySQLConfig(config)
	if err != nil {
		return BuiltinResult{ExitCode: 1}, err
	}
	r, err := mysql.RunRedacted(ctx, c, mysql.Params{Database: values["database"].(string), SQL: values["sql"].(string)}, mask)
	// Execution errors use exit code 1; handler defaults remain unchanged (decisions A16).
	if err != nil {
		return BuiltinResult{ExitCode: 1}, err
	}
	return BuiltinResult{Stdout: r.Output, ResourceLimited: r.Truncated}, nil
}

// ParameterDefinitions adds handler-owned parameters. Catalog overrides can only
// add regex restrictions or lower string lengths; required parameters stay required.
func ParameterDefinitions(a Action) (map[string]params.Definition, error) {
	return parameterDefinitions(a, false)
}

func parameterDefinitions(a Action, allowUnsupported bool) (map[string]params.Definition, error) {
	if a.Builtin == "" {
		return a.Params, nil
	}
	handler, ok := Builtins[a.Builtin]
	if !ok {
		return nil, fmt.Errorf("unsupported builtin %q", a.Builtin)
	}
	defs, err := handler.Parameters(a.BuiltinConfig)
	if err != nil {
		return nil, err
	}
	for name, override := range a.Params {
		base, ok := defs[name]
		if !ok {
			return nil, fmt.Errorf("unknown builtin parameter %q", name)
		}
		// Reader-only capability handling. Validate the understood override
		// fields against the handler, while preserving the original signed type.
		if allowUnsupported && !params.SupportedType(override.Type) && override.Type != "" {
			override.Type = base.Type
		}
		if override.Type != base.Type || override.Optional || override.Default != nil || override.MaxLen > base.MaxLen || override.MaxLen < 0 || override.MaxItems != 0 || override.Min != nil || override.Max != nil || override.Values != nil || override.AllowedRoots != nil || override.AllowedPrefixes != nil || override.Format != "" {
			return nil, fmt.Errorf("builtin parameter %s may only tighten defaults", name)
		}
		if override.MaxLen > 0 {
			base.MaxLen = override.MaxLen
		}
		// Preserve handler regex. Additional patterns are applied separately by executor.
		if override.Description != "" {
			base.Description = override.Description
		}
		defs[name] = base
	}
	return defs, nil
}
