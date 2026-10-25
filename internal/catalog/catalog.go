package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/params"
	"github.com/liubing0806/allowops/internal/redact"
	"gopkg.in/yaml.v3"
)

type Defaults struct {
	Timeout     string `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	MaxOutput   Size   `json:"max_output,omitempty" yaml:"max_output,omitempty"`
	BatchSize   int    `json:"batch_size,omitempty" yaml:"batch_size,omitempty"`
	MaxFailures *int   `json:"max_failures,omitempty" yaml:"max_failures,omitempty"`
}

type Config struct {
	SchemaVersion int            `json:"schema_version" yaml:"schema_version"`
	CatalogID     string         `json:"catalog_id" yaml:"catalog_id"`
	Defaults      Defaults       `json:"defaults,omitempty" yaml:"defaults,omitempty"`
	Redact        *redact.Config `json:"redact,omitempty" yaml:"redact,omitempty"`
}

type Step struct {
	Name string `json:"name" yaml:"name"`
	Exec []any  `json:"exec" yaml:"exec"`
}

type Script struct {
	File        string `json:"file" yaml:"file"`
	Interpreter string `json:"interpreter" yaml:"interpreter"`
	Content     []byte `json:"content" yaml:"-"`
	SHA256      string `json:"sha256" yaml:"-"`
}

type Action struct {
	Name             string                       `json:"name" yaml:"name"`
	Description      string                       `json:"description" yaml:"description"`
	Risk             string                       `json:"risk" yaml:"risk"`
	Idempotent       *bool                        `json:"idempotent,omitempty" yaml:"idempotent,omitempty"`
	RunAs            string                       `json:"run_as,omitempty" yaml:"run_as,omitempty"`
	Params           map[string]params.Definition `json:"params,omitempty" yaml:"params,omitempty"`
	Exec             []any                        `json:"exec,omitempty" yaml:"exec,omitempty"`
	Steps            []Step                       `json:"steps,omitempty" yaml:"steps,omitempty"`
	Script           *Script                      `json:"script,omitempty" yaml:"script,omitempty"`
	Args             []any                        `json:"args,omitempty" yaml:"args,omitempty"`
	Builtin          string                       `json:"builtin,omitempty" yaml:"builtin,omitempty"`
	BuiltinConfig    map[string]any               `json:"builtin_config,omitempty" yaml:"builtin_config,omitempty"`
	ExecFallbacks    []string                     `json:"exec_fallbacks,omitempty" yaml:"exec_fallbacks,omitempty"`
	Filters          []string                     `json:"filters,omitempty" yaml:"filters,omitempty"`
	OnError          string                       `json:"on_error,omitempty" yaml:"on_error,omitempty"`
	MaxScan          Size                         `json:"max_scan,omitempty" yaml:"max_scan,omitempty"`
	Timeout          string                       `json:"timeout" yaml:"timeout"`
	MaxOutput        Size                         `json:"max_output" yaml:"max_output"`
	Redact           *redact.Config               `json:"redact,omitempty" yaml:"redact,omitempty"`
	BatchSize        int                          `json:"batch_size,omitempty" yaml:"batch_size,omitempty"`
	MaxFailures      *int                         `json:"max_failures,omitempty" yaml:"max_failures,omitempty"`
	AllowInterpreter bool                         `json:"allow_interpreter,omitempty" yaml:"allow_interpreter,omitempty"`
	maxOutputSet     bool
}

type Catalog struct {
	Config   Config
	Actions  map[string]Action
	Warnings []string
}

func decodeYAML(data []byte, out any) error {
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	err := d.Decode(&extra)
	if err != io.EOF {
		if err == nil {
			return fmt.Errorf("only one YAML document allowed")
		}
		return err
	}
	return nil
}

// ParseAction decodes without applying catalog defaults; validation is a separate step.
func ParseAction(data []byte) (Action, error) {
	var a Action
	if err := decodeYAML(data, &a); err != nil {
		return a, err
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return a, err
	}
	if len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
		return a, fmt.Errorf("action must be a YAML mapping")
	}
	content := node.Content[0].Content
	for i := 0; i < len(content); i += 2 {
		if content[i].Value == "max_output" {
			a.maxOutputSet = true
		}
	}
	return a, nil
}

func applyDefaults(a Action, c Config) Action {
	if a.Timeout == "" {
		a.Timeout = c.Defaults.Timeout
	}
	if a.MaxOutput == 0 && !a.maxOutputSet {
		a.MaxOutput = c.Defaults.MaxOutput
	}
	if a.BatchSize == 0 {
		a.BatchSize = c.Defaults.BatchSize
	}
	if a.MaxFailures == nil {
		a.MaxFailures = c.Defaults.MaxFailures
	}
	if a.Redact == nil {
		a.Redact = c.Redact
	}
	return a
}

func validateConfig(c Config) error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("schema_version %d unsupported; allowed: 1", c.SchemaVersion)
	}
	if strings.TrimSpace(c.CatalogID) == "" {
		return fmt.Errorf("catalog_id required")
	}
	if c.Defaults.Timeout != "" {
		n, err := time.ParseDuration(c.Defaults.Timeout)
		if err != nil || n <= 0 {
			return fmt.Errorf("defaults.timeout must be positive Go duration")
		}
	}
	if c.Defaults.MaxOutput != 0 {
		if _, err := ParseSize(c.Defaults.MaxOutput); err != nil {
			return err
		}
	}
	if c.Defaults.BatchSize < 0 || (c.Defaults.MaxFailures != nil && *c.Defaults.MaxFailures < 0) {
		return fmt.Errorf("invalid default batch_size or max_failures")
	}
	_, err := redact.New(c.Redact)
	return err
}

// Load reads a local directory; it never runs executables or checks host-specific paths.
func Load(dir string) (*Catalog, error) {
	data, err := os.ReadFile(filepath.Join(dir, "catalog.yaml"))
	if err != nil {
		return nil, err
	}
	var config Config
	if err := decodeYAML(data, &config); err != nil {
		return nil, fmt.Errorf("catalog.yaml: %w", err)
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(dir, "actions"))
	if err != nil {
		return nil, err
	}
	result := &Catalog{Config: config, Actions: map[string]Action{}}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "actions", entry.Name()))
		if err != nil {
			return nil, err
		}
		a, err := ParseAction(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		a = applyDefaults(a, config)
		if a.Script != nil {
			if err := loadScript(dir, a.Script); err != nil {
				return nil, fmt.Errorf("%s: %w", entry.Name(), err)
			}
		}
		if entry.Name() != a.Name+".yaml" {
			return nil, fmt.Errorf("action filename %s must match name %s", entry.Name(), a.Name)
		}
		if _, exists := result.Actions[a.Name]; exists {
			return nil, fmt.Errorf("duplicate action %s", a.Name)
		}
		warnings, err := ValidateAction(a)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		result.Warnings = append(result.Warnings, warnings...)
		result.Actions[a.Name] = a
	}
	if len(result.Actions) == 0 {
		return nil, fmt.Errorf("catalog must contain at least one action")
	}
	return result, nil
}

var actionName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func IsInterpreter(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return strings.HasPrefix(name, "python") || slices.Contains([]string{"sh", "bash", "zsh", "dash", "ash", "ksh", "mksh", "rbash", "csh", "tcsh", "perl", "ruby", "node", "php", "lua", "awk", "gawk", "mawk", "sed"}, name)
}

func words(template []any) []string {
	var result []string
	for _, v := range template {
		switch value := v.(type) {
		case string:
			result = append(result, value)
		case []any:
			result = append(result, words(value)...)
		}
	}
	return result
}

func ValidateAction(a Action) ([]string, error) {
	return validateAction(a, false)
}

// Loading a known schema preserves future handlers/types for per-action
// reporting. Authoring and execution still require supported capabilities.
// Checks run in a fixed order, so the first failing category is the one reported.
func validateAction(a Action, allowUnsupported bool) ([]string, error) {
	if err := validateIdentity(a); err != nil {
		return nil, err
	}
	_, knownBuiltin := Builtins[a.Builtin]
	unknownBuiltin := a.Builtin != "" && !knownBuiltin
	defs, err := validateActionParams(a, allowUnsupported, unknownBuiltin)
	if err != nil {
		return nil, err
	}
	if err := validateModeFields(a); err != nil {
		return nil, err
	}
	if err := validateBody(a, defs, unknownBuiltin); err != nil {
		return nil, err
	}
	if err := validateLimits(a); err != nil {
		return nil, err
	}
	return actionWarnings(a), nil
}

func validateIdentity(a Action) error {
	if !actionName.MatchString(a.Name) || slices.Contains([]string{"hosts_search", "jobs_get", "jobs_list", "jobs_cancel"}, a.Name) {
		return fmt.Errorf("invalid or reserved action name %q", a.Name)
	}
	if strings.TrimSpace(a.Description) == "" {
		return fmt.Errorf("description required")
	}
	if !slices.Contains([]string{"read", "write", "dangerous"}, a.Risk) {
		return fmt.Errorf("risk allowed: read, write, dangerous")
	}
	return nil
}

// validateActionParams resolves the effective parameter definitions (including
// builtin-owned ones) and validates both them and the action's own.
func validateActionParams(a Action, allowUnsupported, unknownBuiltin bool) (map[string]params.Definition, error) {
	var defs map[string]params.Definition
	var err error
	if unknownBuiltin && allowUnsupported {
		defs = a.Params
	} else {
		defs, err = parameterDefinitions(a, allowUnsupported)
	}
	if err != nil {
		return nil, err
	}
	validateDefinitions := params.ValidateDefinitions
	if allowUnsupported {
		validateDefinitions = params.ValidateDefinitionsForReader
	}
	if err := validateDefinitions(defs); err != nil {
		return nil, err
	}
	if err := validateDefinitions(a.Params); err != nil {
		return nil, err
	}
	return defs, nil
}

// validateModeFields checks which execution mode is selected and the fields
// that only apply to a particular mode, plus the output filters.
func validateModeFields(a Action) error {
	modes := 0
	if a.Exec != nil {
		modes++
	}
	if a.Steps != nil {
		modes++
	}
	if a.Script != nil {
		modes++
	}
	if a.Builtin != "" {
		modes++
	}
	if modes != 1 {
		return fmt.Errorf("exactly one of exec, steps, script, builtin required")
	}
	if a.OnError != "" && (a.Steps == nil || (a.OnError != "continue" && a.OnError != "stop")) {
		return fmt.Errorf("on_error allowed for steps: continue, stop")
	}
	if a.ExecFallbacks != nil && a.Exec == nil {
		return fmt.Errorf("exec_fallbacks requires exec")
	}
	if a.Args != nil && a.Script == nil {
		return fmt.Errorf("args requires script")
	}
	if a.BuiltinConfig != nil && a.Builtin == "" {
		return fmt.Errorf("builtin_config requires builtin")
	}
	if a.MaxScan < 0 {
		return fmt.Errorf("max_scan must be nonnegative")
	}
	seenFilters := map[string]bool{}
	for _, filter := range a.Filters {
		if !slices.Contains([]string{"match", "exclude", "tail", "head", "count"}, filter) || seenFilters[filter] {
			return fmt.Errorf("invalid or duplicate filter %q", filter)
		}
		seenFilters[filter] = true
	}
	return nil
}

// validateBody validates the selected mode's payload. Modes are mutually
// exclusive here, so the order among them does not change which error is reported.
func validateBody(a Action, defs map[string]params.Definition, unknownBuiltin bool) error {
	if a.Exec != nil {
		if err := validateExecWithFallbacks(a, defs); err != nil {
			return err
		}
	}
	if a.Steps != nil {
		if err := validateSteps(a, defs); err != nil {
			return err
		}
	}
	if a.Script != nil {
		if err := validateScript(*a.Script); err != nil {
			return err
		}
		if err := params.ValidateTemplate(a.Args, defs); err != nil {
			return err
		}
	}
	if a.Builtin != "" && !unknownBuiltin {
		if err := Builtins[a.Builtin].ValidateConfig(a.BuiltinConfig); err != nil {
			return err
		}
		if validator, ok := Builtins[a.Builtin].(ActionBuiltinValidator); ok {
			if err := validator.ValidateActionFields(a); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateExecWithFallbacks(a Action, defs map[string]params.Definition) error {
	if err := validateExec(a.Exec, defs, a.AllowInterpreter); err != nil {
		return err
	}
	for _, fallback := range a.ExecFallbacks {
		candidate := append([]any(nil), a.Exec...)
		candidate[0] = fallback
		if err := validateExec(candidate, defs, a.AllowInterpreter); err != nil {
			return err
		}
	}
	return nil
}

func validateSteps(a Action, defs map[string]params.Definition) error {
	if len(a.Steps) == 0 {
		return fmt.Errorf("steps must not be empty")
	}
	seen := map[string]bool{}
	for _, step := range a.Steps {
		if !actionName.MatchString(step.Name) || seen[step.Name] {
			return fmt.Errorf("invalid or duplicate step name %q", step.Name)
		}
		seen[step.Name] = true
		if err := validateExec(step.Exec, defs, a.AllowInterpreter); err != nil {
			return fmt.Errorf("step %s: %w", step.Name, err)
		}
	}
	return nil
}

// validateLimits checks timeout, output and batch limits, run_as and redaction.
func validateLimits(a Action) error {
	timeout, err := time.ParseDuration(a.Timeout)
	if err != nil || timeout <= 0 {
		return fmt.Errorf("timeout required: positive Go duration")
	}
	if a.MaxOutput <= 0 {
		return fmt.Errorf("max_output must be positive integer bytes")
	}
	if a.BatchSize < 0 || (a.MaxFailures != nil && *a.MaxFailures < 0) {
		return fmt.Errorf("batch_size and max_failures must be nonnegative")
	}
	if strings.ContainsAny(a.RunAs, "\x00\r\n") || strings.HasPrefix(a.RunAs, "-") {
		return fmt.Errorf("invalid run_as")
	}
	_, err = redact.New(a.Redact)
	return err
}

func actionWarnings(a Action) []string {
	var warnings []string
	if a.Script != nil {
		warnings = append(warnings, fmt.Sprintf("action %s: signed script permits arbitrary execution", a.Name))
	}
	if a.AllowInterpreter {
		warnings = append(warnings, fmt.Sprintf("action %s: allow_interpreter permits arbitrary interpreter/script execution", a.Name))
	}
	return warnings
}

type Package struct {
	SchemaVersion int               `json:"schema_version"`
	CatalogID     string            `json:"catalog_id"`
	Version       int64             `json:"version"`
	CreatedAt     time.Time         `json:"created_at"`
	ExpiresAt     time.Time         `json:"expires_at"`
	GitCommit     string            `json:"git_commit"`
	Actions       map[string]Action `json:"actions"`
	Digests       map[string]string `json:"digests"`
}

type BuildOptions struct {
	Now       time.Time
	TTL       time.Duration
	GitCommit string
}

// CanonicalJSON emits deterministic, compact JSON with lexically ordered object keys.
func CanonicalJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var object any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(object); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

func ActionDigest(a Action) (string, error) {
	data, err := CanonicalJSON(a)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Build sets expires_at to the build-time created_at plus TTL (90 days by default).
// Signing preserves that interval; build and sign run consecutively in one pipeline.
func Build(c *Catalog, opts BuildOptions) (*Package, error) {
	if c == nil {
		return nil, fmt.Errorf("catalog required")
	}
	if err := validateConfig(c.Config); err != nil {
		return nil, err
	}
	if len(c.Actions) == 0 {
		return nil, fmt.Errorf("catalog must contain actions")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC().Truncate(time.Second)
	ttl := opts.TTL
	if ttl == 0 {
		ttl = 90 * 24 * time.Hour
	}
	if ttl < 0 {
		return nil, fmt.Errorf("TTL must be positive")
	}
	version, err := strconv.ParseInt(now.Format("20060102150405"), 10, 64)
	if err != nil {
		return nil, err
	}
	p := &Package{SchemaVersion: c.Config.SchemaVersion, CatalogID: c.Config.CatalogID, Version: version, CreatedAt: now, ExpiresAt: now.Add(ttl), GitCommit: opts.GitCommit, Actions: map[string]Action{}, Digests: map[string]string{}}
	for name, a := range c.Actions {
		a = applyDefaults(a, c.Config)
		if name != a.Name {
			return nil, fmt.Errorf("action key %s differs from name %s", name, a.Name)
		}
		if _, err := ValidateAction(a); err != nil {
			return nil, err
		}
		digest, err := ActionDigest(a)
		if err != nil {
			return nil, err
		}
		p.Actions[name] = a
		p.Digests[name] = digest
	}
	return p, nil
}
