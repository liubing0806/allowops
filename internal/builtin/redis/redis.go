// Package redis executes a fixed allowlist of read-only Redis commands.
package redis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
	redisclient "github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
)

// Config is trusted catalog configuration. Address is host:port or an absolute
// unix:// socket path. Credential is a root-owned regular 0600 JSON file with
// optional username and password fields, at most 16KiB, without unknown fields.
// MaxResponseBytes limits aggregate raw value bytes for GET/HGET/MGET before
// retrieval, and returned response text for other commands. Final max_output
// belongs to the executor after redaction and filtering. Defaults are DB 0,
// timeout 10s, response 64KiB and SCAN COUNT <= 1000.
type Config struct {
	Address          string        `yaml:"address"`
	Credential       string        `yaml:"credential"`
	DB               int           `yaml:"db"`
	Timeout          time.Duration `yaml:"timeout"`
	MaxResponseBytes int64         `yaml:"max_response_bytes"`
	MaxScanCount     int           `yaml:"max_scan_count"`
	Commands         []string      `yaml:"commands" json:"commands"`
	KeyPrefixes      []string      `yaml:"key_prefixes" json:"key_prefixes"`
	InfoSections     []string      `yaml:"info_sections" json:"info_sections"`
}

var allowedCommands = []string{"GET", "MGET", "HGET", "HLEN", "TTL", "TYPE", "EXISTS", "STRLEN", "LLEN", "SCARD", "ZCARD", "SCAN", "INFO"}

// Aggregate selectors (all/default/everything) cannot represent one restricted section.
var allowedInfoSections = []string{"server", "clients", "memory", "persistence", "stats", "replication", "cpu", "commandstats", "errorstats", "latencystats", "cluster", "keyspace", "modules", "sentinel"}

type Params struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

type Result = builtin.Result

func (c Config) Validate() error {
	if !filepath.IsAbs(c.Credential) {
		return errors.New("credential path must be absolute")
	}
	if strings.HasPrefix(c.Address, "unix://") {
		if !filepath.IsAbs(strings.TrimPrefix(c.Address, "unix://")) {
			return errors.New("redis unix socket path must be absolute")
		}
	} else {
		host, port, err := net.SplitHostPort(c.Address)
		if err != nil || host == "" {
			return errors.New("redis address must be host:port or unix:///absolute/path")
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return errors.New("invalid Redis port")
		}
	}
	if c.DB < 0 || c.Timeout < 0 || c.MaxResponseBytes < 0 || c.MaxResponseBytes > 16<<20 || c.MaxScanCount < 0 || c.MaxScanCount > builtin.DefaultRedisMaxScanCount {
		return errors.New("invalid Redis limits: DB and timeout nonnegative, response <= 16MiB, SCAN COUNT <= 1000")
	}
	for _, list := range []struct {
		name            string
		values, allowed []string
	}{
		{"commands", c.Commands, allowedCommands},
		{"info_sections", c.InfoSections, allowedInfoSections},
	} {
		if list.values != nil && len(list.values) == 0 {
			return fmt.Errorf("%s must be a nonempty subset of: %s", list.name, strings.Join(list.allowed, ", "))
		}
		for _, value := range list.values {
			if !containsFold(list.allowed, value) {
				return fmt.Errorf("%s may only contain: %s", list.name, strings.Join(list.allowed, ", "))
			}
		}
	}
	if c.KeyPrefixes != nil && len(c.KeyPrefixes) == 0 {
		return errors.New("key_prefixes must be a nonempty list of nonempty literal prefixes (1..4096 bytes, no NUL/newlines)")
	}
	for _, prefix := range c.KeyPrefixes {
		if len(prefix) == 0 || len(prefix) > 4096 || strings.ContainsAny(prefix, "\x00\r\n") {
			return errors.New("key_prefixes must contain nonempty literal prefixes (1..4096 bytes, no NUL/newlines)")
		}
	}
	return nil
}

func containsFold(values []string, value string) bool {
	return slices.ContainsFunc(values, func(allowed string) bool { return strings.EqualFold(allowed, value) })
}

func ParamsSchema() map[string]any {
	return map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false, "required": []string{"command"}, "properties": map[string]any{
		"command": map[string]any{"type": "string", "enum": slices.Clone(allowedCommands)},
		"args":    map[string]any{"type": "array", "maxItems": 128, "items": map[string]any{"type": "string", "maxLength": 4096, "pattern": "^([^-].*)?$"}},
	}}
}

func command(p Params, maxCount int) ([]any, error) {
	name := strings.ToUpper(p.Command)
	if len(p.Command) > 16 || len(p.Args) > 128 {
		return nil, errors.New("invalid Redis command or argument count")
	}
	for _, arg := range p.Args {
		if len(arg) > 4096 || strings.HasPrefix(arg, "-") || strings.ContainsAny(arg, "\x00\r\n") {
			return nil, errors.New("invalid Redis argument")
		}
	}
	n := len(p.Args)
	switch name {
	case "GET", "HLEN", "TTL", "TYPE", "STRLEN", "LLEN", "SCARD", "ZCARD":
		if n != 1 {
			return nil, errors.New("redis command requires one argument")
		}
	case "HGET":
		if n != 2 {
			return nil, errors.New("HGET requires key and field")
		}
	case "MGET", "EXISTS":
		if n == 0 {
			return nil, errors.New("redis command requires at least one key")
		}
	case "INFO":
		if n > 1 {
			return nil, errors.New("INFO accepts at most one section")
		}
	case "SCAN":
		if n == 0 || n%2 != 1 {
			return nil, errors.New("SCAN requires cursor and optional MATCH/COUNT pairs")
		}
		if _, err := strconv.ParseUint(p.Args[0], 10, 64); err != nil {
			return nil, errors.New("invalid SCAN cursor")
		}
		seen := map[string]bool{}
		for i := 1; i < n; i += 2 {
			key := strings.ToUpper(p.Args[i])
			if seen[key] {
				return nil, errors.New("duplicate SCAN option")
			}
			seen[key] = true
			switch key {
			case "MATCH":
			case "COUNT":
				count, err := strconv.ParseUint(p.Args[i+1], 10, 32)
				if err != nil || count == 0 || count > uint64(maxCount) {
					return nil, errors.New("SCAN COUNT exceeds configured limit or is invalid")
				}
			default:
				return nil, errors.New("SCAN only accepts MATCH and COUNT")
			}
		}
		if !seen["COUNT"] {
			p.Args = append(append([]string(nil), p.Args...), "COUNT", strconv.Itoa(min(builtin.DefaultRedisScanCount, maxCount)))
		}
	default:
		return nil, fmt.Errorf("redis command is not allowed; legal commands: %s", strings.Join(allowedCommands, ", "))
	}
	args := make([]any, 1, len(p.Args)+1)
	args[0] = name
	for _, arg := range p.Args {
		args = append(args, arg)
	}
	return args, nil
}

func (c Config) validateCommand(args []any) error {
	name := args[0].(string)
	if c.Commands != nil && !containsFold(c.Commands, name) {
		return fmt.Errorf("commands allows only: %s", strings.Join(c.Commands, ", "))
	}
	if name == "INFO" {
		if c.InfoSections != nil && len(args) > 1 && !containsFold(c.InfoSections, args[1].(string)) {
			return fmt.Errorf("info_sections allows only: %s", strings.Join(c.InfoSections, ", "))
		}
		return nil
	}
	if c.KeyPrefixes == nil {
		return nil
	}
	keys := args[1:]
	switch name {
	case "SCAN":
		for i := 2; i < len(args); i += 2 {
			if strings.EqualFold(args[i].(string), "MATCH") {
				if c.hasKeyPrefix(globLiteralPrefix(args[i+1].(string))) {
					return nil
				}
				break
			}
		}
		return fmt.Errorf("key_prefixes requires SCAN MATCH with a fixed literal prefix from: %s", strings.Join(c.KeyPrefixes, ", "))
	case "HGET":
		keys = args[1:2] // The field is not a key.
	}
	for _, key := range keys {
		if !c.hasKeyPrefix(key.(string)) {
			return fmt.Errorf("key_prefixes requires every key to start with one of: %s", strings.Join(c.KeyPrefixes, ", "))
		}
	}
	return nil
}

func (c Config) hasKeyPrefix(key string) bool {
	return slices.ContainsFunc(c.KeyPrefixes, func(prefix string) bool { return strings.HasPrefix(key, prefix) })
}

// Redis glob * ? [ start variable matches. Backslash quotes the next byte.
// Only the decoded literal prefix before the first wildcard can authorize SCAN.
func globLiteralPrefix(pattern string) string {
	var prefix strings.Builder
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*', '?', '[':
			return prefix.String()
		case '\\':
			if i+1 < len(pattern) {
				i++
			}
		}
		prefix.WriteByte(pattern[i])
	}
	return prefix.String()
}

type credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func readCredential(path string) (credential, error) {
	var c credential
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return c, errors.New("cannot open Redis credential file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return c, errors.New("cannot stat Redis credential file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return c, errors.New("redis credential file must be owned by root")
	}
	if info.Mode() != 0600 {
		return c, errors.New("redis credential file must be regular with mode 0600")
	}
	data, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(data) > 16384 {
		return c, errors.New("cannot read Redis credential file or size exceeds 16KiB")
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return c, errors.New("redis credential must contain one JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return credential{}, errors.New("invalid Redis credential JSON")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return credential{}, errors.New("redis credential must contain one JSON object")
	}
	return c, nil
}

func Run(ctx context.Context, cfg Config, p Params) (Result, error) {
	return RunRedacted(ctx, cfg, p, nil)
}

// RunRedacted transforms complete string values before JSON encoding. The
// executor supplies the selected action/inherited policy; nil preserves raw values.
func RunRedacted(ctx context.Context, cfg Config, p Params, mask func(string) string) (Result, error) {
	r := Result{ExitCode: builtin.ExitFailure}
	if err := cfg.Validate(); err != nil {
		return r, err
	}
	if cfg.MaxScanCount == 0 {
		cfg.MaxScanCount = builtin.DefaultRedisMaxScanCount
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = builtin.DefaultRedisMaxResponseBytes
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = builtin.DefaultTimeout
	}
	args, err := command(p, cfg.MaxScanCount)
	if err != nil {
		return r, err
	}
	if err := cfg.validateCommand(args); err != nil {
		return r, err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return r, err
	}
	cred, err := readCredential(cfg.Credential)
	if err != nil {
		return r, err
	}
	opts := &redisclient.Options{Addr: cfg.Address, Username: cred.Username, Password: cred.Password, DB: cfg.DB, Protocol: 2, DisableIdentity: true, ContextTimeoutEnabled: true, DialTimeout: cfg.Timeout, ReadTimeout: cfg.Timeout, WriteTimeout: cfg.Timeout, MaxRetries: -1, PoolSize: 1, MaintNotificationsConfig: &maintnotifications.Config{Mode: maintnotifications.ModeDisabled}}
	if strings.HasPrefix(cfg.Address, "unix://") {
		opts.Network = "unix"
		opts.Addr = strings.TrimPrefix(cfg.Address, "unix://")
	}
	client := redisclient.NewClient(opts)
	defer client.Close()
	value, truncated, err := readConfiguredResponse(ctx, client, args, cfg)
	r.Truncated = truncated
	if errors.Is(err, redisclient.Nil) {
		value = nil
		err = nil
	}
	if err != nil {
		return r, fmt.Errorf("redis command failed: %w", err)
	}
	if truncated {
		// A decoded record cut by INFO aggregation or GETRANGE growth is
		// incomplete. Do not encode any part of it as a complete safe value.
		r.ExitCode = builtin.ExitSuccess
		return r, nil
	}
	output, err := json.Marshal(value)
	if err != nil {
		return r, errors.New("cannot encode Redis result")
	}
	output = append(output, '\n')
	// INFO/SCAN cannot be size-checked before decoding. G13 limits their
	// returned text here; GET/HGET/MGET are checked before reading instead.
	if args[0] != "GET" && args[0] != "HGET" && args[0] != "MGET" && int64(len(output)) > cfg.MaxResponseBytes {
		r.Truncated = true
		r.ExitCode = builtin.ExitSuccess
		return r, nil // JSON is one record; no partial serialized record is safe.
	}
	if mask != nil {
		output, err = json.Marshal(maskResponse(value, mask))
		if err != nil {
			return r, errors.New("cannot encode Redis result")
		}
		output = append(output, '\n')
	}
	r.Stdout = string(output)
	r.ExitCode = builtin.ExitSuccess
	return r, nil
}

func maskResponse(value any, mask func(string) string) any {
	switch value := value.(type) {
	case string:
		return mask(value)
	case []any:
		for i, item := range value {
			value[i] = maskResponse(item, mask)
		}
		return value
	default:
		return value
	}
}

// ErrResponseLimit means values exceeded the configured response resource limit.
var ErrResponseLimit = errors.New("redis response limit exceeded")

func readConfiguredResponse(ctx context.Context, client *redisclient.Client, args []any, cfg Config) (any, bool, error) {
	if args[0] == "INFO" && len(args) == 1 && cfg.InfoSections != nil {
		var output strings.Builder
		for _, section := range cfg.InfoSections {
			text, err := client.Info(ctx, strings.ToLower(section)).Result()
			if err != nil {
				return nil, false, err
			}
			remaining := cfg.MaxResponseBytes - int64(output.Len())
			if int64(len(text)) > remaining {
				output.WriteString(text[:remaining])
				return output.String(), true, nil
			}
			output.WriteString(text)
		}
		return output.String(), false, nil
	}
	return readResponse(ctx, client, args, cfg.MaxResponseBytes)
}

func readResponse(ctx context.Context, client *redisclient.Client, args []any, limit int64) (any, bool, error) {
	name := args[0].(string)
	var size int64
	switch name {
	case "GET":
		key := args[1].(string)
		length, err := client.StrLen(ctx, key).Result()
		if err != nil {
			return nil, false, err
		}
		if length > limit {
			return nil, true, fmt.Errorf("%w: value exceeds %d bytes", ErrResponseLimit, limit)
		}
		if length == 0 {
			exists, err := client.Exists(ctx, key).Result()
			if err != nil {
				return nil, false, err
			}
			if exists == 0 {
				return nil, false, redisclient.Nil
			}
		}
		// GETRANGE bounds allocation even when the key grows after STRLEN.
		// These reads do not provide an atomic snapshot of a changing key.
		// Reading one byte past the limit is the only evidence of growth:
		// a prefix of exactly limit bytes is complete only if nothing follows.
		value, err := client.GetRange(ctx, key, 0, limit).Result()
		if err != nil {
			return value, false, err
		}
		if int64(len(value)) > limit {
			return value[:limit], true, nil
		}
		return value, false, nil
	case "HGET":
		length, err := client.HStrLen(ctx, args[1].(string), args[2].(string)).Result()
		if err != nil {
			return nil, false, err
		}
		size = length
	case "MGET":
		for _, arg := range args[1:] {
			length, err := client.StrLen(ctx, arg.(string)).Result()
			// MGET returns null for non-string keys. Preserve that behavior.
			if err != nil && strings.HasPrefix(err.Error(), "WRONGTYPE") {
				continue
			}
			if err != nil {
				return nil, false, err
			}
			if length > limit-size {
				return nil, true, fmt.Errorf("%w: values exceed %d bytes", ErrResponseLimit, limit)
			}
			size += length
		}
		return readBoundedMGet(ctx, client, args[1:], limit)
	}
	if size > limit {
		return nil, true, fmt.Errorf("%w: value exceeds %d bytes", ErrResponseLimit, limit)
	}
	// G13: the HGET preflight is not atomic. Concurrent writes between the
	// length check and read may enlarge a value beyond this memory limit.
	value, err := client.Do(ctx, args...).Result()
	if err == nil {
		if text, ok := value.(string); ok && name == "HGET" && int64(len(text)) > limit {
			return nil, true, fmt.Errorf("%w: value changed after size check", ErrResponseLimit)
		}
	}
	return value, false, err
}

// readBoundedMGet answers MGET with one bounded GETRANGE per key, so a key that
// grew after the STRLEN precheck cannot make the client allocate its full size.
// Each read is capped at the unused budget plus one byte; the extra byte shows
// growth past the limit. The reads are not an atomic snapshot.
func readBoundedMGet(ctx context.Context, client *redisclient.Client, keys []any, limit int64) (any, bool, error) {
	values := make([]any, len(keys))
	var total int64
	for i, key := range keys {
		remaining := limit - total
		text, err := client.GetRange(ctx, key.(string), 0, remaining).Result()
		// MGET returns null for non-string keys. Preserve that behavior.
		if err != nil && strings.HasPrefix(err.Error(), "WRONGTYPE") {
			continue
		}
		if err != nil {
			return nil, false, err
		}
		if int64(len(text)) > remaining {
			return nil, true, fmt.Errorf("%w: values changed after size check", ErrResponseLimit)
		}
		if text == "" {
			// GETRANGE answers "" for a missing key as well as an empty string.
			exists, err := client.Exists(ctx, key.(string)).Result()
			if err != nil {
				return nil, false, err
			}
			if exists == 0 {
				continue
			}
		}
		values[i] = text
		total += int64(len(text))
	}
	return values, false, nil
}
