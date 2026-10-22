// Package httpget implements GET requests constrained by configured URL prefixes.
package httpget

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/params"
)

// Config is trusted catalog configuration. MaxResponseBytes limits response
// body bytes, independently of status and headers. Final max_output is applied
// only by the executor after redaction and filtering. Zero selects defaults.
type Config struct {
	AllowedPrefixes  []string          `yaml:"allowed_prefixes"`
	Headers          map[string]string `yaml:"headers"`
	Timeout          time.Duration     `yaml:"timeout"`
	MaxResponseBytes int64             `yaml:"max_response_bytes"`
}

type Params struct {
	URL string `json:"url"`
}

type Result struct {
	builtin.Result
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

func (c Config) Validate() error {
	if len(c.AllowedPrefixes) == 0 {
		return errors.New("allowed_prefixes is required")
	}
	for _, raw := range c.AllowedPrefixes {
		if len(raw) > 4096 {
			return errors.New("invalid allowed_prefix")
		}
		u, err := params.NormalizeURL(raw)
		if err != nil {
			return fmt.Errorf("invalid allowed_prefix: %w", err)
		}
		if u.RawQuery != "" || u.ForceQuery {
			return errors.New("allowed_prefix must not contain a query")
		}
	}
	if c.Timeout < 0 || c.MaxResponseBytes < 0 || c.MaxResponseBytes > 16<<20 {
		return errors.New("timeout must be nonnegative and max_response_bytes must be between 0 and 16777216 bytes")
	}
	for key, value := range c.Headers {
		if key == "" {
			return errors.New("request header name must not be empty")
		}
		for _, ch := range key {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", ch)) {
				return errors.New("invalid request header name")
			}
		}
		for _, ch := range value {
			if ch < 32 && ch != '\t' || ch == 127 {
				return errors.New("invalid request header value")
			}
		}
	}
	return nil
}

func ParamsSchema() map[string]any {
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false,
		"required": []string{"url"}, "properties": map[string]any{
			"url": map[string]any{"type": "string", "format": "uri", "minLength": 1, "maxLength": 4096, "pattern": "^[^-]"},
		},
	}
}

// ValidateURL delegates origin and path checks to the shared canonical parser.
func ValidateURL(raw string, allowedPrefixes []string) error {
	if len(raw) > 4096 {
		return errors.New("invalid URL")
	}
	_, err := params.ParseURL(raw, allowedPrefixes)
	return err
}

func Run(ctx context.Context, cfg Config, p Params) (Result, error) {
	r := Result{Result: builtin.Result{ExitCode: builtin.ExitFailure}}
	if err := cfg.Validate(); err != nil {
		return r, err
	}
	if len(p.URL) > 4096 {
		return r, errors.New("invalid URL")
	}
	u, err := params.ParseURL(p.URL, cfg.AllowedPrefixes)
	if err != nil {
		return r, err
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = builtin.DefaultTimeout
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = builtin.DefaultHTTPMaxResponseBytes
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return r, errors.New("cannot construct GET request")
	}
	for key, value := range cfg.Headers {
		req.Header.Set(key, value)
	}
	if _, configured := req.Header["User-Agent"]; !configured {
		req.Header["User-Agent"] = nil
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // Only the configured origin receives the fixed headers.
	transport.DisableCompression = true
	transport.MaxResponseHeaderBytes = builtin.DefaultHTTPMaxHeaderBytes
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return r, fmt.Errorf("GET request failed: %w", err)
	}
	defer response.Body.Close()
	r.StatusCode, r.Headers = response.StatusCode, make(map[string]string)
	var out strings.Builder
	fmt.Fprintf(&out, "HTTP %d\n", response.StatusCode)
	for _, key := range []string{"Content-Type", "Content-Length", "Location"} {
		if value := response.Header.Get(key); value != "" {
			r.Headers[key] = value
			out.WriteString(key + ": " + value + "\n")
		}
	}
	out.WriteString("\n")
	body, err := io.ReadAll(io.LimitReader(response.Body, cfg.MaxResponseBytes+1))
	if err != nil {
		r.Stdout = out.String()
		return r, fmt.Errorf("reading GET response failed: %w", err)
	}
	if int64(len(body)) > cfg.MaxResponseBytes {
		body = body[:cfg.MaxResponseBytes]
		// The final record has no complete recognition context. Discard it,
		// including when a custom rule requires an arbitrarily long suffix.
		body = body[:bytes.LastIndexByte(body, '\n')+1]
		r.Truncated = true
	}
	r.Body = string(body)
	out.Write(body)
	r.Stdout = out.String()
	r.ExitCode = builtin.ExitSuccess
	return r, nil
}
