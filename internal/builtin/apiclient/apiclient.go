// Package apiclient implements the read-only HTTP client shared by the
// Prometheus and Alertmanager builtins.
package apiclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// Config is trusted catalog configuration. Zero Timeout and MaxResponseBytes
// select the package defaults; callers apply their own defaults and upper
// limits with Tighten before constructing a Client.
type Config struct {
	Address          string        `yaml:"address"`
	Credential       string        `yaml:"credential"`
	CAFile           string        `yaml:"ca_file"`
	Timeout          time.Duration `yaml:"timeout"`
	MaxResponseBytes int64         `yaml:"max_response_bytes"`
}

// Response is a completed GET exchange. Non-2xx statuses are not errors.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

var (
	// ErrRedirect reports a 3xx response. Redirects are never followed.
	ErrRedirect = errors.New("apiclient: redirect response")
	// ErrResponseTooLarge reports a body above Config.MaxResponseBytes.
	ErrResponseTooLarge = errors.New("apiclient: response body exceeds max_response_bytes")

	errNotImplemented = errors.New("apiclient: not implemented")
)

type Client struct {
	transport *http.Transport
}

func (Config) Validate() error { return errNotImplemented }

func Tighten[T ~int | ~int64](name string, value, def, max T) (T, error) {
	return 0, errNotImplemented
}

func New(Config) (*Client, error) { return nil, errNotImplemented }

func (*Client) Get(ctx context.Context, apiPath string, query url.Values) (Response, error) {
	return Response{}, errNotImplemented
}

func (*Client) Close() {}
