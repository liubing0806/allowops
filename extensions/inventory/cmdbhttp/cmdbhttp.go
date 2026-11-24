// Package cmdbhttp resolves inventory from a read-only JSON CMDB endpoint.
package cmdbhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/inventory"
)

func init() { plugin.Register(Module{}) }

type Module struct {
	URL              string        `yaml:"url"`
	CredentialRef    string        `yaml:"credential_ref"`
	AuthHeader       string        `yaml:"auth_header"`
	AuthScheme       *string       `yaml:"auth_scheme"`
	CacheTTL         time.Duration `yaml:"cache_ttl"`
	MaxResponseBytes int64         `yaml:"max_response_bytes"`

	host       plugin.Host
	endpoint   *url.URL
	authScheme string
}

func (Module) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "inventory.cmdb_http", New: func() plugin.Module { return &Module{} }}
}

var (
	headerPattern   = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
	errCredential   = errors.New("cmdb inventory: credential unavailable or invalid")
	errRequest      = errors.New("cmdb inventory: request failed")
	errResponse     = errors.New("cmdb inventory: invalid response")
	errResponseSize = errors.New("cmdb inventory: response exceeds max_response_bytes")
	errDuplicate    = errors.New("cmdb inventory: duplicate entity kind and name")
)

func (m *Module) Validate() error {
	endpoint, err := url.Parse(m.URL)
	if err != nil || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Fragment != "" ||
		(endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return errors.New("cmdb inventory: url must be an HTTP(S) URL")
	}
	if m.CredentialRef != "" && endpoint.Scheme != "https" {
		return errors.New("cmdb inventory: url must use HTTPS with credential_ref")
	}
	if _, err := url.ParseQuery(endpoint.RawQuery); err != nil {
		return errors.New("cmdb inventory: invalid url query")
	}
	if m.AuthHeader != "" && !headerPattern.MatchString(m.AuthHeader) {
		return errors.New("cmdb inventory: invalid auth_header")
	}
	switch strings.ToLower(m.AuthHeader) {
	case "accept", "host", "content-length", "transfer-encoding":
		return errors.New("cmdb inventory: reserved auth_header")
	}
	if m.AuthScheme != nil {
		switch *m.AuthScheme {
		case "", "Bearer", "Basic":
		default:
			return errors.New("cmdb inventory: invalid auth_scheme")
		}
	}
	if m.CacheTTL < 0 || m.CacheTTL > 10*time.Minute {
		return errors.New("cmdb inventory: invalid cache_ttl")
	}
	if m.MaxResponseBytes < 0 || m.MaxResponseBytes > 16<<20 {
		return errors.New("cmdb inventory: invalid max_response_bytes")
	}
	return nil
}

func (m *Module) Provision(_ context.Context, h plugin.Host) error {
	if err := m.Validate(); err != nil {
		return err
	}
	m.endpoint, _ = url.Parse(m.URL)
	query := m.endpoint.Query()
	for key := range query {
		if strings.EqualFold(key, "kind") || strings.EqualFold(key, "name") {
			query.Del(key)
		}
	}
	m.endpoint.RawQuery = query.Encode()
	m.host = h
	if m.AuthHeader == "" {
		m.AuthHeader = "Authorization"
	}
	m.authScheme = "Bearer"
	if m.AuthScheme != nil {
		m.authScheme = *m.AuthScheme
	}
	if m.CacheTTL == 0 {
		m.CacheTTL = 60 * time.Second
	}
	if m.MaxResponseBytes == 0 {
		m.MaxResponseBytes = 4 << 20
	}
	return nil
}

func (m *Module) Resolve(ctx context.Context, q inventory.Query) ([]inventory.Entity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := "entities:" + q.Kind
	cache := m.host.Cache()
	var entities []inventory.Entity
	if data, ok := cache.Get(key); ok && json.Unmarshal(data, &entities) == nil {
		return entities, nil
	}
	entities, err := m.fetch(ctx, q)
	if err != nil {
		return nil, err
	}
	if data, err := json.Marshal(entities); err == nil {
		cache.Set(key, data, m.CacheTTL)
	}
	return entities, nil
}

func (m *Module) setAuthorization(req *http.Request) error {
	if m.CredentialRef == "" {
		return nil
	}
	value, err := m.host.Credential(m.CredentialRef)
	credential := strings.TrimSpace(string(value))
	if err != nil || credential == "" {
		return errCredential
	}
	for _, char := range []byte(credential) {
		if (char < ' ' && char != '\t') || char == 127 {
			return errCredential
		}
	}
	if m.authScheme != "" {
		credential = m.authScheme + " " + credential
	}
	req.Header.Set(m.AuthHeader, credential)
	return nil
}

type cmdbEntity struct {
	inventory.Entity
	Dependencies []string `json:"depends_on"`
}

func (m *Module) fetch(ctx context.Context, q inventory.Query) ([]inventory.Entity, error) {
	endpoint := *m.endpoint
	if q.Kind != "" {
		query := endpoint.Query()
		query.Set("kind", q.Kind)
		endpoint.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errRequest
	}
	req.Header.Set("Accept", "application/json")
	if err := m.setAuthorization(req); err != nil {
		return nil, err
	}
	resp, err := m.host.HTTPClient().Do(req)
	if err != nil {
		return nil, errRequest
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errResponse
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, m.MaxResponseBytes+1))
	if err != nil {
		return nil, errRequest
	}
	if int64(len(data)) > m.MaxResponseBytes {
		return nil, errResponseSize
	}
	var payload struct {
		Entities []cmdbEntity `json:"entities"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || payload.Entities == nil || decoder.Decode(new(json.RawMessage)) != io.EOF {
		return nil, errResponse
	}
	seen := make(map[[2]string]bool)
	out := []inventory.Entity{}
	for _, entity := range payload.Entities {
		key := [2]string{entity.Kind, entity.Name}
		if seen[key] {
			return nil, errDuplicate
		}
		seen[key] = true
		if entity.Dependencies != nil {
			if entity.DependsOn != nil {
				return nil, errResponse
			}
			entity.DependsOn = entity.Dependencies
		}
		if q.Kind == "" || q.Kind == entity.Kind {
			out = append(out, entity.Entity)
		}
	}
	slices.SortFunc(out, func(a, b inventory.Entity) int {
		if order := strings.Compare(a.Kind, b.Kind); order != 0 {
			return order
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}
