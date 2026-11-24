// Package httpfeed lists changes from a read-only HTTP JSON feed.
package httpfeed

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/changes"
	"golang.org/x/net/http/httpguts"
)

func init() { plugin.Register(Module{}) }

type Module struct {
	URL              string        `yaml:"url"`
	CredentialRef    string        `yaml:"credential_ref"`
	AuthHeader       string        `yaml:"auth_header"`
	AuthScheme       string        `yaml:"auth_scheme"`
	CacheTTL         time.Duration `yaml:"cache_ttl"`
	MaxResponseBytes int64         `yaml:"max_response_bytes"`

	endpoint *url.URL
	host     plugin.Host
}

func (Module) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "changes.http", New: func() plugin.Module { return new(Module) }}
}

func (m *Module) Validate() error {
	u, err := url.Parse(m.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("url must be an absolute HTTP or HTTPS URL without user information or fragments")
	}
	if m.CredentialRef != "" && u.Scheme != "https" {
		return errors.New("url must use HTTPS with credential_ref")
	}
	switch strings.ToLower(m.AuthHeader) {
	case "accept", "host", "content-length", "transfer-encoding":
		return errors.New("auth_header is reserved")
	}
	if m.AuthHeader != "" && !httpguts.ValidHeaderFieldName(m.AuthHeader) {
		return errors.New("invalid auth_header")
	}
	if m.AuthScheme != "" && !httpguts.ValidHeaderFieldName(m.AuthScheme) {
		return errors.New("invalid auth_scheme")
	}
	if m.CacheTTL < 0 || m.CacheTTL > 10*time.Minute {
		return errors.New("cache_ttl must be between 0 and 10 minutes")
	}
	if m.MaxResponseBytes < 0 || m.MaxResponseBytes > 16<<20 {
		return errors.New("max_response_bytes must be between 0 and 16 MiB")
	}
	return nil
}

func (m *Module) Provision(_ context.Context, h plugin.Host) error {
	if err := m.Validate(); err != nil {
		return err
	}
	m.endpoint, _ = url.Parse(m.URL)
	if m.AuthHeader == "" {
		m.AuthHeader = "Authorization"
	}
	if m.AuthScheme == "" {
		m.AuthScheme = "Bearer"
	}
	if m.CacheTTL == 0 {
		m.CacheTTL = 30 * time.Second
	}
	if m.MaxResponseBytes == 0 {
		m.MaxResponseBytes = 4 << 20
	}
	m.host = h
	return nil
}

type feedChange struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Service string    `json:"service"`
	Summary string    `json:"summary"`
	Actor   string    `json:"actor"`
	Ref     string    `json:"ref"`
}

func (m *Module) List(ctx context.Context, q changes.Query) (changes.ListResult, error) {
	if err := ctx.Err(); err != nil {
		return changes.ListResult{}, err
	}
	limit := q.MaxItems
	if limit <= 0 {
		limit = 1000
	}
	endpoint := *m.endpoint
	endpoint.RawQuery = url.Values{
		"from":  {q.From.UTC().Format(time.RFC3339Nano)},
		"to":    {q.To.UTC().Format(time.RFC3339Nano)},
		"limit": {strconv.Itoa(limit)},
	}.Encode()
	cache := m.host.Cache()
	var result changes.ListResult
	if data, ok := cache.Get(endpoint.RawQuery); ok && json.Unmarshal(data, &result) == nil {
		return result, nil
	}
	body, err := m.fetch(ctx, endpoint.String())
	if err != nil {
		return changes.ListResult{}, err
	}
	var feed struct {
		Changes *[]feedChange `json:"changes"`
		HasMore *bool         `json:"has_more"`
	}
	if err := json.Unmarshal(body, &feed, json.RejectUnknownMembers(true)); err != nil || feed.Changes == nil || feed.HasMore == nil {
		return changes.ListResult{}, errors.New("invalid change feed response")
	}
	result = changes.ListResult{Changes: make([]changes.Change, 0, min(len(*feed.Changes), limit)), HasMore: *feed.HasMore}
	for _, item := range *feed.Changes {
		if item.At.IsZero() || item.At.Before(q.From) || item.At.After(q.To) {
			continue
		}
		result.Changes = append(result.Changes, changes.Change{
			At: item.At.UTC(), Kind: item.Kind, Service: item.Service, Summary: item.Summary, Actor: item.Actor, Ref: item.Ref,
		})
	}
	slices.SortStableFunc(result.Changes, func(a, b changes.Change) int { return b.At.Compare(a.At) })
	if len(result.Changes) > limit {
		result.Changes = result.Changes[:limit]
		result.HasMore = true
	}
	if data, err := json.Marshal(result); err == nil {
		cache.Set(endpoint.RawQuery, data, m.CacheTTL)
	}
	return result, nil
}

func (m *Module) fetch(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("change feed request invalid")
	}
	req.Header.Set("Accept", "application/json")
	if m.CredentialRef != "" {
		data, err := m.host.Credential(m.CredentialRef)
		credential := strings.TrimSpace(string(data))
		if err != nil || credential == "" || !httpguts.ValidHeaderFieldValue(credential) {
			return nil, errors.New("change feed credential unavailable")
		}
		req.Header.Set(m.AuthHeader, m.AuthScheme+" "+credential)
	}
	resp, err := m.host.HTTPClient().Do(req)
	if err != nil {
		return nil, errors.New("change feed request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("change feed returned an unsuccessful HTTP status")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, m.MaxResponseBytes+1))
	if err != nil {
		return nil, errors.New("change feed response read failed")
	}
	if int64(len(body)) > m.MaxResponseBytes {
		return nil, errors.New("change feed response exceeds max_response_bytes")
	}
	return body, nil
}
