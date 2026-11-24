// Package promtargets resolves inventory from active Prometheus targets.
package promtargets

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
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
	Address          string        `yaml:"address"`
	CredentialRef    string        `yaml:"credential_ref"`
	Kind             string        `yaml:"kind"`
	NameLabel        string        `yaml:"name_label"`
	HostLabel        string        `yaml:"host_label"`
	Cluster          string        `yaml:"cluster"`
	LabelAllowlist   []string      `yaml:"label_allowlist"`
	CacheTTL         time.Duration `yaml:"cache_ttl"`
	MaxResponseBytes int64         `yaml:"max_response_bytes"`

	host     plugin.Host
	endpoint string
}

func (Module) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "inventory.prometheus_targets", New: func() plugin.Module { return &Module{} }}
}

var (
	kindPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	attrPattern     = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	bearerPattern   = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)
	errCredential   = errors.New("prometheus inventory: credential unavailable or invalid")
	errRequest      = errors.New("prometheus inventory: request failed")
	errResponse     = errors.New("prometheus inventory: invalid response")
	errResponseSize = errors.New("prometheus inventory: response exceeds max_response_bytes")
)

func (m *Module) Validate() error {
	address, err := url.Parse(m.Address)
	if err != nil || address.Hostname() == "" || address.User != nil || address.Fragment != "" ||
		(address.Scheme != "http" && address.Scheme != "https") {
		return errors.New("prometheus inventory: address must be an HTTP(S) URL")
	}
	if m.CredentialRef != "" && address.Scheme != "https" {
		return errors.New("prometheus inventory: address must use HTTPS with credential_ref")
	}
	if m.Kind != "" && !kindPattern.MatchString(m.Kind) {
		return errors.New("prometheus inventory: invalid kind")
	}
	if m.NameLabel != "" && !attrPattern.MatchString(m.NameLabel) {
		return errors.New("prometheus inventory: invalid name_label")
	}
	for _, label := range m.LabelAllowlist {
		if !attrPattern.MatchString(label) {
			return errors.New("prometheus inventory: invalid label_allowlist key")
		}
	}
	if m.CacheTTL < 0 || m.CacheTTL > 10*time.Minute {
		return errors.New("prometheus inventory: invalid cache_ttl")
	}
	if m.MaxResponseBytes < 0 || m.MaxResponseBytes > 16<<20 {
		return errors.New("prometheus inventory: invalid max_response_bytes")
	}
	return nil
}

func (m *Module) Provision(_ context.Context, h plugin.Host) error {
	if err := m.Validate(); err != nil {
		return err
	}
	address, _ := url.Parse(m.Address)
	endpoint := address.JoinPath("api", "v1", "targets")
	query := endpoint.Query()
	query.Set("state", "active")
	endpoint.RawQuery = query.Encode()
	m.endpoint = endpoint.String()
	m.host = h
	if m.Kind == "" {
		m.Kind = "service"
	}
	if m.NameLabel == "" {
		m.NameLabel = "job"
	}
	if m.HostLabel == "" {
		m.HostLabel = "instance"
	}
	if m.CacheTTL == 0 {
		m.CacheTTL = 30 * time.Second
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
	if q.Kind != "" && q.Kind != m.Kind {
		return []inventory.Entity{}, nil
	}
	const key = "entities"
	cache := m.host.Cache()
	var entities []inventory.Entity
	if data, ok := cache.Get(key); ok && json.Unmarshal(data, &entities) == nil {
		return entities, nil
	}
	entities, err := m.fetch(ctx)
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
	if err != nil {
		return errCredential
	}
	token := strings.TrimSpace(string(value))
	if strings.HasPrefix(token, "{") {
		var credential struct {
			BearerToken string  `json:"bearer_token"`
			Username    *string `json:"username"`
			Password    *string `json:"password"`
		}
		if json.Unmarshal([]byte(token), &credential) != nil {
			return errCredential
		}
		if credential.Username != nil || credential.Password != nil {
			if credential.BearerToken != "" || credential.Username == nil || credential.Password == nil ||
				*credential.Username == "" || strings.Contains(*credential.Username, ":") {
				return errCredential
			}
			req.SetBasicAuth(*credential.Username, *credential.Password)
			return nil
		}
		token = credential.BearerToken
	}
	if !bearerPattern.MatchString(token) {
		return errCredential
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (m *Module) fetch(ctx context.Context) ([]inventory.Entity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.endpoint, nil)
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
		Status string `json:"status"`
		Data   struct {
			ActiveTargets []struct {
				Labels map[string]string `json:"labels"`
			} `json:"activeTargets"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &payload) != nil || payload.Status != "success" || payload.Data.ActiveTargets == nil {
		return nil, errResponse
	}

	type targetGroup struct {
		entity    inventory.Entity
		hosts     map[string]struct{}
		conflicts map[string]bool
	}
	groups := make(map[string]*targetGroup)
	for _, target := range payload.Data.ActiveTargets {
		name := target.Labels[m.NameLabel]
		if name == "" {
			continue
		}
		group := groups[name]
		if group == nil {
			group = &targetGroup{
				entity:    inventory.Entity{Kind: m.Kind, Name: name, Attrs: make(map[string]string)},
				hosts:     make(map[string]struct{}),
				conflicts: make(map[string]bool),
			}
			groups[name] = group
		}
		host := target.Labels[m.HostLabel]
		if m.HostLabel == "instance" {
			if hostname, _, err := net.SplitHostPort(host); err == nil {
				host = hostname
			}
		}
		if host != "" {
			group.hosts[host] = struct{}{}
		}
		for _, label := range m.LabelAllowlist {
			value, exists := target.Labels[label]
			if !exists || group.conflicts[label] {
				continue
			}
			if previous, set := group.entity.Attrs[label]; set && previous != value {
				delete(group.entity.Attrs, label)
				group.conflicts[label] = true
			} else {
				group.entity.Attrs[label] = value
			}
		}
	}

	out := make([]inventory.Entity, 0, len(groups))
	for _, name := range slices.Sorted(maps.Keys(groups)) {
		group := groups[name]
		if len(group.hosts) > 0 {
			group.entity.Hosts = slices.Sorted(maps.Keys(group.hosts))
		}
		if m.Cluster != "" {
			group.entity.Attrs["cluster"] = m.Cluster
		}
		group.entity.Attrs[m.NameLabel] = name
		out = append(out, group.entity)
	}
	return out, nil
}
