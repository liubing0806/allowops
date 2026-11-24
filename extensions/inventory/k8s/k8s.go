// Package k8s resolves inventory from Kubernetes workloads and running Pods.
package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
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
	APIServer        string        `yaml:"api_server"`
	CredentialRef    string        `yaml:"credential_ref"`
	Namespaces       []string      `yaml:"namespaces"`
	Cluster          string        `yaml:"cluster"`
	Workloads        []string      `yaml:"workloads"`
	EntityKind       string        `yaml:"entity_kind"`
	IncludePods      *bool         `yaml:"include_pods"`
	LabelAllowlist   []string      `yaml:"label_allowlist"`
	SelectorLabel    string        `yaml:"selector_label"`
	CacheTTL         time.Duration `yaml:"cache_ttl"`
	MaxResponseBytes int64         `yaml:"max_response_bytes"`

	host   plugin.Host
	server *url.URL
}

func (Module) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "inventory.k8s", New: func() plugin.Module { return &Module{} }}
}

var (
	namespacePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	kindPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	attrPattern      = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	bearerPattern    = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)
	workloadPaths    = map[string]string{"deployment": "deployments", "statefulset": "statefulsets", "daemonset": "daemonsets"}
	errCredential    = errors.New("kubernetes inventory: credential unavailable or invalid")
	errRequest       = errors.New("kubernetes inventory: request failed")
	errResponse      = errors.New("kubernetes inventory: invalid response")
	errResponseSize  = errors.New("kubernetes inventory: response exceeds max_response_bytes")
)

func (m *Module) Validate() error {
	server, err := url.Parse(m.APIServer)
	if err != nil || server.Hostname() == "" || server.User != nil || server.Fragment != "" ||
		(server.Scheme != "http" && server.Scheme != "https") {
		return errors.New("kubernetes inventory: api_server must be an HTTP(S) URL")
	}
	if m.CredentialRef != "" && server.Scheme != "https" {
		return errors.New("kubernetes inventory: api_server must use HTTPS with credential_ref")
	}
	if len(m.Namespaces) < 1 || len(m.Namespaces) > 64 {
		return errors.New("kubernetes inventory: namespaces must contain 1 to 64 entries")
	}
	for _, ns := range m.Namespaces {
		if !namespacePattern.MatchString(ns) {
			return errors.New("kubernetes inventory: namespace must be a DNS-1123 label")
		}
	}
	for _, kind := range m.Workloads {
		if workloadPaths[kind] == "" {
			return errors.New("kubernetes inventory: invalid workload kind")
		}
	}
	if m.EntityKind != "" && !kindPattern.MatchString(m.EntityKind) {
		return errors.New("kubernetes inventory: invalid entity_kind")
	}
	if m.CacheTTL < 0 || m.CacheTTL > 10*time.Minute {
		return errors.New("kubernetes inventory: invalid cache_ttl")
	}
	if m.MaxResponseBytes < 0 || m.MaxResponseBytes > 16<<20 {
		return errors.New("kubernetes inventory: invalid max_response_bytes")
	}
	return nil
}

func (m *Module) Provision(_ context.Context, h plugin.Host) error {
	if err := m.Validate(); err != nil {
		return err
	}
	m.server, _ = url.Parse(m.APIServer)
	m.host = h
	m.Namespaces = sortedUnique(m.Namespaces)
	m.Workloads = sortedUnique(m.Workloads)
	if len(m.Workloads) == 0 {
		m.Workloads = []string{"deployment", "statefulset", "daemonset"}
	}
	m.LabelAllowlist = sortedUnique(m.LabelAllowlist)
	if m.CacheTTL == 0 {
		m.CacheTTL = 30 * time.Second
	}
	if m.MaxResponseBytes == 0 {
		m.MaxResponseBytes = 4 << 20
	}
	return nil
}

func sortedUnique(values []string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	return slices.Compact(out)
}

type metadata struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

type workload struct {
	Metadata metadata `json:"metadata"`
	Spec     struct {
		Selector labelSelector `json:"selector"`
	} `json:"spec"`
}

type pod struct {
	Metadata metadata `json:"metadata"`
	Spec     struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
}

type labelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values"`
	} `json:"matchExpressions"`
}

func (s labelSelector) matches(labels map[string]string) bool {
	if len(s.MatchLabels)+len(s.MatchExpressions) == 0 {
		return false
	}
	for key, value := range s.MatchLabels {
		if label, exists := labels[key]; !exists || label != value {
			return false
		}
	}
	for _, expr := range s.MatchExpressions {
		value, exists := labels[expr.Key]
		switch expr.Operator {
		case "In":
			if !exists || !slices.Contains(expr.Values, value) {
				return false
			}
		case "NotIn":
			if len(expr.Values) == 0 || exists && slices.Contains(expr.Values, value) {
				return false
			}
		case "Exists":
			if len(expr.Values) != 0 || !exists {
				return false
			}
		case "DoesNotExist":
			if len(expr.Values) != 0 || exists {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (m *Module) Resolve(ctx context.Context, q inventory.Query) ([]inventory.Entity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	const key = "entities"
	cache := m.host.Cache()
	var entities []inventory.Entity
	data, ok := cache.Get(key)
	if !ok || json.Unmarshal(data, &entities) != nil {
		var err error
		entities, err = m.fetch(ctx)
		if err != nil {
			return nil, err
		}
		if data, err = json.Marshal(entities); err == nil {
			cache.Set(key, data, m.CacheTTL)
		}
	}
	if q.Kind != "" {
		entities = slices.DeleteFunc(entities, func(e inventory.Entity) bool { return e.Kind != q.Kind })
	}
	return entities, nil
}

func (m *Module) fetch(ctx context.Context) ([]inventory.Entity, error) {
	var authorization string
	if m.CredentialRef != "" {
		value, err := m.host.Credential(m.CredentialRef)
		if err != nil {
			return nil, errCredential
		}
		token := strings.TrimSpace(string(value))
		if strings.HasPrefix(token, "{") {
			var credential struct {
				BearerToken string `json:"bearer_token"`
			}
			if json.Unmarshal([]byte(token), &credential) != nil {
				return nil, errCredential
			}
			token = credential.BearerToken
		}
		if !bearerPattern.MatchString(token) {
			return nil, errCredential
		}
		authorization = "Bearer " + token
	}

	out := []inventory.Entity{}
	for _, ns := range m.Namespaces {
		var pods []pod
		if m.IncludePods == nil || *m.IncludePods {
			endpoint := m.server.JoinPath("api", "v1", "namespaces", ns, "pods")
			query := endpoint.Query()
			query.Set("fieldSelector", "status.phase=Running")
			endpoint.RawQuery = query.Encode()
			var err error
			pods, err = getItems[pod](ctx, m, endpoint, authorization)
			if err != nil {
				return nil, err
			}
		}
		var entries []inventory.Entity
		counts := make(map[string]int)
		for _, kind := range m.Workloads {
			endpoint := m.server.JoinPath("apis", "apps", "v1", "namespaces", ns, workloadPaths[kind])
			items, err := getItems[workload](ctx, m, endpoint, authorization)
			if err != nil {
				return nil, err
			}
			for _, item := range items {
				name := ns + "/" + item.Metadata.Name
				if item.Metadata.Name == "" {
					return nil, errResponse
				}
				counts[name]++
				entries = append(entries, m.entity(kind, name, item, pods))
			}
		}
		for _, entry := range entries {
			if m.EntityKind != "" {
				if counts[entry.Name] > 1 {
					entry.Name += "/" + entry.Kind
				}
				entry.Kind = m.EntityKind
			}
			out = append(out, entry)
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

func (m *Module) entity(kind, name string, item workload, pods []pod) inventory.Entity {
	e := inventory.Entity{Kind: kind, Name: name, Attrs: map[string]string{}}
	labels := item.Metadata.Labels
	for _, key := range m.LabelAllowlist {
		value, exists := labels[key]
		attr := strings.ReplaceAll(key, "/", "_")
		if _, set := e.Attrs[attr]; exists && !set && attrPattern.MatchString(attr) {
			e.Attrs[attr] = value
		}
	}
	if m.Cluster != "" {
		e.Attrs["cluster"] = m.Cluster
	}
	if key := m.SelectorLabel; key != "" {
		value := labels[key]
		attr := strings.ReplaceAll(key, "/", "_")
		if value != "" && attrPattern.MatchString(attr) && !strings.ContainsAny(value, ",=\r\n") && strings.TrimSpace(value) == value {
			e.Selector = attr + "=" + value
		}
	}

	nodes := make(map[string]struct{})
	for _, pod := range pods {
		if node := pod.Spec.NodeName; node != "" && item.Spec.Selector.matches(pod.Metadata.Labels) {
			nodes[node] = struct{}{}
		}
	}
	if len(nodes) > 0 {
		e.Hosts = slices.Sorted(maps.Keys(nodes))
	}
	return e
}

func getItems[T any](ctx context.Context, m *Module, endpoint *url.URL, authorization string) ([]T, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errRequest
	}
	req.Header.Set("Accept", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
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
		Items []T `json:"items"`
	}
	if json.Unmarshal(data, &payload) != nil || payload.Items == nil {
		return nil, errResponse
	}
	return payload.Items, nil
}
