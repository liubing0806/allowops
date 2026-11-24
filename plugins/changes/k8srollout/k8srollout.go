// Package k8srollout lists Kubernetes workload rollout revisions.
package k8srollout

import (
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
	"unicode/utf8"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/changes"
	"golang.org/x/net/http/httpguts"
)

func init() { plugin.Register(Module{}) }

type Module struct {
	APIServer        string        `yaml:"api_server"`
	CredentialRef    string        `yaml:"credential_ref"`
	Namespaces       []string      `yaml:"namespaces"`
	Cluster          string        `yaml:"cluster"`
	CacheTTL         time.Duration `yaml:"cache_ttl"`
	MaxResponseBytes int64         `yaml:"max_response_bytes"`

	endpoint *url.URL
	host     plugin.Host
}

func (Module) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "changes.k8s_rollout", New: func() plugin.Module { return new(Module) }}
}

var namespaceName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func (m *Module) Validate() error {
	u, err := url.Parse(m.APIServer)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("api_server must be an absolute HTTP or HTTPS URL without user information, query or fragment")
	}
	if m.CredentialRef != "" && u.Scheme != "https" {
		return errors.New("api_server must use HTTPS with credential_ref")
	}
	if len(m.Namespaces) < 1 || len(m.Namespaces) > 64 {
		return errors.New("namespaces must contain 1 to 64 entries")
	}
	for _, namespace := range m.Namespaces {
		if !namespaceName.MatchString(namespace) {
			return errors.New("invalid Kubernetes namespace")
		}
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
	m.endpoint, _ = url.Parse(m.APIServer)
	if m.CacheTTL == 0 {
		m.CacheTTL = 30 * time.Second
	}
	if m.MaxResponseBytes == 0 {
		m.MaxResponseBytes = 4 << 20
	}
	m.host = h
	return nil
}

var rolloutResources = []struct{ resource, kind string }{
	{"replicasets", "ReplicaSet"},
	{"controllerrevisions", "ControllerRevision"},
}

func (m *Module) List(ctx context.Context, q changes.Query) (changes.ListResult, error) {
	limit := q.MaxItems
	if limit <= 0 {
		limit = 1000
	}
	var result changes.ListResult
	newestFirst := func(a, b changes.Change) int { return b.At.Compare(a.At) }
	namespaces := make(map[string]bool, len(m.Namespaces))
	for _, namespace := range m.Namespaces {
		if namespaces[namespace] {
			continue
		}
		namespaces[namespace] = true
		for _, r := range rolloutResources {
			page, err := m.listResource(ctx, namespace, r.resource, r.kind)
			if err != nil {
				return changes.ListResult{}, err
			}
			result.HasMore = result.HasMore || page.HasMore
			for _, item := range page.Changes {
				if !item.At.Before(q.From) && !item.At.After(q.To) {
					result.Changes = append(result.Changes, item)
				}
			}
			if len(result.Changes) > limit {
				slices.SortStableFunc(result.Changes, newestFirst)
				result.Changes = result.Changes[:limit]
				result.HasMore = true
			}
		}
	}
	slices.SortStableFunc(result.Changes, newestFirst)
	return result, nil
}

type imageContainer struct {
	Image string `json:"image"`
}

type podTemplate struct {
	Spec struct {
		Template struct {
			Spec struct {
				Containers     []imageContainer `json:"containers"`
				InitContainers []imageContainer `json:"initContainers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

type rollout struct {
	Metadata struct {
		Name              string    `json:"name"`
		CreationTimestamp time.Time `json:"creationTimestamp"`
		Owners            []struct {
			Kind       string `json:"kind"`
			Name       string `json:"name"`
			Controller bool   `json:"controller"`
		} `json:"ownerReferences"`
		Annotations struct {
			Revision string `json:"deployment.kubernetes.io/revision"`
		} `json:"annotations"`
	} `json:"metadata"`
	podTemplate
	Data json.RawMessage `json:"data"`
}

func (m *Module) listResource(ctx context.Context, namespace, resource, kind string) (changes.ListResult, error) {
	if err := ctx.Err(); err != nil {
		return changes.ListResult{}, err
	}
	endpoint := m.endpoint.JoinPath("apis", "apps", "v1", "namespaces", namespace, resource)
	cache := m.host.Cache()
	var page changes.ListResult
	if data, ok := cache.Get(endpoint.Path); ok && json.Unmarshal(data, &page) == nil {
		return page, nil
	}
	body, err := m.fetch(ctx, endpoint.String())
	if err != nil {
		return changes.ListResult{}, err
	}
	var response struct {
		Metadata struct {
			Continue string `json:"continue"`
		} `json:"metadata"`
		Items []rollout `json:"items"`
	}
	if err := json.Unmarshal(body, &response); err != nil || response.Items == nil {
		return changes.ListResult{}, errors.New("invalid Kubernetes rollout response")
	}
	page.HasMore = response.Metadata.Continue != ""
	for _, item := range response.Items {
		change, ok, err := m.change(item, namespace, kind)
		if err != nil {
			return changes.ListResult{}, err
		}
		if ok {
			page.Changes = append(page.Changes, change)
		}
	}
	if data, err := json.Marshal(page); err == nil {
		cache.Set(endpoint.Path, data, m.CacheTTL)
	}
	return page, nil
}

func (m *Module) change(item rollout, namespace, kind string) (changes.Change, bool, error) {
	meta := item.Metadata
	if meta.Name == "" || meta.CreationTimestamp.IsZero() {
		return changes.Change{}, false, nil
	}
	var ownerKind, ownerName string
	for _, owner := range meta.Owners {
		if owner.Name == "" || !slices.Contains([]string{"Deployment", "StatefulSet", "DaemonSet"}, owner.Kind) {
			continue
		}
		if ownerName == "" || owner.Controller {
			ownerKind, ownerName = owner.Kind, owner.Name
		}
		if owner.Controller {
			break
		}
	}
	if ownerName == "" {
		return changes.Change{}, false, nil
	}
	template := item.podTemplate
	if len(item.Data) > 0 && kind == "ControllerRevision" {
		if err := json.Unmarshal(item.Data, &template); err != nil {
			return changes.Change{}, false, errors.New("invalid Kubernetes rollout response")
		}
	}
	pod := template.Spec.Template.Spec
	var images []string
	for _, containers := range [][]imageContainer{pod.Containers, pod.InitContainers} {
		for _, c := range containers {
			if c.Image != "" {
				images = append(images, c.Image)
			}
		}
	}
	summary := ownerKind + " " + ownerName + " rollout"
	if meta.Annotations.Revision != "" {
		summary += " revision " + meta.Annotations.Revision
	}
	if len(images) > 0 {
		summary += " (images: " + strings.Join(images, ", ") + ")"
	}
	summary = strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ").Replace(summary)
	if len(summary) > 512 {
		end := 512
		for !utf8.RuneStart(summary[end]) {
			end--
		}
		summary = summary[:end]
	}
	ref := namespace + "/" + kind + "/" + meta.Name
	if m.Cluster != "" {
		ref = m.Cluster + "/" + ref
	}
	return changes.Change{
		At: meta.CreationTimestamp.UTC(), Kind: "rollout", Service: namespace + "/" + ownerName,
		Summary: summary, Ref: "k8s:" + ref,
	}, true, nil
}

func (m *Module) fetch(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("Kubernetes rollout request invalid")
	}
	req.Header.Set("Accept", "application/json")
	if m.CredentialRef != "" {
		data, err := m.host.Credential(m.CredentialRef)
		token := strings.TrimSpace(string(data))
		if err != nil || token == "" || !httpguts.ValidHeaderFieldValue(token) {
			return nil, errors.New("Kubernetes rollout credential unavailable")
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := m.host.HTTPClient().Do(req)
	if err != nil {
		return nil, errors.New("Kubernetes rollout request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("Kubernetes rollout returned an unsuccessful HTTP status")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, m.MaxResponseBytes+1))
	if err != nil {
		return nil, errors.New("Kubernetes rollout response read failed")
	}
	if int64(len(body)) > m.MaxResponseBytes {
		return nil, errors.New("Kubernetes rollout response exceeds max_response_bytes")
	}
	return body, nil
}
