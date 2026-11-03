package api

import (
	"context"
	"encoding/json"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
)

// VisibleHostnames returns requested active hostnames the caller may view.
func (s *Service) VisibleHostnames(ctx context.Context, names []string) (map[string]bool, error) {
	visible := map[string]bool{}
	hosts, err := activeHostLabels(ctx, s.Store.Pool)
	if err != nil {
		return nil, dbError(err)
	}
	requested := map[string]bool{}
	for _, name := range names {
		requested[name] = true
	}
	for _, h := range hosts {
		if !requested[h.Hostname] {
			continue
		}
		var labels map[string]string
		if err := json.Unmarshal(h.AuthorizationLabels, &labels); err != nil {
			return nil, dbError(err)
		}
		ok, err := s.can(ctx, authz.ViewHosts, authz.Action{}, hostAttributes(&v1.Host{HostId: h.HostID, AuthorizationLabels: labels}))
		if err != nil {
			return nil, err
		}
		if ok {
			visible[h.Hostname] = true
		}
	}
	return visible, nil
}

// ConfigurePluginHealth is called during startup before serving requests.
func (s *Service) ConfigurePluginHealth(health func() []pluginhost.Health) { s.pluginHealth = health }
