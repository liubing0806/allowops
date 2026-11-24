// Package hostlabels derives inventory from current active host labels.
package hostlabels

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/inventory"
)

func init() { plugin.Register(Module{}) }

var attrKey = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

type Module struct {
	Label string `yaml:"label"`
	Kind  string `yaml:"kind"`
	host  plugin.Host
}

func (Module) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "inventory.host_labels", New: func() plugin.Module { return &Module{} }}
}

func (m *Module) Provision(ctx context.Context, h plugin.Host) error {
	if m.Label == "" {
		return fmt.Errorf("label required")
	}
	// The label is returned as an attribute, so the gateway redacts the value
	// with its key; the key must therefore be a valid attribute key.
	if !attrKey.MatchString(strings.TrimPrefix(m.Label, "reported.")) {
		return fmt.Errorf("label must match %s", attrKey)
	}
	if m.Kind == "" {
		m.Kind = "service"
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`).MatchString(m.Kind) {
		return fmt.Errorf("invalid inventory kind")
	}
	m.host = h
	return nil
}

func (m *Module) Resolve(ctx context.Context, q inventory.Query) ([]inventory.Entity, error) {
	hosts, err := m.host.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	groups := map[string][]string{}
	for _, h := range hosts {
		labels, key := h.Labels, m.Label
		if strings.HasPrefix(key, "reported.") {
			labels = h.ReportedLabels
			key = strings.TrimPrefix(key, "reported.")
		}
		if value, ok := labels[key]; ok {
			groups[value] = append(groups[value], h.Hostname)
		}
	}
	out := []inventory.Entity{}
	if q.Kind != "" && q.Kind != m.Kind {
		return out, nil
	}
	for value, hosts := range groups {
		slices.Sort(hosts)
		// The attribute gives the gateway the label key, so it can tell
		// whether the value is a credential.
		e := inventory.Entity{Kind: m.Kind, Name: value, Hosts: hosts, Attrs: map[string]string{strings.TrimPrefix(m.Label, "reported."): value}}
		if !strings.ContainsAny(value, ",=") && strings.TrimSpace(value) == value {
			e.Selector = m.Label + "=" + value
		}
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b inventory.Entity) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
