package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/liubing0806/allowops/extensions/inventory/hostlabels"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/inventory"
)

type inventoryHosts []plugin.HostInfo

func (inventoryHosts) HTTPClient() *http.Client { return nil }
func (inventoryHosts) Credential(string) ([]byte, error) {
	return nil, errors.New("plugin credential: unavailable")
}
func (inventoryHosts) Cache() plugin.Cache { return nil }
func (inventoryHosts) Now() time.Time      { return time.Now().UTC() }

func (inventoryHosts) InstanceID() string                                 { return "test" }
func (inventoryHosts) Logger() *slog.Logger                               { return slog.Default() }
func (h inventoryHosts) Hosts(context.Context) ([]plugin.HostInfo, error) { return h, nil }

func TestInventorySelectorsMatchExactlyTheirGroups(t *testing.T) {
	hosts := inventoryHosts{
		{Hostname: "a", Labels: map[string]string{"service": "api"}, ReportedLabels: map[string]string{"service": "worker"}},
		{Hostname: "b", Labels: map[string]string{"service": "api"}, ReportedLabels: map[string]string{"service": "api"}},
		{Hostname: "c", Labels: map[string]string{"service": "other"}},
		{Hostname: "unsafe", Labels: map[string]string{"service": "api,env=prod"}},
	}
	for _, label := range []string{"service", "reported.service"} {
		m := &hostlabels.Module{Label: label}
		if err := m.Provision(context.Background(), hosts); err != nil {
			t.Fatal(err)
		}
		entities, err := m.Resolve(context.Background(), inventory.Query{})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entities {
			if e.Selector == "" {
				continue
			}
			conditions, err := parseSelector(e.Selector, false)
			if err != nil {
				t.Fatal(err)
			}
			var matched []string
			for _, h := range hosts {
				if matches(&v1.Host{Hostname: h.Hostname, AuthorizationLabels: h.Labels, ReportedLabels: h.ReportedLabels}, conditions) {
					matched = append(matched, h.Hostname)
				}
			}
			slices.Sort(matched)
			if !reflect.DeepEqual(matched, e.Hosts) {
				t.Fatalf("selector %q matched %v; group %v", e.Selector, matched, e.Hosts)
			}
		}
	}
}
