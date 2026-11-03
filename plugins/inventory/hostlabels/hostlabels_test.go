package hostlabels

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"testing"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/inventory"
)

type testHost struct {
	hosts []plugin.HostInfo
	err   error
}

func (testHost) InstanceID() string                                 { return "test" }
func (testHost) Logger() *slog.Logger                               { return slog.Default() }
func (h testHost) Hosts(context.Context) ([]plugin.HostInfo, error) { return h.hosts, h.err }

func TestLabelSourcesAndGrouping(t *testing.T) {
	hosts := []plugin.HostInfo{
		{Hostname: "b", Labels: map[string]string{"service": "API"}, ReportedLabels: map[string]string{"service": "db"}},
		{Hostname: "a", Labels: map[string]string{"service": "API"}}, {Hostname: "no-label"},
	}
	for _, label := range []string{"service", "reported.service"} {
		t.Run(label, func(t *testing.T) {
			m := &Module{Label: label}
			if err := m.Provision(context.Background(), testHost{hosts: hosts}); err != nil {
				t.Fatal(err)
			}
			got, err := m.Resolve(context.Background(), inventory.Query{})
			name, wantHosts := "API", []string{"a", "b"}
			if label == "reported.service" {
				name, wantHosts = "db", []string{"b"}
			}
			if err != nil || len(got) != 1 || got[0].Kind != "service" || got[0].Name != name || !reflect.DeepEqual(got[0].Hosts, wantHosts) || got[0].Selector != label+"="+name {
				t.Fatalf("%+v %v", got, err)
			}
			got, _ = m.Resolve(context.Background(), inventory.Query{Kind: "other"})
			if len(got) != 0 {
				t.Fatal(got)
			}
			got, _ = m.Resolve(context.Background(), inventory.Query{Name: "absent"})
			if len(got) != 0 {
				t.Fatal(got)
			}
		})
	}
}
func TestUnsafeSelectors(t *testing.T) {
	for _, label := range []string{"service", "bad,key", "bad=key", " key", "key "} {
		for _, value := range []string{"normal", "a,b", "a=b", " leading", "trailing "} {
			m := &Module{Label: label, Kind: "database"}
			if err := m.Provision(context.Background(), testHost{hosts: []plugin.HostInfo{{Hostname: "host", Labels: map[string]string{label: value}}}}); err != nil {
				t.Fatal(err)
			}
			got, err := m.Resolve(context.Background(), inventory.Query{})
			if err != nil || len(got) != 1 || len(got[0].Hosts) != 1 {
				t.Fatalf("%+v %v", got, err)
			}
			if label == "service" && value == "normal" {
				if got[0].Selector != "service=normal" {
					t.Fatal(got)
				}
			} else if got[0].Selector != "" {
				t.Fatalf("unsafe selector: %+v", got)
			}
		}
	}
}
func TestProvisionAndHostErrors(t *testing.T) {
	for _, m := range []*Module{{}, {Label: "service", Kind: "bad-kind"}} {
		if err := m.Provision(context.Background(), testHost{}); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
	m := &Module{Label: "service"}
	_ = m.Provision(context.Background(), testHost{err: errors.New("failed")})
	if _, err := m.Resolve(context.Background(), inventory.Query{}); err == nil {
		t.Fatal("host error lost")
	}
}
