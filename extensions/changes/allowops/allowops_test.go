package allowops

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/changes"
	"github.com/liubing0806/allowops/plugin/plugintest"
)

func TestListerContract(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	plugintest.RunListerContract(t, Module{}, "{}", plugintest.WithNow(now), plugintest.WithControlPlaneChanges(
		func(_ context.Context, from, to time.Time, limit int) ([]plugin.ControlPlaneChange, bool, error) {
			items := []plugin.ControlPlaneChange{
				{At: to, Kind: "catalog", Version: 3, CatalogID: "system", ActionCount: 4},
				{At: from, Kind: "policy", Version: 5, Actor: "admin"},
			}
			return items[:min(len(items), limit)], len(items) > limit, nil
		},
	))
}

func TestProvisionRequiresControlPlaneReader(t *testing.T) {
	disabled := false
	m := Module{IncludeCatalog: &disabled, IncludePolicy: &disabled}
	if err := m.Validate(); err == nil {
		t.Fatal("accepted both change categories disabled")
	}
	m = Module{}
	// Embedding the base interface hides the optional reader on TestHost.
	host := struct{ plugin.Host }{plugintest.NewHost(t)}
	if err := m.Provision(t.Context(), host); err == nil {
		t.Fatal("accepted host with no control plane change reader")
	}
}

func TestControlPlaneChanges(t *testing.T) {
	to := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	from := to.Add(-time.Hour)
	reason := "fix\r\nline\rthree\nfour " + strings.Repeat("更", 200)
	items := []plugin.ControlPlaneChange{
		{At: from, Kind: "catalog", CatalogID: "base", Version: 3, ActionCount: 17},
		{At: to, Kind: "policy", Version: 7, Actor: "admin", Reason: reason, RolledBackFrom: 5},
		{At: to, Kind: "catalog", CatalogID: "system", Version: 2, ActionCount: 1},
		{At: from, Kind: "policy", Version: 5, Actor: "alice"},
		{At: to.Add(time.Nanosecond), Kind: "policy", Version: 8},
		{At: from.Add(-time.Nanosecond), Kind: "catalog", CatalogID: "early"},
	}
	disabled := false
	for _, tc := range []struct {
		name          string
		config        Module
		max, sqlLimit int
		sourceMore    bool
		want          []string
		wantMore      bool
	}{
		{name: "defaults", sqlLimit: 1000, want: []string{"policy:v7", "catalog:system@v2", "catalog:base@v3", "policy:v5"}},
		{name: "catalog only", config: Module{IncludePolicy: &disabled}, max: 1500, sqlLimit: 1000, want: []string{"catalog:system@v2", "catalog:base@v3"}},
		{name: "policy only", config: Module{IncludeCatalog: &disabled}, max: 2, sqlLimit: 2, sourceMore: true, want: []string{"policy:v7", "policy:v5"}, wantMore: true},
		{name: "local truncation", max: 1, sqlLimit: 1, want: []string{"policy:v7"}, wantMore: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := plugintest.NewHost(t, plugintest.WithControlPlaneChanges(func(_ context.Context, start, end time.Time, limit int) ([]plugin.ControlPlaneChange, bool, error) {
				if !start.Equal(from) || !end.Equal(to) || limit != tc.sqlLimit {
					t.Fatalf("reader got [%v, %v] limit %d", start, end, limit)
				}
				return items, tc.sourceMore, nil
			}))
			m := tc.config
			if err := m.Provision(t.Context(), host); err != nil {
				t.Fatal(err)
			}
			result, err := m.List(t.Context(), changes.Query{From: from, To: to, MaxItems: tc.max})
			if err != nil || result.HasMore != tc.wantMore {
				t.Fatalf("result = %+v, error = %v", result, err)
			}
			var refs []string
			for _, item := range result.Changes {
				refs = append(refs, item.Ref)
				switch item.Ref {
				case "policy:v7":
					if item.Kind != "policy" || item.Actor != "admin" || item.Service != "allowops-policy" ||
						!strings.HasPrefix(item.Summary, "policy v7 rolled back from v5: fix line three four ") ||
						strings.ContainsAny(item.Summary, "\r\n") || !utf8.ValidString(item.Summary) || len(item.Summary) < 510 || len(item.Summary) > 512 {
						t.Fatalf("rollback = %+v", item)
					}
				case "policy:v5":
					if item.Summary != "policy v5 applied" {
						t.Fatal(item)
					}
				case "catalog:base@v3":
					if item.Kind != "catalog" || item.Service != "base" || item.Summary != "catalog base v3 published (17 actions)" {
						t.Fatal(item)
					}
				}
			}
			if !slices.Equal(refs, tc.want) {
				t.Fatalf("refs = %v, want %v", refs, tc.want)
			}
		})
	}
}
