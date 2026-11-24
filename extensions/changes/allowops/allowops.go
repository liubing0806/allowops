// Package allowops lists catalog publications and policy changes.
package allowops

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/changes"
)

func init() { plugin.Register(Module{}) }

type Module struct {
	IncludeCatalog *bool `yaml:"include_catalog"`
	IncludePolicy  *bool `yaml:"include_policy"`
	reader         plugin.ControlPlaneChangeReader
}

func (Module) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "changes.allowops", New: func() plugin.Module { return new(Module) }}
}

func (m *Module) Validate() error {
	if !enabled(m.IncludeCatalog) && !enabled(m.IncludePolicy) {
		return errors.New("include_catalog and include_policy cannot both be disabled")
	}
	return nil
}

func (m *Module) Provision(_ context.Context, h plugin.Host) error {
	reader, ok := h.(plugin.ControlPlaneChangeReader)
	if !ok {
		return errors.New("control plane change reader unavailable")
	}
	m.reader = reader
	return nil
}

func (m *Module) List(ctx context.Context, q changes.Query) (changes.ListResult, error) {
	if err := ctx.Err(); err != nil {
		return changes.ListResult{}, err
	}
	limit := 1000
	if q.MaxItems > 0 {
		limit = min(q.MaxItems, limit)
	}
	rows, hasMore, err := m.reader.ListControlPlaneChanges(ctx, q.From, q.To, limit)
	if err != nil {
		return changes.ListResult{}, errors.New("control plane change history unavailable")
	}
	result := changes.ListResult{HasMore: hasMore}
	for _, row := range rows {
		if row.At.Before(q.From) || row.At.After(q.To) {
			continue
		}
		switch row.Kind {
		case "catalog":
			if !enabled(m.IncludeCatalog) {
				continue
			}
			result.Changes = append(result.Changes, changes.Change{
				At: row.At.UTC(), Kind: "catalog", Service: row.CatalogID,
				Summary: fmt.Sprintf("catalog %s v%d published (%d actions)", row.CatalogID, row.Version, row.ActionCount),
				Ref:     fmt.Sprintf("catalog:%s@v%d", row.CatalogID, row.Version),
			})
		case "policy":
			if !enabled(m.IncludePolicy) {
				continue
			}
			result.Changes = append(result.Changes, changes.Change{
				At: row.At.UTC(), Kind: "policy", Service: "allowops-policy", Actor: row.Actor,
				Summary: policySummary(row), Ref: fmt.Sprintf("policy:v%d", row.Version),
			})
		}
	}
	slices.SortStableFunc(result.Changes, func(a, b changes.Change) int { return b.At.Compare(a.At) })
	if len(result.Changes) > limit {
		result.Changes = result.Changes[:limit]
		result.HasMore = true
	}
	return result, nil
}

func enabled(setting *bool) bool { return setting == nil || *setting }

var policyLineBreaks = strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ")

func policySummary(row plugin.ControlPlaneChange) string {
	summary := fmt.Sprintf("policy v%d applied", row.Version)
	if row.RolledBackFrom > 0 {
		summary = fmt.Sprintf("policy v%d rolled back from v%d", row.Version, row.RolledBackFrom)
	}
	if row.Reason != "" {
		summary += ": " + policyLineBreaks.Replace(row.Reason)
	}
	const maxBytes = 512
	if len(summary) > maxBytes {
		end := maxBytes
		for !utf8.RuneStart(summary[end]) {
			end--
		}
		summary = summary[:end]
	}
	return summary
}
