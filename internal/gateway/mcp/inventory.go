package mcp

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
)

type inventoryEntity struct {
	Kind               string                       `json:"kind"`
	Name               string                       `json:"name"`
	Attrs              map[string]string            `json:"attrs,omitempty"`
	Hosts              []string                     `json:"hosts,omitempty"`
	HostCount          int                          `json:"host_count"`
	Selector           string                       `json:"selector,omitempty"`
	DependsOn          []string                     `json:"depends_on,omitempty"`
	Sources            []string                     `json:"sources"`
	Source             string                       `json:"source,omitempty"`
	Conflicts          map[string]map[string]string `json:"conflicts,omitempty"`
	SelectorConflicts  map[string]string            `json:"selector_conflicts,omitempty"`
	ConflictsTruncated bool                         `json:"conflicts_truncated,omitempty"`
	AttrsTruncated     bool                         `json:"attrs_truncated,omitempty"`
}

type inventoryResult struct {
	Entities     []inventoryEntity        `json:"entities"`
	Truncated    bool                     `json:"truncated"`
	SourceErrors []pluginhost.SourceError `json:"source_errors"`
	OutputTrust  string                   `json:"output_trust"`
}

func (s *Service) searchEntities(ctx context.Context, raw json.RawMessage) (*ToolResult, error) {
	args, err := fixedArguments(raw, "kind", "name", "sources", "limit")
	if err != nil {
		return nil, err
	}
	var q pluginhost.Query
	if err := decodeField(args, "kind", &q.Kind, false); err != nil {
		return nil, invalidArguments(err)
	}
	if err := decodeField(args, "name", &q.Name, false); err != nil {
		return nil, invalidArguments(err)
	}
	var sources []string
	allowed := s.config.Inventory.InventorySources()
	if err := decodeField(args, "sources", &sources, false); err != nil {
		return nil, accessError(connect.CodeInvalidArgument, "sources allowed: array of instance IDs: "+strings.Join(allowed, ", "))
	}
	for _, source := range sources {
		if !slices.Contains(allowed, source) {
			return nil, accessError(connect.CodeInvalidArgument, "sources allowed: "+strings.Join(allowed, ", "))
		}
	}
	limit := 20
	if err := decodeField(args, "limit", &limit, false); err != nil || limit < 1 || limit > 100 {
		return nil, accessError(connect.CodeInvalidArgument, "limit allowed: integer in [1,100]")
	}
	if _, err := s.identity.Require(ctx, authz.ViewInventory, authz.Action{}, authz.Host{}); err != nil {
		return nil, err
	}
	event := reqctx.RequestAuditInfo(ctx)
	event.Operation = "mcp/entities_search"
	event.Phase = "authorized"
	event.Outcome = "allow"
	if err := s.identity.AppendResultAudit(ctx, event); err != nil {
		return nil, accessError(connect.CodeUnavailable, "authorization audit unavailable")
	}
	search := s.config.Inventory.SearchInventory
	if merge, ok := s.config.Inventory.(interface {
		SearchInventoryForMerge(context.Context, pluginhost.Query, []string) ([]pluginhost.Result, []pluginhost.SourceError)
	}); ok {
		search = merge.SearchInventoryForMerge
	}
	entities, sourceErrors := search(ctx, q, sources)
	names := []string{}
	for _, e := range entities {
		names = append(names, e.Hosts...)
	}
	visibleHosts, err := s.identity.VisibleHostnames(ctx, names)
	if err != nil {
		return nil, err
	}
	visible := make([]pluginhost.Result, 0, len(entities))
	for _, e := range entities {
		hosts := []string{}
		for _, name := range e.Hosts {
			if visibleHosts[name] {
				hosts = append(hosts, name)
			}
		}
		if len(e.Hosts) > 0 && len(hosts) == 0 {
			continue
		}
		e.Hosts = hosts
		visible = append(visible, e)
	}
	merged := pluginhost.MergeVisibleInventory(visible, q.Name)
	out := inventoryResult{
		Entities: make([]inventoryEntity, 0, min(len(merged), limit)), Truncated: len(merged) > limit,
		SourceErrors: sourceErrors, OutputTrust: "untrusted",
	}
	if out.SourceErrors == nil {
		out.SourceErrors = []pluginhost.SourceError{}
	}
	for _, e := range merged[:min(len(merged), limit)] {
		out.Entities = append(out.Entities, inventoryEntity{
			Kind: e.Kind, Name: e.Name, Attrs: e.Attrs, Hosts: e.Hosts[:min(len(e.Hosts), 20)], HostCount: e.HostCount,
			Selector: e.Selector, DependsOn: e.DependsOn, Sources: e.Sources, Source: e.Source,
			Conflicts: e.Conflicts, SelectorConflicts: e.SelectorConflicts,
		})
	}
	return fitInventoryResult(out)
}

func fitInventoryResult(out inventoryResult) (*ToolResult, error) {
	result, size, err := toolResult(out)
	if err != nil {
		return nil, err
	}
	if size <= resultByteLimit {
		return result, nil
	}
	out.Truncated = true
	if len(out.Entities) > 0 {
		// Only degrade a row that cannot fit even as the entire page.
		firstPage := out
		firstPage.Entities = out.Entities[:1]
		first := &firstPage.Entities[0]
		_, size, err = toolResult(firstPage)
		if err != nil {
			return nil, err
		}
		if size > resultByteLimit && (len(first.Conflicts) > 0 || len(first.SelectorConflicts) > 0) {
			first.Conflicts, first.SelectorConflicts = nil, nil
			first.ConflictsTruncated = true
			_, size, err = toolResult(firstPage)
			if err != nil {
				return nil, err
			}
		}
		if size > resultByteLimit && (len(first.Attrs) > 0 || len(first.DependsOn) > 0) {
			first.Attrs, first.DependsOn = nil, nil
			first.AttrsTruncated = true
			_, size, err = toolResult(firstPage)
			if err != nil {
				return nil, err
			}
		}
		if size > resultByteLimit && first.Selector != "" {
			first.Selector = ""
			_, size, err = toolResult(firstPage)
			if err != nil {
				return nil, err
			}
		}
		// Escaped hostnames can exceed the budget even within the 20-host preview.
		for size > resultByteLimit && len(first.Hosts) > 1 {
			first.Hosts = first.Hosts[:len(first.Hosts)-1]
			_, size, err = toolResult(firstPage)
			if err != nil {
				return nil, err
			}
		}
	}
	low, high := 0, len(out.Entities)
	var best *ToolResult
	for low <= high {
		middle := low + (high-low)/2
		candidate := out
		candidate.Entities = out.Entities[:middle]
		result, size, err := toolResult(candidate)
		if err != nil {
			return nil, err
		}
		if size <= resultByteLimit {
			best = result
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	if best == nil {
		return nil, accessError(connect.CodeUnavailable, "inventory result exceeds output budget")
	}
	return best, nil
}
