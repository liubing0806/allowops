package mcp

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
	"github.com/liubing0806/allowops/plugin/inventory"
)

type inventoryEntity struct {
	Kind      string            `json:"kind"`
	Name      string            `json:"name"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	Hosts     []string          `json:"hosts,omitempty"`
	HostCount int               `json:"host_count"`
	Selector  string            `json:"selector,omitempty"`
	DependsOn []string          `json:"depends_on,omitempty"`
	Source    string            `json:"source"`
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
	var q inventory.Query
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
	entities, sourceErrors := s.config.Inventory.SearchInventory(ctx, q, sources)
	names := []string{}
	for _, e := range entities {
		names = append(names, e.Hosts...)
	}
	visible, err := s.identity.VisibleHostnames(ctx, names)
	if err != nil {
		return nil, err
	}
	out := inventoryResult{Entities: []inventoryEntity{}, SourceErrors: sourceErrors, OutputTrust: "untrusted"}
	if out.SourceErrors == nil {
		out.SourceErrors = []pluginhost.SourceError{}
	}
	for _, e := range entities {
		hosts := []string{}
		for _, name := range e.Hosts {
			if visible[name] {
				hosts = append(hosts, name)
			}
		}
		if len(e.Hosts) > 0 && len(hosts) == 0 {
			continue
		}
		out.Entities = append(out.Entities, inventoryEntity{Kind: e.Kind, Name: e.Name, Attrs: e.Attrs, Hosts: hosts[:min(len(hosts), 20)], HostCount: len(hosts), Selector: e.Selector, DependsOn: e.DependsOn, Source: e.Source})
	}
	if len(out.Entities) > limit {
		out.Entities = out.Entities[:limit]
		out.Truncated = true
	}
	result, size, err := toolResult(out)
	if err != nil {
		return nil, err
	}
	if size <= resultByteLimit {
		return result, nil
	}
	out.Truncated = true
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
	return best, nil
}
