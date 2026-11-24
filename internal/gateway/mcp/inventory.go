package mcp

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
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

// recommendedAction is a visible action whose entity_kinds include the kind
// of a returned entity. It is a display precheck; calls are still authorized.
type recommendedAction struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
	Toolset     string `json:"toolset,omitempty"`
}

type inventoryResult struct {
	Entities []inventoryEntity `json:"entities"`
	// RecommendedActions maps entity kinds to at most recommendationsPerKind
	// actions; RecommendedActionsTruncated reports omitted recommendations.
	RecommendedActions          map[string][]recommendedAction `json:"recommended_actions,omitempty"`
	RecommendedActionsTruncated bool                           `json:"recommended_actions_truncated,omitempty"`
	// Truncated reports omitted entities only.
	Truncated    bool                     `json:"truncated"`
	SourceErrors []pluginhost.SourceError `json:"source_errors"`
	OutputTrust  string                   `json:"output_trust"`
}

const recommendationsPerKind = 10

// searchEntities searches inventory entities. actions are the visible
// actions of the request scope from which recommended_actions are chosen.
func (s *Service) searchEntities(ctx context.Context, raw json.RawMessage, actions map[string]catalog.Action) (*ToolResult, error) {
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
		return recommendActions(out, result, actions)
	}
	out.Truncated = true
	low, high := 0, len(out.Entities)
	var best *ToolResult
	kept := 0
	for low <= high {
		middle := low + (high-low)/2
		candidate := out
		candidate.Entities = out.Entities[:middle]
		result, size, err := toolResult(candidate)
		if err != nil {
			return nil, err
		}
		if size <= resultByteLimit {
			best, kept = result, middle
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	if best == nil {
		return nil, nil
	}
	out.Entities = out.Entities[:kept]
	return recommendActions(out, best, actions)
}

// recommendActions adds recommended_actions for the kinds of the entities in
// out, which is already within budget as result. Kinds are added in name
// order as whole groups while the result stays within budget; omitted groups
// and kinds with more than recommendationsPerKind matches set
// recommended_actions_truncated. If the truncation marker alone exceeds the
// budget, entities are trimmed and truncated is set so both markers fit.
func recommendActions(out inventoryResult, result *ToolResult, actions map[string]catalog.Action) (*ToolResult, error) {
	var kinds []string
	for _, e := range out.Entities {
		kinds = append(kinds, e.Kind)
	}
	slices.Sort(kinds)
	groups := map[string][]recommendedAction{}
	truncated := false
	for _, kind := range slices.Compact(kinds) {
		var matches []catalog.Action
		for _, a := range actions {
			if slices.Contains(a.EntityKinds, kind) {
				matches = append(matches, a)
			}
		}
		if len(matches) == 0 {
			continue
		}
		sortActions(matches)
		if len(matches) > recommendationsPerKind {
			matches = matches[:recommendationsPerKind]
			truncated = true
		}
		group := make([]recommendedAction, len(matches))
		for i, a := range matches {
			group[i] = recommendedAction{Name: a.Name, Description: a.Description, Risk: a.Risk, Toolset: a.Toolset}
		}
		groups[kind] = group
	}
	if len(groups) == 0 {
		return result, nil
	}
	added := map[string][]recommendedAction{}
	for _, kind := range slices.Sorted(maps.Keys(groups)) {
		// Measure with the truncation marker set, so that clearing it later
		// cannot exceed the budget.
		candidate := out
		candidate.RecommendedActions = maps.Clone(added)
		candidate.RecommendedActions[kind] = groups[kind]
		candidate.RecommendedActionsTruncated = true
		_, size, err := toolResult(candidate)
		if err != nil {
			return nil, err
		}
		if size <= resultByteLimit {
			added[kind] = groups[kind]
		} else {
			truncated = true
		}
	}
	if len(added) > 0 {
		out.RecommendedActions = added
	}
	out.RecommendedActionsTruncated = truncated
	final, size, err := toolResult(out)
	if err != nil {
		return nil, err
	}
	if size <= resultByteLimit {
		return final, nil
	}
	// Entities sit right at the 32 KiB limit so even the truncation marker of
	// an empty recommendation set pushed the response over budget. Trim
	// entities to keep both truncation markers accurate within budget.
	out.Truncated = true
	low, high := 0, len(out.Entities)-1
	var best *ToolResult
	kept := 0
	for low <= high {
		middle := low + (high-low)/2
		candidate := out
		candidate.Entities = out.Entities[:middle]
		r, s, err := toolResult(candidate)
		if err != nil {
			return nil, err
		}
		if s <= resultByteLimit {
			best, kept = r, middle
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	if best == nil {
		return result, nil
	}
	hasRecommendedKind := false
	for _, e := range out.Entities[:kept] {
		if _, ok := groups[e.Kind]; ok {
			hasRecommendedKind = true
			break
		}
	}
	if hasRecommendedKind {
		return best, nil
	}
	out.Entities = out.Entities[:kept]
	out.RecommendedActionsTruncated = false
	trimmed, _, err := toolResult(out)
	if err != nil {
		return nil, err
	}
	return trimmed, nil
}
