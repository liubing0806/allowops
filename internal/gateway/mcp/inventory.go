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
	return fitInventoryResult(out, actions)
}

func fitInventoryResult(out inventoryResult, actions map[string]catalog.Action) (*ToolResult, error) {
	result, size, err := toolResult(out)
	if err != nil {
		return nil, err
	}
	if size <= resultByteLimit {
		return recommendActions(out, result, actions)
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
		return nil, accessError(connect.CodeUnavailable, "inventory result exceeds output budget")
	}
	out.Entities = out.Entities[:kept]
	return recommendActions(out, best, actions)
}

// recommendActions adds recommended_actions for the kinds of the entities in
// out, which is already within budget as result. Kinds are added in name
// order as whole groups while the result stays within budget; omitted groups
// and kinds with more than recommendationsPerKind matches set
// recommended_actions_truncated. If the truncation marker alone exceeds the
// budget, entities are trimmed, truncated is set, and recommendations are
// packed again into the newly freed budget.
func recommendActions(out inventoryResult, result *ToolResult, actions map[string]catalog.Action) (*ToolResult, error) {
	final, size, hasGroups, err := packRecommendations(out, actions)
	if err != nil {
		return nil, err
	}
	if !hasGroups {
		return result, nil
	}
	if size <= resultByteLimit {
		return final, nil
	}
	// Entities sit right at the 32 KiB limit so even the truncation marker of
	// an empty recommendation set pushed the response over budget. Trim
	// entities so the truncation markers fit, then pack recommendations for
	// the retained entities into the remaining budget.
	out.Truncated = true
	low, high := 0, len(out.Entities)-1
	var best *ToolResult
	kept := 0
	for low <= high {
		middle := low + (high-low)/2
		candidate := out
		candidate.Entities = out.Entities[:middle]
		candidate.RecommendedActions = nil
		candidate.RecommendedActionsTruncated = true
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
	out.Entities = out.Entities[:kept]
	out.RecommendedActions = nil
	out.RecommendedActionsTruncated = false
	final, _, hasGroups, err = packRecommendations(out, actions)
	if err != nil {
		return nil, err
	}
	if !hasGroups {
		trimmed, _, err := toolResult(out)
		if err != nil {
			return nil, err
		}
		return trimmed, nil
	}
	return final, nil
}

func packRecommendations(out inventoryResult, actions map[string]catalog.Action) (*ToolResult, int, bool, error) {
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
		return nil, 0, false, nil
	}
	// Try all groups with the final truncation flag first, so a set that fits
	// completely is not dropped just to reserve bytes for a truncation marker
	// that would not be emitted.
	allCandidate := out
	allCandidate.RecommendedActions = groups
	allCandidate.RecommendedActionsTruncated = truncated
	if full, size, err := toolResult(allCandidate); err != nil {
		return nil, 0, true, err
	} else if size <= resultByteLimit {
		return full, size, true, nil
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
			return nil, 0, true, err
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
		return nil, 0, true, err
	}
	return final, size, true, nil
}
