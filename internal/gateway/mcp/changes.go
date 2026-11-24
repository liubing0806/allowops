package mcp

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
)

// time.Parse also accepts some timestamps outside the RFC3339 syntax.
const changesTimestampPattern = `^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt]([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`

var changesTimestamp = regexp.MustCompile(changesTimestampPattern)

func changesTool(sources []string) ToolDefinition {
	sourceSchema := map[string]any{
		"type":        "array",
		"description": "Change source instance IDs. Omit or leave empty for all available sources.",
		"items":       false,
	}
	if len(sources) > 0 {
		sourceSchema["items"] = map[string]any{"type": "string", "enum": slices.Clone(sources)}
	}
	return ToolDefinition{
		Name:        "changes_list",
		Description: "List recent changes in an inclusive time window of up to seven days, newest first. Requires view_changes. Narrow the time window or select sources when results are truncated." + toolInstructions,
		Annotations: ToolAnnotations{ReadOnlyHint: true},
		InputSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"properties": map[string]any{
				"services": map[string]any{
					"type": "array", "maxItems": 20,
					"items":       map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
					"description": "Exact service names, matched case-insensitively. Each name may use up to 128 UTF-8 bytes.",
				},
				"from":    map[string]any{"type": "string", "format": "date-time", "pattern": changesTimestampPattern, "description": "Inclusive RFC3339 start. Defaults to 24 hours before the current time."},
				"to":      map[string]any{"type": "string", "format": "date-time", "pattern": changesTimestampPattern, "description": "Inclusive RFC3339 end. Defaults to the current time."},
				"sources": sourceSchema,
				"limit":   map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
			},
		},
	}
}

type changeEntry struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Service string    `json:"service"`
	Summary string    `json:"summary"`
	Actor   string    `json:"actor"`
	Ref     string    `json:"ref"`
	Source  string    `json:"source"`
}

type changesResult struct {
	Changes      []changeEntry            `json:"changes"`
	From         time.Time                `json:"from"`
	To           time.Time                `json:"to"`
	Truncated    bool                     `json:"truncated"`
	SourceErrors []pluginhost.SourceError `json:"source_errors"`
	OutputTrust  string                   `json:"output_trust"`
}

func (s *Service) nowTime() time.Time { return time.Now() }

func (s *Service) listChanges(ctx context.Context, raw json.RawMessage) (*ToolResult, error) {
	args, err := fixedArguments(raw, "services", "from", "to", "sources", "limit")
	if err != nil {
		return nil, err
	}
	var query pluginhost.ChangesQuery
	if err := decodeField(args, "services", &query.Services, false); err != nil || len(query.Services) > 20 {
		return nil, accessError(connect.CodeInvalidArgument, "services allowed: array of up to 20 service names")
	}
	for _, service := range query.Services {
		if len(service) < 1 || len(service) > 128 {
			return nil, accessError(connect.CodeInvalidArgument, "service names allowed: 1 to 128 UTF-8 bytes")
		}
	}

	now := s.nowTime().UTC()
	query.From, query.To = now.Add(-24*time.Hour), now
	for _, field := range []struct {
		name  string
		value *time.Time
	}{{"from", &query.From}, {"to", &query.To}} {
		if args[field.name] == nil {
			continue
		}
		var input string
		if err := decodeField(args, field.name, &input, true); err != nil {
			return nil, invalidArguments(err)
		}
		value, err := time.Parse(time.RFC3339, strings.ToUpper(input))
		value = value.UTC()
		if err != nil || !changesTimestamp.MatchString(input) || value.Year() < 0 || value.Year() > 9999 {
			return nil, accessError(connect.CodeInvalidArgument, field.name+" allowed: RFC3339 timestamp")
		}
		*field.value = value
	}
	if query.To.Before(query.From) || query.To.Sub(query.From) > 168*time.Hour {
		return nil, accessError(connect.CodeInvalidArgument, "time window must be ordered and at most 168 hours")
	}

	var sources []string
	allowed := s.config.Changes.ChangesSources()
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

	if _, err := s.identity.Require(ctx, authz.ViewChanges, authz.Action{}, authz.Host{}); err != nil {
		return nil, err
	}
	event := reqctx.RequestAuditInfo(ctx)
	event.Operation, event.Phase, event.Outcome = "mcp/changes_list", "authorized", "allow"
	if err := s.identity.AppendResultAudit(ctx, event); err != nil {
		return nil, accessError(connect.CodeUnavailable, "authorization audit unavailable")
	}

	items, sourceTruncated, sourceErrors := s.config.Changes.ListChanges(ctx, query, sources)
	out := changesResult{
		Changes: make([]changeEntry, 0, min(len(items), limit)),
		From:    query.From, To: query.To, Truncated: sourceTruncated || len(items) > limit,
		SourceErrors: sourceErrors, OutputTrust: "untrusted",
	}
	if out.SourceErrors == nil {
		out.SourceErrors = []pluginhost.SourceError{}
	}
	for _, item := range items[:min(len(items), limit)] {
		out.Changes = append(out.Changes, changeEntry{
			At: item.At, Kind: item.Kind, Service: item.Service, Summary: item.Summary,
			Actor: item.Actor, Ref: item.Ref, Source: item.Source,
		})
	}
	result, size, err := toolResult(out)
	if err != nil || size <= resultByteLimit {
		return result, err
	}

	// Measure the whole ToolResult, including both copies of the payload.
	out.Truncated = true
	low, high := 0, len(out.Changes)-1
	var best *ToolResult
	for low <= high {
		middle := low + (high-low)/2
		candidate := out
		candidate.Changes = out.Changes[:middle]
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
		return nil, accessError(connect.CodeUnavailable, "change source errors exceed result size limit")
	}
	return best, nil
}
