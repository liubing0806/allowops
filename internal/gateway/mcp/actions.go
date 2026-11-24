package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
)

// actionsQuery is the canonical actions_search filter set. It is hashed into
// the cursor, so a cursor only continues the query that produced it.
type actionsQuery struct {
	Query         string   `json:"query,omitempty"`
	Names         []string `json:"names,omitempty"`
	Toolset       string   `json:"toolset,omitempty"`
	Tag           string   `json:"tag,omitempty"`
	EntityKind    string   `json:"entity_kind,omitempty"`
	Risk          string   `json:"risk,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	IncludeSchema bool     `json:"include_schema"`
	Limit         int      `json:"limit"`
}

type actionInputSchema struct {
	Params               any      `json:"params"`
	EffectiveBatchSize   uint32   `json:"effective_batch_size"`
	EffectiveMaxFailures uint32   `json:"effective_max_failures"`
	MaxTargets           *int     `json:"max_targets,omitempty"`
	AllowedFilters       []string `json:"allowed_filters,omitempty"`
}

type actionEntry struct {
	Name           string             `json:"name"`
	Description    string             `json:"description"`
	Risk           string             `json:"risk"`
	Idempotent     bool               `json:"idempotent"`
	Toolset        string             `json:"toolset,omitempty"`
	Tags           []string           `json:"tags,omitempty"`
	EntityKinds    []string           `json:"entity_kinds,omitempty"`
	MaxTargets     *int               `json:"max_targets,omitempty"`
	Filters        []string           `json:"filters,omitempty"`
	RequiredParams []string           `json:"required_params,omitempty"`
	OptionalParams []string           `json:"optional_params,omitempty"`
	InvokeTool     string             `json:"invoke_tool"`
	InputSchema    *actionInputSchema `json:"input_schema,omitempty"`
}

type toolsetCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type actionsSearchResult struct {
	Actions []actionEntry `json:"actions"`
	// Toolsets counts all matches per annotated toolset, on the first page only.
	Toolsets []toolsetCount `json:"toolsets,omitempty"`
	Total    int            `json:"total"`
	// Truncated reports that the 32 KiB budget shortened this page or
	// dropped the toolset counts; next_cursor still continues losslessly.
	Truncated   bool   `json:"truncated"`
	NextCursor  string `json:"next_cursor"`
	OutputTrust string `json:"output_trust"`
}

type actionsCursor struct {
	Offset int    `json:"offset"`
	Tag    string `json:"tag"`
}

const invalidActionsCursor = "invalid actions_search cursor; restart without next_cursor"

// errActionEntryTooLarge is the only ResourceExhausted error whose message
// toolError shows.
var errActionEntryTooLarge = accessError(connect.CodeResourceExhausted, "action entry exceeds 32KB result limit")

func riskRank(risk string) int {
	return slices.Index(actionRisks, risk)
}

// sortActions orders actions by risk, read first, then by name.
func sortActions(actions []catalog.Action) {
	slices.SortFunc(actions, func(a, b catalog.Action) int {
		if rank := riskRank(a.Risk) - riskRank(b.Risk); rank != 0 {
			return rank
		}
		return strings.Compare(a.Name, b.Name)
	})
}

func (s *Service) searchActions(ctx context.Context, raw json.RawMessage, scope *serverScope) (*ToolResult, error) {
	q, cursor, err := parseActionsQuery(raw)
	if err != nil {
		return nil, err
	}
	matched := matchActions(q, scope.visible)
	if q.Hostname != "" && len(matched) > 0 {
		candidates := make([]authz.Action, len(matched))
		for i, a := range matched {
			candidates[i] = authz.Action{Name: a.Name, Risk: a.Risk}
		}
		allowed, err := s.identity.AllowedActionsOnHost(ctx, q.Hostname, candidates)
		if err != nil {
			return nil, err
		}
		matched = slices.DeleteFunc(matched, func(a catalog.Action) bool { return !allowed[a.Name] })
	}
	snapshot, err := actionsSnapshot(ctx, scope, q, matched)
	if err != nil {
		return nil, err
	}
	start := 0
	if cursor != "" {
		if start, err = decodeActionsCursor(cursor, snapshot); err != nil {
			return nil, err
		}
		if start >= len(matched) {
			return nil, accessError(connect.CodeInvalidArgument, invalidActionsCursor)
		}
	}
	out := actionsSearchResult{Total: len(matched), OutputTrust: "untrusted"}
	if cursor == "" {
		out.Toolsets = toolsetCounts(matched)
	}
	end := min(start+q.Limit, len(matched))
	entries := make([]actionEntry, 0, end-start)
	for _, a := range matched[start:end] {
		entries = append(entries, actionResult(a, scope.flatDefs[a.Name], q.IncludeSchema))
	}
	toolsetsDropped := false
	// page measures the complete MCP result holding the first n entries.
	page := func(n int) (*ToolResult, int, error) {
		out.Actions = entries[:n]
		out.NextCursor = ""
		if start+n < len(matched) {
			out.NextCursor = encodeActionsCursor(snapshot, start+n)
		}
		out.Truncated = n < len(entries) || toolsetsDropped
		return toolResult(out)
	}
	if len(entries) == 0 {
		result, _, err := page(0)
		return result, err
	}
	result, size, err := page(1)
	if err == nil && size > resultByteLimit && out.Toolsets != nil {
		out.Toolsets = nil
		toolsetsDropped = true
		result, size, err = page(1)
	}
	if err != nil {
		return nil, err
	}
	if size > resultByteLimit {
		return nil, errActionEntryTooLarge
	}
	for n := 2; n <= len(entries); n++ {
		candidate, size, err := page(n)
		if err != nil {
			return nil, err
		}
		if size > resultByteLimit {
			break
		}
		result = candidate
	}
	return result, nil
}

// parseActionsQuery decodes the arguments strictly: unknown names, null,
// empty strings and empty arrays are rejected.
func parseActionsQuery(raw json.RawMessage) (actionsQuery, string, error) {
	q := actionsQuery{Limit: 20}
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	args, err := argumentObject(raw)
	if err != nil {
		return q, "", invalidArguments(err)
	}
	allowed := []string{"query", "names", "toolset", "tag", "entity_kind", "risk", "hostname", "include_schema", "limit", "next_cursor"}
	for name := range args {
		if !slices.Contains(allowed, name) {
			return q, "", accessError(connect.CodeInvalidArgument, "unknown argument; allowed: "+strings.Join(allowed, ", "))
		}
	}
	invalid := func(message string) (actionsQuery, string, error) {
		return q, "", accessError(connect.CodeInvalidArgument, message)
	}
	if decodeField(args, "query", &q.Query, false) != nil || args["query"] != nil && (strings.TrimSpace(q.Query) == "" || utf8.RuneCountInString(q.Query) > 200) {
		return invalid("query allowed: non-whitespace string of at most 200 characters")
	}
	if decodeField(args, "names", &q.Names, false) != nil || args["names"] != nil && (len(q.Names) == 0 || len(q.Names) > 20) {
		return invalid("names allowed: array of 1 to 20 unique action names")
	}
	for _, name := range q.Names {
		if !actionName.MatchString(name) {
			return invalid("names allowed: array of 1 to 20 unique action names")
		}
	}
	q.Names = slices.Sorted(slices.Values(q.Names))
	if len(slices.Compact(slices.Clone(q.Names))) != len(q.Names) {
		return invalid("names allowed: array of 1 to 20 unique action names")
	}
	for _, field := range []struct {
		name  string
		value *string
	}{{"toolset", &q.Toolset}, {"tag", &q.Tag}, {"entity_kind", &q.EntityKind}} {
		if decodeField(args, field.name, field.value, false) != nil || args[field.name] != nil && !metadataName.MatchString(*field.value) {
			return invalid(field.name + " allowed: name matching ^[a-z][a-z0-9_]{0,31}$")
		}
	}
	if decodeField(args, "risk", &q.Risk, false) != nil || args["risk"] != nil && !slices.Contains(actionRisks, q.Risk) {
		return invalid("risk allowed: read, write, dangerous")
	}
	if decodeField(args, "hostname", &q.Hostname, false) != nil || args["hostname"] != nil && (strings.TrimSpace(q.Hostname) == "" || strings.ContainsAny(q.Hostname, "\x00\r\n")) {
		return invalid("hostname allowed: nonempty hostname without CR/LF/NUL")
	}
	if decodeField(args, "include_schema", &q.IncludeSchema, false) != nil {
		return invalid("include_schema allowed: boolean")
	}
	if decodeField(args, "limit", &q.Limit, false) != nil || q.Limit < 1 || q.Limit > 50 {
		return invalid("limit allowed: integer in [1,50]")
	}
	var cursor string
	if decodeField(args, "next_cursor", &cursor, false) != nil || args["next_cursor"] != nil && cursor == "" {
		return invalid("next_cursor allowed: nonempty string")
	}
	return q, cursor, nil
}

// matchActions applies every filter except hostname and sorts the matches.
func matchActions(q actionsQuery, visible map[string]catalog.Action) []catalog.Action {
	words := strings.Fields(strings.ToLower(q.Query))
	matched := []catalog.Action{}
	for _, a := range visible {
		if len(q.Names) > 0 && !slices.Contains(q.Names, a.Name) ||
			q.Toolset != "" && a.Toolset != q.Toolset ||
			q.Tag != "" && !slices.Contains(a.Tags, q.Tag) ||
			q.EntityKind != "" && !slices.Contains(a.EntityKinds, q.EntityKind) ||
			q.Risk != "" && a.Risk != q.Risk {
			continue
		}
		text := strings.ToLower(strings.Join(append([]string{a.Name, a.Description, a.Toolset}, append(slices.Clone(a.Tags), a.EntityKinds...)...), " "))
		found := true
		for _, word := range words {
			if !strings.Contains(text, word) {
				found = false
				break
			}
		}
		if found {
			matched = append(matched, a)
		}
	}
	sortActions(matched)
	return matched
}

func toolsetCounts(matched []catalog.Action) []toolsetCount {
	counts := map[string]int{}
	for _, a := range matched {
		if a.Toolset != "" {
			counts[a.Toolset]++
		}
	}
	out := []toolsetCount{}
	for _, name := range slices.Sorted(maps.Keys(counts)) {
		out = append(out, toolsetCount{Name: name, Count: counts[name]})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// actionResult describes one action from its prebuilt flat tool definition,
// which holds the signed params schema and the effective limits.
func actionResult(a catalog.Action, definition ToolDefinition, includeSchema bool) actionEntry {
	properties := definition.InputSchema["properties"].(map[string]any)
	params := properties["params"].(map[string]any)
	required, _ := params["required"].([]string)
	var optional []string
	for name := range params["properties"].(map[string]any) {
		if !slices.Contains(required, name) {
			optional = append(optional, name)
		}
	}
	slices.Sort(optional)
	entry := actionEntry{Name: a.Name, Description: a.Description, Risk: a.Risk, Toolset: a.Toolset, Tags: a.Tags, EntityKinds: a.EntityKinds, MaxTargets: a.MaxTargets, Filters: a.Filters, RequiredParams: required, OptionalParams: optional, InvokeTool: invokeToolName(a.Risk)}
	if a.Idempotent != nil {
		entry.Idempotent = *a.Idempotent
	}
	if includeSchema {
		batch := properties["batch_size"].(map[string]any)["maximum"].(uint32)
		failures := properties["max_failures"].(map[string]any)["maximum"].(uint32)
		entry.InputSchema = &actionInputSchema{Params: params, EffectiveBatchSize: batch, EffectiveMaxFailures: failures, MaxTargets: a.MaxTargets, AllowedFilters: a.Filters}
	}
	return entry
}

// actionsSnapshot binds a cursor to the caller, the catalog and policy
// versions, the server mode and toolsets, the query, and the ordered matched
// action names (including the post-host-precheck result).
func actionsSnapshot(ctx context.Context, scope *serverScope, q actionsQuery, matched []catalog.Action) (string, error) {
	id, ok := reqctx.FromContext(ctx)
	if !ok {
		return "", accessError(connect.CodeUnauthenticated, "authentication required")
	}
	names := make([]string, len(matched))
	for i, a := range matched {
		names[i] = a.Name
	}
	data, err := json.Marshal(struct {
		Actor    string
		Subject  authz.Subject
		Versions string
		Mode     string
		Toolsets []string
		Query    actionsQuery
		Matched  []string
	}{reqctx.RequestAuditInfo(ctx).ActorID, id.Subject, scope.versions, scope.mode, scope.toolsets, q, names})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func actionsCursorTag(snapshot string, offset int) string {
	sum := sha256.Sum256([]byte("actions_search_cursor_v1:" + snapshot + ":" + strconv.Itoa(offset)))
	return hex.EncodeToString(sum[:])
}

func encodeActionsCursor(snapshot string, offset int) string {
	data, _ := json.Marshal(actionsCursor{Offset: offset, Tag: actionsCursorTag(snapshot, offset)})
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeActionsCursor(cursor, snapshot string) (int, error) {
	invalid := accessError(connect.CodeInvalidArgument, invalidActionsCursor)
	if len(cursor) > 256 {
		return 0, invalid
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
	if err != nil {
		return 0, invalid
	}
	args, err := argumentObject(data)
	if err != nil || len(args) != 2 {
		return 0, invalid
	}
	var offset int
	var tag string
	if decodeField(args, "offset", &offset, true) != nil || decodeField(args, "tag", &tag, true) != nil {
		return 0, invalid
	}
	want := actionsCursorTag(snapshot, offset)
	if offset < 1 || subtle.ConstantTimeCompare([]byte(tag), []byte(want)) != 1 {
		return 0, invalid
	}
	return offset, nil
}
