package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/plugin/knowledge"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	runbookResourceTemplateURI = "allowops://runbooks/{source}/{+id}"
	runbookURIPrefix           = "allowops://runbooks/"
	maxRunbookSections         = 50
	defaultRunbookMaxBytes     = 16384
	minRunbookMaxBytes         = 256
	maxRunbookMaxBytes         = 24576
)

func runbookURI(source, id string) string {
	return runbookURIPrefix + source + "/" + id
}

func parseRunbookURI(uri string) (source, id string, ok bool) {
	if !strings.HasPrefix(uri, runbookURIPrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(uri, runbookURIPrefix)
	if strings.ContainsAny(rest, "?#\r\n\x00") {
		return "", "", false
	}
	source, id, found := strings.Cut(rest, "/")
	if !found || source == "" || id == "" {
		return "", "", false
	}
	return source, id, true
}

func runbooksSearchTool(sources []string) ToolDefinition {
	enumSources := slices.Clone(sources)
	return ToolDefinition{
		Name:        "runbooks_search",
		Description: "Search operational runbooks by case-insensitive query substring (matched against ID, title, summary, tags, and headings) and optional tags. Returned URIs can be read via runbooks_read or MCP resources/read. Results may be truncated; narrow the query or filter by tags/sources." + toolInstructions,
		Annotations: ToolAnnotations{ReadOnlyHint: true},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{
					"type":        "string",
					"description": "Case-insensitive substring matched against document ID, title, summary, tags, and headings; omit or leave empty for all documents.",
				},
				"tags": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string", "minLength": 1},
					"description": "Filter documents that include all specified tags (case-insensitive).",
				},
				"sources": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string", "enum": enumSources},
					"description": "Knowledge instance IDs; omit or leave empty for all available sources.",
				},
				"limit": map[string]any{
					"type":        "integer",
					"minimum":     1,
					"maximum":     100,
					"default":     20,
					"description": "Maximum documents to return.",
				},
			},
			"additionalProperties": false,
		},
	}
}

func runbooksReadTool(sources []string) ToolDefinition {
	enumSources := slices.Clone(sources)
	return ToolDefinition{
		Name:        "runbooks_read",
		Description: "Read a runbook by source and document ID with optional unique section selection, UTF-8 byte-offset pagination, and revision concurrency check. Pass next_offset as offset and revision from the previous page to read losslessly across pages." + toolInstructions,
		Annotations: ToolAnnotations{ReadOnlyHint: true},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"source": map[string]any{
					"type":        "string",
					"enum":        enumSources,
					"description": "Knowledge source instance ID.",
				},
				"id": map[string]any{
					"type":        "string",
					"minLength":   1,
					"description": "Document ID returned by runbooks_search.",
				},
				"section": map[string]any{
					"type":        "string",
					"minLength":   1,
					"description": "Optional unique heading title from sections to read only that section.",
				},
				"offset": map[string]any{
					"type":        "integer",
					"minimum":     0,
					"description": "UTF-8 byte offset within the document or selected section; use next_offset to continue.",
				},
				"max_bytes": map[string]any{
					"type":        "integer",
					"minimum":     minRunbookMaxBytes,
					"maximum":     maxRunbookMaxBytes,
					"default":     defaultRunbookMaxBytes,
					"description": "Maximum UTF-8 bytes of content to return in this page.",
				},
				"revision": map[string]any{
					"type":        "string",
					"minLength":   1,
					"description": "Optional document revision from a previous page; fails if the document changed.",
				},
			},
			"required":             []string{"source", "id"},
			"additionalProperties": false,
		},
	}
}

type runbookSummary struct {
	Source  string   `json:"source"`
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Summary string   `json:"summary,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	URI     string   `json:"uri"`
}

type runbookSearchResult struct {
	Docs         []runbookSummary         `json:"docs"`
	Truncated    bool                     `json:"truncated"`
	SourceErrors []pluginhost.SourceError `json:"source_errors"`
	OutputTrust  string                   `json:"output_trust"`
}

type runbookReadResult struct {
	Source            string   `json:"source"`
	ID                string   `json:"id"`
	URI               string   `json:"uri"`
	Title             string   `json:"title"`
	Summary           string   `json:"summary,omitempty"`
	Tags              []string `json:"tags,omitempty"`
	Revision          string   `json:"revision"`
	Section           string   `json:"section,omitempty"`
	Sections          []string `json:"sections"`
	SectionsTruncated bool     `json:"sections_truncated,omitempty"`
	Content           string   `json:"content"`
	Offset            int      `json:"offset"`
	NextOffset        int      `json:"next_offset"`
	TotalBytes        int      `json:"total_bytes"`
	EOF               bool     `json:"eof"`
	OutputTrust       string   `json:"output_trust"`
}

func (s *Service) appendKnowledgeAudit(ctx context.Context, operation, phase, outcome string) error {
	event := reqctx.RequestAuditInfo(ctx)
	event.Operation = operation
	event.Phase = phase
	event.Outcome = outcome
	return s.identity.AppendResultAudit(ctx, event)
}

func (s *Service) searchRunbooks(ctx context.Context, raw json.RawMessage) (*ToolResult, error) {
	if s.config.Knowledge == nil {
		return nil, accessError(connect.CodeUnavailable, "knowledge service unavailable")
	}
	args, err := fixedArguments(raw, "query", "tags", "sources", "limit")
	if err != nil {
		return nil, err
	}
	var q pluginhost.KnowledgeQuery
	if err := decodeField(args, "query", &q.Query, false); err != nil {
		return nil, invalidArguments(err)
	}
	if err := decodeField(args, "tags", &q.Tags, false); err != nil {
		return nil, accessError(connect.CodeInvalidArgument, "tags allowed: array of nonempty strings")
	}
	for _, tag := range q.Tags {
		if tag == "" {
			return nil, accessError(connect.CodeInvalidArgument, "tags allowed: array of nonempty strings")
		}
	}
	allowed := s.config.Knowledge.KnowledgeSources()
	var sources []string
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
	if _, err := s.identity.Require(ctx, authz.ViewKnowledge, authz.Action{}, authz.Host{}); err != nil {
		return nil, err
	}
	if err := s.appendKnowledgeAudit(ctx, "mcp/runbooks_search", "authorized", "allow"); err != nil {
		return nil, accessError(connect.CodeUnavailable, "authorization audit unavailable")
	}
	docs, _, sourceErrors := s.config.Knowledge.SearchKnowledge(ctx, q, sources)
	out := runbookSearchResult{
		Docs:         make([]runbookSummary, 0, min(len(docs), limit)),
		SourceErrors: sourceErrors,
		OutputTrust:  "untrusted",
	}
	if out.SourceErrors == nil {
		out.SourceErrors = []pluginhost.SourceError{}
	}
	if len(docs) > limit {
		docs = docs[:limit]
		out.Truncated = true
	}
	for _, doc := range docs {
		out.Docs = append(out.Docs, runbookSummary{
			Source:  doc.Source,
			ID:      doc.ID,
			Title:   doc.Title,
			Summary: doc.Summary,
			Tags:    slices.Clone(doc.Tags),
			URI:     runbookURI(doc.Source, doc.ID),
		})
	}
	result, size, err := toolResult(out)
	if err != nil {
		return nil, err
	}
	if size <= resultByteLimit {
		return result, nil
	}
	out.Truncated = true
	low, high := 0, len(out.Docs)
	var best *ToolResult
	for low <= high {
		mid := low + (high-low)/2
		candidate := out
		candidate.Docs = out.Docs[:mid]
		res, sz, err := toolResult(candidate)
		if err != nil {
			return nil, err
		}
		if sz <= resultByteLimit {
			best = res
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	if best == nil {
		return nil, accessError(connect.CodeUnavailable, "runbook search metadata exceeds 32KB result limit")
	}
	return best, nil
}

func (s *Service) readRunbook(ctx context.Context, raw json.RawMessage) (*ToolResult, error) {
	if s.config.Knowledge == nil {
		return nil, accessError(connect.CodeUnavailable, "knowledge service unavailable")
	}
	args, err := fixedArguments(raw, "source", "id", "section", "offset", "max_bytes", "revision")
	if err != nil {
		return nil, err
	}
	allowed := s.config.Knowledge.KnowledgeSources()
	var source string
	if err := decodeField(args, "source", &source, true); err != nil || !slices.Contains(allowed, source) {
		return nil, accessError(connect.CodeInvalidArgument, "source allowed: "+strings.Join(allowed, ", "))
	}
	var id string
	if err := decodeField(args, "id", &id, true); err != nil || id == "" {
		return nil, accessError(connect.CodeInvalidArgument, "id required; allowed: nonempty string")
	}
	var section string
	if _, present := args["section"]; present {
		if err := decodeField(args, "section", &section, false); err != nil || section == "" {
			return nil, accessError(connect.CodeInvalidArgument, "section allowed: nonempty string")
		}
	}
	offset := 0
	if err := decodeField(args, "offset", &offset, false); err != nil || offset < 0 {
		return nil, accessError(connect.CodeInvalidArgument, "offset allowed: nonnegative integer")
	}
	maxBytes := defaultRunbookMaxBytes
	if err := decodeField(args, "max_bytes", &maxBytes, false); err != nil || maxBytes < minRunbookMaxBytes || maxBytes > maxRunbookMaxBytes {
		return nil, accessError(connect.CodeInvalidArgument, fmt.Sprintf("max_bytes allowed: integer in [%d,%d]", minRunbookMaxBytes, maxRunbookMaxBytes))
	}
	var revision string
	if _, present := args["revision"]; present {
		if err := decodeField(args, "revision", &revision, false); err != nil || revision == "" {
			return nil, accessError(connect.CodeInvalidArgument, "revision allowed: nonempty string")
		}
	}
	if _, err := s.identity.Require(ctx, authz.ViewKnowledge, authz.Action{}, authz.Host{}); err != nil {
		return nil, err
	}
	if err := s.appendKnowledgeAudit(ctx, "mcp/runbooks_read", "authorized", "allow"); err != nil {
		return nil, accessError(connect.CodeUnavailable, "authorization audit unavailable")
	}
	docRes, err := s.config.Knowledge.ReadKnowledge(ctx, source, id)
	if err != nil {
		if errors.Is(err, knowledge.ErrNotFound) {
			return nil, accessError(connect.CodeNotFound, "runbook not found")
		}
		return nil, accessError(connect.CodeUnavailable, "runbook unavailable")
	}
	if revision != "" && revision != docRes.Revision {
		return nil, accessError(connect.CodeFailedPrecondition, "runbook revision changed; restart read without revision")
	}
	content := docRes.Content
	if section != "" {
		sliced, ok := sliceRunbookSection(docRes.Content, docRes.Sections, section)
		if !ok {
			return nil, accessError(connect.CodeNotFound, "runbook section not found")
		}
		content = sliced
	}
	totalBytes := len(content)
	if offset > totalBytes {
		return nil, accessError(connect.CodeInvalidArgument, "offset exceeds total_bytes")
	}
	if offset < totalBytes && !utf8.RuneStart(content[offset]) {
		return nil, accessError(connect.CodeInvalidArgument, "offset must align to a UTF-8 character boundary")
	}

	sectionCap := min(len(docRes.Sections), maxRunbookSections)
	allSections := make([]string, 0, sectionCap)
	for i := range sectionCap {
		allSections = append(allSections, docRes.Sections[i].Title)
	}

	remaining := content[offset:]
	capBytes := min(len(remaining), maxBytes)
	minBytes := 0
	if len(remaining) > 0 {
		_, minBytes = utf8.DecodeRuneInString(remaining)
	}

	build := func(sectionCount, byteLimit int) (*ToolResult, int, error) {
		n := utf8PrefixLen(remaining, byteLimit)
		sections := allSections[:sectionCount]
		if sections == nil {
			sections = []string{}
		}
		out := runbookReadResult{
			Source:            source,
			ID:                id,
			URI:               runbookURI(source, id),
			Title:             docRes.Title,
			Summary:           docRes.Summary,
			Tags:              slices.Clone(docRes.Tags),
			Revision:          docRes.Revision,
			Section:           section,
			Sections:          sections,
			SectionsTruncated: len(docRes.Sections) > sectionCount,
			Content:           remaining[:n],
			Offset:            offset,
			NextOffset:        offset + n,
			TotalBytes:        totalBytes,
			EOF:               offset+n == totalBytes,
			OutputTrust:       "untrusted",
		}
		res, size, err := toolResult(out)
		return res, size, err
	}

	// Ensure at least one full UTF-8 rune fits when !eof by shrinking sections if needed.
	chosenSections := len(allSections)
	if _, size, err := build(chosenSections, minBytes); err != nil {
		return nil, err
	} else if size > resultByteLimit {
		low, high := 0, len(allSections)-1
		chosenSections = -1
		for low <= high {
			mid := low + (high-low)/2
			_, sz, err := build(mid, minBytes)
			if err != nil {
				return nil, err
			}
			if sz <= resultByteLimit {
				chosenSections = mid
				low = mid + 1
			} else {
				high = mid - 1
			}
		}
		if chosenSections < 0 {
			return nil, accessError(connect.CodeUnavailable, "runbook metadata exceeds 32KB result limit")
		}
	}

	if len(remaining) == 0 {
		res, _, err := build(chosenSections, 0)
		return res, err
	}

	low, high := minBytes, capBytes
	var best *ToolResult
	for low <= high {
		mid := low + (high-low)/2
		res, sz, err := build(chosenSections, mid)
		if err != nil {
			return nil, err
		}
		if sz <= resultByteLimit {
			best = res
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	if best == nil {
		return nil, accessError(connect.CodeUnavailable, "runbook page exceeds 32KB result limit")
	}
	return best, nil
}

func sliceRunbookSection(content string, sections []pluginhost.KnowledgeSection, title string) (string, bool) {
	idx := -1
	for i, sec := range sections {
		if sec.Title == title {
			idx = i
			break
		}
	}
	if idx < 0 {
		return "", false
	}
	start := sections[idx].Offset
	if start < 0 || start > len(content) {
		return "", false
	}
	targetLevel := markdownHeadingLevelAt(content, start)
	end := len(content)
	if targetLevel > 0 {
		for j := idx + 1; j < len(sections); j++ {
			nextOff := sections[j].Offset
			if nextOff < start || nextOff > len(content) {
				continue
			}
			level := markdownHeadingLevelAt(content, nextOff)
			if level > 0 && level <= targetLevel {
				end = nextOff
				break
			}
		}
	}
	return content[start:end], true
}

func markdownHeadingLevelAt(content string, offset int) int {
	if offset < 0 || offset >= len(content) {
		return 0
	}
	i := offset
	for i < len(content) && content[i] == ' ' && i-offset < 3 {
		i++
	}
	level := 0
	for i < len(content) && content[i] == '#' && level < 6 {
		level++
		i++
	}
	return level
}

func utf8PrefixLen(s string, limit int) int {
	if limit >= len(s) {
		return len(s)
	}
	if limit <= 0 {
		return 0
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return limit
}

func encodeResourceCursor(revision string, offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%d", revision, offset)))
}

func decodeResourceCursor(cursor string) (revision string, offset int, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", 0, false
	}
	rev, offStr, found := strings.Cut(string(raw), ":")
	if !found || rev == "" {
		return "", 0, false
	}
	off, err := strconv.Atoi(offStr)
	if err != nil || off <= 0 {
		return "", 0, false
	}
	return rev, off, true
}

func wireResourceMeta(meta sdk.Meta) sdk.Meta {
	cloned := maps.Clone(meta)
	if cloned == nil {
		cloned = sdk.Meta{}
	}
	cloned[sdk.MetaKeyServerInfo] = map[string]string{"name": "allowops", "version": "1"}
	return cloned
}

func measureListResourcesResult(res *sdk.ListResourcesResult) (int, error) {
	wire := struct {
		ResultType string   `json:"resultType,omitempty"`
		Meta       sdk.Meta `json:"_meta,omitempty"`
		sdk.Cacheable
		NextCursor string          `json:"nextCursor,omitempty"`
		Resources  []*sdk.Resource `json:"resources"`
	}{
		ResultType: "complete",
		Meta:       wireResourceMeta(res.Meta),
		Cacheable:  res.Cacheable,
		NextCursor: res.NextCursor,
		Resources:  res.Resources,
	}
	b, err := json.Marshal(wire)
	return len(b), err
}

func measureReadResourceResult(res *sdk.ReadResourceResult) (int, error) {
	wire := struct {
		ResultType string   `json:"resultType,omitempty"`
		Meta       sdk.Meta `json:"_meta,omitempty"`
		sdk.Cacheable
		Contents []*sdk.ResourceContents `json:"contents"`
	}{
		ResultType: "complete",
		Meta:       wireResourceMeta(res.Meta),
		Cacheable:  res.Cacheable,
		Contents:   res.Contents,
	}
	b, err := json.Marshal(wire)
	return len(b), err
}

func (s *Service) listRunbookResources(ctx context.Context, req *sdk.ListResourcesRequest) (*sdk.ListResourcesResult, error) {
	if s.config.Knowledge == nil {
		return nil, accessError(connect.CodeUnavailable, "knowledge service unavailable")
	}
	var cursor string
	if req != nil && req.Params != nil {
		cursor = req.Params.Cursor
	}
	docs, indexRevision, _ := s.config.Knowledge.SearchKnowledge(ctx, pluginhost.KnowledgeQuery{}, nil)
	offset := 0
	if cursor != "" {
		rev, off, ok := decodeResourceCursor(cursor)
		if !ok || rev != indexRevision || off >= len(docs) {
			return nil, accessError(connect.CodeInvalidArgument, "invalid or stale cursor; restart resources/list without cursor")
		}
		offset = off
	}

	remaining := docs[offset:]
	maxCount := len(remaining)
	if s.identity != nil && s.identity.PageSize() > 0 && maxCount > s.identity.PageSize() {
		maxCount = s.identity.PageSize()
	}

	buildPage := func(count int) (*sdk.ListResourcesResult, int, error) {
		items := make([]*sdk.Resource, 0, count)
		for _, doc := range remaining[:count] {
			items = append(items, &sdk.Resource{
				URI:         runbookURI(doc.Source, doc.ID),
				Name:        doc.ID,
				Title:       doc.Title,
				Description: doc.Summary,
				MIMEType:    "text/markdown",
			})
		}
		nextCursor := ""
		if offset+count < len(docs) {
			nextCursor = encodeResourceCursor(indexRevision, offset+count)
		}
		res := &sdk.ListResourcesResult{
			Meta:       sdk.Meta{"output_trust": "untrusted"},
			Cacheable:  sdk.Cacheable{TTLMs: 0, CacheScope: "private"},
			NextCursor: nextCursor,
			Resources:  items,
		}
		size, err := measureListResourcesResult(res)
		return res, size, err
	}

	if maxCount == 0 {
		res, _, err := buildPage(0)
		return res, err
	}
	if res, size, err := buildPage(maxCount); err != nil {
		return nil, err
	} else if size <= resultByteLimit {
		return res, nil
	}

	low, high := 1, maxCount-1
	var best *sdk.ListResourcesResult
	for low <= high {
		mid := low + (high-low)/2
		res, size, err := buildPage(mid)
		if err != nil {
			return nil, err
		}
		if size <= resultByteLimit {
			best = res
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	if best == nil {
		return nil, accessError(connect.CodeUnavailable, "resource listing entry exceeds 32KB result limit")
	}
	return best, nil
}

func (s *Service) readRunbookResource(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
	if s.config.Knowledge == nil {
		return nil, accessError(connect.CodeUnavailable, "knowledge service unavailable")
	}
	if req == nil || req.Params == nil {
		return nil, sdk.ResourceNotFoundError("")
	}
	uri := req.Params.URI
	source, id, ok := parseRunbookURI(uri)
	if !ok {
		return nil, sdk.ResourceNotFoundError(uri)
	}
	docRes, err := s.config.Knowledge.ReadKnowledge(ctx, source, id)
	if err != nil {
		if errors.Is(err, knowledge.ErrNotFound) {
			return nil, sdk.ResourceNotFoundError(uri)
		}
		return nil, accessError(connect.CodeUnavailable, "runbook unavailable")
	}

	full := &sdk.ReadResourceResult{
		Meta:      sdk.Meta{"output_trust": "untrusted"},
		Cacheable: sdk.Cacheable{TTLMs: 0, CacheScope: "private"},
		Contents: []*sdk.ResourceContents{{
			URI:      uri,
			MIMEType: "text/markdown",
			Text:     docRes.Content,
			Meta: sdk.Meta{
				"output_trust": "untrusted",
				"revision":     docRes.Revision,
				"total_bytes":  len(docRes.Content),
			},
		}},
	}
	if size, err := measureReadResourceResult(full); err != nil {
		return nil, err
	} else if size <= resultByteLimit {
		return full, nil
	}

	buildTruncated := func(limit int) (*sdk.ReadResourceResult, int, error) {
		n := utf8PrefixLen(docRes.Content, limit)
		notice := fmt.Sprintf(
			"\n\n[Truncated at %d of %d bytes. Call runbooks_read with source=%q, id=%q, offset=%d, revision=%q to continue.]",
			n, len(docRes.Content), source, id, n, docRes.Revision,
		)
		res := &sdk.ReadResourceResult{
			Meta:      sdk.Meta{"output_trust": "untrusted"},
			Cacheable: sdk.Cacheable{TTLMs: 0, CacheScope: "private"},
			Contents: []*sdk.ResourceContents{{
				URI:      uri,
				MIMEType: "text/markdown",
				Text:     docRes.Content[:n] + notice,
				Meta: sdk.Meta{
					"output_trust": "untrusted",
					"revision":     docRes.Revision,
					"truncated":    true,
					"next_offset":  n,
					"total_bytes":  len(docRes.Content),
				},
			}},
		}
		size, err := measureReadResourceResult(res)
		return res, size, err
	}

	low, high := 0, len(docRes.Content)
	var best *sdk.ReadResourceResult
	for low <= high {
		mid := low + (high-low)/2
		res, size, err := buildTruncated(mid)
		if err != nil {
			return nil, err
		}
		if size <= resultByteLimit {
			best = res
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	if best == nil {
		return nil, accessError(connect.CodeUnavailable, "runbook resource metadata exceeds 32KB result limit")
	}
	return best, nil
}

func (s *Service) handleKnowledgeResourceMethod(ctx context.Context, method string, r sdk.Request, next sdk.MethodHandler) (sdk.Result, error) {
	switch method {
	case "resources/list", "resources/templates/list", "resources/read":
	default:
		return next(ctx, method, r)
	}
	ctx = reqctx.ForkRequestContext(ctx)
	op := "mcp/" + method
	if _, err := s.identity.Require(ctx, authz.ViewKnowledge, authz.Action{}, authz.Host{}); err != nil {
		if auditErr := s.appendKnowledgeAudit(ctx, op, "result", "deny"); auditErr != nil {
			return nil, accessError(connect.CodeUnavailable, "result audit unavailable")
		}
		return nil, err
	}
	if err := s.appendKnowledgeAudit(ctx, op, "authorized", "allow"); err != nil {
		return nil, accessError(connect.CodeUnavailable, "authorization audit unavailable")
	}
	var (
		res sdk.Result
		err error
	)
	if method == "resources/list" {
		var listReq *sdk.ListResourcesRequest
		if r != nil {
			typed, ok := r.(*sdk.ListResourcesRequest)
			if !ok {
				err = accessError(connect.CodeInvalidArgument, "invalid resources/list request")
			} else {
				listReq = typed
			}
		}
		if err == nil {
			res, err = s.listRunbookResources(ctx, listReq)
		}
	} else {
		res, err = next(ctx, method, r)
	}
	outcome := "allow"
	if err != nil {
		outcome = "deny"
	}
	if auditErr := s.appendKnowledgeAudit(ctx, op, "result", outcome); auditErr != nil {
		return nil, accessError(connect.CodeUnavailable, "result audit unavailable")
	}
	return res, err
}
