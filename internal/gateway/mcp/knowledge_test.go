package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	"github.com/google/jsonschema-go/jsonschema"
	_ "github.com/liubing0806/allowops/extensions/knowledge/gitdocs"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/plugin/knowledge"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

type knowledgeStub struct {
	mu           sync.Mutex
	sources      []string
	docs         []pluginhost.KnowledgeDocResult
	indexRev     string
	sourceErrors []pluginhost.SourceError
	reads        map[[2]string]pluginhost.KnowledgeReadResult
	readErr      error
	searchCalls  int
	readCalls    int
	lastQuery    pluginhost.KnowledgeQuery
	lastSources  []string
}

func (k *knowledgeStub) KnowledgeSources() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.sources)
}

func (k *knowledgeStub) SearchKnowledge(_ context.Context, q pluginhost.KnowledgeQuery, sources []string) ([]pluginhost.KnowledgeDocResult, string, []pluginhost.SourceError) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.searchCalls++
	k.lastQuery = q
	k.lastSources = slices.Clone(sources)
	return slices.Clone(k.docs), k.indexRev, slices.Clone(k.sourceErrors)
}

func (k *knowledgeStub) ReadKnowledge(_ context.Context, source, id string) (pluginhost.KnowledgeReadResult, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.readCalls++
	if k.readErr != nil {
		return pluginhost.KnowledgeReadResult{}, k.readErr
	}
	res, ok := k.reads[[2]string{source, id}]
	if !ok {
		return pluginhost.KnowledgeReadResult{}, knowledge.ErrNotFound
	}
	return res, nil
}

type knowledgeIdentity struct {
	Identity
	mu            sync.Mutex
	denied        bool
	required      bool
	pageSize      int
	failAuditAt   int // 1-based audit call index to fail; 0 disables
	failAllAudits bool
	events        []reqctx.AuditEvent
}

func (i *knowledgeIdentity) Require(_ context.Context, op authz.Operation, a authz.Action, h authz.Host) (authz.Result, error) {
	if op != authz.ViewKnowledge || !reflect.DeepEqual(a, authz.Action{}) || !reflect.DeepEqual(h, authz.Host{}) {
		panic("wrong knowledge authorization input")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.required = true
	if i.denied {
		return authz.Result{Decision: "deny"}, accessError(connect.CodePermissionDenied, "operation denied")
	}
	return authz.Result{Decision: "allow"}, nil
}

func (i *knowledgeIdentity) AppendResultAudit(_ context.Context, e reqctx.AuditEvent) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	callNum := len(i.events) + 1
	if i.failAllAudits || (i.failAuditAt > 0 && callNum == i.failAuditAt) {
		return errors.New("audit unavailable")
	}
	i.events = append(i.events, e)
	return nil
}

func (i *knowledgeIdentity) PageSize() int {
	if i.pageSize > 0 {
		return i.pageSize
	}
	return 50
}

func (i *knowledgeIdentity) auditSnapshot() []reqctx.AuditEvent {
	i.mu.Lock()
	defer i.mu.Unlock()
	return slices.Clone(i.events)
}

func TestKnowledgeToolSchemas(t *testing.T) {
	searchTool := runbooksSearchTool([]string{"ops", "sec"})
	if searchTool.Name != "runbooks_search" || !searchTool.Annotations.ReadOnlyHint || !strings.HasSuffix(searchTool.Description, toolInstructions) {
		t.Fatalf("bad search tool: %+v", searchTool)
	}
	readTool := runbooksReadTool([]string{"ops", "sec"})
	if readTool.Name != "runbooks_read" || !readTool.Annotations.ReadOnlyHint || !strings.HasSuffix(readTool.Description, toolInstructions) {
		t.Fatalf("bad read tool: %+v", readTool)
	}

	resolveSchema := func(raw any) *jsonschema.Resolved {
		t.Helper()
		b, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		var s jsonschema.Schema
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		r, err := s.Resolve(nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	sr := resolveSchema(searchTool.InputSchema)
	for _, valid := range []any{
		map[string]any{},
		map[string]any{"query": "restart", "tags": []any{"ops"}, "sources": []any{"ops"}, "limit": float64(10)},
	} {
		if err := sr.Validate(valid); err != nil {
			t.Fatalf("search schema rejected %v: %v", valid, err)
		}
	}
	for _, invalid := range []any{
		map[string]any{"unknown": true},
		map[string]any{"sources": []any{"missing"}},
		map[string]any{"tags": []any{""}},
		map[string]any{"limit": float64(0)},
		map[string]any{"limit": float64(101)},
	} {
		if err := sr.Validate(invalid); err == nil {
			t.Fatalf("search schema accepted %v", invalid)
		}
	}

	rr := resolveSchema(readTool.InputSchema)
	for _, valid := range []any{
		map[string]any{"source": "ops", "id": "api/restart.md"},
		map[string]any{"source": "sec", "id": "a.md", "section": "Steps", "offset": float64(0), "max_bytes": float64(1024), "revision": "abc123"},
	} {
		if err := rr.Validate(valid); err != nil {
			t.Fatalf("read schema rejected %v: %v", valid, err)
		}
	}
	for _, invalid := range []any{
		map[string]any{},
		map[string]any{"source": "ops"},
		map[string]any{"source": "unknown", "id": "a.md"},
		map[string]any{"source": "ops", "id": ""},
		map[string]any{"source": "ops", "id": "a.md", "offset": float64(-1)},
		map[string]any{"source": "ops", "id": "a.md", "max_bytes": float64(100)},
		map[string]any{"source": "ops", "id": "a.md", "max_bytes": float64(30000)},
	} {
		if err := rr.Validate(invalid); err == nil {
			t.Fatalf("read schema accepted %v", invalid)
		}
	}
}

func TestRunbooksSearchValidationAuditAndBudget(t *testing.T) {
	for _, bad := range []string{
		`[]`, `{"extra":1}`, `{"query":1}`, `{"query":null}`,
		`{"tags":"ops"}`, `{"tags":[""]}`, `{"tags":[null]}`,
		`{"sources":"ops"}`, `{"sources":["missing"]}`, `{"sources":[null]}`,
		`{"limit":0}`, `{"limit":101}`, `{"limit":1.5}`, `{"limit":null}`,
	} {
		t.Run("bad/"+bad, func(t *testing.T) {
			stub := &knowledgeStub{sources: []string{"ops"}}
			id := &knowledgeIdentity{}
			s := &Service{identity: id, config: Config{Knowledge: stub}}
			_, err := s.searchRunbooks(t.Context(), json.RawMessage(bad))
			if connect.CodeOf(err) != connect.CodeInvalidArgument || id.required || stub.searchCalls != 0 {
				t.Fatalf("input=%s err=%v required=%v calls=%d", bad, err, id.required, stub.searchCalls)
			}
		})
	}

	t.Run("permission denied", func(t *testing.T) {
		stub := &knowledgeStub{sources: []string{"ops"}}
		id := &knowledgeIdentity{denied: true}
		s := &Service{identity: id, config: Config{Knowledge: stub}}
		_, err := s.searchRunbooks(t.Context(), json.RawMessage(`{}`))
		if connect.CodeOf(err) != connect.CodePermissionDenied || stub.searchCalls != 0 {
			t.Fatalf("err=%v calls=%d", err, stub.searchCalls)
		}
	})

	t.Run("authorized audit fail-closed zero plugin calls", func(t *testing.T) {
		stub := &knowledgeStub{sources: []string{"ops"}}
		id := &knowledgeIdentity{failAllAudits: true}
		s := &Service{identity: id, config: Config{Knowledge: stub}}
		_, err := s.searchRunbooks(t.Context(), json.RawMessage(`{}`))
		if connect.CodeOf(err) != connect.CodeUnavailable || stub.searchCalls != 0 {
			t.Fatalf("err=%v calls=%d", err, stub.searchCalls)
		}
	})

	t.Run("32KiB budget binary search and uri format", func(t *testing.T) {
		stub := &knowledgeStub{
			sources:      []string{"ops"},
			indexRev:     "rev0001",
			sourceErrors: []pluginhost.SourceError{{Source: "broken", Reason: "timeout"}},
		}
		for i := range 100 {
			stub.docs = append(stub.docs, pluginhost.KnowledgeDocResult{
				Source: "ops",
				Doc: knowledge.Doc{
					ID:      fmt.Sprintf("dir/doc-%03d.md", i),
					Title:   fmt.Sprintf("Title %d", i),
					Summary: strings.Repeat(`"<`, 180),
					Tags:    []string{"ops"},
				},
			})
		}
		id := &knowledgeIdentity{}
		s := &Service{identity: id, config: Config{Knowledge: stub}}
		res, err := s.searchRunbooks(t.Context(), json.RawMessage(`{"limit":100}`))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(res)
		if err != nil || len(raw) > resultByteLimit {
			t.Fatalf("size=%d err=%v", len(raw), err)
		}
		out := res.StructuredContent.(runbookSearchResult)
		if !out.Truncated || len(out.Docs) == 0 || len(out.Docs) >= 100 || out.OutputTrust != "untrusted" || len(out.SourceErrors) != 1 {
			t.Fatalf("unexpected search output: %+v", out)
		}
		if out.Docs[0].URI != "allowops://runbooks/ops/dir/doc-000.md" {
			t.Fatalf("unexpected uri: %q", out.Docs[0].URI)
		}
		events := id.auditSnapshot()
		if len(events) != 1 || events[0].Operation != "mcp/runbooks_search" || events[0].Phase != "authorized" || events[0].Outcome != "allow" {
			t.Fatalf("unexpected audit events: %+v", events)
		}
	})
}

func TestRunbooksReadSectionsUTF8RevisionAnd50LongHeadings(t *testing.T) {
	content := strings.Join([]string{
		"# Steps (#3)",
		"intro text",
		"# Steps",
		"first steps body",
		"## Substep",
		"substep body",
		"## Steps",
		"duplicate steps body",
		"### Deep",
		"deep body",
		"# Next Top",
		"tail",
	}, "\n") + "\n"

	// Offsets matching pluginhost.documentSections behavior.
	off := func(substr string) int {
		idx := strings.Index(content, substr)
		if idx < 0 {
			t.Fatalf("missing %q", substr)
		}
		return idx
	}
	sections := []pluginhost.KnowledgeSection{
		{Title: "Steps (#3)", Offset: off("# Steps (#3)")},
		{Title: "Steps", Offset: off("\n# Steps\n") + 1},
		{Title: "Substep", Offset: off("## Substep")},
		{Title: "Steps (#4)", Offset: off("## Steps\n")},
		{Title: "Deep", Offset: off("### Deep")},
		{Title: "Next Top", Offset: off("# Next Top")},
	}

	stub := &knowledgeStub{
		sources: []string{"ops"},
		reads: map[[2]string]pluginhost.KnowledgeReadResult{
			{"ops", "guide.md"}: {
				KnowledgeDocResult: pluginhost.KnowledgeDocResult{
					Source: "ops",
					Doc:    knowledge.Doc{ID: "guide.md", Title: "Guide", Tags: []string{"ops"}},
				},
				Content:  content,
				Revision: "rev-v1",
				Sections: sections,
			},
		},
	}
	id := &knowledgeIdentity{}
	s := &Service{identity: id, config: Config{Knowledge: stub}}

	t.Run("unique duplicate section slicing respects heading level", func(t *testing.T) {
		// Selecting level-2 "Steps (#4)" includes its level-3 child "### Deep" and stops at level-1 "# Next Top".
		res, err := s.readRunbook(t.Context(), json.RawMessage(`{"source":"ops","id":"guide.md","section":"Steps (#4)"}`))
		if err != nil {
			t.Fatal(err)
		}
		out := res.StructuredContent.(runbookReadResult)
		want := "## Steps\nduplicate steps body\n### Deep\ndeep body\n"
		if out.Content != want || !out.EOF || out.NextOffset != len(want) || out.TotalBytes != len(want) {
			t.Fatalf("got content=%q want=%q out=%+v", out.Content, want, out)
		}
		// Selecting level-1 "Steps" includes "## Substep", "## Steps", "### Deep" and stops at "# Next Top".
		res2, err := s.readRunbook(t.Context(), json.RawMessage(`{"source":"ops","id":"guide.md","section":"Steps"}`))
		if err != nil {
			t.Fatal(err)
		}
		out2 := res2.StructuredContent.(runbookReadResult)
		if !strings.HasPrefix(out2.Content, "# Steps\nfirst steps body") || !strings.Contains(out2.Content, "### Deep\ndeep body\n") || strings.Contains(out2.Content, "# Next Top") {
			t.Fatalf("unexpected level-1 slice: %q", out2.Content)
		}
	})

	t.Run("revision mismatch fails with FailedPrecondition", func(t *testing.T) {
		_, err := s.readRunbook(t.Context(), json.RawMessage(`{"source":"ops","id":"guide.md","revision":"stale-rev"}`))
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("expected FailedPrecondition, got %v", err)
		}
	})

	t.Run("offset boundary and EOF behavior with multi-byte UTF-8", func(t *testing.T) {
		// Multi-byte UTF-8 content: each Chinese char is 3 bytes, emoji is 4 bytes.
		utf8Content := strings.Repeat("排障手册🚀", 200) // 16 bytes * 200 = 3200 bytes
		stub.mu.Lock()
		stub.reads[[2]string{"ops", "utf8.md"}] = pluginhost.KnowledgeReadResult{
			KnowledgeDocResult: pluginhost.KnowledgeDocResult{
				Source: "ops",
				Doc:    knowledge.Doc{ID: "utf8.md", Title: "UTF8"},
			},
			Content:  utf8Content,
			Revision: "rev-utf8",
		}
		stub.mu.Unlock()

		// Non-boundary offset (byte 1 inside 3-byte char '排') -> InvalidArgument.
		_, err := s.readRunbook(t.Context(), json.RawMessage(`{"source":"ops","id":"utf8.md","offset":1}`))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("expected InvalidArgument for mid-rune offset, got %v", err)
		}
		// Offset > total_bytes -> InvalidArgument.
		_, err = s.readRunbook(t.Context(), json.RawMessage(fmt.Sprintf(`{"source":"ops","id":"utf8.md","offset":%d}`, len(utf8Content)+1)))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("expected InvalidArgument for offset > total_bytes, got %v", err)
		}
		// Offset == total_bytes -> empty content, eof=true.
		eofRes, err := s.readRunbook(t.Context(), json.RawMessage(fmt.Sprintf(`{"source":"ops","id":"utf8.md","offset":%d}`, len(utf8Content))))
		if err != nil {
			t.Fatal(err)
		}
		eofOut := eofRes.StructuredContent.(runbookReadResult)
		if eofOut.Content != "" || !eofOut.EOF || eofOut.NextOffset != len(utf8Content) {
			t.Fatalf("unexpected exact-EOF output: %+v", eofOut)
		}

		// Lossless pagination across pages with small max_bytes=257 (not aligned to 16-byte cycle).
		var rebuilt strings.Builder
		offset := 0
		for range 50 {
			args := fmt.Sprintf(`{"source":"ops","id":"utf8.md","offset":%d,"max_bytes":257,"revision":"rev-utf8"}`, offset)
			pageRes, err := s.readRunbook(t.Context(), json.RawMessage(args))
			if err != nil {
				t.Fatalf("offset=%d err=%v", offset, err)
			}
			raw, _ := json.Marshal(pageRes)
			if len(raw) > resultByteLimit {
				t.Fatalf("page size=%d exceeds limit", len(raw))
			}
			out := pageRes.StructuredContent.(runbookReadResult)
			if !utf8.ValidString(out.Content) {
				t.Fatalf("invalid UTF-8 page at offset %d", offset)
			}
			rebuilt.WriteString(out.Content)
			if out.EOF {
				if out.NextOffset != len(utf8Content) {
					t.Fatalf("eof next_offset=%d want=%d", out.NextOffset, len(utf8Content))
				}
				break
			}
			if out.NextOffset <= offset {
				t.Fatalf("stalled pagination: offset=%d next=%d", offset, out.NextOffset)
			}
			offset = out.NextOffset
		}
		if rebuilt.String() != utf8Content {
			t.Fatalf("rebuilt content mismatch: len=%d want=%d", rebuilt.Len(), len(utf8Content))
		}
	})

	t.Run("50 long quote-heavy headings shrink sections to guarantee next_offset > offset", func(t *testing.T) {
		longSections := make([]pluginhost.KnowledgeSection, 50)
		for i := range 50 {
			// Quote-heavy 128-byte headings expand dramatically when JSON-escaped and doubled in ToolResult.
			longSections[i] = pluginhost.KnowledgeSection{
				Title:  fmt.Sprintf("%02d-%s", i, strings.Repeat(`"<`, 62)),
				Offset: 0,
			}
		}
		body := strings.Repeat("排障正文", 200)
		stub.mu.Lock()
		stub.reads[[2]string{"ops", "heavy.md"}] = pluginhost.KnowledgeReadResult{
			KnowledgeDocResult: pluginhost.KnowledgeDocResult{
				Source: "ops",
				Doc:    knowledge.Doc{ID: "heavy.md", Title: "Heavy"},
			},
			Content:  body,
			Revision: "rev-heavy",
			Sections: longSections,
		}
		stub.mu.Unlock()

		res, err := s.readRunbook(t.Context(), json.RawMessage(`{"source":"ops","id":"heavy.md","offset":0,"max_bytes":24576}`))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(res)
		if err != nil || len(raw) > resultByteLimit {
			t.Fatalf("complete ToolResult size=%d err=%v", len(raw), err)
		}
		out := res.StructuredContent.(runbookReadResult)
		if !out.SectionsTruncated || len(out.Sections) >= 50 {
			t.Fatalf("expected sections to be truncated, got len=%d truncated=%v", len(out.Sections), out.SectionsTruncated)
		}
		if !out.EOF && out.NextOffset <= out.Offset {
			t.Fatalf("expected forward progress when !eof: offset=%d next_offset=%d", out.Offset, out.NextOffset)
		}
		if len(out.Content) == 0 || !utf8.ValidString(out.Content) {
			t.Fatalf("expected non-empty valid UTF-8 content, got %q", out.Content)
		}
	})

	t.Run("authorized audit failure aborts with zero plugin calls", func(t *testing.T) {
		before := stub.readCalls
		failID := &knowledgeIdentity{failAllAudits: true}
		failSvc := &Service{identity: failID, config: Config{Knowledge: stub}}
		_, err := failSvc.readRunbook(t.Context(), json.RawMessage(`{"source":"ops","id":"guide.md"}`))
		if connect.CodeOf(err) != connect.CodeUnavailable || stub.readCalls != before {
			t.Fatalf("err=%v readCalls before=%d after=%d", err, before, stub.readCalls)
		}
	})
}

func TestKnowledgeResourceMiddlewareAuditAndAuth(t *testing.T) {
	t.Run("denied writes result/deny audit and makes zero plugin calls", func(t *testing.T) {
		stub := &knowledgeStub{sources: []string{"ops"}, indexRev: "r1"}
		id := &knowledgeIdentity{denied: true}
		s := &Service{identity: id, config: Config{Knowledge: stub}}
		nextCalled := false
		_, err := s.handleKnowledgeResourceMethod(t.Context(), "resources/list", nil, func(context.Context, string, sdk.Request) (sdk.Result, error) {
			nextCalled = true
			return nil, nil
		})
		if connect.CodeOf(err) != connect.CodePermissionDenied || nextCalled || stub.searchCalls != 0 {
			t.Fatalf("err=%v next=%v calls=%d", err, nextCalled, stub.searchCalls)
		}
		events := id.auditSnapshot()
		if len(events) != 1 || events[0].Operation != "mcp/resources/list" || events[0].Phase != "result" || events[0].Outcome != "deny" {
			t.Fatalf("events=%+v", events)
		}
	})

	t.Run("authorized audit failure aborts immediately with zero plugin calls and no result audit", func(t *testing.T) {
		stub := &knowledgeStub{sources: []string{"ops"}, indexRev: "r1"}
		id := &knowledgeIdentity{failAuditAt: 1} // fail only the first audit call (authorized)
		s := &Service{identity: id, config: Config{Knowledge: stub}}
		nextCalled := false
		_, err := s.handleKnowledgeResourceMethod(t.Context(), "resources/read", &sdk.ReadResourceRequest{Params: &sdk.ReadResourceParams{URI: "allowops://runbooks/ops/a.md"}}, func(context.Context, string, sdk.Request) (sdk.Result, error) {
			nextCalled = true
			return nil, nil
		})
		if connect.CodeOf(err) != connect.CodeUnavailable || nextCalled || stub.readCalls != 0 {
			t.Fatalf("err=%v next=%v readCalls=%d", err, nextCalled, stub.readCalls)
		}
		// Because failAuditAt == 1 failed authorized audit, if code tried to write a 2nd result audit it would have succeeded and appeared in events!
		if events := id.auditSnapshot(); len(events) != 0 {
			t.Fatalf("expected zero secondary result audit calls after authorized failure, got %+v", events)
		}
	})

	t.Run("business error still writes authorized and result/deny audit", func(t *testing.T) {
		stub := &knowledgeStub{sources: []string{"ops"}, indexRev: "r1"}
		id := &knowledgeIdentity{}
		s := &Service{identity: id, config: Config{Knowledge: stub}}
		_, err := s.handleKnowledgeResourceMethod(t.Context(), "resources/read", &sdk.ReadResourceRequest{Params: &sdk.ReadResourceParams{URI: "allowops://runbooks/ops/missing.md"}}, func(ctx context.Context, _ string, r sdk.Request) (sdk.Result, error) {
			return s.readRunbookResource(ctx, r.(*sdk.ReadResourceRequest))
		})
		if err == nil {
			t.Fatal("expected not found error")
		}
		events := id.auditSnapshot()
		if len(events) != 2 ||
			events[0].Phase != "authorized" || events[0].Outcome != "allow" ||
			events[1].Phase != "result" || events[1].Outcome != "deny" {
			t.Fatalf("unexpected events: %+v", events)
		}
	})
}

func TestKnowledgeResourcesOverRealHTTPTransportAnd32KiBBudget(t *testing.T) {
	// Build a large set of resources AND a >40 KiB multi-byte UTF-8 document to stress-test exact HTTP wire size <= 32768.
	stub := &knowledgeStub{
		sources:  []string{"ops"},
		indexRev: "idx-rev-1",
		reads:    make(map[[2]string]pluginhost.KnowledgeReadResult),
	}
	for i := range 60 {
		id := fmt.Sprintf("runbook-%03d.md", i)
		stub.docs = append(stub.docs, pluginhost.KnowledgeDocResult{
			Source: "ops",
			Doc: knowledge.Doc{
				ID:      id,
				Title:   fmt.Sprintf("Runbook %03d", i),
				Summary: strings.Repeat("排障说明", 100), // 1200 bytes each -> 60 items > 72 KiB!
			},
		})
	}
	bigContent := strings.Repeat("多字节中文排障步骤🚀\n", 1800) // > 50 KiB
	stub.reads[[2]string{"ops", "big.md"}] = pluginhost.KnowledgeReadResult{
		KnowledgeDocResult: pluginhost.KnowledgeDocResult{
			Source: "ops",
			Doc:    knowledge.Doc{ID: "big.md", Title: "Big Runbook"},
		},
		Content:  bigContent,
		Revision: "rev-big-1",
	}

	id := &knowledgeIdentity{pageSize: 100}
	svc := &Service{identity: id, config: Config{Knowledge: stub}}

	server := sdk.NewServer(
		&sdk.Implementation{Name: "allowops", Version: "1"},
		&sdk.ServerOptions{
			Capabilities: &sdk.ServerCapabilities{Resources: &sdk.ResourceCapabilities{}},
			SetCacheable: func(_ context.Context, _ sdk.Request, c *sdk.Cacheable) { c.TTLMs = 0; c.CacheScope = "private" },
		},
	)
	server.AddResourceTemplate(&sdk.ResourceTemplate{
		Name:        "runbooks",
		URITemplate: runbookResourceTemplateURI,
		MIMEType:    "text/markdown",
	}, svc.readRunbookResource)
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, r sdk.Request) (sdk.Result, error) {
			return svc.handleKnowledgeResourceMethod(ctx, method, r, next)
		}
	})

	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{Stateless: true})
	httpSrv := httptest.NewTLSServer(handler)
	defer httpSrv.Close()

	postRPC := func(t *testing.T, protocolVersion, method, name, body string) (json.RawMessage, *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, httpSrv.URL, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if protocolVersion != "" {
			req.Header.Set("MCP-Protocol-Version", protocolVersion)
		}
		if method != "" {
			req.Header.Set("Mcp-Method", method)
		}
		if name != "" {
			req.Header.Set("Mcp-Name", name)
		}
		resp, err := httpSrv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		rawBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d body=%s", resp.StatusCode, string(rawBody))
		}
		// Extract JSON payload whether returned directly or via SSE data line.
		payload := bytes.TrimSpace(rawBody)
		if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
			for line := range strings.Lines(string(rawBody)) {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "data:") {
					data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
					if data != "" {
						payload = []byte(data)
					}
				}
			}
		}
		var envelope struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(payload, &envelope); err != nil {
			t.Fatalf("unmarshal rpc response %q: %v", string(payload), err)
		}
		return envelope.Result, envelope.Error
	}

	// 1a. resources/list with completely OMITTED "params" field must succeed!
	omittedResult, rpcErr := postRPC(t, "2025-11-25", "", "", `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)
	if rpcErr != nil {
		t.Fatalf("resources/list without params failed: %+v", rpcErr)
	}
	if len(omittedResult) > resultByteLimit {
		t.Fatalf("real wire resources/list (omitted params) result size = %d > %d", len(omittedResult), resultByteLimit)
	}

	// 1b. Current protocol 2026-07-28 adds resultType + _meta["io.modelcontextprotocol/serverInfo"] + Cacheable: verify real wire <= 32768!
	const newProto = "2026-07-28"
	const newProtoMeta = `{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}`
	firstResult, rpcErr := postRPC(t, newProto, "resources/list", "", fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"resources/list","params":{"_meta":%s}}`, newProtoMeta))
	if rpcErr != nil {
		t.Fatalf("resources/list (2026-07-28) failed: %+v", rpcErr)
	}
	if len(firstResult) > resultByteLimit {
		t.Fatalf("real wire resources/list result size = %d > %d", len(firstResult), resultByteLimit)
	}
	var page1 struct {
		ResultType string          `json:"resultType"`
		Meta       map[string]any  `json:"_meta"`
		TTLMs      int             `json:"ttlMs"`
		CacheScope string          `json:"cacheScope"`
		NextCursor string          `json:"nextCursor"`
		Resources  []*sdk.Resource `json:"resources"`
	}
	if err := json.Unmarshal(firstResult, &page1); err != nil {
		t.Fatal(err)
	}
	if page1.ResultType != "complete" || page1.CacheScope != "private" || page1.TTLMs != 0 ||
		page1.Meta["output_trust"] != "untrusted" || page1.Meta[sdk.MetaKeyServerInfo] == nil ||
		len(page1.Resources) == 0 || page1.NextCursor == "" {
		t.Fatalf("unexpected page1: %+v", page1)
	}

	// 2. Follow nextCursor across all pages until complete, checking every page <= 32768 bytes.
	totalSeen := len(page1.Resources)
	cursor := page1.NextCursor
	for step := 3; cursor != "" && step < 20; step++ {
		resRaw, rpcErr := postRPC(t, newProto, "resources/list", "", fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"resources/list","params":{"cursor":%q,"_meta":%s}}`, step, cursor, newProtoMeta))
		if rpcErr != nil {
			t.Fatalf("page %d failed: %+v", step, rpcErr)
		}
		if len(resRaw) > resultByteLimit {
			t.Fatalf("page %d wire size = %d > %d", step, len(resRaw), resultByteLimit)
		}
		var p struct {
			NextCursor string          `json:"nextCursor"`
			Resources  []*sdk.Resource `json:"resources"`
		}
		if err := json.Unmarshal(resRaw, &p); err != nil {
			t.Fatal(err)
		}
		totalSeen += len(p.Resources)
		cursor = p.NextCursor
	}
	if totalSeen != 60 || cursor != "" {
		t.Fatalf("paginated totalSeen=%d cursor=%q, want 60 and empty", totalSeen, cursor)
	}

	// 3. Stale cursor after index revision change returns InvalidArgument.
	stub.mu.Lock()
	stub.indexRev = "idx-rev-2"
	stub.mu.Unlock()
	if _, err := svc.listRunbookResources(t.Context(), &sdk.ListResourcesRequest{Params: &sdk.ListResourcesParams{Cursor: page1.NextCursor}}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument on stale cursor, got %v", err)
	}

	// 4. resources/templates/list works through middleware.
	tmplRaw, rpcErr := postRPC(t, newProto, "resources/templates/list", "", fmt.Sprintf(`{"jsonrpc":"2.0","id":30,"method":"resources/templates/list","params":{"_meta":%s}}`, newProtoMeta))
	if rpcErr != nil {
		t.Fatalf("resources/templates/list failed: %+v", rpcErr)
	}
	if !strings.Contains(string(tmplRaw), runbookResourceTemplateURI) {
		t.Fatalf("template missing in %s", string(tmplRaw))
	}

	// 5. resources/read of >50 KiB document returns real wire result <= 32768 bytes with truncation notice and valid next_offset!
	readRaw, rpcErr := postRPC(t, newProto, "resources/read", "allowops://runbooks/ops/big.md", fmt.Sprintf(`{"jsonrpc":"2.0","id":40,"method":"resources/read","params":{"uri":"allowops://runbooks/ops/big.md","_meta":%s}}`, newProtoMeta))
	if rpcErr != nil {
		t.Fatalf("resources/read failed: %+v", rpcErr)
	}
	if len(readRaw) > resultByteLimit {
		t.Fatalf("real wire resources/read result size = %d > %d", len(readRaw), resultByteLimit)
	}
	var readResp struct {
		ResultType string         `json:"resultType"`
		Meta       map[string]any `json:"_meta"`
		TTLMs      int            `json:"ttlMs"`
		CacheScope string         `json:"cacheScope"`
		Contents   []struct {
			URI      string         `json:"uri"`
			MIMEType string         `json:"mimeType"`
			Text     string         `json:"text"`
			Meta     map[string]any `json:"_meta"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(readRaw, &readResp); err != nil {
		t.Fatal(err)
	}
	if readResp.ResultType != "complete" || readResp.CacheScope != "private" || readResp.TTLMs != 0 ||
		readResp.Meta[sdk.MetaKeyServerInfo] == nil || len(readResp.Contents) != 1 {
		t.Fatalf("unexpected readResp: %+v", readResp)
	}
	c := readResp.Contents[0]
	nextOff := int(c.Meta["next_offset"].(float64))
	totalBytes := int(c.Meta["total_bytes"].(float64))
	if c.Meta["output_trust"] != "untrusted" || c.Meta["revision"] != "rev-big-1" ||
		c.Meta["truncated"] != true || totalBytes != len(bigContent) || nextOff <= 0 || nextOff >= len(bigContent) {
		t.Fatalf("unexpected content meta: %+v", c.Meta)
	}
	if !utf8.RuneStart(bigContent[nextOff]) || !strings.Contains(c.Text, "runbooks_read") {
		t.Fatalf("next_offset=%d not UTF-8 aligned or missing continuation hint", nextOff)
	}
	// Verify seamless continuation via runbooks_read from next_offset!
	contRes, err := svc.readRunbook(t.Context(), json.RawMessage(fmt.Sprintf(`{"source":"ops","id":"big.md","offset":%d,"revision":"rev-big-1"}`, nextOff)))
	if err != nil {
		t.Fatalf("continuation via runbooks_read failed: %v", err)
	}
	contOut := contRes.StructuredContent.(runbookReadResult)
	if !strings.HasPrefix(bigContent[nextOff:], contOut.Content) || len(contOut.Content) == 0 {
		t.Fatalf("continuation content mismatch")
	}
}

func TestKnowledgeEndToEndSnapshotRefreshTOCTOUAndRevision(t *testing.T) {
	dir := t.TempDir()
	docPath := filepath.Join(dir, "guide.md")
	if err := os.WriteFile(docPath, []byte("---\ntitle: Guide\nsummary: password=topsecret\n---\n# Steps\nUse topsecret carefully.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var nowMu sync.Mutex
	curNow := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curNow
	}

	var cfgNode yaml.Node
	if err := yaml.Unmarshal([]byte(fmt.Sprintf("dir: %q\nrefresh_ttl: 1m\n", dir)), &cfgNode); err != nil {
		t.Fatal(err)
	}
	host, err := pluginhost.New(t.Context(), []pluginhost.Config{{
		ID:     "ops",
		Module: "knowledge.git_markdown",
		Config: *cfgNode.Content[0],
	}}, pluginhost.Deps{Now: nowFn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { host.Close(context.Background()) })

	svc := &Service{identity: &knowledgeIdentity{}, config: Config{Knowledge: host}}

	// 1. Search finds guide.md; read redacts metadata secret from body too.
	sRes, err := svc.searchRunbooks(t.Context(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	sOut := sRes.StructuredContent.(runbookSearchResult)
	if len(sOut.Docs) != 1 || sOut.Docs[0].ID != "guide.md" || strings.Contains(sOut.Docs[0].Summary, "topsecret") {
		t.Fatalf("unexpected search out: %+v", sOut)
	}
	rRes, err := svc.readRunbook(t.Context(), json.RawMessage(`{"source":"ops","id":"guide.md"}`))
	if err != nil {
		t.Fatal(err)
	}
	rOut := rRes.StructuredContent.(runbookReadResult)
	if strings.Contains(rOut.Content, "topsecret") || rOut.Revision == "" {
		t.Fatalf("metadata secret leaked into content or missing revision: %+v", rOut)
	}

	// 2. Modify file & advance clock past TTL -> old revision fails with FailedPrecondition.
	if err := os.WriteFile(docPath, []byte("# Steps\nUpdated body.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	nowMu.Lock()
	curNow = curNow.Add(2 * time.Minute)
	nowMu.Unlock()
	if _, err := svc.readRunbook(t.Context(), json.RawMessage(fmt.Sprintf(`{"source":"ops","id":"guide.md","revision":%q}`, rOut.Revision))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("expected FailedPrecondition after refresh, got %v", err)
	}

	// 3. Refresh makes guide.md's ID match a metadata secret -> both runbooks_read and resources/read return NotFound (no TOCTOU leak).
	if err := os.WriteFile(docPath, []byte("---\ntitle: Guide\nsummary: password=guide\n---\n# Hidden\nsecret body\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	nowMu.Lock()
	curNow = curNow.Add(2 * time.Minute)
	nowMu.Unlock()
	if _, err := svc.readRunbook(t.Context(), json.RawMessage(`{"source":"ops","id":"guide.md"}`)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("expected NotFound when refreshed doc becomes hidden, got %v", err)
	}
	if _, err := svc.readRunbookResource(t.Context(), &sdk.ReadResourceRequest{Params: &sdk.ReadResourceParams{URI: "allowops://runbooks/ops/guide.md"}}); err == nil {
		t.Fatal("expected ResourceNotFoundError when refreshed doc becomes hidden")
	}
}
