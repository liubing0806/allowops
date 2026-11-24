package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/plugin/changes"
)

type changesStub struct {
	sources  []string
	items    []pluginhost.ChangeResult
	more     bool
	errors   []pluginhost.SourceError
	query    pluginhost.ChangesQuery
	selected []string
	calls    int
	trace    *[]string
}

func (c *changesStub) ChangesSources() []string { return c.sources }

func (c *changesStub) ListChanges(_ context.Context, q pluginhost.ChangesQuery, selected []string) ([]pluginhost.ChangeResult, bool, []pluginhost.SourceError) {
	c.calls++
	c.query, c.selected = q, selected
	if c.trace != nil {
		*c.trace = append(*c.trace, "list")
	}
	return c.items, c.more, c.errors
}

type changesIdentity struct {
	Identity
	authErr  error
	auditErr error
	required int
	events   []reqctx.AuditEvent
	trace    *[]string
}

func (id *changesIdentity) Require(_ context.Context, operation authz.Operation, action authz.Action, host authz.Host) (authz.Result, error) {
	if operation != authz.ViewChanges || !reflect.DeepEqual(action, authz.Action{}) || !reflect.DeepEqual(host, authz.Host{}) {
		panic("wrong authorization input")
	}
	id.required++
	if id.trace != nil {
		*id.trace = append(*id.trace, "require")
	}
	return authz.Result{}, id.authErr
}

func (id *changesIdentity) AppendResultAudit(_ context.Context, e reqctx.AuditEvent) error {
	id.events = append(id.events, e)
	if id.trace != nil {
		*id.trace = append(*id.trace, e.Phase)
	}
	return id.auditErr
}

type changesRequest struct{ reqctx.Request }

func (changesRequest) Identity() *reqctx.Identity {
	return &reqctx.Identity{Subject: authz.Subject{ID: "svc-operations"}}
}
func (changesRequest) SourceIP() string       { return "192.0.2.1" }
func (changesRequest) PolicyVersion() uint64  { return 7 }
func (changesRequest) MatchedRules() []string { return []string{"changes-reader"} }

func TestChangesToolSchema(t *testing.T) {
	tool := changesTool([]string{"local", "feed"})
	if tool.Name != "changes_list" || !tool.Annotations.ReadOnlyHint || !strings.HasSuffix(tool.Description, toolInstructions) {
		t.Fatal(tool)
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(mustJSON(t, tool.InputSchema), &schema); err != nil {
		t.Fatal(err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []map[string]any{
		{},
		{"services": []any{"api"}, "sources": []any{"local", "feed"}, "from": "2026-01-01T00:00:00Z", "to": "2026-01-02T00:00:00Z", "limit": float64(100)},
		{"services": []any{}, "sources": []any{}, "limit": float64(1)},
	} {
		if err := resolved.Validate(input); err != nil {
			t.Fatalf("schema rejected %v: %v", input, err)
		}
	}
	for _, input := range []map[string]any{
		{"extra": true}, {"services": "api"}, {"services": []any{""}}, {"services": []any{strings.Repeat("x", 129)}},
		{"services": slices.Repeat([]any{"api"}, 21)}, {"sources": []any{"unknown"}}, {"sources": []any{nil}},
		{"limit": float64(0)}, {"limit": float64(101)}, {"limit": float64(1.5)}, {"from": 123}, {"to": nil},
		{"from": "2026-01-01T0:00:00Z"}, {"to": "2026-01-01T00:00:00+00:60"},
	} {
		if err := resolved.Validate(input); err == nil {
			t.Fatalf("schema accepted %v", input)
		}
	}
}

func TestChangesInvalidArgumentsBeforeAuthorization(t *testing.T) {
	for _, input := range []string{
		`[]`, `{"extra":true}`, `{"limit":1,"limit":2}`, `{"limit":0}`, `{"limit":101}`, `{"limit":1.5}`, `{"limit":null}`,
		`{"services":null}`, `{"services":[null]}`, `{"services":[""]}`, `{"services":[1]}`,
		string(mustJSON(t, map[string]any{"services": slices.Repeat([]string{"api"}, 21)})),
		string(mustJSON(t, map[string]any{"services": []string{strings.Repeat("中", 43)}})),
		`{"from":""}`, `{"from":null}`, `{"from":"2026-02-30T00:00:00Z"}`, `{"to":"2026-01-01T00:00:00"}`,
		`{"from":"2026-01-01T0:00:00Z","to":"2026-01-01T01:00:00Z"}`,
		`{"from":"2026-01-01T00:00:00,1Z","to":"2026-01-01T01:00:00Z"}`,
		`{"from":"2026-01-02T00:00:00+24:00","to":"2026-01-01T01:00:00Z"}`,
		`{"from":"2026-01-01T01:00:00+00:60","to":"2026-01-01T01:00:00Z"}`,
		`{"from":"9999-12-31T23:00:00-02:00","to":"9999-12-31T23:00:00-02:00"}`,
		`{"to":"2026-01-01T00:00:00Z","from":"2026-01-01T00:00:01Z"}`,
		`{"from":"2026-01-01T00:00:00Z","to":"2026-01-08T00:00:00.000000001Z"}`,
		`{"sources":"local"}`, `{"sources":[1]}`, `{"sources":[null]}`, `{"sources":["unknown-source"]}`,
	} {
		t.Run(input, func(t *testing.T) {
			id := &changesIdentity{}
			source := &changesStub{sources: []string{"local"}}
			s := &Service{identity: id, config: Config{Changes: source}}
			_, err := s.listChanges(t.Context(), json.RawMessage(input))
			if connect.CodeOf(err) != connect.CodeInvalidArgument || id.required != 0 || len(id.events) != 0 || source.calls != 0 {
				t.Fatalf("error = %v, auth calls = %d, audits = %d, source calls = %d", err, id.required, len(id.events), source.calls)
			}
			if strings.Contains(err.Error(), "unknown-source") {
				t.Fatal("returned the caller's unknown source value")
			}
		})
	}
}

func TestChangesWindowAndSelection(t *testing.T) {
	id := &changesIdentity{}
	source := &changesStub{sources: []string{"local", "feed"}}
	s := &Service{identity: id, config: Config{Changes: source}}
	before := time.Now()
	result, err := s.listChanges(t.Context(), nil)
	after := time.Now()
	if err != nil {
		t.Fatal(err)
	}
	q := source.query
	if q.To.Location() != time.UTC || q.From.Location() != time.UTC || q.To.Before(before) || q.To.After(after) || q.To.Sub(q.From) != 24*time.Hour ||
		result.StructuredContent.(changesResult).To != q.To || result.StructuredContent.(changesResult).From != q.From {
		t.Fatalf("default window = [%v, %v], before = %v, after = %v", q.From, q.To, before, after)
	}
	service := strings.Repeat("中", 42) + "xy"
	for _, end := range []string{"2026-01-01T06:00:00+06:00", "2026-01-08t00:00:00z"} {
		raw := mustJSON(t, map[string]any{
			"from": "2026-01-01T01:00:00+01:00", "to": end, "services": []string{"api", service}, "sources": []string{"feed"},
		})
		result, err := s.listChanges(t.Context(), raw)
		if err != nil {
			t.Fatal(err)
		}
		out := result.StructuredContent.(changesResult)
		if source.query.From.Format(time.RFC3339) != "2026-01-01T00:00:00Z" || source.query.To.Location() != time.UTC ||
			source.query.From != out.From || source.query.To != out.To || !slices.Equal(source.query.Services, []string{"api", service}) ||
			!slices.Equal(source.selected, []string{"feed"}) {
			t.Fatalf("query = %+v, selected = %v, result = %+v", source.query, source.selected, out)
		}
	}
}

func TestChangesAuthorizationAndAuditPrecedeSource(t *testing.T) {
	for _, tc := range []struct {
		name              string
		authErr, auditErr error
		code              connect.Code
		trace             []string
	}{
		{name: "allowed", trace: []string{"require", "authorized", "list"}},
		{name: "permission denied", authErr: accessError(connect.CodePermissionDenied, "operation denied"), code: connect.CodePermissionDenied, trace: []string{"require"}},
		{name: "audit failed", auditErr: errors.New("private audit provider error"), code: connect.CodeUnavailable, trace: []string{"require", "authorized"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var trace []string
			id := &changesIdentity{authErr: tc.authErr, auditErr: tc.auditErr, trace: &trace}
			source := &changesStub{trace: &trace}
			s := &Service{identity: id, config: Config{Changes: source}}
			ctx := reqctx.With(t.Context(), changesRequest{})
			result, err := s.listChanges(ctx, nil)
			if !slices.Equal(trace, tc.trace) {
				t.Fatalf("order = %v, want %v", trace, tc.trace)
			}
			if tc.code != 0 {
				if result != nil || connect.CodeOf(err) != tc.code || source.calls != 0 || strings.Contains(err.Error(), "private audit provider error") {
					t.Fatalf("result = %v, error = %v, calls = %d", result, err, source.calls)
				}
			} else if result == nil || err != nil || source.calls != 1 {
				t.Fatalf("result = %v, error = %v, calls = %d", result, err, source.calls)
			}
			if tc.authErr == nil {
				want := reqctx.AuditEvent{
					ActorID: "svc-operations", SourceIP: "192.0.2.1", PolicyVersion: 7, MatchedRules: []string{"changes-reader"},
					Operation: "mcp/changes_list", Phase: "authorized", Outcome: "allow",
				}
				if !reflect.DeepEqual(id.events, []reqctx.AuditEvent{want}) {
					t.Fatalf("audit events = %+v, want %+v", id.events, want)
				}
			}
		})
	}
}

func TestChangesFailuresAndTruncation(t *testing.T) {
	item := pluginhost.ChangeResult{Change: changes.Change{
		At: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Kind: "policy", Service: "allowops-policy", Summary: "applied", Actor: "alice", Ref: "policy:v1",
	}, Source: "local"}
	for _, tc := range []struct {
		name      string
		items     []pluginhost.ChangeResult
		errors    []pluginhost.SourceError
		more      bool
		raw       string
		wantCount int
		truncated bool
	}{
		{name: "empty"},
		{name: "partial failure", items: []pluginhost.ChangeResult{item}, errors: []pluginhost.SourceError{{Source: "feed", Reason: "failed"}}, wantCount: 1},
		{name: "all sources failed", errors: []pluginhost.SourceError{{Source: "feed", Reason: "failed"}, {Source: "local", Reason: "timeout"}}},
		{name: "source has more", more: true, truncated: true},
		{name: "default limit", items: slices.Repeat([]pluginhost.ChangeResult{item}, 21), wantCount: 20, truncated: true},
		{name: "explicit limit", items: []pluginhost.ChangeResult{item, item}, raw: `{"limit":1}`, wantCount: 1, truncated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &changesStub{items: tc.items, more: tc.more, errors: tc.errors}
			s := &Service{identity: &changesIdentity{}, config: Config{Changes: source}}
			result, err := s.listChanges(t.Context(), json.RawMessage(tc.raw))
			if err != nil || result.IsError {
				t.Fatalf("result = %v, error = %v", result, err)
			}
			out := result.StructuredContent.(changesResult)
			if out.Changes == nil || out.SourceErrors == nil || len(out.Changes) != tc.wantCount || !slices.Equal(out.SourceErrors, tc.errors) ||
				out.Truncated != tc.truncated || out.OutputTrust != "untrusted" {
				t.Fatalf("result = %+v", out)
			}
			if tc.wantCount > 0 && out.Changes[0] != (changeEntry{At: item.At, Kind: item.Kind, Service: item.Service, Summary: item.Summary, Actor: item.Actor, Ref: item.Ref, Source: item.Source}) {
				t.Fatalf("first change = %+v", out.Changes[0])
			}
		})
	}
}

func TestChangesCompleteToolResultBudget(t *testing.T) {
	source := &changesStub{}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for n := range 32 {
		source.errors = append(source.errors, pluginhost.SourceError{Source: fmt.Sprintf("source-%057d", n), Reason: "timeout"})
	}
	for n := range 100 {
		source.items = append(source.items, pluginhost.ChangeResult{
			Change: changes.Change{At: at, Kind: "deploy", Service: "api", Ref: fmt.Sprint(n), Summary: strings.Repeat(`"<`, 256)},
			Source: "local",
		})
	}
	s := &Service{identity: &changesIdentity{}, config: Config{Changes: source}}
	raw := json.RawMessage(`{"limit":100}`)
	result, err := s.listChanges(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if size := len(mustJSON(t, result)); size > resultByteLimit {
		t.Fatalf("complete tool result = %d bytes, budget = %d", size, resultByteLimit)
	}
	if size := len(mustJSON(t, sdkResult(result))); size > resultByteLimit {
		t.Fatalf("SDK tool result = %d bytes, budget = %d", size, resultByteLimit)
	}
	out := result.StructuredContent.(changesResult)
	count := len(out.Changes)
	if count == 0 || count >= len(source.items) || !out.Truncated || !slices.Equal(out.SourceErrors, source.errors) {
		t.Fatalf("changes = %d, truncated = %v, source errors = %d", count, out.Truncated, len(out.SourceErrors))
	}
	oneMore := out
	next := source.items[count]
	oneMore.Changes = append(out.Changes, changeEntry{At: next.At, Kind: next.Kind, Service: next.Service, Ref: next.Ref, Summary: next.Summary, Source: next.Source})
	if _, size, err := toolResult(oneMore); err != nil || size <= resultByteLimit {
		t.Fatalf("one extra change = %d bytes, error = %v", size, err)
	}
	source.items = source.items[:1]
	source.items[0].Summary = strings.Repeat("x", resultByteLimit)
	result, err = s.listChanges(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	out = result.StructuredContent.(changesResult)
	if len(out.Changes) != 0 || !out.Truncated || !slices.Equal(out.SourceErrors, source.errors) {
		t.Fatalf("changes = %d, truncated = %v, source errors = %d", len(out.Changes), out.Truncated, len(out.SourceErrors))
	}
}
