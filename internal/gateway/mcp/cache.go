package mcp

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/store/db"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type ruleSnapshot []authz.Rule

func (r ruleSnapshot) LoadRules(context.Context) ([]authz.Rule, error) { return r, nil }

func (s *Service) serverFor(ctx context.Context) (*sdk.Server, error) {
	version, rules, err := s.identity.PolicySnapshot(ctx)
	if err != nil {
		return nil, err
	}
	current, err := s.identity.Store.Queries.CurrentCatalogs(ctx)
	if err != nil {
		return nil, err
	}
	live := make([]db.CurrentCatalogsRow, 0, len(current))
	for _, c := range current {
		if time.Now().After(c.ExpiresAt.Time.Add(catalog.ClockSkew)) {
			continue
		}
		live = append(live, c)
	}
	data, err := json.Marshal(struct {
		Policy   uint64
		Catalogs []db.CurrentCatalogsRow
	}{version, live})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	versions := hex.EncodeToString(sum[:])
	id, ok := api.FromContext(ctx)
	if !ok {
		return nil, errors.New("authentication required")
	}
	actor := api.RequestAuditInfo(ctx).ActorID
	data, err = json.Marshal(struct {
		Actor    string
		Subject  authz.Subject
		Versions string
	}{actor, id.Subject, versions})
	if err != nil {
		return nil, err
	}
	sum = sha256.Sum256(data)
	key := hex.EncodeToString(sum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if versions != s.versions {
		s.entries = map[string]*list.Element{}
		s.lru.Init()
		s.versions = versions
	}
	if element := s.entries[key]; element != nil {
		s.lru.MoveToFront(element)
		return element.Value.(*cacheEntry).server, nil
	}
	actions := map[string]catalog.Action{}
	for _, c := range live {
		if c.EnvelopeSizeBytes > int64(s.catalogs.MaxEnvelopeBytes) {
			return nil, errors.New("catalog exceeds envelope limit")
		}
		stored, err := s.identity.Store.Queries.GetCatalog(ctx, db.GetCatalogParams{CatalogID: c.CatalogID, Version: c.Version})
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(stored.Dsse)
		if !slices.Equal(digest[:], c.Digest) {
			return nil, errors.New("stored catalog digest mismatch")
		}
		pkg, err := s.catalogs.Verify(stored.Dsse)
		if err != nil {
			return nil, err
		}
		if pkg.CatalogID != c.CatalogID || pkg.Version != c.Version {
			return nil, errors.New("stored catalog reference mismatch")
		}
		for name, a := range pkg.Actions {
			if _, duplicate := actions[name]; duplicate {
				return nil, errors.New("duplicate catalog action")
			}
			actions[name] = a
		}
	}
	// G40: discovery ignores host, time and source IP. A deny with any of
	// these conditions cannot prove that every possible call is denied.
	projected := ruleSnapshot{}
	for _, rule := range rules {
		if rule.Effect == "deny" && (len(rule.HostLabels) > 0 || rule.Hours != nil || len(rule.SourceCIDRs) > 0) {
			continue
		}
		rule.HostLabels = nil
		rule.Hours = nil
		rule.SourceCIDRs = nil
		projected = append(projected, rule)
	}
	engine, err := authz.New(ctx, projected, nil)
	if err != nil {
		return nil, err
	}
	definitions := fixedTools(s.config.Jobs)
	names := slices.Collect(maps.Keys(actions))
	slices.Sort(names)
	available := map[string]bool{}
	unsupported := map[string]bool{}
	for _, tool := range definitions {
		available[tool.Name] = true
	}
	for _, name := range names {
		a := actions[name]
		result, err := engine.Evaluate(ctx, authz.Input{Subject: id.Subject, Operation: authz.ExecuteAction, Action: authz.Action{Name: name, Risk: a.Risk}})
		if err != nil {
			return nil, err
		}
		if result.Decision != "allow" {
			continue
		}
		tool, err := actionTool(a, s.config.Jobs)
		if errors.Is(err, errUnsupportedActionSchema) {
			// Preserve projected visibility for a stable direct-call error without
			// registering an invalid SDK schema or dispatching the action.
			available[name] = true
			unsupported[name] = true
			continue
		}
		if err != nil {
			return nil, err
		}
		definitions = append(definitions, *tool)
		available[name] = true
	}
	server := sdk.NewServer(&sdk.Implementation{Name: "allowops", Version: "1"}, &sdk.ServerOptions{Instructions: toolInstructions, PageSize: s.identity.Config.PageSize, Capabilities: &sdk.ServerCapabilities{Tools: &sdk.ToolCapabilities{}}, SetCacheable: func(_ context.Context, _ sdk.Request, c *sdk.Cacheable) { c.TTLMs = 0; c.CacheScope = "private" }})
	for _, definition := range definitions {
		tool := &sdk.Tool{Name: definition.Name, Description: definition.Description, InputSchema: definition.InputSchema, Annotations: &sdk.ToolAnnotations{ReadOnlyHint: definition.Annotations.ReadOnlyHint, DestructiveHint: definition.Annotations.DestructiveHint, IdempotentHint: definition.Annotations.IdempotentHint}}
		server.AddTool(tool, func(ctx context.Context, r *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return s.call(ctx, r, available)
		})
	}
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, r sdk.Request) (sdk.Result, error) {
			if method != "tools/call" {
				return next(ctx, method, r)
			}
			// The SDK has validated the POST and set SSE headers before publishing
			// the request. Commit them now so G50 comments can keep a waiting call alive.
			if writer, ok := ctx.Value(heartbeatContextKey{}).(*sseWriter); ok {
				writer.Flush()
			}
			ctx = api.ForkRequestContext(ctx)
			call, ok := r.(*sdk.CallToolRequest)
			if !ok {
				return nil, errors.New("invalid tool request")
			}
			if !available[call.Params.Name] || unsupported[call.Params.Name] {
				return s.call(ctx, call, available)
			}
			return next(ctx, method, r)
		}
	})
	element := s.lru.PushFront(&cacheEntry{key: key, server: server})
	s.entries[key] = element
	if s.lru.Len() > s.config.CacheEntries {
		old := s.lru.Back()
		delete(s.entries, old.Value.(*cacheEntry).key)
		s.lru.Remove(old)
	}
	return server, nil
}
