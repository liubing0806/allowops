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
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store/db"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type ruleSnapshot []authz.Rule

func (r ruleSnapshot) LoadRules(context.Context) ([]authz.Rule, error) { return r, nil }

// serverSnapshot is what serverFor derives from the request before it takes the
// cache lock: the policy rules, the unexpired catalogs, and the cache keys.
type serverSnapshot struct {
	rules    []authz.Rule
	live     []db.CurrentCatalogsRow
	id       *reqctx.Identity
	versions string
	key      string
}

func (s *Service) serverFor(ctx context.Context) (*sdk.Server, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.versions != s.versions {
		s.entries = map[string]*list.Element{}
		s.lru.Init()
		s.versions = snap.versions
	}
	if element := s.entries[snap.key]; element != nil {
		s.lru.MoveToFront(element)
		return element.Value.(*cacheEntry).server, nil
	}
	actions, err := s.loadActions(ctx, snap.live)
	if err != nil {
		return nil, err
	}
	engine, err := authz.New(ctx, projectRules(snap.rules), nil)
	if err != nil {
		return nil, err
	}
	definitions, available, unsupported, err := visibleTools(ctx, engine, snap.id, actions)
	if err != nil {
		return nil, err
	}
	server := s.newServer(definitions, available, unsupported)
	s.storeServer(snap.key, server)
	return server, nil
}

// snapshot reads the policy and catalog versions and hashes them, with the
// caller identity, into the cache keys.
func (s *Service) snapshot(ctx context.Context) (*serverSnapshot, error) {
	version, rules, err := s.identity.PolicySnapshot(ctx)
	if err != nil {
		return nil, err
	}
	current, err := s.identity.Database().Queries.CurrentCatalogs(ctx)
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
	id, ok := reqctx.FromContext(ctx)
	if !ok {
		return nil, errors.New("authentication required")
	}
	actor := reqctx.RequestAuditInfo(ctx).ActorID
	data, err = json.Marshal(struct {
		Actor    string
		Subject  authz.Subject
		Versions string
	}{actor, id.Subject, versions})
	if err != nil {
		return nil, err
	}
	sum = sha256.Sum256(data)
	return &serverSnapshot{rules: rules, live: live, id: id, versions: versions, key: hex.EncodeToString(sum[:])}, nil
}

// loadActions verifies each live catalog against its stored digest and merges
// the actions. It runs under the cache lock.
func (s *Service) loadActions(ctx context.Context, live []db.CurrentCatalogsRow) (map[string]catalog.Action, error) {
	actions := map[string]catalog.Action{}
	for _, c := range live {
		if c.EnvelopeSizeBytes > int64(s.catalogs.MaxEnvelopeBytes) {
			return nil, errors.New("catalog exceeds envelope limit")
		}
		stored, err := s.identity.Database().Queries.GetCatalog(ctx, db.GetCatalogParams{CatalogID: c.CatalogID, Version: c.Version})
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
	return actions, nil
}

// projectRules drops conditions that discovery cannot evaluate.
// Discovery ignores host, time and source IP. A deny with any of
// these conditions cannot prove that every possible call is denied (design G40).
func projectRules(rules []authz.Rule) ruleSnapshot {
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
	return projected
}

// visibleTools returns the tool definitions to register, plus the set of
// callable names and the subset whose schema the SDK cannot register.
func visibleTools(ctx context.Context, engine *authz.Engine, id *reqctx.Identity, actions map[string]catalog.Action) ([]ToolDefinition, map[string]bool, map[string]bool, error) {
	definitions := fixedTools()
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
			return nil, nil, nil, err
		}
		if result.Decision != "allow" {
			continue
		}
		tool, err := actionTool(a)
		if errors.Is(err, errUnsupportedActionSchema) {
			// Preserve projected visibility for a stable direct-call error without
			// registering an invalid SDK schema or dispatching the action.
			available[name] = true
			unsupported[name] = true
			continue
		}
		if err != nil {
			return nil, nil, nil, err
		}
		definitions = append(definitions, *tool)
		available[name] = true
	}
	return definitions, available, unsupported, nil
}

func (s *Service) newServer(definitions []ToolDefinition, available, unsupported map[string]bool) *sdk.Server {
	server := sdk.NewServer(&sdk.Implementation{Name: "allowops", Version: "1"}, &sdk.ServerOptions{Instructions: toolInstructions, PageSize: s.identity.PageSize(), Capabilities: &sdk.ServerCapabilities{Tools: &sdk.ToolCapabilities{}}, SetCacheable: func(_ context.Context, _ sdk.Request, c *sdk.Cacheable) { c.TTLMs = 0; c.CacheScope = "private" }})
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
			// the request. Commit them now so SSE keepalive comments can keep a waiting call alive (design G50).
			if writer, ok := ctx.Value(heartbeatContextKey{}).(*sseWriter); ok {
				writer.Flush()
			}
			ctx = reqctx.ForkRequestContext(ctx)
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
	return server
}

// storeServer adds a server to the LRU and evicts the oldest entry over the
// limit. The caller holds s.mu.
func (s *Service) storeServer(key string, server *sdk.Server) {
	element := s.lru.PushFront(&cacheEntry{key: key, server: server})
	s.entries[key] = element
	if s.lru.Len() > s.config.CacheEntries {
		old := s.lru.Back()
		delete(s.entries, old.Value.(*cacheEntry).key)
		s.lru.Remove(old)
	}
}
