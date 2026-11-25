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

// serverSnapshot is what viewFor derives from the request before it takes the
// cache lock: the policy rules, the unexpired catalogs, and the cache keys.
type serverSnapshot struct {
	rules    []authz.Rule
	live     []db.CurrentCatalogsRow
	id       *reqctx.Identity
	versions string
	key      string
}

// catalogSnapshot is tier 1: the verified merged actions and the projected
// policy engine for one versions key, shared by every identity.
type catalogSnapshot struct {
	versions string
	actions  map[string]catalog.Action
	engine   *authz.Engine
}

// catalogLoad lets concurrent requests for the same versions wait for one
// load instead of repeating the database reads and signature checks.
type catalogLoad struct {
	done     chan struct{}
	snapshot *catalogSnapshot
	err      error
}

// identityView is tier 2: everything one identity may see under one versions
// key, before request headers narrow it. Header-narrowed servers are built
// from it per request and never cached, so header combinations cannot evict
// other identities.
type identityView struct {
	// allAvailable holds every action the projected policy allows or requires
	// approval for, including actions with schemas this gateway cannot register.
	allAvailable map[string]catalog.Action
	// visible is allAvailable without the unsupported actions.
	visible     map[string]catalog.Action
	unsupported map[string]bool
	// flatDefs holds the prebuilt tool definition of each visible action.
	flatDefs      map[string]ToolDefinition
	defaultMode   string
	defaultServer *sdk.Server
}

const catalogLoadTimeout = 30 * time.Second

// serverScope is the read-only state the tools of one *sdk.Server use. Its
// action sets are already narrowed by X-Allowops-Toolsets.
type serverScope struct {
	// tools are the names registered with the SDK server.
	tools map[string]bool
	// metaTools are the progressive discovery/invocation tools registered in
	// this scope, distinguishing them from historical actions of the same name.
	metaTools    map[string]bool
	allAvailable map[string]catalog.Action
	visible      map[string]catalog.Action
	unsupported  map[string]bool
	flatDefs     map[string]ToolDefinition
	mode         string
	// toolsets is nil when the request did not narrow toolsets.
	toolsets []string
	versions string
}

// known reports whether a tool call names a registered tool or an action
// this identity may see, which decides whether its name is audited.
func (s *serverScope) known(name string) bool {
	_, action := s.allAvailable[name]
	return s.tools[name] || action
}

func (s *Service) serverFor(ctx context.Context, request requestScope) (*sdk.Server, error) {
	view, versions, err := s.viewFor(ctx)
	if err != nil {
		return nil, err
	}
	if request.toolsets == nil && (request.mode == "" || request.mode == view.defaultMode) {
		return view.defaultServer, nil
	}
	server, _ := s.buildServer(view, versions, request)
	return server, nil
}

// viewFor returns the cached view of the caller, building it outside the
// cache lock on a miss.
func (s *Service) viewFor(ctx context.Context) (*identityView, string, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, "", err
	}
	s.mu.Lock()
	if snap.versions != s.versions {
		s.entries = map[string]*list.Element{}
		s.lru.Init()
		s.versions = snap.versions
	}
	if element := s.entries[snap.key]; element != nil {
		s.lru.MoveToFront(element)
		view := element.Value.(*cacheEntry).view
		s.mu.Unlock()
		return view, snap.versions, nil
	}
	s.mu.Unlock()
	snapshot, err := s.catalogFor(ctx, snap)
	if err != nil {
		return nil, "", err
	}
	view, err := s.buildView(ctx, snapshot, snap.id)
	if err != nil {
		return nil, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.versions != s.versions {
		// A newer snapshot reset the cache while this view was built.
		return view, snap.versions, nil
	}
	if element := s.entries[snap.key]; element != nil {
		// Another request built the same view first; keep one server per key.
		s.lru.MoveToFront(element)
		return element.Value.(*cacheEntry).view, snap.versions, nil
	}
	s.storeView(snap.key, view)
	return view, snap.versions, nil
}

// catalogFor returns the tier 1 snapshot for the request versions. Only one
// request per versions key loads it; the others wait for that result. The
// shared load is decoupled from the initiating caller's cancellation so a
// disconnecting client does not abort concurrent waiters.
func (s *Service) catalogFor(ctx context.Context, snap *serverSnapshot) (*catalogSnapshot, error) {
	s.catalogMu.Lock()
	if current := s.catalog; current != nil && current.versions == snap.versions {
		s.catalogMu.Unlock()
		return current, nil
	}
	load := s.loads[snap.versions]
	if load != nil {
		s.catalogMu.Unlock()
		select {
		case <-load.done:
			return load.snapshot, load.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	load = &catalogLoad{done: make(chan struct{})}
	s.loads[snap.versions] = load
	s.catalogMu.Unlock()
	go func() {
		loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), catalogLoadTimeout)
		defer cancel()
		load.snapshot, load.err = s.loadCatalog(loadCtx, snap)
		s.catalogMu.Lock()
		delete(s.loads, snap.versions)
		if load.err == nil {
			s.catalog = load.snapshot
		}
		s.catalogMu.Unlock()
		close(load.done)
	}()
	select {
	case <-load.done:
		return load.snapshot, load.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Service) loadCatalog(ctx context.Context, snap *serverSnapshot) (*catalogSnapshot, error) {
	actions, err := s.loadActions(ctx, snap.live)
	if err != nil {
		return nil, err
	}
	engine, err := authz.New(ctx, projectRules(snap.rules), nil)
	if err != nil {
		return nil, err
	}
	return &catalogSnapshot{versions: snap.versions, actions: actions, engine: engine}, nil
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
// the actions. It runs outside the cache locks.
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

// buildView evaluates every action with the projected engine and prebuilds the
// flat tool definitions and the default server of one identity.
func (s *Service) buildView(ctx context.Context, snapshot *catalogSnapshot, id *reqctx.Identity) (*identityView, error) {
	view := &identityView{allAvailable: map[string]catalog.Action{}, visible: map[string]catalog.Action{}, unsupported: map[string]bool{}, flatDefs: map[string]ToolDefinition{}}
	names := slices.Collect(maps.Keys(snapshot.actions))
	slices.Sort(names)
	for _, name := range names {
		a := snapshot.actions[name]
		result, err := snapshot.engine.Evaluate(ctx, authz.Input{Subject: id.Subject, Operation: authz.ExecuteAction, Action: authz.Action{Name: name, Risk: a.Risk}})
		if err != nil {
			return nil, err
		}
		if result.Decision != "allow" && result.Decision != "require_approval" {
			continue
		}
		view.allAvailable[name] = a
		tool, err := actionTool(a, s.config.Jobs)
		if errors.Is(err, errUnsupportedActionSchema) {
			// Preserve projected visibility for a stable direct-call error without
			// registering an invalid SDK schema or dispatching the action.
			view.unsupported[name] = true
			continue
		}
		if err != nil {
			return nil, err
		}
		view.visible[name] = a
		view.flatDefs[name] = *tool
	}
	view.defaultServer, view.defaultMode = s.buildServer(view, snapshot.versions, requestScope{})
	return view, nil
}

// buildServer narrows the view to the requested toolsets, picks the
// effective mode and registers the tools of that mode (design 5.3). It only
// reads the view, so a request cannot learn about actions outside it.
func (s *Service) buildServer(view *identityView, versions string, request requestScope) (*sdk.Server, string) {
	scope := &serverScope{tools: map[string]bool{}, metaTools: map[string]bool{}, allAvailable: view.allAvailable, visible: view.visible, unsupported: view.unsupported, flatDefs: view.flatDefs, toolsets: request.toolsets, versions: versions}
	if request.toolsets != nil {
		scope.allAvailable = map[string]catalog.Action{}
		scope.visible = map[string]catalog.Action{}
		scope.unsupported = map[string]bool{}
		for name, a := range view.allAvailable {
			if !slices.Contains(request.toolsets, a.Toolset) {
				continue
			}
			scope.allAvailable[name] = a
			if view.unsupported[name] {
				scope.unsupported[name] = true
			} else {
				scope.visible[name] = a
			}
		}
	}
	scope.mode = s.effectiveMode(request.mode, len(scope.visible))
	var invSources, changeSources, knowledgeSources []string
	if s.config.Inventory != nil {
		invSources = s.config.Inventory.InventorySources()
	}
	if s.config.Changes != nil {
		changeSources = s.config.Changes.ChangesSources()
	}
	if s.config.Knowledge != nil {
		knowledgeSources = s.config.Knowledge.KnowledgeSources()
	}
	definitions := fixedPluginTools(s.config.Jobs, invSources, changeSources, knowledgeSources)
	if len(scope.visible) > 0 {
		if scope.mode == modeFlat {
			names := slices.Collect(maps.Keys(scope.visible))
			slices.Sort(names)
			for _, name := range names {
				definitions = append(definitions, view.flatDefs[name])
			}
		} else {
			definitions = append(definitions, actionsSearchTool())
			scope.metaTools["actions_search"] = true
			for _, risk := range actionRisks {
				for _, a := range scope.visible {
					if a.Risk == risk {
						tool := invokeTool(risk, s.config.Jobs)
						definitions = append(definitions, tool)
						scope.metaTools[tool.Name] = true
						break
					}
				}
			}
		}
	}
	for _, definition := range definitions {
		scope.tools[definition.Name] = true
	}
	return s.newServer(definitions, scope, len(knowledgeSources) > 0), scope.mode
}

// effectiveMode applies the X-Allowops-MCP-Mode header, then the gateway mode.
func (s *Service) effectiveMode(header string, supported int) string {
	if header != "" {
		return header
	}
	if s.config.Mode == modeAuto {
		if supported > s.config.AutoThreshold {
			return modeProgressive
		}
		return modeFlat
	}
	return s.config.Mode
}

func (s *Service) newServer(definitions []ToolDefinition, scope *serverScope, hasKnowledge bool) *sdk.Server {
	caps := &sdk.ServerCapabilities{Tools: &sdk.ToolCapabilities{}}
	if hasKnowledge {
		caps.Resources = &sdk.ResourceCapabilities{}
	}
	server := sdk.NewServer(&sdk.Implementation{Name: "allowops", Version: "1"}, &sdk.ServerOptions{Instructions: toolInstructions, PageSize: s.identity.PageSize(), Capabilities: caps, SetCacheable: func(_ context.Context, _ sdk.Request, c *sdk.Cacheable) { c.TTLMs = 0; c.CacheScope = "private" }})
	for _, definition := range definitions {
		tool := &sdk.Tool{Name: definition.Name, Description: definition.Description, InputSchema: definition.InputSchema, Annotations: &sdk.ToolAnnotations{ReadOnlyHint: definition.Annotations.ReadOnlyHint, DestructiveHint: definition.Annotations.DestructiveHint, IdempotentHint: definition.Annotations.IdempotentHint}}
		server.AddTool(tool, func(ctx context.Context, r *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return s.call(ctx, r, scope)
		})
	}
	if hasKnowledge {
		server.AddResourceTemplate(&sdk.ResourceTemplate{
			URITemplate: runbookResourceTemplateURI,
			Name:        "allowops-runbooks",
			Description: "Read-only team runbooks (untrusted data).",
			MIMEType:    "text/markdown",
		}, s.readRunbookResource)
	}
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, r sdk.Request) (sdk.Result, error) {
			if hasKnowledge && (method == "resources/list" || method == "resources/templates/list" || method == "resources/read") {
				return s.handleKnowledgeResourceMethod(ctx, method, r, next)
			}
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
			// Unknown names, unsupported actions and actions not registered in this
			// mode get a tool error rather than an SDK protocol error.
			if !scope.tools[call.Params.Name] {
				return s.call(ctx, call, scope)
			}
			return next(ctx, method, r)
		}
	})
	return server
}

// storeView adds a view to the LRU and evicts the oldest entry over the
// limit. The caller holds s.mu.
func (s *Service) storeView(key string, view *identityView) {
	element := s.lru.PushFront(&cacheEntry{key: key, view: view})
	s.entries[key] = element
	if s.lru.Len() > s.config.CacheEntries {
		old := s.lru.Back()
		delete(s.entries, old.Value.(*cacheEntry).key)
		s.lru.Remove(old)
	}
}
