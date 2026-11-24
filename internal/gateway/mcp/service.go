package mcp

import (
	"container/list"
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Identity is the part of the management API the MCP service uses.
// *api.Service implements it.
type Identity interface {
	Require(context.Context, authz.Operation, authz.Action, authz.Host) (authz.Result, error)
	VisibleHostnames(context.Context, []string) (map[string]bool, error)
	// AllowedActionsOnHost returns the candidate actions the caller may execute
	// on one host; a missing, hidden or unlabeled host returns an empty map.
	AllowedActionsOnHost(context.Context, string, []authz.Action) (map[string]bool, error)
	// Middleware authenticates requests and stores the caller in the context.
	Middleware(http.Handler) http.Handler
	// PolicySnapshot returns the current policy rules for display prechecks.
	PolicySnapshot(ctx context.Context) (uint64, []authz.Rule, error)
	// AppendResultAudit appends a result audit event for the request.
	AppendResultAudit(ctx context.Context, e reqctx.AuditEvent) error
	// ListHosts lists the hosts visible to the caller.
	ListHosts(ctx context.Context, r *connect.Request[v1.ListHostsRequest]) (*connect.Response[v1.ListHostsResponse], error)
	// Database returns the gateway store holding the catalogs.
	Database() *store.Store
	// AuditConfigured reports whether an audit sink is configured.
	AuditConfigured() bool
	Origin() string
	MessageBytes() int
	PageSize() int
}

type Inventory interface {
	InventorySources() []string
	SearchInventory(context.Context, pluginhost.Query, []string) ([]pluginhost.Result, []pluginhost.SourceError)
}

type Changes interface {
	ChangesSources() []string
	ListChanges(context.Context, pluginhost.ChangesQuery, []string) ([]pluginhost.ChangeResult, bool, []pluginhost.SourceError)
}

type Knowledge interface {
	KnowledgeSources() []string
	SearchKnowledge(context.Context, pluginhost.KnowledgeQuery, []string) ([]pluginhost.KnowledgeDocResult, string, []pluginhost.SourceError)
	ReadKnowledge(context.Context, string, string) (pluginhost.KnowledgeReadResult, error)
}

type Config struct {
	Inventory        Inventory
	Changes          Changes
	Knowledge        Knowledge
	CacheEntries     int
	ProgressInterval time.Duration
	// Jobs is the gateway job configuration. Tool schemas and argument checks use
	// the same limits as job validation; the zero value means job.DefaultConfig.
	Jobs job.Config
	// Mode is how tools/list exposes actions: flat registers one tool per
	// action, progressive registers actions_search and actions_invoke_<risk>,
	// and auto is progressive above AutoThreshold supported visible actions.
	// Empty means flat.
	Mode string
	// AutoThreshold is the auto mode action count; zero means 40.
	AutoThreshold int
	// CursorKey authenticates stateless actions_search pagination cursors with
	// HMAC-SHA256. Gateway replicas sharing the same key verify each other's
	// cursors; when empty, New generates a random 32-byte per-process key.
	CursorKey []byte
}

const (
	modeFlat        = "flat"
	modeProgressive = "progressive"
	modeAuto        = "auto"
)

type Service struct {
	identity Identity
	catalogs *catalogsvc.Service
	jobs     JobService
	config   Config
	// mu guards the identity view LRU (tier 2).
	mu       sync.Mutex
	entries  map[string]*list.Element
	lru      *list.List
	versions string
	// catalogMu guards the verified catalog snapshot (tier 1) and its loads.
	catalogMu     sync.Mutex
	catalog       *catalogSnapshot
	loads         map[string]*catalogLoad
	cursorKeyOnce sync.Once
	cursorKey     []byte
}

type cacheEntry struct {
	key  string
	view *identityView
}

type serverContextKey struct{}
type heartbeatContextKey struct{}

func New(identity Identity, catalogs *catalogsvc.Service, jobs JobService, cfg Config) (*Service, error) {
	if identity == nil || identity.Database() == nil || !identity.AuditConfigured() || catalogs == nil {
		return nil, errors.New("MCP identity, catalog verifier and auditor required")
	}
	if cfg.CacheEntries == 0 {
		cfg.CacheEntries = 128
	}
	if cfg.ProgressInterval == 0 {
		cfg.ProgressInterval = 10 * time.Second
	}
	if cfg.Jobs == (job.Config{}) {
		cfg.Jobs = job.DefaultConfig()
	}
	if cfg.Mode == "" {
		cfg.Mode = modeFlat
	}
	if cfg.AutoThreshold == 0 {
		cfg.AutoThreshold = 40
	}
	if cfg.CacheEntries < 1 || cfg.ProgressInterval <= 0 || cfg.Jobs.MaxWaitSeconds == 0 || cfg.Jobs.WaitSeconds > cfg.Jobs.MaxWaitSeconds || cfg.Jobs.BatchSize == 0 {
		return nil, errors.New("invalid MCP limits")
	}
	if cfg.Mode != modeFlat && cfg.Mode != modeProgressive && cfg.Mode != modeAuto {
		return nil, errors.New("MCP mode allowed: flat, progressive, auto")
	}
	if cfg.AutoThreshold < 1 || cfg.AutoThreshold > 1000 {
		return nil, errors.New("MCP auto threshold allowed: integer in [1,1000]")
	}
	s := &Service{identity: identity, catalogs: catalogs, jobs: jobs, config: cfg, entries: map[string]*list.Element{}, lru: list.New(), loads: map[string]*catalogLoad{}}
	if len(cfg.CursorKey) > 0 {
		s.cursorKey = slices.Clone(cfg.CursorKey)
	}
	return s, nil
}

func (s *Service) Handler() http.Handler {
	stream := sdk.NewStreamableHTTPHandler(func(r *http.Request) *sdk.Server {
		server, _ := r.Context().Value(serverContextKey{}).(*sdk.Server)
		return server
	}, &sdk.StreamableHTTPOptions{Stateless: true, MaxRequestBodyBytes: int64(s.identity.MessageBytes()), PropagateRequestCancellation: true})
	authenticated := s.identity.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := reqctx.FromContext(r.Context())
		if !ok || id == nil {
			if s.auditHTTP(r.Context(), "mcp/authenticate", "deny") != nil {
				http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="allowops"`)
			http.Error(w, "Bearer authentication required", http.StatusUnauthorized)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != s.identity.Origin() {
			if s.auditHTTP(r.Context(), "mcp/authenticate", "deny") != nil {
				http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "origin rejected", http.StatusForbidden)
			return
		}
		scope, err := parseScopeHeaders(r.Header)
		if err != nil {
			if s.auditHTTP(r.Context(), "mcp/request", "deny") != nil {
				http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		server, err := s.serverFor(r.Context(), scope)
		if err != nil {
			http.Error(w, "MCP catalog or policy unavailable", http.StatusServiceUnavailable)
			return
		}
		ctx := context.WithValue(r.Context(), serverContextKey{}, server)
		writer := newSSEWriter(w)
		ctx = context.WithValue(ctx, heartbeatContextKey{}, writer)
		done := make(chan struct{})
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			ticker := time.NewTicker(s.config.ProgressInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					writer.keepalive()
				case <-done:
					return
				}
			}
		}()
		defer func() { close(done); <-stopped }()
		stream.ServeHTTP(writer, r.WithContext(ctx))
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/mcp" && r.URL.Path != "/mcp/" {
			http.NotFound(w, r)
			return
		}
		// No MCP request parameters belong in the URL, including credentials.
		if r.URL.RawQuery != "" {
			http.Error(w, "MCP query parameters are not accepted", http.StatusBadRequest)
			return
		}
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(r.Header.Values("Authorization")) != 1 || len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			// Still use the identity middleware (design P5B) to collect authenticated audit context, while preventing
			// its console-cookie fallback from authenticating the MCP request.
			copy := r.Clone(r.Context())
			copy.Header.Del("Cookie")
			copy.Header.Del("Authorization")
			authenticated.ServeHTTP(w, copy)
			return
		}
		copy := r.Clone(r.Context())
		copy.Header.Del("Mcp-Session-Id")
		authenticated.ServeHTTP(w, copy)
	})
}

func (s *Service) auditHTTP(ctx context.Context, operation, outcome string) error {
	e := reqctx.RequestAuditInfo(ctx)
	e.Operation = operation
	e.Phase = "result"
	e.Outcome = outcome
	return s.identity.AppendResultAudit(ctx, e)
}

// metadataName matches toolset names, as catalog metadata values.
var metadataName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// requestScope holds the optional request headers that narrow tools/list.
// They shape the view only; policy still authorizes every call.
type requestScope struct {
	// toolsets is sorted and unique; nil without X-Allowops-Toolsets.
	toolsets []string
	// mode is flat or progressive; empty without X-Allowops-MCP-Mode.
	mode string
}

// parseScopeHeaders reads X-Allowops-Toolsets and X-Allowops-MCP-Mode.
// Toolset names are not checked against the catalog, so a response does not
// reveal which toolsets exist.
func parseScopeHeaders(h http.Header) (requestScope, error) {
	var scope requestScope
	toolsets := h.Values("X-Allowops-Toolsets")
	if len(toolsets) > 1 {
		return scope, errors.New("X-Allowops-Toolsets allowed once")
	}
	if len(toolsets) == 1 {
		if strings.TrimSpace(toolsets[0]) == "" {
			return scope, errors.New("X-Allowops-Toolsets allowed: comma-separated toolset names")
		}
		items := strings.Split(toolsets[0], ",")
		if len(items) > 16 {
			return scope, errors.New("X-Allowops-Toolsets allowed: at most 16 toolset names")
		}
		for _, item := range items {
			name := strings.TrimSpace(item)
			if !metadataName.MatchString(name) {
				return scope, errors.New("X-Allowops-Toolsets allowed: names matching ^[a-z][a-z0-9_]{0,31}$")
			}
			scope.toolsets = append(scope.toolsets, name)
		}
		slices.Sort(scope.toolsets)
		scope.toolsets = slices.Compact(scope.toolsets)
	}
	modes := h.Values("X-Allowops-MCP-Mode")
	if len(modes) > 1 {
		return scope, errors.New("X-Allowops-MCP-Mode allowed once")
	}
	if len(modes) == 1 {
		scope.mode = strings.TrimSpace(modes[0])
		if scope.mode != modeFlat && scope.mode != modeProgressive {
			return scope, errors.New("X-Allowops-MCP-Mode allowed: flat, progressive")
		}
	}
	return scope, nil
}
