package mcp

import (
	"container/list"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Identity is the part of the management API the MCP service uses.
// *api.Service implements it.
type Identity interface {
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

type Config struct {
	CacheEntries     int
	ProgressInterval time.Duration
}
type Service struct {
	identity Identity
	catalogs *catalogsvc.Service
	jobs     JobService
	config   Config
	mu       sync.Mutex
	entries  map[string]*list.Element
	lru      *list.List
	versions string
}
type cacheEntry struct {
	key    string
	server *sdk.Server
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
	if cfg.CacheEntries < 1 || cfg.ProgressInterval <= 0 {
		return nil, errors.New("invalid MCP limits")
	}
	return &Service{identity: identity, catalogs: catalogs, jobs: jobs, config: cfg, entries: map[string]*list.Element{}, lru: list.New()}, nil
}

func (s *Service) Handler() http.Handler {
	stream := sdk.NewStreamableHTTPHandler(func(r *http.Request) *sdk.Server {
		server, _ := r.Context().Value(serverContextKey{}).(*sdk.Server)
		return server
	}, &sdk.StreamableHTTPOptions{Stateless: true, MaxRequestBodyBytes: int64(s.identity.MessageBytes()), PropagateRequestCancellation: true})
	authenticated := s.identity.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := reqctx.FromContext(r.Context())
		if !ok || id == nil {
			if s.auditHTTP(r.Context(), "deny") != nil {
				http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="allowops"`)
			http.Error(w, "Bearer authentication required", http.StatusUnauthorized)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != s.identity.Origin() {
			if s.auditHTTP(r.Context(), "deny") != nil {
				http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "origin rejected", http.StatusForbidden)
			return
		}
		server, err := s.serverFor(r.Context())
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
func (s *Service) auditHTTP(ctx context.Context, outcome string) error {
	e := reqctx.RequestAuditInfo(ctx)
	e.Operation = "mcp/authenticate"
	e.Phase = "result"
	e.Outcome = outcome
	return s.identity.AppendResultAudit(ctx, e)
}
