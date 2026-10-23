package mcp

import (
	"container/list"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/job"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type Config struct {
	CacheEntries     int
	ProgressInterval time.Duration
	// Jobs is the gateway job configuration. Tool schemas and argument checks use
	// the same limits as job validation; the zero value means job.DefaultConfig.
	Jobs job.Config
}
type Service struct {
	identity *api.Service
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

func New(identity *api.Service, catalogs *catalogsvc.Service, jobs JobService, cfg Config) (*Service, error) {
	if identity == nil || identity.Store == nil || identity.Audit == nil || catalogs == nil {
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
	if cfg.CacheEntries < 1 || cfg.ProgressInterval <= 0 || cfg.Jobs.MaxWaitSeconds == 0 || cfg.Jobs.WaitSeconds > cfg.Jobs.MaxWaitSeconds || cfg.Jobs.BatchSize == 0 {
		return nil, errors.New("invalid MCP limits")
	}
	return &Service{identity: identity, catalogs: catalogs, jobs: jobs, config: cfg, entries: map[string]*list.Element{}, lru: list.New()}, nil
}

func (s *Service) Handler() http.Handler {
	stream := sdk.NewStreamableHTTPHandler(func(r *http.Request) *sdk.Server {
		server, _ := r.Context().Value(serverContextKey{}).(*sdk.Server)
		return server
	}, &sdk.StreamableHTTPOptions{Stateless: true, MaxRequestBodyBytes: int64(s.identity.Config.MessageBytes), PropagateRequestCancellation: true})
	authenticated := s.identity.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := api.FromContext(r.Context())
		if !ok || id == nil {
			if s.auditHTTP(r.Context(), "deny") != nil {
				http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="allowops"`)
			http.Error(w, "Bearer authentication required", http.StatusUnauthorized)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != s.identity.Config.Origin {
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
			// Still use P5B to collect authenticated audit context, while preventing
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
	e := api.RequestAuditInfo(ctx)
	e.Operation = "mcp/authenticate"
	e.Phase = "result"
	e.Outcome = outcome
	return s.identity.AppendResultAudit(ctx, e)
}
