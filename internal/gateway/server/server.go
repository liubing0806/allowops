package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/console"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"golang.org/x/net/http2"
)

const AgentALPN = "allowops-agent/1"
const JoinALPN = "allowops-join/1"
const MCPALPN = "allowops-mcp/1"

// UseIdentity mounts P5B without changing host ALPN or catalog synchronization.
// Future MCP handlers use the same context and api.Service.Require for ABAC.
func (s *Server) UseIdentity(identity *api.Service) {
	s.identity = identity
	if s.Audit != nil {
		s.Audit.Access = identity
	}
	s.API = identity.Handler()
	s.MCP = identity.Middleware(s.MCP)
}

type Server struct {
	Agent       *hostconn.Service
	Catalogs    *catalogsvc.Service
	Audit       *audit.Service
	Jobs        *job.Service
	Output      interface{ Check(context.Context) error }
	TLS         *tls.Config
	API, MCP    http.Handler
	Console     http.Handler
	identity    *api.Service
	mu          sync.Mutex
	listener    net.Listener
	connections map[net.Conn]struct{}
	wg          sync.WaitGroup
	closed      bool
}

func New(agent *hostconn.Service, certificate tls.Certificate) *Server {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(agent.CA.PEM)
	base := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	s := &Server{Agent: agent, connections: map[net.Conn]struct{}{}}
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		cfg := base.Clone()
		cfg.GetConfigForClient = nil
		if len(hello.SupportedProtos) == 0 {
			return cfg, nil
		}
		for _, protocol := range hello.SupportedProtos {
			switch protocol {
			case AgentALPN:
				cfg.NextProtos = []string{AgentALPN}
				cfg.ClientAuth = tls.RequireAndVerifyClientCert
				cfg.ClientCAs = roots
				cfg.VerifyConnection = func(state tls.ConnectionState) error {
					cert := state.PeerCertificates[0]
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if _, err := hostconn.WithIdentity(ctx, cert); err != nil {
						return err
					}
					return agent.Store.CheckIdentity(ctx, cert.Subject.CommonName, cert.SerialNumber.Text(16))
				}
				return cfg, nil
			case JoinALPN, MCPALPN, "h2", "http/1.1":
				cfg.NextProtos = []string{protocol}
				return cfg, nil
			}
		}
		return nil, fmt.Errorf("unsupported ALPN")
	}
	s.TLS = base
	placeholder := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "P4 placeholder", http.StatusNotImplemented)
	})
	s.API = placeholder
	s.MCP = placeholder
	s.Console = console.Handler()
	return s
}

func (s *Server) handler(protocol string) http.Handler {
	_, agent := allowopsv1connect.NewAgentServiceHandler(s.Agent, connect.WithReadMaxBytes(s.Agent.Config.MessageBytes), connect.WithSendMaxBytes(s.Agent.Config.MessageBytes))
	var auditHandler http.Handler
	var jobHandler http.Handler
	if s.Jobs != nil {
		jobHandler = s.Jobs.Handler()
	}
	if s.Audit != nil {
		opts := []connect.HandlerOption{connect.WithReadMaxBytes(s.Audit.Store.Config.ResponseBytes), connect.WithSendMaxBytes(s.Audit.Store.Config.ResponseBytes)}
		if s.identity != nil {
			opts = append(opts, connect.WithInterceptors(s.identity.InterceptorFor(map[string]api.RPCPermission{
				allowopsv1connect.AuditServiceListAuditEventsProcedure: {Operation: authz.ViewAudit},
				allowopsv1connect.AuditServiceExportAuditProcedure:     {Operation: authz.ViewAudit},
				allowopsv1connect.AuditServiceVerifyAuditProcedure:     {Operation: authz.ViewAudit},
			})))
		}
		_, auditHandler = allowopsv1connect.NewAuditServiceHandler(s.Audit, opts...)
		if s.identity != nil {
			auditHandler = s.identity.Middleware(auditHandler)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch protocol {
		case AgentALPN:
			if r.URL.Path == allowopsv1connect.AgentServiceJoinProcedure || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx, err := hostconn.WithIdentity(r.Context(), r.TLS.PeerCertificates[0])
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if r.Header.Get("Content-Type") != "application/grpc" && r.Header.Get("Content-Type") != "application/grpc+proto" {
				http.Error(w, "gRPC required", http.StatusUnsupportedMediaType)
				return
			}
			ctx = hostconn.WithWriteDeadline(ctx, http.NewResponseController(w).SetWriteDeadline)
			agent.ServeHTTP(w, r.WithContext(ctx))
		case JoinALPN:
			if r.URL.Path != allowopsv1connect.AgentServiceJoinProcedure {
				http.NotFound(w, r)
				return
			}
			agent.ServeHTTP(w, r)
		case MCPALPN:
			s.MCP.ServeHTTP(w, r)
		default:
			if r.URL.Path == "/health/live" || r.URL.Path == "/health/ready" {
				s.health(w, r)
			} else if jobHandler != nil && strings.HasPrefix(r.URL.Path, "/allowops.v1.JobService/") {
				jobHandler.ServeHTTP(w, r)
			} else if r.URL.Path == "/mcp" || r.URL.Path == "/mcp/" {
				s.MCP.ServeHTTP(w, r)
			} else if auditHandler != nil && (r.URL.Path == allowopsv1connect.AuditServiceListAuditEventsProcedure || r.URL.Path == allowopsv1connect.AuditServiceExportAuditProcedure || r.URL.Path == allowopsv1connect.AuditServiceVerifyAuditProcedure) {
				auditHandler.ServeHTTP(w, r)
			} else if strings.HasPrefix(r.URL.Path, "/allowops.v1.") || strings.HasPrefix(r.URL.Path, "/auth/") {
				s.API.ServeHTTP(w, r)
			} else {
				s.Console.ServeHTTP(w, r)
			}
		}
	})
}

// Serve terminates TLS once, then routes a single listening port by ALPN.
// Custom ALPN protocols carry ordinary HTTP/2 frames and standard gRPC.
func (s *Server) Serve(listener net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		listener.Close()
		return nil
	}
	s.listener = listener
	s.mu.Unlock()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return nil
		}
		s.connections[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			defer func() { s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
			tlsConn := tls.Server(conn, s.TLS)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := tlsConn.HandshakeContext(ctx)
			cancel()
			if err != nil {
				return
			}
			protocol := tlsConn.ConnectionState().NegotiatedProtocol
			handler := s.handler(protocol)
			state := tlsConn.ConnectionState()
			wrapped := handler
			handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.TLS = &state; wrapped.ServeHTTP(w, r) })
			if protocol == "http/1.1" || protocol == "" {
				h := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10}
				_ = h.Serve(&singleListener{conn: tlsConn, done: make(chan struct{})})
			} else {
				//lint:ignore SA1019 Custom ALPN requires raw ServeConn; net/http has no exported equivalent. On Go 1.27 x/net delegates to net/http.
				h := &http2.Server{MaxConcurrentStreams: 16, MaxReadFrameSize: 1 << 20, IdleTimeout: time.Minute}
				//lint:ignore SA1019 ServeConn preserves custom ALPN while using standard HTTP/2 frames.
				h.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
			}
		}()
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	err := s.Agent.Drain(ctx)
	s.mu.Lock()
	s.closed = true
	if s.listener != nil {
		s.listener.Close()
	}
	for c := range s.connections {
		c.Close()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		if err == nil {
			err = ctx.Err()
		}
	}
	s.Agent.Close()
	return err
}

type singleListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func (l *singleListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() { conn = &notifyConn{Conn: l.conn, done: l.done} })
	if conn != nil {
		return conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *singleListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *singleListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *notifyConn) Close() error { c.once.Do(func() { close(c.done) }); return c.Conn.Close() }
