package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/store"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DefaultConsoleTTL is the configurable seven-day console lifetime (A20).
const DefaultConsoleTTL = 7 * 24 * time.Hour
const PolicyChannel = "allowops_policy"

// AuditEvent is an allowlist: request bodies, credentials and provider errors
// must never be added. NewAuditor maps this boundary to P7 Append.
type AuditEvent struct {
	JobID         string
	Resource      string
	Hostname      string
	ActorID       string
	Operation     string
	Phase         string // authorized before a write; result after an operation
	Outcome       string
	PolicyVersion uint64
	MatchedRules  []string
	SourceIP      string
}
type Auditor interface {
	Append(context.Context, AuditEvent) error
}

type Config struct {
	Origin             string              `yaml:"origin"`
	BootstrapAdmins    []string            `yaml:"bootstrap_admins"`
	ConsoleTTL         time.Duration       `yaml:"console_ttl"`
	CliTTL             time.Duration       `yaml:"cli_ttl"`
	LoginTTL           time.Duration       `yaml:"login_ttl"`
	CodeTTL            time.Duration       `yaml:"code_ttl"`
	TestTTL            time.Duration       `yaml:"test_ttl"`
	MaxTestEvaluations int                 `yaml:"max_test_evaluations"`
	PageSize           int                 `yaml:"page_size"`
	MaxPageSize        int                 `yaml:"max_page_size"`
	MessageBytes       int                 `yaml:"message_bytes"`
	RoleMappings       []RoleMappingConfig `yaml:"role_mappings"`
}
type RoleMappingConfig struct {
	ProviderID string   `yaml:"provider_id"`
	Group      string   `yaml:"group"`
	Roles      []string `yaml:"roles"`
}

type policyState struct {
	engine  *authz.Engine
	version uint64
}
type Service struct {
	Store         *store.Store
	Config        Config
	Audit         Auditor
	management    *management
	jobStatistics JobStatistics
	objectStorage ObjectStorageHealth
	oidc          map[string]*OIDCProvider
	ldap          map[string]LDAPProvider
	state         atomic.Pointer[policyState]
	refreshMu     sync.Mutex
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

func New(ctx context.Context, db *store.Store, cfg Config, audit Auditor) (*Service, error) {
	u, err := url.Parse(cfg.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("identity requires an HTTPS origin")
	}
	if audit == nil {
		return nil, errors.New("identity audit Append implementation required (P7)")
	}
	if cfg.ConsoleTTL == 0 {
		cfg.ConsoleTTL = DefaultConsoleTTL
	}
	if cfg.CliTTL == 0 {
		cfg.CliTTL = 7 * 24 * time.Hour
	}
	if cfg.LoginTTL == 0 {
		cfg.LoginTTL = 10 * time.Minute
	}
	if cfg.CodeTTL == 0 {
		cfg.CodeTTL = time.Minute
	}
	if cfg.TestTTL == 0 {
		cfg.TestTTL = 10 * time.Minute
	}
	if cfg.MaxTestEvaluations == 0 {
		cfg.MaxTestEvaluations = 100000
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 50
	}
	if cfg.MaxPageSize == 0 {
		cfg.MaxPageSize = 200
	}
	if cfg.MessageBytes == 0 {
		cfg.MessageBytes = 1 << 20
	}
	if cfg.ConsoleTTL <= 0 || cfg.CliTTL <= 0 || cfg.LoginTTL <= 0 || cfg.CodeTTL <= 0 || cfg.TestTTL <= 0 || cfg.MaxTestEvaluations < 1 || cfg.PageSize < 1 || cfg.MaxPageSize < cfg.PageSize || cfg.MessageBytes < 256 {
		return nil, errors.New("invalid identity limits")
	}
	s := &Service{management: defaultManagement(), Store: db, Config: cfg, Audit: audit, oidc: map[string]*OIDCProvider{}, ldap: map[string]LDAPProvider{}}
	if err := s.initialize(ctx); err != nil {
		return nil, err
	}
	if err := s.refresh(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	opts := []connect.HandlerOption{connect.WithInterceptors(s.interceptor()), connect.WithReadMaxBytes(s.Config.MessageBytes), connect.WithSendMaxBytes(s.Config.MessageBytes)}
	mux.Handle(rpc.NewPolicyServiceHandler(s, opts...))
	mux.Handle(rpc.NewServiceAccountServiceHandler(s, opts...))
	mux.Handle(rpc.NewUserServiceHandler(s, opts...))
	mux.Handle(rpc.NewAuthServiceHandler(s, opts...))
	s.mountManagement(mux)
	mux.HandleFunc("/auth/oidc/start", s.oidcStart)
	mux.HandleFunc("/auth/oidc/callback", s.oidcCallback)
	mux.HandleFunc("/auth/oidc/complete", s.oidcPage)
	return s.Middleware(mux)
}

type Identity struct {
	Subject authz.Subject
	User    *v1.User
	Session *v1.CliSession
	Client  v1.LoginClient
	CSRF    string
}
type requestKey struct{}
type requestState struct {
	identity                 *Identity
	err                      error
	writer                   http.ResponseWriter
	ip                       string
	header                   http.Header
	tls                      bool
	auditActor               string
	auditTargets             []auditTarget
	auditHostname            string
	transportChecked         bool
	policyVersion            uint64
	matchedRules             []string
	resource                 bool
	procedure                string
	writeAuthorized          bool
	authorizationAuditFailed bool
}

func FromContext(ctx context.Context) (*Identity, bool) {
	r, _ := ctx.Value(requestKey{}).(*requestState)
	if r == nil || r.identity == nil {
		return nil, false
	}
	return r.identity, true
}
func transport(ctx context.Context) *requestState {
	r, _ := ctx.Value(requestKey{}).(*requestState)
	return r
}

// Middleware is shared by Connect and future MCP routes. It never authenticates
// query parameters, forwarded headers or host certificates as console identities.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		state := &requestState{writer: w, ip: ip, header: r.Header, tls: r.TLS != nil}
		if r.TLS == nil || len(r.Header.Values("Authorization")) > 1 {
			state.err = authn.ErrInvalidCredentials
		} else if auth := r.Header.Get("Authorization"); auth != "" {
			parts := strings.Fields(auth)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				state.err = authn.ErrInvalidCredentials
			} else {
				state.identity, state.err = s.authenticate(r.Context(), parts[1], false)
			}
		} else if cookie, err := r.Cookie("__Host-allowops-session"); err == nil {
			state.identity, state.err = s.authenticate(r.Context(), cookie.Value, true)
		}
		ctx := context.WithValue(r.Context(), requestKey{}, state)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Require is the reusable ABAC boundary for P4B and MCP. Host/action attributes
// must come from the gateway store, never from caller-supplied roles or labels.
func (s *Service) Require(ctx context.Context, op authz.Operation, action authz.Action, host authz.Host) (authz.Result, error) {
	id, ok := FromContext(ctx)
	if !ok {
		return authz.Result{Decision: "deny"}, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	if err := s.refresh(ctx); err != nil {
		return authz.Result{Decision: "deny"}, failure(connect.CodeUnavailable, "policy unavailable")
	}
	r := transport(ctx)
	if !r.transportChecked && id.Client == v1.LoginClient_LOGIN_CLIENT_CONSOLE {
		if err := s.checkCSRF(ctx); err != nil {
			return authz.Result{Decision: "deny"}, err
		}
	}
	current := s.state.Load()
	result, reason, err := evaluate(ctx, current.engine, authz.Input{Subject: id.Subject, Operation: op, Action: action, Host: host, Env: authz.Environment{TimeNS: time.Now().UnixNano(), SourceIP: r.ip}})
	r.policyVersion = current.version
	if r.resource {
		r.matchedRules = unique(append(r.matchedRules, result.RuleIDs...))
	} else {
		r.matchedRules = result.RuleIDs
	}
	if reason == "HOST_UNLABELED" {
		return result, failure(connect.CodePermissionDenied, "host has no authorization labels")
	}
	if err != nil || result.Decision != "allow" {
		return result, failure(connect.CodePermissionDenied, "operation denied")
	}
	return result, nil
}

// Authorization labels are a prerequisite for execution, including admin.
// Keep this gateway invariant identical in live authorization and policy trials.
func evaluate(ctx context.Context, engine *authz.Engine, input authz.Input) (authz.Result, string, error) {
	if input.Operation == authz.ExecuteAction && len(input.Host.Labels) == 0 {
		return authz.Result{Decision: "deny"}, "HOST_UNLABELED", nil
	}
	result, err := engine.Evaluate(ctx, input)
	return result, "", err
}

func operation(procedure string) (authz.Operation, bool, bool) {
	if strings.HasPrefix(procedure, "/allowops.v1.PolicyService/") {
		return authz.ModifyPolicy, false, strings.HasSuffix(procedure, "TestPolicy") || strings.HasSuffix(procedure, "SavePolicy") || strings.HasSuffix(procedure, "RollbackPolicy")
	}
	if strings.HasPrefix(procedure, "/allowops.v1.ServiceAccountService/") {
		return authz.ManageServiceAccounts, false, !strings.Contains(procedure, "/Get") && !strings.Contains(procedure, "/List")
	}
	if strings.HasPrefix(procedure, "/allowops.v1.UserService/") {
		return authz.ManageUserRoles, false, strings.Contains(procedure, "/Set") || strings.Contains(procedure, "/Save")
	}
	switch procedure {
	case rpc.AuthServiceGetLoginMethodsProcedure:
		return "", true, false
	case rpc.AuthServiceBeginOidcLoginProcedure, rpc.AuthServiceCompleteOidcLoginProcedure, rpc.AuthServiceLoginLdapProcedure, rpc.AuthServiceExchangeCliSessionProcedure:
		return "", true, true
	case rpc.AuthServiceGetCurrentSessionProcedure, rpc.AuthServiceListCliSessionsProcedure:
		return "", false, false
	case rpc.AuthServiceLogoutProcedure, rpc.AuthServiceRevokeCliSessionProcedure:
		return "", false, true
	}
	return authz.Operation("unknown_operation"), false, true
}

func (s *Service) interceptor() connect.Interceptor {
	return s.unaryInterceptor(operation)
}

// RPCPermission lets later services reuse authentication, CSRF, ABAC and audit
// with an explicit permission for each RPC. Unlisted RPCs are denied.
type RPCPermission struct {
	Operation authz.Operation
	Write     bool
	// Resource defers ABAC to the handler using stored host/action attributes.
	// Writes must call authorizeWrite before changing any data.
	Resource bool
}

func (s *Service) InterceptorFor(procedures map[string]RPCPermission) connect.Interceptor {
	permissions := make(map[string]RPCPermission, len(procedures))
	for k, v := range procedures {
		permissions[k] = v
	}
	return s.unaryInterceptor(func(procedure string) (authz.Operation, bool, bool) {
		p, ok := permissions[procedure]
		if !ok || p.Operation == "" {
			return authz.Operation("unknown_operation"), false, true
		}
		return p.Operation, false, p.Write
	}, func(procedure string) bool { return permissions[procedure].Resource })
}
func (s *Service) checkCSRF(ctx context.Context) error {
	t := transport(ctx)
	if t.header.Get("Origin") != s.Config.Origin || subtle.ConstantTimeCompare([]byte(t.header.Get("X-CSRF-Token")), []byte(t.identity.CSRF)) != 1 {
		return failure(connect.CodePermissionDenied, "CSRF rejected")
	}
	return nil
}
func (s *Service) unaryInterceptor(resolve func(string) (authz.Operation, bool, bool), resource ...func(string) bool) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (response connect.AnyResponse, err error) {
			op, public, write := resolve(req.Spec().Procedure)
			t := transport(ctx)
			if t == nil {
				return nil, failure(connect.CodeUnauthenticated, "authentication required")
			}
			event := AuditEvent{Operation: req.Spec().Procedure, SourceIP: t.ip, Phase: "result", Outcome: "deny"}
			event.ActorID = actorID(ctx)
			recordResult, executed := true, false
			defer func() {
				if !recordResult || t.authorizationAuditFailed {
					return
				}
				event.PolicyVersion, event.MatchedRules = t.policyVersion, t.matchedRules
				if t.auditActor != "" {
					event.ActorID = t.auditActor
				}
				if err == nil {
					if response != nil {
						resultTarget(ctx, req, response)
					}
					event.Outcome = "allow"
				}
				if aerr := s.AppendResultAudit(ctx, event); aerr != nil {
					response = nil
					err = resultAuditError(write && executed && (!t.resource || t.writeAuthorized))
				}
			}()
			if !t.tls {
				return nil, failure(connect.CodeUnauthenticated, "TLS required")
			}
			if t.err != nil && (!public || t.header.Get("Authorization") != "") {
				return nil, credentialError(t.err)
			}
			if !public && t.identity == nil {
				return nil, failure(connect.CodeUnauthenticated, "authentication required")
			}
			if write {
				origin := req.Header().Get("Origin")
				if origin != "" && origin != s.Config.Origin {
					return nil, failure(connect.CodePermissionDenied, "origin rejected")
				}
				// Public login operations have their own Origin and transaction
				// binding checks and must work with existing or revoked cookies.
				if !public && t.identity != nil && t.identity.Client == v1.LoginClient_LOGIN_CLIENT_CONSOLE {
					if err := s.checkCSRF(ctx); err != nil {
						return nil, err
					}
				}
			}
			t.transportChecked = true
			t.procedure = req.Spec().Procedure
			t.resource = len(resource) > 0 && resource[0](t.procedure)
			if op != "" && !t.resource {
				_, aerr := s.Require(ctx, op, authz.Action{}, authz.Host{})
				if aerr != nil {
					return nil, aerr
				}
			}
			if write && !t.resource {
				authorized := event
				authorized.Phase, authorized.Outcome = "authorized", "allow"
				authorized.PolicyVersion, authorized.MatchedRules = t.policyVersion, t.matchedRules
				if aerr := s.Audit.Append(ctx, authorized); aerr != nil {
					recordResult = false
					return nil, failure(connect.CodeUnavailable, "authorization audit unavailable; operation not executed")
				}
			}
			executed = true
			return next(ctx, req)
		}
	})
}

func resultAuditError(mayHaveCommitted bool) error {
	if !mayHaveCommitted {
		return failure(connect.CodeUnavailable, "audit unavailable")
	}
	err := connect.NewError(connect.CodeUnavailable, errors.New("result audit unavailable; operation may have committed"))
	detail, detailErr := connect.NewErrorDetail(&v1.ErrorDetail{Reason: "AUDIT_RESULT_UNAVAILABLE"})
	if detailErr == nil {
		err.AddDetail(detail)
	}
	return err
}

// credentialError maps a failed request authentication to its RPC error:
// an unavailable identity store is reported as such, everything else is an
// invalid credential.
func credentialError(err error) error {
	if connect.CodeOf(err) == connect.CodeUnavailable {
		return err
	}
	return failure(connect.CodeUnauthenticated, "invalid credential")
}
func failure(code connect.Code, message string) error {
	return connect.NewError(code, errors.New(message))
}
func hash(secret string) []byte { h := sha256.Sum256([]byte(secret)); return h[:] }
func secret(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}
func stamp(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }
func unique(values []string) []string {
	v := slices.Clone(values)
	slices.Sort(v)
	return slices.Compact(v)
}
func encode(m proto.Message) ([]byte, error) {
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
	if err != nil {
		return nil, err
	}
	// ProtoJSON deliberately varies whitespace between binaries. Reuse the
	// catalog's canonical JSON so a preview can be saved on another instance.
	return catalog.CanonicalJSON(json.RawMessage(b))
}
func decode(b []byte, m proto.Message) error { return protojson.Unmarshal(b, m) }
