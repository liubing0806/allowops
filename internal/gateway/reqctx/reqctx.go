package reqctx

import (
	"context"
	"slices"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
)

// Identity is the authenticated caller of a request.
type Identity struct {
	Subject authz.Subject
	User    *v1.User
	Session *v1.CliSession
	Client  v1.LoginClient
	CSRF    string
}

// AuditEvent is an allowlist: request bodies, credentials and provider errors
// must never be added. NewAuditor maps this boundary to the audit module's Append (design P7).
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

// Request is the per-request state stored in the context by the
// authentication middleware. It exposes only what other packages may read.
type Request interface {
	Identity() *Identity
	SourceIP() string
	PolicyVersion() uint64
	MatchedRules() []string
	// Fork returns a copy whose mutable authorization and audit metadata is
	// reset. Authentication and transport values are preserved.
	Fork() Request
}

type requestKey struct{}

// With returns a context that carries r.
func With(ctx context.Context, r Request) context.Context {
	return context.WithValue(ctx, requestKey{}, r)
}

// From returns the request stored in ctx, or nil.
func From(ctx context.Context) Request {
	r, _ := ctx.Value(requestKey{}).(Request)
	return r
}

// FromContext returns the authenticated identity of the request in ctx.
func FromContext(ctx context.Context) (*Identity, bool) {
	r := From(ctx)
	if r == nil {
		return nil, false
	}
	id := r.Identity()
	if id == nil {
		return nil, false
	}
	return id, true
}

// ActorID returns the user or service-account ID of the caller, or "".
func ActorID(ctx context.Context) string {
	id, _ := FromContext(ctx)
	if id == nil {
		return ""
	}
	if id.User != nil {
		return id.User.UserId
	}
	return id.Subject.ID
}

// RequestInfo contains gateway-authenticated audit identifiers only.
func RequestInfo(ctx context.Context) (actor, sourceIP string) {
	if r := From(ctx); r != nil {
		return ActorID(ctx), r.SourceIP()
	}
	return "", ""
}

// RequestAuditInfo exposes only the existing audit allowlist.
func RequestAuditInfo(ctx context.Context) AuditEvent {
	e := AuditEvent{ActorID: ActorID(ctx)}
	if r := From(ctx); r != nil {
		e.SourceIP = r.SourceIP()
		e.PolicyVersion = r.PolicyVersion()
		e.MatchedRules = slices.Clone(r.MatchedRules())
	}
	return e
}

// ForkRequestContext isolates mutable authorization/audit metadata for MCP
// calls sharing an HTTP batch. Authentication and transport values are preserved.
func ForkRequestContext(ctx context.Context) context.Context {
	r := From(ctx)
	if r == nil {
		return ctx
	}
	return With(ctx, r.Fork())
}
