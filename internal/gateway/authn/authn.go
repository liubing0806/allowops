package authn

import (
	"crypto/tls"
	"errors"
	"net/http"
	"time"
)

var (
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrDirectoryUnavailable = errors.New("directory unavailable")
	ErrRateLimited          = errors.New("login rate limited")
)

type Identity struct {
	ID     string
	Kind   string
	Email  string // Only a verified OIDC email is returned.
	Groups []string
	Roles  []string
}

type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	RoleMappings map[string]string
	HTTPClient   *http.Client
}

type RateLimit struct {
	Attempts int // Maximum credential rejections in the rolling Window; success clears failures.
	Window   time.Duration
}

type LDAPConfig struct {
	URL                  string
	StartTLS             bool
	TLSConfig            *tls.Config
	UserBaseDN           string
	UserAttribute        string // Defaults to uid.
	GroupBaseDN          string
	GroupMemberAttribute string // Defaults to member (user DN).
	GroupNameAttribute   string // Defaults to cn.
	RoleMappings         map[string]string
	RateLimit            RateLimit     // Zero value uses 5 credential failures per 5 minutes (design A8, G21, G23).
	Timeout              time.Duration // Zero value uses 10 seconds.
}

// DirectoryCredentials are supplied per call and are never retained by LDAP.
type DirectoryCredentials struct {
	BindDN   string
	Password string
}

// TokenRecord contains only the digest and lifecycle metadata; it is safe to persist.
type TokenRecord struct {
	Hash      [32]byte
	ExpiresAt time.Time
	Revoked   bool
}
