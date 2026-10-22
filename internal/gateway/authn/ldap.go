package authn

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type LDAP struct {
	config  LDAPConfig
	address string
	limiter loginLimiter
}

const (
	maxLoginLimiterKeys    = 10000
	maxPendingLoginsPerKey = 64
)

var attributeName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*$`)

func NewLDAP(config LDAPConfig) (*LDAP, error) {
	u, err := url.Parse(config.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "ldaps" && (u.Scheme != "ldap" || !config.StartTLS)) {
		return nil, errors.New("LDAP requires LDAPS or StartTLS")
	}
	if config.UserBaseDN == "" || config.GroupBaseDN == "" {
		return nil, errors.New("LDAP user and group base DNs are required")
	}
	if _, err := ldap.ParseDN(config.UserBaseDN); err != nil {
		return nil, errors.New("invalid LDAP user base DN")
	}
	if _, err := ldap.ParseDN(config.GroupBaseDN); err != nil {
		return nil, errors.New("invalid LDAP group base DN")
	}
	if config.TLSConfig == nil {
		config.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		config.TLSConfig = config.TLSConfig.Clone()
	}
	if config.TLSConfig.InsecureSkipVerify {
		return nil, errors.New("LDAP TLS certificate verification is required")
	}
	if config.TLSConfig.MinVersion < tls.VersionTLS12 {
		config.TLSConfig.MinVersion = tls.VersionTLS12
	}
	if config.TLSConfig.RootCAs != nil {
		config.TLSConfig.RootCAs = config.TLSConfig.RootCAs.Clone()
	}
	if config.TLSConfig.ServerName == "" {
		config.TLSConfig.ServerName = u.Hostname()
	}
	if config.UserAttribute == "" {
		config.UserAttribute = "uid"
	}
	if config.GroupMemberAttribute == "" {
		config.GroupMemberAttribute = "member"
	}
	if config.GroupNameAttribute == "" {
		config.GroupNameAttribute = "cn"
	}
	for _, attribute := range []string{config.UserAttribute, config.GroupMemberAttribute, config.GroupNameAttribute} {
		if !attributeName.MatchString(attribute) {
			return nil, errors.New("invalid LDAP attribute name")
		}
	}
	if config.RateLimit.Attempts == 0 {
		config.RateLimit.Attempts = 5
	}
	if config.RateLimit.Window == 0 {
		config.RateLimit.Window = 5 * time.Minute
	}
	if config.RateLimit.Attempts < 1 || config.RateLimit.Window < 0 {
		return nil, errors.New("invalid LDAP rate limit")
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.Timeout < 0 {
		return nil, errors.New("invalid LDAP timeout")
	}
	config.RoleMappings = maps.Clone(config.RoleMappings)
	port := u.Port()
	if port == "" {
		port = "636"
		if u.Scheme == "ldap" {
			port = "389"
		}
	}
	return &LDAP{config: config, address: net.JoinHostPort(u.Hostname(), port), limiter: loginLimiter{limit: config.RateLimit, entries: map[loginKey]*loginWindow{}, maxKeys: maxLoginLimiterKeys, maxPending: maxPendingLoginsPerKey}}, nil
}

// Login never retains either password. Usernames use case-insensitive uid semantics.
// sourceIP must be a trusted transport peer address, not an unchecked forwarded header.
func (l *LDAP) Login(ctx context.Context, username, password, sourceIP string, directory DirectoryCredentials) (identity Identity, err error) {
	directoryFailure := func(operation string, err error) (Identity, error) {
		// LDAP diagnostics are untrusted and can echo credentials. Log only the
		// error text after redaction, never the error's packet or request fields.
		detail := err.Error()
		for _, secret := range []string{password, directory.Password} {
			if secret != "" {
				detail = strings.ReplaceAll(detail, secret, "[REDACTED]")
			}
		}
		slog.ErrorContext(ctx, "LDAP directory unavailable", "operation", operation, "error", detail)
		return Identity{}, ErrDirectoryUnavailable
	}
	if l == nil || l.address == "" {
		return directoryFailure("configuration", errors.New("LDAP is not initialized"))
	}
	ip, err := netip.ParseAddr(sourceIP)
	username = strings.ToLower(strings.TrimSpace(username))
	if err != nil || username == "" {
		return Identity{}, ErrInvalidCredentials
	}
	ctx, cancel := context.WithTimeout(ctx, l.config.Timeout)
	defer cancel()
	finish, limitErr := l.limiter.begin(ctx, username, ip.Unmap().String(), time.Now)
	if limitErr != nil {
		if errors.Is(limitErr, ErrRateLimited) {
			return Identity{}, ErrRateLimited
		}
		return directoryFailure("login_wait", limitErr)
	}
	defer func() { finish(err == nil, errors.Is(err, ErrInvalidCredentials)) }()
	if password == "" {
		return Identity{}, ErrInvalidCredentials
	}
	if (directory.BindDN == "") != (directory.Password == "") {
		return directoryFailure("configuration", errors.New("incomplete directory credentials"))
	}
	networkConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", l.address)
	if err != nil {
		return directoryFailure("connect", err)
	}
	if strings.HasPrefix(l.config.URL, "ldaps://") {
		tlsConn := tls.Client(networkConn, l.config.TLSConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = networkConn.Close()
			return directoryFailure("tls", err)
		}
		networkConn = tlsConn
	}
	connection := ldap.NewConn(networkConn, strings.HasPrefix(l.config.URL, "ldaps://"))
	connection.Start()
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	connection.SetTimeout(l.config.Timeout)
	if l.config.StartTLS && strings.HasPrefix(l.config.URL, "ldap://") {
		if err := connection.StartTLS(l.config.TLSConfig); err != nil {
			return directoryFailure("start_tls", err)
		}
	}
	if directory.BindDN != "" {
		if err := connection.Bind(directory.BindDN, directory.Password); err != nil {
			return directoryFailure("directory_bind", err)
		}
	}
	filter := "(" + l.config.UserAttribute + "=" + ldap.EscapeFilter(username) + ")"
	users, err := connection.Search(ldap.NewSearchRequest(l.config.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false, filter, []string{l.config.UserAttribute}, nil))
	if err != nil {
		return directoryFailure("user_search", err)
	}
	if len(users.Entries) == 0 {
		return Identity{}, ErrInvalidCredentials
	}
	if len(users.Entries) != 1 {
		return directoryFailure("user_search", errors.New("multiple matching LDAP users"))
	}
	user := users.Entries[0]
	groupFilter := "(" + l.config.GroupMemberAttribute + "=" + ldap.EscapeFilter(user.DN) + ")"
	groupResult, err := connection.Search(ldap.NewSearchRequest(l.config.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, groupFilter, []string{l.config.GroupNameAttribute}, nil))
	if err != nil {
		return directoryFailure("group_search", err)
	}
	if err := connection.Bind(user.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return Identity{}, ErrInvalidCredentials
		}
		return directoryFailure("user_bind", err)
	}
	id := user.GetAttributeValue(l.config.UserAttribute)
	if id == "" {
		return directoryFailure("user_attribute", errors.New("LDAP user has no identity attribute"))
	}
	groups := []string{}
	for _, group := range groupResult.Entries {
		groups = append(groups, group.GetAttributeValues(l.config.GroupNameAttribute)...)
	}
	return Identity{ID: id, Kind: "ldap", Groups: groups, Roles: mappedRoles(groups, l.config.RoleMappings)}, nil
}

// Hashing the username keeps retained key size bounded even for long login inputs.
type loginKey struct {
	username [sha256.Size]byte
	ip       string
}
type loginWindow struct {
	failures []time.Time
	gate     chan struct{}
	users    int
}
type loginLimiter struct {
	mu         sync.Mutex
	limit      RateLimit
	entries    map[loginKey]*loginWindow
	maxKeys    int
	maxPending int
	nextSweep  time.Time
}

func (s *loginWindow) expire(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	i := 0
	for i < len(s.failures) && !s.failures[i].After(cutoff) {
		i++
	}
	if i > 0 {
		s.failures = append(s.failures[:0], s.failures[i:]...)
	}
}

// begin serializes authentication per key. finish must run once: success clears
// failures, credential rejection adds one, and directory failure preserves them.
// A key retains at most Attempts timestamps and maxPending active/waiting requests.
func (l *loginLimiter) begin(ctx context.Context, username, ip string, now func() time.Time) (func(bool, bool), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := loginKey{username: sha256.Sum256([]byte(username)), ip: ip}
	l.mu.Lock()
	clock := now()
	// Sweep at most once per minute of login traffic; the key cap also bounds idle state.
	if !clock.Before(l.nextSweep) {
		for key, entry := range l.entries {
			entry.expire(clock, l.limit.Window)
			if entry.users == 0 && len(entry.failures) == 0 {
				delete(l.entries, key)
			}
		}
		l.nextSweep = clock.Add(min(l.limit.Window, time.Minute))
	}
	entry := l.entries[key]
	if entry == nil {
		if len(l.entries) >= l.maxKeys {
			l.mu.Unlock()
			return nil, ErrRateLimited
		}
		entry = &loginWindow{gate: make(chan struct{}, 1)}
		l.entries[key] = entry
	}
	if entry.users >= l.maxPending {
		l.mu.Unlock()
		return nil, ErrRateLimited
	}
	entry.users++
	l.mu.Unlock()
	release := func() {
		entry.users--
		if entry.users == 0 && len(entry.failures) == 0 {
			delete(l.entries, key)
		}
	}
	select {
	case entry.gate <- struct{}{}:
	case <-ctx.Done():
		l.mu.Lock()
		release()
		l.mu.Unlock()
		return nil, ctx.Err()
	}
	l.mu.Lock()
	if err := ctx.Err(); err != nil {
		release()
		l.mu.Unlock()
		<-entry.gate
		return nil, err
	}
	entry.expire(now(), l.limit.Window)
	if len(entry.failures) >= l.limit.Attempts {
		release()
		l.mu.Unlock()
		<-entry.gate
		return nil, ErrRateLimited
	}
	l.mu.Unlock()
	return func(success, credentialRejected bool) {
		l.mu.Lock()
		if success {
			entry.failures = nil
		} else if credentialRejected {
			clock := now()
			entry.expire(clock, l.limit.Window)
			entry.failures = append(entry.failures, clock)
		}
		release()
		l.mu.Unlock()
		<-entry.gate
	}, nil
}
