package pluginhost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/liubing0806/allowops/internal/params"
	"golang.org/x/sys/unix"
)

var (
	errEgress = errors.New("plugin egress: denied")
	errCA     = errors.New("plugin egress: invalid CA file")
)

type canonicalEndpoint struct {
	scheme, host, port, pathPrefix string
	isIPLiteral                    bool
	ip                             netip.Addr
}

func endpoint(u *url.URL) (canonicalEndpoint, error) {
	if u == nil {
		return canonicalEndpoint{}, errEgress
	}
	normalized, err := params.NormalizeURL(u.String())
	if err != nil || u.Path != "" && u.Path != normalized.Path || u.RawPath != "" && u.RawPath != u.EscapedPath() {
		return canonicalEndpoint{}, errEgress
	}
	host, port := normalized.Hostname(), normalized.Port()
	if strings.Contains(host, "*") || strings.HasSuffix(host, ".") {
		return canonicalEndpoint{}, errEgress
	}
	ip, err := netip.ParseAddr(host)
	if strings.ContainsAny(host, ":%[]") && (err != nil || ip.Zone() != "") {
		return canonicalEndpoint{}, errEgress
	}
	if port == "" {
		port = "443"
		if normalized.Scheme == "http" {
			port = "80"
		}
	}
	return canonicalEndpoint{normalized.Scheme, host, port, normalized.Path, ip.IsValid(), ip.Unmap()}, nil
}

func (e canonicalEndpoint) sameOrigin(other canonicalEndpoint) bool {
	return e.scheme == other.scheme && e.host == other.host && e.port == other.port
}

type egressPolicy struct {
	endpoints []canonicalEndpoint
	private   bool
	cross     bool
}

func egressConfig(c Config) (egressPolicy, error) {
	policy := egressPolicy{private: c.AllowPrivateEgress, cross: c.AllowCrossOriginRedirects}
	if len(c.Egress) > 16 {
		return policy, errors.New("plugin egress: too many endpoints")
	}
	for _, raw := range c.Egress {
		u, err := params.NormalizeURL(raw)
		if err != nil || u.RawQuery != "" || u.ForceQuery {
			return policy, errEgress
		}
		e, err := endpoint(u)
		if err != nil {
			return policy, err
		}
		policy.endpoints = append(policy.endpoints, e)
	}
	if c.CAFile != "" && (!filepath.IsAbs(c.CAFile) || !slices.ContainsFunc(policy.endpoints, func(e canonicalEndpoint) bool {
		return e.scheme == "https"
	})) {
		return policy, errCA
	}
	return policy, nil
}

func (p egressPolicy) permits(target canonicalEndpoint) bool {
	for _, e := range p.endpoints {
		if e.sameOrigin(target) && (e.pathPrefix == target.pathPrefix ||
			strings.HasPrefix(target.pathPrefix, strings.TrimSuffix(e.pathPrefix, "/")+"/")) {
			return true
		}
	}
	return false
}

func (p egressPolicy) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 || len(via) > 3 {
		return errEgress
	}
	target, err := endpoint(req.URL)
	if err != nil || !p.permits(target) || via[len(via)-1].URL.Scheme == "https" && target.scheme != "https" {
		return errEgress
	}
	initial, err := endpoint(via[0].URL)
	if err != nil {
		return errEgress
	}
	left := !initial.sameOrigin(target)
	for _, previous := range via[1:] {
		e, err := endpoint(previous.URL)
		if err != nil {
			return errEgress
		}
		left = left || !initial.sameOrigin(e)
	}
	if left {
		if !p.cross || target.scheme != "https" {
			return errEgress
		}
		req.Header = http.Header{"Accept": {"*/*"}}
		req.Host = ""
		if req.Body != nil {
			req.Body.Close()
		}
		req.Body, req.GetBody = nil, nil
		req.ContentLength, req.TransferEncoding, req.Trailer = 0, nil, nil
	}
	return nil
}

type ipResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (p egressPolicy) dialContext(resolver ipResolver, dial dialFunc) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, errEgress
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errEgress
		}
		index := slices.IndexFunc(p.endpoints, func(e canonicalEndpoint) bool {
			return e.host == strings.ToLower(host) && e.port == port
		})
		if index < 0 {
			return nil, errEgress
		}
		e := p.endpoints[index]
		ips := []netip.Addr{e.ip}
		if !e.isIPLiteral {
			ips, err = resolver.LookupNetIP(ctx, "ip", e.host)
			if err != nil {
				return nil, errEgress
			}
		}
		for _, ip := range ips {
			ip = ip.Unmap()
			if !allowedIP(ip, e.isIPLiteral, p.private) || network == "tcp4" && !ip.Is4() || network == "tcp6" && !ip.Is6() {
				continue
			}
			conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, errEgress
	}
}

var blockedIPPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.100.100.200/32"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
}

var (
	ipv4Compatible = netip.MustParsePrefix("::/96")
	cgnat          = netip.MustParsePrefix("100.64.0.0/10")
)

func allowedIP(ip netip.Addr, literal, private bool) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() ||
		(ipv4Compatible.Contains(ip) && !ip.IsLoopback()) {
		return false
	}
	// The link-local rule also covers the IPv4 169.254.* metadata addresses.
	for _, prefix := range blockedIPPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	if ip.IsLoopback() {
		return literal
	}
	if ip.IsPrivate() || cgnat.Contains(ip) {
		return literal || private
	}
	return ip.IsGlobalUnicast()
}

type egressTransport struct {
	policy egressPolicy
	base   *http.Transport
}

func (t egressTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	deny := func() (*http.Response, error) {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, errEgress
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return deny()
	}
	e, err := endpoint(req.URL)
	if err != nil || !t.policy.permits(e) {
		return deny()
	}
	normalized, err := params.NormalizeURL(req.URL.String())
	if err != nil {
		return deny()
	}
	safe := req.Clone(req.Context())
	safe.URL = normalized
	safe.Host = ""
	return t.base.RoundTrip(safe)
}

func (t egressTransport) CloseIdleConnections() { t.base.CloseIdleConnections() }

func newEgressClient(c Config, resolver ipResolver) (*http.Client, error) {
	policy, err := egressConfig(c)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		tlsConfig.RootCAs, err = loadCA(c.CAFile)
		if err != nil {
			return nil, err
		}
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := &net.Dialer{}
	base := &http.Transport{
		DialContext:            policy.dialContext(resolver, dialer.DialContext),
		DisableCompression:     true,
		MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig:        tlsConfig,
	}
	return &http.Client{
		Timeout:       c.Timeout,
		Transport:     egressTransport{policy: policy, base: base},
		CheckRedirect: policy.checkRedirect,
	}, nil
}

func loadCA(path string) (*x509.CertPool, error) {
	const maxCABytes = 1 << 20
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errCA
	}
	f := os.NewFile(uintptr(fd), "plugin CA")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxCABytes {
		return nil, errCA
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCABytes+1))
	if err != nil || len(data) > maxCABytes {
		return nil, errCA
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errCA
	}
	return pool, nil
}
