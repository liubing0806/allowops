package params

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode"
)

// ParseURL is shared with HTTP handlers. Prefixes compare parsed origins and path
// components, rather than raw string prefixes. Encoded separators, dot segments
// and nested escapes are rejected before an HTTP client can normalize them.
func ParseURL(value string, prefixes []string) (*url.URL, error) {
	u, err := NormalizeURL(value)
	if err != nil {
		return nil, err
	}
	for _, prefix := range prefixes {
		p, err := NormalizeURL(prefix)
		if err != nil || p.RawQuery != "" || p.ForceQuery {
			return nil, fmt.Errorf("invalid allowed_prefixes URL")
		}
		if sameOrigin(u, p) && (u.Path == p.Path || strings.HasPrefix(u.Path, strings.TrimSuffix(p.Path, "/")+"/")) {
			return u, nil
		}
	}
	return nil, fmt.Errorf("URL outside allowed_prefixes")
}

// NormalizeURL is the single normalization boundary used by parameter parsing
// and HTTP requests. Hostnames are lowercase and default ports are omitted.
func NormalizeURL(value string) (*url.URL, error) {
	invalid := fmt.Errorf("invalid URL: require http(s), host and safe path without credentials")
	if invalidText(value) || strings.ContainsAny(value, "\\#") || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return nil, invalid
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return nil, invalid
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, invalid
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return nil, invalid
		}
	}
	// Percent escapes may encode ordinary characters, but never structural bytes.
	escaped := strings.ToLower(u.EscapedPath())
	for _, v := range []string{"%2f", "%5c", "%25", "%00", "%0a", "%0d"} {
		if strings.Contains(escaped, v) {
			return nil, invalid
		}
	}
	for _, component := range strings.Split(u.Path, "/") {
		if component == "." || component == ".." {
			return nil, invalid
		}
	}
	if strings.ContainsAny(u.Path, "\\\x00\r\n") || strings.IndexFunc(u.Path, unicode.IsControl) >= 0 {
		return nil, invalid
	}
	if u.Path == "" {
		u.Path = "/"
	}
	if path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/") && u.Path != "/" {
		return nil, invalid
	}

	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" {
		n, _ := strconv.Atoi(port)
		port = strconv.Itoa(n)
	}
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	return u, nil
}

// Both URLs must come from NormalizeURL; comparison performs no normalization.
func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && a.Host == b.Host
}
