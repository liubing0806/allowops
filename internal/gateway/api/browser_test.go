package api

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authn"
)

// Optional real-browser verification uses an isolated profile and an HTTP proxy
// that permits only the two fixture endpoints. No browser request can reach an
// external site, including browser startup/background traffic.
func TestBrowserStrictCookieOIDCCompletion(t *testing.T) {
	chrome := "/opt/google/chrome/chrome"
	if _, err := os.Stat(chrome); err != nil {
		t.Skip("local headless Chrome unavailable")
	}
	var completionStarted, completionFinished, rootRequested, authenticated atomic.Bool
	f := newFixture(t, func(s *Service, base http.Handler) http.Handler {
		return s.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				rootRequested.Store(true)
				id, ok := FromContext(r.Context())
				if ok && id.User != nil && id.User.Email == "oidc@example.org" {
					authenticated.Store(true)
					io.WriteString(w, "allowops browser login success")
				} else {
					w.WriteHeader(401)
				}
				return
			}
			if r.URL.Path == "/allowops.v1.AuthService/CompleteOidcLogin" {
				completionStarted.Store(true)
				defer completionFinished.Store(true)
			}
			base.ServeHTTP(w, r)
		}))
	})
	p := newOIDC(t)
	providerAddress := p.server.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(providerAddress)
	p.server.URL = "https://example.com:" + port // Different site from the gateway.
	client := p.server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "example.com:"+port {
			address = providerAddress
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	client.Transport = transport
	if err := f.service.AddOIDC(context.Background(), "test", "cross-site test", "", authn.OIDCConfig{IssuerURL: p.server.URL, ClientID: "allowops", HTTPClient: client}); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]string{f.server.Listener.Addr().String(): f.server.Listener.Addr().String(), "example.com:" + port: providerAddress}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address, ok := allowed[r.Host]
		if r.Method != http.MethodConnect || !ok {
			http.Error(w, "fixture endpoints only", http.StatusForbidden)
			return
		}
		remote, err := net.Dial("tcp", address)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer remote.Close()
		local, reader, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer local.Close()
		io.WriteString(local, "HTTP/1.1 200 Connection Established\r\n\r\n")
		done := make(chan struct{})
		go func() { io.Copy(remote, reader); remote.Close(); close(done) }()
		io.Copy(local, remote)
		local.Close()
		<-done
	}))
	defer proxy.Close()
	req := connect.NewRequest(&v1.BeginOidcLoginRequest{ProviderId: "test", Client: v1.LoginClient_LOGIN_CLIENT_CONSOLE})
	req.Header().Set("Origin", f.server.URL)
	begun, err := f.auth("").BeginOidcLogin(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(f.server.Certificate().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(spki)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, chrome, "--headless", "--no-sandbox", "--disable-gpu", "--disable-background-networking", "--disable-component-update", "--disable-domain-reliability", "--disable-sync", "--no-first-run", "--no-default-browser-check", "--disable-client-side-phishing-detection", "--safebrowsing-disable-auto-update", "--disable-features=OptimizationHints,MediaRouter", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", "--user-data-dir="+filepath.Join(t.TempDir(), "profile"), "--proxy-server="+proxy.URL, "--proxy-bypass-list=<-loopback>", "--ignore-certificate-errors-spki-list="+base64.StdEncoding.EncodeToString(digest[:]), "--virtual-time-budget=10000", "--dump-dom", begun.Msg.AuthorizationUrl)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("local headless Chrome exited: %v", err)
	}
	if !strings.Contains(string(output), "allowops browser login success") {
		t.Fatalf("cross-site OIDC did not establish a Strict-cookie console session: completion_started=%t completion_finished=%t root_requested=%t authenticated=%t completing_dom=%t failed_dom=%t", completionStarted.Load(), completionFinished.Load(), rootRequested.Load(), authenticated.Load(), strings.Contains(string(output), `<p id="status">Completing login</p>`), strings.Contains(string(output), `<p id="status">Login failed</p>`))
	}
	var sessions int
	if err := f.db.Pool.QueryRow(context.Background(), "SELECT count(*) FROM identity_sessions s JOIN console_users u USING(user_id) WHERE client='console' AND provider_subject='oidc-user'").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("browser console sessions=%d; want 1", sessions)
	}
	t.Log("real Chrome: cross-site provider -> gateway callback -> same-origin completion -> authenticated Strict-cookie request")
}
