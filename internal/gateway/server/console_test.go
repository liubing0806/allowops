package server_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/server"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestConsoleHTTPSCookieAndCSRF(t *testing.T) {
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ca, err := hostconn.OpenCA(filepath.Join(t.TempDir(), "ca.pem"), filepath.Join(t.TempDir(), "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	agent, err := hostconn.New(db, ca, hostconn.DefaultConfig(), hostconn.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Start(ctx); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://" + listener.Addr().String()
	chain := audit.New(db.Pool, audit.Config{})
	identity, err := api.New(ctx, db, api.Config{Origin: origin, Version: "0.4.0"}, api.NewAuditor(chain))
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	certificate, roots := managementTLS(t)
	native := server.New(agent, certificate)
	if err := identity.ConfigureManagement(api.ManagementConfig{Upstream: origin, CAPin: api.TLSCAPin(certificate.Certificate)}, agent, nil); err != nil {
		t.Fatal(err)
	}
	native.UseIdentity(identity)
	done := make(chan error, 1)
	go func() { done <- native.Serve(listener) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := native.Shutdown(shutdown); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true}, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	// P5B console session fixture: the browser never reads the HttpOnly token.
	digest := sha256.Sum256([]byte("aops_web_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if _, err := db.Pool.Exec(ctx, `INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username,manual_roles) VALUES ('console-admin','fixture','admin','ldap','admin',ARRAY['admin'])`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO identity_sessions(session_id,user_id,token_hash,client,csrf_token,expires_at) VALUES ('fixture-session','console-admin',$1,'console','fixture-csrf',now()+interval '1 hour')`, digest[:]); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(origin)
	jar.SetCookies(u, []*http.Cookie{{Name: "__Host-allowops-session", Value: "aops_web_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}})
	home, err := client.Get(origin + "/hosts/example-host")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(home.Body)
	home.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if home.StatusCode != http.StatusOK || !strings.Contains(string(body), `<div id="root"></div>`) {
		t.Fatalf("console homepage: status=%d body=%q", home.StatusCode, body)
	}
	if home.Header.Get("Content-Security-Policy") == "" || home.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("console headers: %v", home.Header)
	}
	script := regexp.MustCompile(`src="(/assets/[^"]+\.js)"`).FindSubmatch(body)
	if len(script) != 2 {
		t.Fatal("homepage does not reference a built JavaScript entry")
	}
	asset, err := client.Get(origin + string(script[1]))
	if err != nil {
		t.Fatal(err)
	}
	asset.Body.Close()
	if asset.StatusCode != http.StatusOK || asset.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("HTTPS JavaScript asset: status=%d headers=%v", asset.StatusCode, asset.Header)
	}
	unknown, err := client.Get(origin + "/allowops.v1.UnknownService/Unknown")
	if err != nil {
		t.Fatal(err)
	}
	unknown.Body.Close()
	if unknown.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown RPC became an SPA response: status=%d", unknown.StatusCode)
	}
	auth := rpc.NewAuthServiceClient(client, origin)
	current, err := auth.GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if current.Msg.User.UserId != "console-admin" || current.Msg.CsrfToken == "" {
		t.Fatal("console session fixture was not authenticated")
	}
	if current.Msg.GatewayVersion != "0.4.0" {
		t.Fatalf("gateway version=%q", current.Msg.GatewayVersion)
	}
	joins := rpc.NewJoinTokenServiceClient(client, origin)
	request := func(csrf string) *connect.Request[v1.CreateJoinTokenRequest] {
		r := connect.NewRequest(&v1.CreateJoinTokenRequest{MaxUses: 1, Ttl: durationpb.New(time.Hour)})
		r.Header().Set("Origin", origin)
		if csrf != "" {
			r.Header().Set("X-CSRF-Token", csrf)
		}
		return r
	}
	if _, err := joins.CreateJoinToken(ctx, request("")); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("write without CSRF: %v; want permission_denied", err)
	}
	created, err := joins.CreateJoinToken(ctx, request(current.Msg.CsrfToken))
	if err != nil {
		t.Fatal(err)
	}
	listed, err := joins.ListJoinTokens(ctx, connect.NewRequest(&v1.ListJoinTokensRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Msg.Tokens) != 1 || listed.Msg.Tokens[0].TokenId != created.Msg.Token.TokenId {
		t.Fatal("read did not return the CSRF-authorized write")
	}
}
