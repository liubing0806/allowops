package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/go-ldap/ldap/v3"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	docker "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestLDAPGatewayLoginWithLocalOpenLDAP(t *testing.T) {
	f := newFixture(t) // Pins testcontainers to the local Unix socket.
	ctx := context.Background()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	priv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: testcontainers.ContainerRequest{
		Image: "osixia/openldap:1.5.0", ExposedPorts: []string{"636/tcp"},
		HostConfigModifier: func(c *docker.HostConfig) {
			c.PortBindings = network.PortMap{network.MustParsePort("636/tcp"): {{HostIP: netip.MustParseAddr("127.0.0.1")}}}
		},
		Env:        map[string]string{"LDAP_DOMAIN": "example.org", "LDAP_ADMIN_PASSWORD": "test-directory-password", "LDAP_TLS": "true", "LDAP_TLS_CRT_FILENAME": "server.crt", "LDAP_TLS_KEY_FILENAME": "server.key", "LDAP_TLS_CA_CRT_FILENAME": "ca.crt", "LDAP_TLS_VERIFY_CLIENT": "never"},
		Files:      []testcontainers.ContainerFile{{Reader: strings.NewReader(string(crt)), ContainerFilePath: "/container/service/slapd/assets/certs/server.crt", FileMode: 0644}, {Reader: strings.NewReader(string(priv)), ContainerFilePath: "/container/service/slapd/assets/certs/server.key", FileMode: 0600}, {Reader: strings.NewReader(string(crt)), ContainerFilePath: "/container/service/slapd/assets/certs/ca.crt", FileMode: 0644}},
		WaitingFor: wait.ForAll(wait.ForLog("slapd starting"), wait.ForListeningPort("636/tcp")).WithDeadline(2 * time.Minute),
	}, Started: true})
	if container != nil {
		testcontainers.CleanupContainer(t, container)
	}
	if err != nil {
		t.Fatal(err)
	}
	port, err := container.MappedPort(ctx, "636/tcp")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("local OpenLDAP container %s port=%s", container.GetContainerID()[:12], port.Port())
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(crt)
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	ldapURL := "ldaps://127.0.0.1:" + port.Port()
	directory := authn.DirectoryCredentials{BindDN: "cn=admin,dc=example,dc=org", Password: "test-directory-password"}
	conn, err := ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind(directory.BindDN, directory.Password); err != nil {
		t.Fatal(err)
	}
	add := func(dn string, attrs map[string][]string) {
		t.Helper()
		req := ldap.NewAddRequest(dn, nil)
		for k, v := range attrs {
			req.Attribute(k, v)
		}
		if err := conn.Add(req); err != nil {
			t.Fatal(err)
		}
	}
	add("ou=users,dc=example,dc=org", map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"users"}})
	add("ou=groups,dc=example,dc=org", map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"groups"}})
	dn := "uid=alice,ou=users,dc=example,dc=org"
	add(dn, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"alice"}, "cn": {"Alice"}, "sn": {"Test"}, "userPassword": {"test-user-password"}})
	add("cn=ops,ou=groups,dc=example,dc=org", map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"ops"}, "member": {dn}})
	auth, err := authn.NewLDAP(authn.LDAPConfig{URL: ldapURL, TLSConfig: tlsConfig, UserBaseDN: "ou=users,dc=example,dc=org", GroupBaseDN: "ou=groups,dc=example,dc=org"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.service.AddLDAP("test", "local LDAP", auth, directory); err != nil {
		t.Fatal(err)
	}
	methods, err := f.auth("").GetLoginMethods(ctx, connect.NewRequest(&v1.GetLoginMethodsRequest{}))
	if err != nil || len(methods.Msg.Methods) != 1 || methods.Msg.Methods[0].Kind != "ldap" {
		t.Fatal("LDAP method not exposed")
	}
	login := func(client v1.LoginClient, username, password, origin string) (*connect.Response[v1.LoginLdapResponse], error) {
		req := connect.NewRequest(&v1.LoginLdapRequest{ProviderId: "test", Client: client, Username: username, Password: password})
		if origin != "" {
			req.Header().Set("Origin", origin)
		}
		return f.auth("").LoginLdap(ctx, req)
	}
	response, err := login(v1.LoginClient_LOGIN_CLIENT_CLI, "alice", "test-user-password", "")
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.CliSessionToken == nil || response.Msg.CliSession == nil || strings.Join(response.Msg.User.EffectiveRoles, ",") != "admin" {
		t.Fatal("CLI LDAP login omitted session or DB role mapping")
	}
	console, err := login(v1.LoginClient_LOGIN_CLIENT_CONSOLE, "alice", "test-user-password", f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if console.Msg.CliSessionToken != nil || console.Msg.CliSession != nil {
		t.Fatal("console LDAP login exposed a session token")
	}
	cookies := (&http.Response{Header: console.Header()}).Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("LDAP console cookie is unsafe")
	}
	_, err = login(v1.LoginClient_LOGIN_CLIENT_CONSOLE, "alice", "test-user-password", "https://evil.example")
	code(t, err, connect.CodePermissionDenied)
	for range 5 {
		_, err := login(v1.LoginClient_LOGIN_CLIENT_CLI, "alice", "wrong-password", "")
		code(t, err, connect.CodeUnauthenticated)
	}
	_, err = login(v1.LoginClient_LOGIN_CLIENT_CLI, "alice", "test-user-password", "")
	code(t, err, connect.CodeResourceExhausted)
	_, err = login(v1.LoginClient_LOGIN_CLIENT_CLI, "*)(uid=*)", "test-user-password", "")
	code(t, err, connect.CodeUnauthenticated)
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	found := false
	for _, event := range f.audit.events {
		b, _ := json.Marshal(event)
		if strings.Contains(string(b), "test-user-password") || strings.Contains(string(b), "wrong-password") || strings.Contains(string(b), response.Msg.GetCliSessionToken()) {
			t.Fatal("LDAP audit leaked a credential")
		}
		if event.ActorID == response.Msg.User.UserId && event.Outcome == "allow" {
			found = true
		}
	}
	if !found {
		t.Fatal("successful login audit omitted the authenticated user")
	}
}
