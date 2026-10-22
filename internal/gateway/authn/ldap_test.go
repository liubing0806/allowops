package authn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func ldapConfig() LDAPConfig {
	return LDAPConfig{URL: "ldaps://localhost:636", UserBaseDN: "ou=users,dc=example,dc=org", GroupBaseDN: "ou=groups,dc=example,dc=org", RoleMappings: map[string]string{"ops": "operator"}}
}

func TestLDAPRejectsUnsafeTransport(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*LDAPConfig)
	}{
		{"plaintext", func(c *LDAPConfig) { c.URL = "ldap://localhost:389" }},
		{"invalid scheme", func(c *LDAPConfig) { c.URL = "http://localhost" }},
		{"userinfo", func(c *LDAPConfig) { c.URL = "ldaps://user:password@localhost" }},
		{"skip verify", func(c *LDAPConfig) { c.TLSConfig = &tls.Config{InsecureSkipVerify: true} }},
		{"filter attribute injection", func(c *LDAPConfig) { c.UserAttribute = "uid)(objectClass=*" }},
		{"negative limit", func(c *LDAPConfig) { c.RateLimit.Attempts = -1 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := ldapConfig()
			tt.change(&c)
			if _, err := NewLDAP(c); err == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
	if _, err := NewLDAP(ldapConfig()); err != nil {
		t.Fatal(err)
	}
}

func TestLDAPStartTLSFailureDoesNotSendCredentials(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	packets := make(chan *ber.Packet, 3)
	go func() {
		for range 3 {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			packet, _ := ber.ReadPacket(conn)
			packets <- packet
			_ = conn.Close()
		}
	}()
	c := ldapConfig()
	c.URL = "ldap://" + listener.Addr().String()
	c.StartTLS = true
	c.RateLimit = RateLimit{Attempts: 2, Window: time.Minute}
	authenticator, err := NewLDAP(c)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		_, err = authenticator.Login(context.Background(), "alice", "private-password", "192.0.2.1", DirectoryCredentials{BindDN: "cn=admin", Password: "directory-password"})
		assertDirectoryUnavailable(t, err)
		packet := <-packets
		if packet == nil || len(packet.Children) < 2 || packet.Children[1].Tag != ldap.ApplicationExtendedRequest {
			t.Fatalf("first packet must be StartTLS extended request: %+v", packet)
		}
		if strings.Contains(string(packet.Bytes()), "private-password") || strings.Contains(string(packet.Bytes()), "directory-password") {
			t.Fatal("credentials sent before TLS")
		}
	}
}

func assertDirectoryUnavailable(t *testing.T, err error) {
	t.Helper()
	if err != ErrDirectoryUnavailable {
		t.Fatalf("directory failure: got %v, want directory unavailable", err)
	}
}

func TestLDAPDirectoryFailuresDoNotConsumeFailureLimit(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(*testing.T, *LDAPConfig) DirectoryCredentials
	}{
		{"connection", func(t *testing.T, c *LDAPConfig) DirectoryCredentials {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			c.URL = "ldaps://" + listener.Addr().String()
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			return DirectoryCredentials{}
		}},
		{"TLS", func(t *testing.T, c *LDAPConfig) DirectoryCredentials {
			server := httptest.NewUnstartedServer(nil)
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			t.Cleanup(server.Close)
			c.URL = "ldaps://" + server.Listener.Addr().String()
			return DirectoryCredentials{}
		}},
		{"directory credentials configuration", func(_ *testing.T, _ *LDAPConfig) DirectoryCredentials {
			return DirectoryCredentials{BindDN: "cn=admin"}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := ldapConfig()
			c.RateLimit = RateLimit{Attempts: 2, Window: time.Minute}
			credentials := tt.setup(t, &c)
			authenticator, err := NewLDAP(c)
			if err != nil {
				t.Fatal(err)
			}
			var failures []error
			for range 3 {
				identity, err := authenticator.Login(context.Background(), "alice", "user-password", "192.0.2.1", credentials)
				failures = append(failures, err)
				if identity.ID != "" {
					t.Fatal("directory failure returned an identity")
				}
			}
			if errors.Is(failures[2], ErrRateLimited) {
				t.Fatalf("directory failures consumed credential quota: third attempt=%v", failures[2])
			}
			for _, err := range failures {
				assertDirectoryUnavailable(t, err)
			}
			if len(authenticator.limiter.entries) != 0 {
				t.Fatalf("directory failures retained limiter keys: %d", len(authenticator.limiter.entries))
			}
		})
	}
}

func TestLDAPDirectoryErrorLogsRedactPasswords(t *testing.T) {
	certPEM, keyPEM, roots := ldapTestCertificate(t)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const userPassword, directoryPassword = "private-user-password", "private-directory-password"
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := ber.ReadPacket(conn)
		if err != nil || len(request.Children) < 2 {
			return
		}
		response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP response")
		response.AppendChild(request.Children[0])
		result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "Bind result")
		result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, ldap.LDAPResultInvalidCredentials, "Result code"))
		result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
		result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "server diagnostic: "+userPassword+" "+directoryPassword, "Diagnostic"))
		response.AppendChild(result)
		_, _ = conn.Write(response.Bytes())
	}()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	c := ldapConfig()
	c.URL = "ldaps://" + listener.Addr().String()
	c.TLSConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	authenticator, err := NewLDAP(c)
	if err != nil {
		t.Fatal(err)
	}
	_, err = authenticator.Login(context.Background(), "alice", userPassword, "192.0.2.1", DirectoryCredentials{BindDN: "cn=admin", Password: directoryPassword})
	assertDirectoryUnavailable(t, err)
	if !strings.Contains(logs.String(), "server diagnostic:") || !strings.Contains(logs.String(), "directory_bind") {
		t.Fatalf("underlying directory error missing from slog: %s", logs.String())
	}
	if strings.Contains(logs.String(), userPassword) || strings.Contains(logs.String(), directoryPassword) {
		t.Fatal("directory error log contains a password")
	}
}

func TestLDAPOpenLDAPIntegration(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM, roots := ldapTestCertificate(t)
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: testcontainers.ContainerRequest{
		Image: "osixia/openldap:1.5.0", ExposedPorts: []string{"389/tcp", "636/tcp"},
		HostConfigModifier: func(config *dockercontainer.HostConfig) {
			config.PortBindings = network.PortMap{
				network.MustParsePort("389/tcp"): {{HostIP: netip.MustParseAddr("127.0.0.1")}},
				network.MustParsePort("636/tcp"): {{HostIP: netip.MustParseAddr("127.0.0.1")}},
			}
		},
		Env: map[string]string{"LDAP_DOMAIN": "example.org", "LDAP_ADMIN_PASSWORD": "test-directory-password", "LDAP_TLS": "true", "LDAP_TLS_CRT_FILENAME": "server.crt", "LDAP_TLS_KEY_FILENAME": "server.key", "LDAP_TLS_CA_CRT_FILENAME": "ca.crt", "LDAP_TLS_VERIFY_CLIENT": "never"},
		Files: []testcontainers.ContainerFile{
			{Reader: strings.NewReader(certPEM), ContainerFilePath: "/container/service/slapd/assets/certs/server.crt", FileMode: 0644},
			{Reader: strings.NewReader(keyPEM), ContainerFilePath: "/container/service/slapd/assets/certs/server.key", FileMode: 0600},
			{Reader: strings.NewReader(certPEM), ContainerFilePath: "/container/service/slapd/assets/certs/ca.crt", FileMode: 0644},
		},
		WaitingFor: wait.ForAll(wait.ForLog("slapd starting"), wait.ForListeningPort("636/tcp")).WithDeadline(2 * time.Minute),
	}, Started: true})
	if container != nil {
		testcontainers.CleanupContainer(t, container)
	}
	if err != nil {
		t.Fatal(err)
	}
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ldapsPort, err := container.MappedPort(ctx, "636/tcp")
	if err != nil {
		t.Fatal(err)
	}
	startTLSPort, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	ldapsURL := "ldaps://" + net.JoinHostPort(host, ldapsPort.Port())
	connection, err := ldap.DialURL(ldapsURL, ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	credentials := DirectoryCredentials{BindDN: "cn=admin,dc=example,dc=org", Password: "test-directory-password"}
	if err := connection.Bind(credentials.BindDN, credentials.Password); err != nil {
		t.Fatal(err)
	}
	add := func(dn string, attributes map[string][]string) {
		t.Helper()
		request := ldap.NewAddRequest(dn, nil)
		for name, values := range attributes {
			request.Attribute(name, values)
		}
		if err := connection.Add(request); err != nil {
			t.Fatal(err)
		}
	}
	add("ou=users,dc=example,dc=org", map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"users"}})
	add("ou=groups,dc=example,dc=org", map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"groups"}})
	userDN := "uid=alice,ou=users,dc=example,dc=org"
	add(userDN, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"alice"}, "cn": {"Alice"}, "sn": {"Test"}, "userPassword": {"test-user-password"}})
	add("cn=ops,ou=groups,dc=example,dc=org", map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"ops"}, "member": {userDN}})
	for _, startTLS := range []bool{false, true} {
		t.Run(map[bool]string{false: "LDAPS", true: "StartTLS"}[startTLS], func(t *testing.T) {
			c := ldapConfig()
			c.URL = ldapsURL
			c.TLSConfig = tlsConfig
			c.RateLimit = RateLimit{Attempts: 20, Window: time.Minute}
			if startTLS {
				c.URL = "ldap://" + net.JoinHostPort(host, startTLSPort.Port())
				c.StartTLS = true
			}
			authenticator, err := NewLDAP(c)
			if err != nil {
				t.Fatal(err)
			}
			c.RoleMappings["ops"] = "admin"
			identity, err := authenticator.Login(ctx, "alice", "test-user-password", "192.0.2.1", credentials)
			if err != nil || identity.ID != "alice" || identity.Kind != "ldap" || !reflect.DeepEqual(identity.Roles, []string{"operator"}) {
				t.Fatalf("identity=%+v, err=%v", identity, err)
			}
			for _, username := range []string{"alice", "missing", "*)(uid=*)", "alice)(|(uid=*))"} {
				if _, err := authenticator.Login(ctx, username, "wrong-password", "192.0.2.1", credentials); !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("username %q: %v", username, err)
				}
			}
			// Injection with the real password must still not select Alice.
			if _, err := authenticator.Login(ctx, "*)(uid=*)", "test-user-password", "192.0.2.1", credentials); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("LDAP filter injection: %v", err)
			}
			if _, err := authenticator.Login(ctx, "alice", "", "192.0.2.1", credentials); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("empty password: %v", err)
			}
			untrusted := c
			untrusted.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			other, err := NewLDAP(untrusted)
			if err != nil {
				t.Fatal(err)
			}
			_, err = other.Login(ctx, "alice", "test-user-password", "192.0.2.1", credentials)
			assertDirectoryUnavailable(t, err)
		})
	}
	c := ldapConfig()
	c.URL = ldapsURL
	c.TLSConfig = tlsConfig
	c.RateLimit = RateLimit{Attempts: 2, Window: time.Minute}
	for _, tt := range []struct {
		name   string
		change func(*LDAP, *DirectoryCredentials)
	}{
		{"directory bind", func(_ *LDAP, credentials *DirectoryCredentials) { credentials.Password = "wrong-directory-password" }},
		{"user search", func(l *LDAP, _ *DirectoryCredentials) { l.config.UserBaseDN = "ou=missing,dc=example,dc=org" }},
		{"group search", func(l *LDAP, _ *DirectoryCredentials) { l.config.GroupBaseDN = "ou=missing,dc=example,dc=org" }},
	} {
		t.Run(tt.name+" preserves credential failure quota", func(t *testing.T) {
			authenticator, err := NewLDAP(c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authenticator.Login(ctx, "alice", "wrong", "192.0.2.1", credentials); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("first credential failure: %v", err)
			}
			originalConfig := authenticator.config
			directory := credentials
			tt.change(authenticator, &directory)
			for range 3 {
				_, err := authenticator.Login(ctx, "alice", "test-user-password", "192.0.2.1", directory)
				assertDirectoryUnavailable(t, err)
			}
			authenticator.config = originalConfig
			if _, err := authenticator.Login(ctx, "alice", "wrong", "192.0.2.1", credentials); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("directory errors consumed failure quota: %v", err)
			}
			if _, err := authenticator.Login(ctx, "alice", "test-user-password", "192.0.2.1", credentials); !errors.Is(err, ErrRateLimited) {
				t.Fatalf("directory errors cleared previous credential failure: %v", err)
			}
		})
	}
	for _, tt := range []struct{ name, username, password string }{
		{"unknown user", "missing", "test-user-password"},
		{"empty password", "alice", ""},
	} {
		t.Run(tt.name+" consumes failure quota", func(t *testing.T) {
			authenticator, err := NewLDAP(c)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if _, err := authenticator.Login(ctx, tt.username, tt.password, "192.0.2.1", credentials); !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("credential rejection: %v", err)
				}
			}
			if _, err := authenticator.Login(ctx, tt.username, tt.password, "192.0.2.1", credentials); !errors.Is(err, ErrRateLimited) {
				t.Fatalf("credential rejection not counted: %v", err)
			}
		})
	}
	authenticator, err := NewLDAP(c)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := authenticator.Login(ctx, "alice", "wrong", "192.0.2.1", credentials); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatal(err)
		}
	}
	if _, err := authenticator.Login(ctx, "alice", "test-user-password", "192.0.2.1", credentials); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("rate limit: %v", err)
	}
	if _, err := authenticator.Login(ctx, "ALICE", "test-user-password", "::ffff:192.0.2.1", credentials); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("canonical limiter key: %v", err)
	}
	if _, err := authenticator.Login(ctx, "alice", "test-user-password", "192.0.2.2", credentials); err != nil {
		t.Fatalf("IP isolation: %v", err)
	}
	if _, err := authenticator.Login(ctx, "missing", "wrong", "192.0.2.1", credentials); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("username isolation: %v", err)
	}
	t.Run("successful logins do not consume failure limit", func(t *testing.T) {
		for range 6 {
			if _, err := authenticator.Login(ctx, "alice", "test-user-password", "192.0.2.2", credentials); err != nil {
				t.Fatalf("successful login consumed failure budget: %v", err)
			}
		}
	})
	t.Run("successful login resets failures", func(t *testing.T) {
		authenticator, err := NewLDAP(c)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err := authenticator.Login(ctx, "ALICE", "wrong", "::ffff:192.0.2.2", credentials); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("failure after reset: %v", err)
			}
			if _, err := authenticator.Login(ctx, "alice", "test-user-password", "192.0.2.2", credentials); err != nil {
				t.Fatalf("login below failure threshold: %v", err)
			}
		}
		for range 2 {
			if _, err := authenticator.Login(ctx, "alice", "wrong", "192.0.2.2", credentials); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("failure quota after successful login: %v", err)
			}
		}
		if _, err := authenticator.Login(ctx, "alice", "test-user-password", "192.0.2.2", credentials); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("failure threshold not enforced: %v", err)
		}
	})
}

func ldapTestCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(certPEM)) {
		t.Fatal("invalid test certificate")
	}
	return certPEM, keyPEM, roots
}
