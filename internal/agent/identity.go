package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
	"golang.org/x/net/http2"
)

type Identity struct {
	ClientCA    []byte    `json:"client_ca"`
	HostID      string    `json:"host_id"`
	Hostname    string    `json:"hostname"`
	Upstream    string    `json:"upstream"`
	CAPin       string    `json:"ca_pin"`
	PrivateKey  []byte    `json:"private_key"`
	Certificate []byte    `json:"certificate"`
	ExpiresAt   time.Time `json:"expires_at"`
	RenewAfter  time.Time `json:"renew_after"`
}

func parsePin(pin string) ([]byte, error) {
	if !strings.HasPrefix(pin, "sha256:") {
		return nil, errors.New("INVALID_CA_PIN")
	}
	data, err := hex.DecodeString(strings.TrimPrefix(pin, "sha256:"))
	if err != nil || len(data) != sha256.Size {
		return nil, errors.New("INVALID_CA_PIN")
	}
	return data, nil
}

// Pin is SHA-256 of the DER-encoded CA certificate, not its public key. Trust
// only a CA with that digest, and still verify the chain, hostname and validity.
func pinnedTLS(config Config) (*tls.Config, error) {
	address, err := upstreamURL(config.Upstream)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(address)
	pin, err := parsePin(config.CAPin)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: u.Hostname(), NextProtos: []string{AgentALPN}, InsecureSkipVerify: true, // verified below
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("CA_PIN_MISMATCH")
			}
			roots := x509.NewCertPool()
			intermediates := x509.NewCertPool()
			matched := false
			for _, cert := range state.PeerCertificates {
				sum := sha256.Sum256(cert.Raw)
				if cert.IsCA && hex.EncodeToString(sum[:]) == hex.EncodeToString(pin) {
					roots.AddCert(cert)
					matched = true
				} else {
					intermediates.AddCert(cert)
				}
			}
			if !matched {
				return errors.New("CA_PIN_MISMATCH")
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: u.Hostname()})
			return err
		}}, nil
}

type clientTransport interface{ CloseIdleConnections() }

func newClient(config Config, identity *identityStore) (allowopsv1connect.AgentServiceClient, clientTransport, error) {
	address, err := upstreamURL(config.Upstream)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig, err := pinnedTLS(config)
	if err != nil {
		return nil, nil, err
	}
	if identity != nil {
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			value := identity.get()
			cert, err := tls.X509KeyPair(value.Certificate, value.PrivateKey)
			return &cert, err
		}
	}
	protocol := AgentALPN
	if identity == nil {
		protocol = JoinALPN
	}
	tlsConfig.NextProtos = []string{protocol}
	//lint:ignore SA1019 P4 custom ALPN carries raw HTTP/2; the standard transport only selects h2.
	transport := &http2.Transport{DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
		dialer := tls.Dialer{Config: tlsConfig, NetDialer: &net.Dialer{Timeout: 10 * time.Second}}
		connection, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if connection.(*tls.Conn).ConnectionState().NegotiatedProtocol != protocol {
			connection.Close()
			return nil, errors.New("ALPN_MISMATCH")
		}
		return connection, nil
	}}

	httpClient := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("REDIRECT_FORBIDDEN") }}
	limits := config.Limits.defaults()
	client := allowopsv1connect.NewAgentServiceClient(httpClient, address, connect.WithGRPC(), connect.WithReadMaxBytes(limits.MessageBytes), connect.WithSendMaxBytes(limits.MessageBytes))
	return client, transport, nil
}

func newCSR(hostname string) ([]byte, []byte, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hostname}}, key)
	if err != nil {
		return nil, nil, err
	}
	private, err := catalog.MarshalPrivateKey(key)
	return private, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), err
}

func acceptCertificate(config Config, hostname string, key []byte, response *v1.HostCertificate, expectedHost string, expectedCA []byte) (Identity, error) {
	var value Identity
	if response == nil || response.HostId == "" || (expectedHost != "" && response.HostId != expectedHost) || response.ExpiresAt == nil || response.ExpiresAt.CheckValid() != nil || response.RenewAfter == nil || response.RenewAfter.CheckValid() != nil {
		return value, errors.New("INVALID_HOST_CERTIFICATE")
	}
	cert, err := tls.X509KeyPair(response.CertificateChainPem, key)
	if err != nil || len(cert.Certificate) == 0 {
		return value, errors.New("INVALID_HOST_CERTIFICATE")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return value, errors.New("INVALID_HOST_CERTIFICATE")
	}
	if leaf.Subject.CommonName != response.HostId || len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://allowops/hosts/"+response.HostId {
		return value, errors.New("INVALID_HOST_IDENTITY")
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	clientCA := expectedCA
	if len(clientCA) == 0 {
		if len(cert.Certificate) < 2 {
			return value, errors.New("INVALID_HOST_CA")
		}
		root, err := x509.ParseCertificate(cert.Certificate[len(cert.Certificate)-1])
		if err != nil || !root.IsCA || root.CheckSignatureFrom(root) != nil {
			return value, errors.New("INVALID_HOST_CA")
		}
		clientCA = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	}
	if !roots.AppendCertsFromPEM(clientCA) {
		return value, errors.New("INVALID_HOST_CA")
	}
	for _, data := range cert.Certificate[1:] {
		c, err := x509.ParseCertificate(data)
		if err != nil {
			return value, errors.New("INVALID_HOST_CERTIFICATE")
		}
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return value, errors.New("INVALID_HOST_CERTIFICATE")
	}
	expires, renew := response.ExpiresAt.AsTime(), response.RenewAfter.AsTime()
	if !expires.Truncate(time.Second).Equal(leaf.NotAfter) || !renew.Before(leaf.NotAfter) || !expires.After(time.Now()) {
		return value, errors.New("INVALID_HOST_CERTIFICATE")
	}
	return Identity{HostID: response.HostId, Hostname: hostname, Upstream: config.Upstream, CAPin: config.CAPin, PrivateKey: key, Certificate: response.CertificateChainPem, ExpiresAt: leaf.NotAfter, RenewAfter: renew, ClientCA: clientCA}, nil
}

func saveIdentity(path string, value Identity) error {
	dir, err := execd.OpenDirectory(path, true, os.Getuid(), true)
	if err != nil {
		return err
	}
	defer dir.Close()
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return execd.AtomicWrite(dir, "identity.json", data)
}

func LoadIdentity(path string) (Identity, error) {
	var value Identity
	owner, _, err := identityOwner()
	if err != nil {
		return value, err
	}
	dir, err := execd.OpenDirectory(path, false, owner, true)
	if err != nil {
		return value, err
	}
	defer dir.Close()
	data, err := execd.ReadPrivateFile(dir, "identity.json", 128*1024, owner)
	if err != nil {
		return value, err
	}
	err = execd.DecodeJSON(data, &value)
	if err != nil || value.HostID == "" {
		return value, errors.New("INVALID_IDENTITY")
	}
	return value, nil
}

func Join(ctx context.Context, config Config, token, hostname, dataDir string) (Identity, error) {
	var value Identity
	if err := config.validate(); err != nil {
		return value, err
	}
	if token == "" || hostname == "" {
		return value, errors.New("INVALID_JOIN")
	}
	owner, gid, err := identityOwner()
	if err != nil {
		return value, err
	}
	dir, err := execd.OpenDirectory(dataDir, false, owner, true)
	if err != nil {
		return value, err
	}
	defer dir.Close()
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return value, errors.New("IDENTITY_IN_USE")
	}
	defer syscall.Flock(int(dir.Fd()), syscall.LOCK_UN)
	// Never overwrite an existing identity or consume a second token silently.
	if _, err := os.Lstat(filepath.Join(dataDir, "identity.json")); err == nil {
		return value, errors.New("ALREADY_JOINED")
	} else if !os.IsNotExist(err) {
		return value, err
	}
	private, csr, err := newCSR(hostname)
	if err != nil {
		return value, err
	}
	client, transport, err := newClient(config, nil)
	if err != nil {
		return value, err
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := client.Join(ctx, connect.NewRequest(&v1.JoinRequest{JoinToken: token, Hostname: hostname, CsrPem: csr}))
	if err != nil {
		return value, errors.New("JOIN_FAILED")
	}
	value, err = acceptCertificate(config, hostname, private, response.Msg.Certificate, "", nil)
	if err != nil {
		return value, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return value, err
	}
	return value, execd.AtomicWriteOwned(dir, "identity.json", data, owner, gid)
}

type identityStore struct {
	mu    sync.RWMutex
	value Identity
}

func (s *identityStore) get() Identity      { s.mu.RLock(); defer s.mu.RUnlock(); return s.value }
func (s *identityStore) set(value Identity) { s.mu.Lock(); defer s.mu.Unlock(); s.value = value }

func renew(ctx context.Context, client allowopsv1connect.AgentServiceClient, config Config, dataDir string, store *identityStore) error {
	current := store.get()
	private, csr, err := newCSR(current.Hostname)
	if err != nil {
		return err
	}
	response, err := client.RenewCertificate(ctx, connect.NewRequest(&v1.RenewCertificateRequest{CsrPem: csr}))
	if err != nil {
		return errors.New("RENEW_FAILED")
	}
	value, err := acceptCertificate(config, current.Hostname, private, response.Msg.Certificate, current.HostID, current.ClientCA)
	if err != nil {
		return err
	}
	if err := saveIdentity(dataDir, value); err != nil {
		return err
	}
	store.set(value)
	return nil
}
