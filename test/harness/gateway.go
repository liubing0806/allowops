//go:build scale || vm

// Package harness starts the unchanged gateway binary and disposable local dependencies.
package harness

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
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"github.com/liubing0806/allowops/internal/testseaweedfs"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

type Gateway struct {
	DB                           *store.Store
	Dir, Address, Pin, JoinToken string
	Roots                        *x509.CertPool
	Trusted                      map[string]ed25519.PublicKey
	Catalog                      *catalog.Package
	Client                       rpc.JobServiceClient
	cmd                          *exec.Cmd
	done                         chan error
	env                          []string
	log                          *os.File
	binary                       string
	HTTP                         *http.Client
}

func Check(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func New(t *testing.T, hosts int) *Gateway {
	t.Helper()
	return NewWithActions(t, hosts, nil)
}

// NewWithActions adds extra actions to the signed fixture catalog.
func NewWithActions(t *testing.T, hosts int, extra map[string]catalog.Action) *Gateway {
	t.Helper()
	ctx := context.Background()
	dsn := testpg.Start(t)
	Check(t, store.Migrate(ctx, dsn))
	db, err := store.Open(ctx, dsn)
	Check(t, err)
	t.Cleanup(db.Close)
	objects := testseaweedfs.Start(t)
	g := &Gateway{DB: db, Dir: t.TempDir()}
	g.binary, err = filepath.Abs("../../bin/allowops-gateway")
	Check(t, err)
	_, err = hostconn.OpenCA(filepath.Join(g.Dir, "host-ca.pem"), filepath.Join(g.Dir, "host-ca.key"))
	Check(t, err)
	ca, err := hostconn.OpenCA(filepath.Join(g.Dir, "tls-ca.pem"), filepath.Join(g.Dir, "tls-ca.key"))
	Check(t, err)
	block, _ := pem.Decode(ca.PEM)
	issuer, err := x509.ParseCertificate(block.Bytes)
	Check(t, err)
	keyPEM, err := os.ReadFile(filepath.Join(g.Dir, "tls-ca.key"))
	Check(t, err)
	issuerKey, err := catalog.ParsePrivateKey(keyPEM)
	Check(t, err)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	Check(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.2.2")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, pub, issuerKey)
	Check(t, err)
	Check(t, os.WriteFile(filepath.Join(g.Dir, "server.pem"), append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.PEM...), 0644))
	keyPEM, err = catalog.MarshalPrivateKey(key)
	Check(t, err)
	Check(t, os.WriteFile(filepath.Join(g.Dir, "server.key"), keyPEM, 0600))
	g.Roots = x509.NewCertPool()
	g.Roots.AppendCertsFromPEM(ca.PEM)
	sum := sha256.Sum256(issuer.Raw)
	g.Pin = "sha256:" + hex.EncodeToString(sum[:])
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	Check(t, err)
	g.Trusted = map[string]ed25519.PublicKey{catalog.KeyID(pub): pub}
	keyPEM, err = catalog.MarshalPublicKey(pub)
	Check(t, err)
	Check(t, os.Mkdir(filepath.Join(g.Dir, "keys"), 0700))
	Check(t, os.WriteFile(filepath.Join(g.Dir, "keys", "catalog.pem"), keyPEM, 0644))
	examples, err := catalog.Load("../../examples/catalog")
	Check(t, err)
	actions := map[string]catalog.Action{
		"noop":          {Name: "noop", Description: "Protocol-only zero-duration result", Risk: "read", Exec: []any{"/usr/bin/true"}, Timeout: "10s", MaxOutput: 1024},
		"system_load":   examples.Actions["system_load"],
		"root_identity": {Name: "root_identity", Description: "Verify the packaged sudo helper", Risk: "write", RunAs: "root", Exec: []any{"/usr/bin/id", "-u"}, Timeout: "10s", MaxOutput: 1024},
	}
	for name, action := range extra {
		actions[name] = action
	}
	g.Catalog, err = catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: "p10a"}, Actions: actions}, catalog.BuildOptions{Now: time.Now(), TTL: 2 * time.Hour})
	Check(t, err)
	payload, err := catalog.CanonicalJSON(g.Catalog)
	Check(t, err)
	envelope, err := catalog.Sign(payload, catalog.SigningKey{PrivateKey: signer})
	Check(t, err)
	raw, err := json.Marshal(envelope)
	Check(t, err)
	publication := &catalogsvc.Service{Store: db, Trusted: g.Trusted, MaxEnvelopeBytes: 64 << 20, MaxActionBytes: 256 << 10}
	_, err = publication.Publish(ctx, raw)
	Check(t, err)
	_, err = db.Pool.Exec(ctx, "INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username,manual_roles) VALUES ('owner','fixture','owner','oidc','owner','{admin}'); INSERT INTO service_accounts(account_id,name,owner_user_id,roles) VALUES ('sa','fixture','owner','{admin}')")
	Check(t, err)
	token, _, err := authn.GenerateServiceToken(time.Now(), 1)
	Check(t, err)
	tokenHash := sha256.Sum256([]byte(token))
	_, err = db.Pool.Exec(ctx, "INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES ('token','sa',$1,now()+interval '2 hours')", tokenHash[:])
	Check(t, err)
	g.JoinToken, err = db.CreateJoinToken(ctx, int64(hosts), 2*time.Hour)
	Check(t, err)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	Check(t, err)
	g.Address = l.Addr().String()
	Check(t, l.Close())
	opts := objects.Client.Options()
	creds, err := opts.Credentials.Retrieve(ctx)
	Check(t, err)
	// Credentials exist only in the child environment, never command arguments or logs.
	g.env = append(os.Environ(), "ALLOWOPS_DATABASE_URL="+dsn, "AWS_ACCESS_KEY_ID="+creds.AccessKeyID, "AWS_SECRET_ACCESS_KEY="+creds.SecretAccessKey, "AWS_EC2_METADATA_DISABLED=true")
	config := map[string]any{"address": g.Address, "tls_certificate": filepath.Join(g.Dir, "server.pem"), "tls_key": filepath.Join(g.Dir, "server.key"), "ca_certificate": filepath.Join(g.Dir, "host-ca.pem"), "ca_key": filepath.Join(g.Dir, "host-ca.key"), "catalog_keys": filepath.Join(g.Dir, "keys"), "identity": map[string]any{"origin": "https://" + g.Address}, "output": map[string]any{"endpoint": *opts.BaseEndpoint, "bucket": objects.Bucket, "region": opts.Region}}
	raw, err = yaml.Marshal(config)
	Check(t, err)
	Check(t, os.WriteFile(filepath.Join(g.Dir, "gateway.yaml"), raw, 0600))
	g.log, err = os.Create(filepath.Join(g.Dir, "gateway.log"))
	Check(t, err)
	g.HTTP = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: g.Roots, MinVersion: tls.VersionTLS13}}, Timeout: 3 * time.Minute}
	g.Client = rpc.NewJobServiceClient(g.HTTP, "https://"+g.Address, connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
			r.Header().Set("Authorization", "Bearer "+token)
			return next(ctx, r)
		}
	})))
	t.Cleanup(func() { g.Stop(t); g.HTTP.CloseIdleConnections(); g.log.Close() })
	g.Start(t)
	return g
}

func (g *Gateway) Start(t *testing.T) {
	t.Helper()
	g.cmd = exec.Command(g.binary, "serve", "--config", filepath.Join(g.Dir, "gateway.yaml"))
	g.cmd.Env, g.cmd.Stdout, g.cmd.Stderr = g.env, g.log, g.log
	Check(t, g.cmd.Start())
	g.done = make(chan error, 1)
	go func() { g.done <- g.cmd.Wait() }()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-g.done:
			g.cmd = nil
			t.Fatalf("gateway exited: %v", err)
		default:
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", g.Address, &tls.Config{RootCAs: g.Roots, MinVersion: tls.VersionTLS13})
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("gateway start timeout")
}

func (g *Gateway) Stop(t *testing.T) {
	t.Helper()
	if g.cmd == nil {
		return
	}
	Check(t, g.cmd.Process.Signal(syscall.SIGTERM))
	select {
	case err := <-g.done:
		Check(t, err)
	case <-time.After(30 * time.Second):
		g.cmd.Process.Kill()
		<-g.done
		t.Error("gateway stop timeout")
	}
	g.cmd = nil
}

func (g *Gateway) RunJob(names []string, action string) (*v1.RunJobResponse, time.Duration, error) {
	return g.RunJobWithParams(names, action, nil)
}

// RunJobWithParams passes params as the job's JSON parameter object.
func (g *Gateway) RunJobWithParams(names []string, action string, params map[string]any) (*v1.RunJobResponse, time.Duration, error) {
	start := time.Now()
	request := &v1.RunJobRequest{Action: action, Targets: &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: names}}}, Reason: "local P10A acceptance", WaitSeconds: proto.Uint32(120)}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return nil, 0, err
		}
		request.Params = &v1.Parameters{Json: raw}
	}
	r, err := g.Client.RunJob(context.Background(), connect.NewRequest(request))
	if err != nil {
		return nil, time.Since(start), err
	}
	return r.Msg, time.Since(start), nil
}

func (g *Gateway) Online() (int, error) {
	var n int
	err := g.DB.Pool.QueryRow(context.Background(), "SELECT count(*) FROM hosts WHERE instance_id IN (SELECT instance_id FROM gateway_instances WHERE version='0.1.0') AND connection_id IS NOT NULL").Scan(&n)
	return n, err
}

func Environment(t *testing.T) {
	t.Helper()
	for _, cmd := range [][]string{{"git", "rev-parse", "HEAD"}, {"go", "version"}, {"uptime"}, {"lscpu"}, {"free", "-b"}} {
		out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		Check(t, err)
		t.Logf("environment %s: %s", cmd[0], out)
	}
}

func (g *Gateway) PID() int { return g.cmd.Process.Pid }

func (g *Gateway) Log(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(g.Dir, "gateway.log"))
	Check(t, err)
	t.Logf("gateway log: %s", data)
}
