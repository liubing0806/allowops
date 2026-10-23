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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "allowops-process-fixture" {
		child := exec.Command("/usr/bin/sleep", "120")
		if child.Start() != nil {
			os.Exit(10)
		}
		data, _ := json.Marshal([]int{os.Getpid(), child.Process.Pid})
		if os.WriteFile(os.Args[2], data, 0600) != nil {
			os.Exit(11)
		}
		_ = child.Wait()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type testGateway struct {
	allowopsv1connect.UnimplementedAgentServiceHandler
	ca          *x509.Certificate
	caPEM       []byte
	key         ed25519.PrivateKey
	connections chan *testConnection
	joins       atomic.Int32
	renewals    atomic.Int32
	mu          sync.Mutex
	packages    map[string][]byte
	badOffset   bool
	renewSoon   bool
	// hello overrides the gateway hello. A nil response sends none; an error ends the stream.
	hello func() (*v1.ConnectResponse, error)
	// silent stops the gateway from answering agent heartbeats.
	silent bool
	// blockPull holds catalog pulls open until the stream context ends.
	blockPull bool
}
type testConnection struct {
	stream   *connect.BidiStream[v1.ConnectRequest, v1.ConnectResponse]
	mu       sync.Mutex
	hello    *v1.AgentHello
	messages chan *v1.ConnectRequest
	closed   chan struct{}
}

func (c *testConnection) send(t *testing.T, message *v1.ConnectResponse) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.stream.Send(message); err != nil {
		t.Fatal(err)
	}
}
func (c *testConnection) next(t *testing.T, match func(*v1.ConnectRequest) bool) *v1.ConnectRequest {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case message := <-c.messages:
			if match(message) {
				return message
			}
		case <-c.closed:
			t.Fatal("gateway connection closed")
		case <-timer.C:
			t.Fatal("message timeout")
		}
	}
}

func (g *testGateway) issue(csrPEM []byte) (*v1.HostCertificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("CSR missing")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("CSR invalid")
	}
	now := time.Now().UTC().Truncate(time.Second)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "host-test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{{Scheme: "spiffe", Host: "allowops", Path: "/hosts/host-test"}}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, g.ca, csr.PublicKey, g.key)
	if err != nil {
		return nil, err
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), g.caPEM...)
	renewAt := now.Add(12 * time.Hour)
	if g.renewSoon && g.renewals.Load() == 0 {
		renewAt = now.Add(time.Second)
	}
	return &v1.HostCertificate{HostId: "host-test", CertificateChainPem: chain, ExpiresAt: timestamppb.New(leaf.NotAfter), RenewAfter: timestamppb.New(renewAt)}, nil
}
func (g *testGateway) Join(_ context.Context, request *connect.Request[v1.JoinRequest]) (*connect.Response[v1.JoinResponse], error) {
	if request.Msg.JoinToken != "test-token" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("token"))
	}
	g.joins.Add(1)
	certificate, err := g.issue(request.Msg.CsrPem)
	return connect.NewResponse(&v1.JoinResponse{Certificate: certificate}), err
}
func (g *testGateway) RenewCertificate(_ context.Context, request *connect.Request[v1.RenewCertificateRequest]) (*connect.Response[v1.RenewCertificateResponse], error) {
	g.renewals.Add(1)
	certificate, err := g.issue(request.Msg.CsrPem)
	return connect.NewResponse(&v1.RenewCertificateResponse{Certificate: certificate}), err
}
func (g *testGateway) Connect(ctx context.Context, stream *connect.BidiStream[v1.ConnectRequest, v1.ConnectResponse]) error {
	first, err := stream.Receive()
	if err != nil {
		return err
	}
	if first.GetHello() == nil {
		return errors.New("first message must be hello")
	}
	c := &testConnection{stream: stream, hello: first.GetHello(), messages: make(chan *v1.ConnectRequest, 256), closed: make(chan struct{})}
	defer func() { c.mu.Lock(); defer c.mu.Unlock(); close(c.closed) }()
	g.mu.Lock()
	helloOverride, silent := g.hello, g.silent
	g.mu.Unlock()
	hello := &v1.ConnectResponse{Message: &v1.ConnectResponse_Hello{Hello: &v1.GatewayHello{GatewayVersion: "0.1.0", ConnectionId: "test-connection", Limits: &v1.ConnectionLimits{HeartbeatInterval: durationpb.New(50 * time.Millisecond), HeartbeatTimeout: durationpb.New(time.Second), MaxMessageBytes: MaxMessageBytes, MaxChunkBytes: 7, MaxInflightTasks: MaxConcurrentTasks}}}}
	if helloOverride != nil {
		hello, err = helloOverride()
		if err != nil {
			return err
		}
	}
	if hello != nil {
		if err := stream.Send(hello); err != nil {
			return err
		}
	}
	select {
	case g.connections <- c:
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		message, err := stream.Receive()
		if err != nil {
			return err
		}
		if heartbeat := message.GetHeartbeat(); heartbeat != nil && !silent {
			c.mu.Lock()
			err = stream.Send(&v1.ConnectResponse{Message: &v1.ConnectResponse_Heartbeat{Heartbeat: &v1.GatewayHeartbeat{Sequence: heartbeat.Sequence}}})
			c.mu.Unlock()
			if err != nil {
				return err
			}
		}
		select {
		case c.messages <- proto.Clone(message).(*v1.ConnectRequest):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func (g *testGateway) PullCatalog(ctx context.Context, request *connect.Request[v1.PullCatalogRequest], stream *connect.ServerStream[v1.PullCatalogResponse]) error {
	g.mu.Lock()
	data := g.packages[request.Msg.Catalog.CatalogId+":"+strconv.FormatUint(request.Msg.Catalog.Version, 10)]
	bad := g.badOffset
	block := g.blockPull
	g.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	if len(data) == 0 {
		return connect.NewError(connect.CodeNotFound, errors.New("catalog"))
	}
	sum := sha256.Sum256(data)
	for offset := 0; offset < len(data); offset += 1024 {
		end := min(offset+1024, len(data))
		position := offset
		if bad {
			position++
		}
		if err := stream.Send(&v1.PullCatalogResponse{Catalog: request.Msg.Catalog, Offset: uint64(position), Data: data[offset:end], Eof: end == len(data), EnvelopeSha256: sum[:]}); err != nil {
			return err
		}
	}
	return nil
}

func startGateway(t *testing.T, renewSoon bool) (*testGateway, *httptest.Server, Config) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, public, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	serverPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, serverPublic, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := catalog.MarshalPrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), caPEM...), private)
	if err != nil {
		t.Fatal(err)
	}
	g := &testGateway{ca: ca, caPEM: caPEM, key: key, connections: make(chan *testConnection, 16), packages: map[string][]byte{}, renewSoon: renewSoon}
	path, handler := allowopsv1connect.NewAgentServiceHandler(g)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != allowopsv1connect.AgentServiceJoinProcedure && (r.TLS == nil || len(r.TLS.VerifiedChains) == 0) {
			http.Error(w, "mTLS required", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	server := httptest.NewUnstartedServer(mux)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{AgentALPN, JoinALPN}, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
	server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	for _, protocol := range []string{AgentALPN, JoinALPN} {
		server.Config.TLSNextProto[protocol] = func(_ *http.Server, connection *tls.Conn, handler http.Handler) {
			state := connection.ConnectionState()
			wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.TLS = &state; handler.ServeHTTP(w, r) })
			//lint:ignore SA1019 The gateway substitute must test P4's custom ALPN HTTP/2 framing.
			h2 := &http2.Server{}
			//lint:ignore SA1019 Raw HTTP/2 is required for the custom ALPN gateway substitute.
			h2.ServeConn(connection, &http2.ServeConnOpts{Handler: wrapped})
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	sum := sha256.Sum256(ca.Raw)
	return g, server, Config{Upstream: server.URL, CAPin: "sha256:" + hex.EncodeToString(sum[:]), ReportedLabels: map[string]string{"site": "test"}}
}

func startAgent(t *testing.T, config Config) (*Agent, context.CancelFunc) {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := Join(context.Background(), config, "test-token", "test-host", dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(identity.PrivateKey) == 0 {
		t.Fatal("private key missing")
	}
	info, err := os.Stat(dataDir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("state mode: %v %v", info, err)
	}
	info, err = os.Stat(filepath.Join(dataDir, "identity.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("identity mode: %v %v", info, err)
	}
	keys := t.TempDir()
	a, err := New(config, Options{DataDir: dataDir, KeysDir: keys, KeyOwner: os.Getuid(), Version: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop")
		}
	})
	return a, cancel
}
func connection(t *testing.T, g *testGateway) *testConnection {
	t.Helper()
	select {
	case c := <-g.connections:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("connection timeout")
		return nil
	}
}

func publish(t *testing.T, g *testGateway, a *Agent, actions []catalog.Action, now time.Time, ttl time.Duration) (*catalog.Package, *v1.CatalogAvailable) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := catalog.MarshalPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.options.KeysDir, catalog.KeyID(public)+".pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	items := map[string]catalog.Action{}
	unsupported := map[string]catalog.Action{}
	for _, action := range actions {
		futureParams := false
		for _, d := range action.Params {
			if d.Type == "future_type" {
				futureParams = true
			}
		}
		if futureParams || (action.Builtin != "" && catalog.Builtins[action.Builtin] == nil) {
			unsupported[action.Name] = action
		} else {
			items[action.Name] = action
		}
	}
	p, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: "test"}, Actions: items}, catalog.BuildOptions{Now: now, TTL: ttl})
	if err != nil {
		t.Fatal(err)
	}
	for name, action := range unsupported {
		p.Actions[name] = action
		p.Digests[name], err = catalog.ActionDigest(action)
		if err != nil {
			t.Fatal(err)
		}
	}
	data, err := catalog.CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := catalog.Sign(data, catalog.SigningKey{PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	g.packages[p.CatalogID+":"+strconv.FormatInt(p.Version, 10)] = data
	g.mu.Unlock()
	sum := sha256.Sum256(data)
	return p, &v1.CatalogAvailable{Catalog: &v1.CatalogRef{CatalogId: p.CatalogID, Version: uint64(p.Version)}, EnvelopeSha256: sum[:], EnvelopeSizeBytes: uint64(len(data))}
}
func task(p *catalog.Package, name, id string) *v1.TaskAssignment {
	digest, _ := hex.DecodeString(p.Digests[name])
	return &v1.TaskAssignment{JobId: "job-test", TaskId: id, Catalog: &v1.CatalogRef{CatalogId: p.CatalogID, Version: uint64(p.Version)}, Action: name, ActionSha256: digest, Params: &v1.Parameters{Json: []byte("{}")}, Timeout: durationpb.New(5 * time.Second)}
}
func sendTask(t *testing.T, c *testConnection, assignment *v1.TaskAssignment) {
	t.Helper()
	c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_Task{Task: assignment}})
}
func collectTask(t *testing.T, c *testConnection, id string) []*v1.ConnectRequest {
	t.Helper()
	var messages []*v1.ConnectRequest
	c.next(t, func(m *v1.ConnectRequest) bool {
		if m.GetOutput().GetTaskId() == id || m.GetStepCompleted().GetTaskId() == id || m.GetTaskStarted().GetTaskId() == id || m.GetTaskCompleted().GetTaskId() == id {
			messages = append(messages, m)
		}
		return m.GetTaskCompleted().GetTaskId() == id
	})
	return messages
}

func TestJoinPinAndIdentity(t *testing.T) {
	g, _, config := startGateway(t, false)
	wrong := config
	wrong.CAPin = "sha256:" + strings.Repeat("00", 32)
	wrongDir := t.TempDir()
	if err := os.Chmod(wrongDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Join(context.Background(), wrong, "test-token", "test", wrongDir); err == nil {
		t.Fatal("wrong pin accepted")
	}
	if g.joins.Load() != 0 {
		t.Fatal("token sent before pin verification")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Join(context.Background(), config, "test-token", "test", dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Join(context.Background(), config, "test-token", "test", dir); err == nil {
		t.Fatal("identity overwritten")
	}
	if g.joins.Load() != 1 {
		t.Fatal("join repeated")
	}
}

func TestAgentLifecycleAndOutputs(t *testing.T) {
	g, _, config := startGateway(t, true)
	a, _ := startAgent(t, config)
	c := connection(t, g)
	if c.hello.AgentVersion != "dev" || c.hello.ReportedLabels["site"] != "test" || !strings.Contains(strings.Join(c.hello.Capabilities.ExecutionModes, ","), "steps") {
		t.Fatalf("hello: %v", c.hello)
	}
	hb := c.next(t, func(m *v1.ConnectRequest) bool { return m.GetHeartbeat() != nil }).GetHeartbeat()
	if hb.Sequence != 1 {
		t.Fatalf("heartbeat sequence=%d", hb.Sequence)
	}
	content := []byte("print('script output')\n")
	sum := sha256.Sum256(content)
	actions := []catalog.Action{
		{Name: "print", Description: "print", Risk: "read", Exec: []any{"/usr/bin/printf", "secret=hidden\\npublic\\n"}, Filters: []string{"match"}, Timeout: "5s", MaxOutput: 1024},
		{Name: "steps", Description: "steps", Risk: "read", Steps: []catalog.Step{{Name: "first", Exec: []any{"/usr/bin/printf", "first\\n"}}, {Name: "fail", Exec: []any{"/usr/bin/false"}}, {Name: "skipped", Exec: []any{"/usr/bin/printf", "skipped\\n"}}}, OnError: "stop", Timeout: "5s", MaxOutput: 1024},
		{Name: "script", Description: "script", Risk: "read", Script: &catalog.Script{File: "scripts/test.py", Interpreter: "/usr/bin/python3", Content: content, SHA256: hex.EncodeToString(sum[:])}, Timeout: "5s", MaxOutput: 1024},
		{Name: "missing", Description: "missing", Risk: "read", Exec: []any{"/allowops-nonexistent/executable"}, Timeout: "5s", MaxOutput: 1024},
	}
	p, notice := publish(t, g, a, actions, time.Now(), time.Hour)
	c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}})
	report := c.next(t, func(m *v1.ConnectRequest) bool { return m.GetCatalogLoad() != nil }).GetCatalogLoad()
	if !report.Loaded || len(report.UnsupportedActions) != 1 || report.UnsupportedActions[0].Action != "missing" {
		t.Fatalf("load: %v", report)
	}
	assignment := task(p, "print", "print")
	sendTask(t, c, assignment)
	sendTask(t, c, assignment)
	messages := collectTask(t, c, "print")
	var output strings.Builder
	var offset uint64
	var eof int
	for _, m := range messages {
		if chunk := m.GetOutput(); chunk != nil && chunk.Stream == v1.OutputStream_OUTPUT_STREAM_STDOUT {
			if chunk.Offset != offset || chunk.StepIndex != nil {
				t.Fatalf("chunk: %v", chunk)
			}
			output.Write(chunk.Data)
			offset += uint64(len(chunk.Data))
			if chunk.Eof {
				eof++
			}
		}
	}
	if output.String() != "[REDACTED:credential]\npublic\n" || eof != 1 {
		t.Fatalf("stdout=%q eof=%d", output.String(), eof)
	}
	if messages[len(messages)-1].GetTaskCompleted().Result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED {
		t.Fatal("execution failed")
	}
	filtered := task(p, "print", "filtered")
	filtered.Filters = &v1.OutputFilters{Match: proto.String("hidden")}
	sendTask(t, c, filtered)
	filteredMessages := collectTask(t, c, "filtered")
	if filteredMessages[len(filteredMessages)-1].GetTaskCompleted().Result.Stdout.SizeBytes != 0 {
		t.Fatal("filter probed raw secret")
	}
	sendTask(t, c, task(p, "steps", "steps"))
	stepMessages := collectTask(t, c, "steps")
	var steps []*v1.StepCompleted
	ended := map[uint32]int{}
	for _, m := range stepMessages {
		if o := m.GetOutput(); o != nil {
			if o.StepIndex == nil {
				t.Fatal("step presence lost")
			}
			if o.Eof {
				ended[*o.StepIndex]++
			}
		}
		if s := m.GetStepCompleted(); s != nil {
			if s.Result.Status != v1.TaskStatus_TASK_STATUS_SKIPPED && ended[s.StepIndex] != 2 {
				t.Fatal("step completed before eof")
			}
			steps = append(steps, s)
		}
	}
	final := stepMessages[len(stepMessages)-1].GetTaskCompleted()
	if len(steps) != 3 || steps[2].Result.Status != v1.TaskStatus_TASK_STATUS_SKIPPED || final.CompletedSteps != 3 || final.Result.GetExitCode() != 1 || final.Result.Stdout != nil {
		t.Fatalf("steps=%v final=%v", steps, final)
	}
	sendTask(t, c, task(p, "script", "script"))
	scriptMessages := collectTask(t, c, "script")
	if scriptMessages[len(scriptMessages)-1].GetTaskCompleted().Result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED {
		t.Fatal("signed script failed")
	}
	bad := task(p, "print", "bad-digest")
	bad.ActionSha256 = make([]byte, 32)
	sendTask(t, c, bad)
	badMessages := collectTask(t, c, "bad-digest")
	if badMessages[len(badMessages)-1].GetTaskCompleted().Result.Reason != "ACTION_DIGEST_MISMATCH" {
		t.Fatal("digest mismatch accepted")
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		stored, err := LoadIdentity(a.options.DataDir)
		if err == nil && stored.RenewAfter.After(time.Now().Add(time.Hour)) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	stored, err := LoadIdentity(a.options.DataDir)
	t.Fatalf("renewal not persisted: calls=%d renew_after=%v error=%v", g.renewals.Load(), stored.RenewAfter, err)

}

func waitPIDs(t *testing.T, path string) []int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			var ids []int
			if json.Unmarshal(data, &ids) == nil && len(ids) == 2 {
				t.Cleanup(func() { _ = syscall.Kill(-ids[0], syscall.SIGKILL) })
				return ids
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("process fixture did not start")
	return nil
}
func assertTerminated(t *testing.T, ids []int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for _, id := range ids {
		for {
			data, err := os.ReadFile("/proc/" + strconv.Itoa(id) + "/stat")
			if os.IsNotExist(err) {
				break
			}
			text := string(data)
			position := strings.LastIndex(text, ") ")
			if position >= 0 && len(text) > position+2 && text[position+2] == 'Z' {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("process %d still alive: %s", id, data)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestCancelAndDisconnectTerminateProcessGroup(t *testing.T) {
	for _, mode := range []string{"cancel", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			g, server, config := startGateway(t, false)
			a, _ := startAgent(t, config)
			c := connection(t, g)
			path := filepath.Join(t.TempDir(), "pids")
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			action := catalog.Action{Name: "process", Description: "process", Risk: "read", Exec: []any{binary, "allowops-process-fixture", path}, Timeout: "5s", MaxOutput: 1024}
			p, notice := publish(t, g, a, []catalog.Action{action}, time.Now(), time.Hour)
			c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}})
			if !c.next(t, func(m *v1.ConnectRequest) bool { return m.GetCatalogLoad() != nil }).GetCatalogLoad().Loaded {
				t.Fatal("load failed")
			}
			sendTask(t, c, task(p, "process", "process"))
			ids := waitPIDs(t, path)
			if mode == "cancel" {
				c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{JobId: "job-test", TaskId: "process"}}})
				messages := collectTask(t, c, "process")
				if messages[len(messages)-1].GetTaskCompleted().Result.Status != v1.TaskStatus_TASK_STATUS_CANCELLED {
					t.Fatal("cancel status")
				}
			} else {
				server.CloseClientConnections()
				next := connection(t, g)
				if len(next.hello.LoadedCatalogs) != 1 {
					t.Fatal("loaded catalog missing on reconnect")
				}
				next.next(t, func(m *v1.ConnectRequest) bool { return m.GetHeartbeat() != nil })
				for {
					select {
					case message := <-next.messages:
						if message.GetTaskCompleted() != nil || message.GetOutput() != nil {
							t.Fatal("disconnected result replayed")
						}
					default:
						goto drained
					}
				}
			drained:
			}
			assertTerminated(t, ids)
		})
	}
}

func TestCatalogRejectsBadOffsetExpiryAndRollback(t *testing.T) {
	g, _, config := startGateway(t, false)
	a, _ := startAgent(t, config)
	c := connection(t, g)
	action := catalog.Action{Name: "print", Description: "print", Risk: "read", Exec: []any{"/usr/bin/printf", "test"}, Timeout: "5s", MaxOutput: 1024}
	for _, mode := range []string{"offset", "expired", "valid", "rollback"} {
		now := time.Now().UTC().Truncate(time.Second)
		ttl := time.Hour
		if mode == "expired" {
			now = now.Add(-2 * time.Hour)
		}
		if mode == "rollback" {
			now = now.Add(-time.Minute)
		}
		_, notice := publish(t, g, a, []catalog.Action{action}, now, ttl)
		g.mu.Lock()
		g.badOffset = mode == "offset"
		g.mu.Unlock()
		c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}})
		report := c.next(t, func(m *v1.ConnectRequest) bool { return m.GetCatalogLoad() != nil }).GetCatalogLoad()
		if report.Loaded != (mode == "valid") {
			t.Fatalf("%s loaded=%v reason=%s", mode, report.Loaded, report.Reason)
		}
	}
}

func TestReconnectAndBackoff(t *testing.T) {
	g, _, config := startGateway(t, false)
	a, _ := startAgent(t, config)
	c := connection(t, g)
	started := time.Now()
	c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_Reconnect{Reconnect: &v1.Reconnect{CloseAt: timestamppb.Now(), RetryAfterMin: durationpb.New(time.Second), RetryAfterMax: durationpb.New(time.Second)}}})
	_ = connection(t, g)
	if elapsed := time.Since(started); elapsed < time.Second || elapsed > 4*time.Second {
		t.Fatalf("reconnect delay=%s", elapsed)
	}
	unique := map[time.Duration]bool{}
	for attempt := uint(0); attempt < 9; attempt++ {
		for range 20 {
			delay := a.backoff(attempt)
			upper := min(30*time.Second, time.Second<<min(attempt+1, 5))
			if delay < time.Second || delay > upper {
				t.Fatalf("attempt=%d delay=%s", attempt, delay)
			}
			unique[delay] = true
		}
	}
	if len(unique) < 2 {
		t.Fatal("missing jitter")
	}
}

var _ Runner = LocalRunner{}
