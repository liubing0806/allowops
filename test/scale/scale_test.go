//go:build scale

package scale

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	jitter "math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/server"
	"github.com/liubing0806/allowops/test/harness"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type simulatedHost struct {
	name      string
	client    rpc.AgentServiceClient
	transport interface {
		http.RoundTripper
		CloseIdleConnections()
	}
	gateway *harness.Gateway
	online  *atomic.Int64
	errors  *atomic.Int64
}

func join(ctx context.Context, g *harness.Gateway, name string, online, failures *atomic.Int64) (*simulatedHost, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, err
	}
	transport := agentTransport(&tls.Config{RootCAs: g.Roots, MinVersion: tls.VersionTLS13, NextProtos: []string{server.JoinALPN}})
	client := rpc.NewAgentServiceClient(&http.Client{Transport: transport}, "https://"+g.Address, connect.WithGRPC())
	r, err := client.Join(ctx, connect.NewRequest(&v1.JoinRequest{JoinToken: g.JoinToken, Hostname: name, CsrPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})}))
	transport.CloseIdleConnections()
	if err != nil {
		return nil, err
	}
	keyPEM, err := catalog.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(r.Msg.Certificate.CertificateChainPem, keyPEM)
	if err != nil {
		return nil, err
	}
	transport = agentTransport(&tls.Config{RootCAs: g.Roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{server.AgentALPN}})
	return &simulatedHost{name: name, client: rpc.NewAgentServiceClient(&http.Client{Transport: transport}, "https://"+g.Address, connect.WithGRPC()), transport: transport, gateway: g, online: online, errors: failures}, nil
}

func agentTransport(config *tls.Config) interface {
	http.RoundTripper
	CloseIdleConnections()
} {
	//lint:ignore SA1019 Custom agent/join ALPN requires the same raw HTTP/2 transport as the agent.
	return &http2.Transport{DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
		conn, err := (&tls.Dialer{Config: config, NetDialer: &net.Dialer{Timeout: 10 * time.Second}}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if conn.(*tls.Conn).ConnectionState().NegotiatedProtocol != config.NextProtos[0] {
			conn.Close()
			return nil, fmt.Errorf("ALPN mismatch")
		}
		return conn, nil
	}}
}

func (h *simulatedHost) run(ctx context.Context) {
	defer h.transport.CloseIdleConnections()
	upper := 2 * time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := h.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			h.errors.Add(1)
		}
		if time.Since(started) >= 45*time.Second {
			upper = 2 * time.Second
		}
		// Match the production agent's bounded uniform jitter, including its minimum.
		delay := time.Second + time.Duration(jitter.Int64N(int64(upper-time.Second)+1))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		upper = min(30*time.Second, upper*2)
	}
}

func (h *simulatedHost) session(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stream := h.client.Connect(ctx)
	defer stream.CloseResponse()
	defer stream.CloseRequest()
	if err := stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Hello{Hello: &v1.AgentHello{AgentVersion: "0.1.0", MaxConcurrentTasks: 4}}}); err != nil {
		return err
	}
	hello, err := stream.Receive()
	if err != nil {
		return err
	}
	if hello.GetHello() == nil {
		return fmt.Errorf("expected GatewayHello")
	}
	h.online.Add(1)
	defer h.online.Add(-1)
	var sendMu sync.Mutex
	send := func(m *v1.ConnectRequest) error { sendMu.Lock(); defer sendMu.Unlock(); return stream.Send(m) }
	var heartbeat sync.WaitGroup
	defer heartbeat.Wait()
	defer cancel()
	heartbeat.Go(func() {
		tick := time.NewTicker(hello.GetHello().Limits.HeartbeatInterval.AsDuration())
		defer tick.Stop()
		var seq uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				seq++
				if send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Heartbeat{Heartbeat: &v1.AgentHeartbeat{Sequence: seq}}}) != nil {
					return
				}
			}
		}
	})
	for {
		m, err := stream.Receive()
		if err != nil {
			return err
		}
		if m.GetReconnect() != nil {
			return nil
		}
		if notice := m.GetCatalogAvailable(); notice != nil {
			if err := h.load(ctx, notice, send); err != nil {
				return err
			}
		}
		if task := m.GetTask(); task != nil {
			if task.Action != "noop" {
				return fmt.Errorf("unexpected simulator action")
			}
			digest := sha256.Sum256(nil)
			messages := []*v1.ConnectRequest{
				{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: task.JobId, TaskId: task.TaskId, StartedAt: timestamppb.Now()}}},
			}
			for _, kind := range []v1.OutputStream{v1.OutputStream_OUTPUT_STREAM_STDOUT, v1.OutputStream_OUTPUT_STREAM_STDERR} {
				messages = append(messages, &v1.ConnectRequest{Message: &v1.ConnectRequest_Output{Output: &v1.TaskOutputChunk{JobId: task.JobId, TaskId: task.TaskId, Stream: kind, Eof: true}}})
			}
			messages = append(messages, &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskCompleted{TaskCompleted: &v1.TaskCompleted{JobId: task.JobId, TaskId: task.TaskId, FinishedAt: timestamppb.Now(), Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_SUCCEEDED, ExitCode: new(int32), Duration: durationpb.New(0), Stdout: &v1.OutputMetadata{Sha256: digest[:]}, Stderr: &v1.OutputMetadata{Sha256: digest[:]}}}}})
			for _, m := range messages {
				if err := send(m); err != nil {
					return err
				}
			}
		}
	}
}

func (h *simulatedHost) load(ctx context.Context, notice *v1.CatalogAvailable, send func(*v1.ConnectRequest) error) error {
	pull, err := h.client.PullCatalog(ctx, connect.NewRequest(&v1.PullCatalogRequest{Catalog: notice.Catalog}))
	if err != nil {
		return err
	}
	defer pull.Close()
	var raw []byte
	eof := false
	for pull.Receive() {
		chunk := pull.Msg()
		if eof || chunk.Offset != uint64(len(raw)) {
			return fmt.Errorf("catalog chunk order")
		}
		raw = append(raw, chunk.Data...)
		eof = chunk.Eof
	}
	if err := pull.Err(); err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	if !eof || uint64(len(raw)) != notice.EnvelopeSizeBytes || !bytes.Equal(digest[:], notice.EnvelopeSha256) {
		return fmt.Errorf("catalog envelope hash")
	}
	env, err := catalog.ParseEnvelope(raw)
	if err != nil {
		return err
	}
	p, err := catalog.Verify(env, h.gateway.Trusted, catalog.VerifyOptions{})
	if err != nil {
		return err
	}
	if p.CatalogID != notice.Catalog.CatalogId || uint64(p.Version) != notice.Catalog.Version {
		return fmt.Errorf("catalog reference mismatch")
	}
	return send(&v1.ConnectRequest{Message: &v1.ConnectRequest_CatalogLoad{CatalogLoad: &v1.CatalogLoadReport{Catalog: notice.Catalog, ReportId: strconv.FormatInt(time.Now().UnixNano(), 10), Loaded: true, FinalPage: true}}})
}

func TestScale(t *testing.T) {
	harness.Environment(t)
	const hosts, targets = 5000, 1000
	g := harness.New(t, hosts)
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	t.Cleanup(func() { cancel(); workers.Wait() })
	var online, failures atomic.Int64
	names := make([]string, targets)
	sem := make(chan struct{}, 32)
	joinErrors := make(chan error, hosts)
	for i := range hosts {
		name := fmt.Sprintf("scale-%04d", i)
		if i < targets {
			names[i] = name
		}
		sem <- struct{}{}
		workers.Go(func() {
			h, err := join(ctx, g, name, &online, &failures)
			<-sem
			if err != nil {
				joinErrors <- err
				return
			}
			h.run(ctx)
		})
	}
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) && online.Load() != hosts {
		select {
		case err := <-joinErrors:
			t.Fatalf("join failed: %v", err)
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	n, err := g.Online()
	harness.Check(t, err)
	onlineOK := online.Load() == hosts && n == hosts
	// Hold for more than one heartbeat timeout, checking both live streams and ownership.
	for i := 0; onlineOK && i < 50; i++ {
		time.Sleep(time.Second)
		n, err = g.Online()
		harness.Check(t, err)
		onlineOK = online.Load() == hosts && n == hosts
	}
	t.Logf("RESULT online actual=%d database=%d threshold=5000 hold_seconds=50 pass=%t session_errors=%d", online.Load(), n, onlineOK, failures.Load())
	// Join deliberately does not grant authorization labels. Only this disposable DB is changed.
	_, err = g.DB.Pool.Exec(ctx, `UPDATE hosts SET authorization_labels='{"env":"p10a"}'`)
	harness.Check(t, err)
	var loaded int
	harness.Check(t, g.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM host_catalog_reports WHERE catalog_id='p10a' AND loaded").Scan(&loaded))
	t.Logf("catalog_loaded=%d threshold=5000", loaded)
	if loaded != hosts {
		onlineOK = false
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", g.PID()))
	harness.Check(t, err)
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "VmRSS:") || strings.HasPrefix(line, "Threads:") {
			t.Logf("gateway %s", line)
		}
	}
	// Sample authoritative PostgreSQL waits while the real scheduler processes the job.
	diagCtx, stopDiag := context.WithCancel(ctx)
	var diag sync.WaitGroup
	waits := map[string]int{}
	diag.Go(func() {
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-diagCtx.Done():
				return
			case <-tick.C:
				rows, err := g.DB.Pool.Query(diagCtx, "SELECT coalesce(wait_event_type,'CPU'),coalesce(wait_event,'running'),count(*) FROM pg_stat_activity WHERE datname=current_database() AND state='active' AND pid<>pg_backend_pid() GROUP BY 1,2")
				if err != nil {
					continue
				}
				for rows.Next() {
					var kind, event string
					var n int
					if rows.Scan(&kind, &event, &n) == nil {
						waits[kind+"/"+event] += n
					}
				}
				rows.Close()
			}
		}
	})
	result, elapsed, jobErr := g.RunJob(names, "noop")
	stopDiag()
	diag.Wait()
	jobOK := jobErr == nil && result.Job.Status == v1.JobStatus_JOB_STATUS_SUCCEEDED && result.Job.TotalTasks == targets && elapsed <= 10*time.Second
	t.Logf("RESULT job actual_seconds=%.6f threshold_seconds=10 targets=1000 batch_size=20 pass=%t error=%v", elapsed.Seconds(), jobOK, jobErr)
	if result != nil {
		t.Logf("job status=%s total=%d counts=%v", result.Job.Status, result.Job.TotalTasks, result.Job.Counts)
	}
	t.Logf("PostgreSQL active wait samples (200ms): %v", waits)
	start := time.Now()
	g.Stop(t)
	g.Start(t)
	deadline = start.Add(180 * time.Second)
	for time.Now().Before(deadline) && online.Load() != hosts {
		time.Sleep(50 * time.Millisecond)
	}
	elapsed = time.Since(start)
	n, err = g.Online()
	harness.Check(t, err)
	reconnectOK := online.Load() == hosts && n == hosts && elapsed <= 60*time.Second
	t.Logf("RESULT reconnect actual_seconds=%.6f online=%d database=%d threshold_seconds=60 pass=%t", elapsed.Seconds(), online.Load(), n, reconnectOK)
	harness.Environment(t)
	if !onlineOK || !jobOK || !reconnectOK {
		g.Log(t)
		t.Error("scale acceptance threshold failed; product code unchanged")
	}
}
