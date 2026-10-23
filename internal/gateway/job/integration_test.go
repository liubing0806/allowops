package job_test

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
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/agent"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"github.com/liubing0806/allowops/internal/gateway/server"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"github.com/liubing0806/allowops/internal/testseaweedfs"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type failingStorage struct {
	output.Storage
	Fail atomic.Bool
}

func (s *failingStorage) Put(ctx context.Context, key string, b []byte) error {
	if s.Fail.Load() {
		return errors.New("fixture write failure")
	}
	return s.Storage.Put(ctx, key, b)
}

type gateway struct {
	Host    *hostconn.Service
	Job     *job.Service
	Server  *server.Server
	Address string
	Client  rpc.JobServiceClient
	HTTP    *http.Client
}
type fixture struct {
	DB                  *store.Store
	DSN, RootDir        string
	A, B                *gateway
	CA                  *hostconn.CA
	Certificate         tls.Certificate
	Roots               *x509.CertPool
	Pin, KeysDir, Token string
	Trusted             map[string]ed25519.PublicKey
	Signer              ed25519.PrivateKey
	Storage             *failingStorage
	Package             *catalog.Package
	Hosts               []string
	Stop                []context.CancelFunc
	BeforeMessage       func(hostconn.Event)
	BeforeStart         func(*hostconn.Service, *job.Service)
	HeartbeatTimeout    time.Duration
}

func setup(t *testing.T, configure ...func(*fixture)) *fixture {
	t.Helper()
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	objects := testseaweedfs.Start(t)
	// Integration scenarios must tolerate short scheduling and database stalls.
	// Tests of heartbeat expiry override this value explicitly.
	f := &fixture{DB: db, DSN: dsn, Storage: &failingStorage{Storage: objects}, HeartbeatTimeout: 30 * time.Second}
	dir := t.TempDir()
	f.RootDir = dir
	f.CA, err = hostconn.OpenCA(filepath.Join(dir, "host-ca.pem"), filepath.Join(dir, "host-ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	tlsCA, err := hostconn.OpenCA(filepath.Join(dir, "tls-ca.pem"), filepath.Join(dir, "tls-ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(tlsCA.PEM)
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	private, err := os.ReadFile(filepath.Join(dir, "tls-ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := catalog.ParsePrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, issuer, pub, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err = catalog.MarshalPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f.Certificate, err = tls.X509KeyPair(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), tlsCA.PEM...), private)
	if err != nil {
		t.Fatal(err)
	}
	f.Roots = x509.NewCertPool()
	f.Roots.AppendCertsFromPEM(tlsCA.PEM)
	sum := sha256.Sum256(issuer.Raw)
	f.Pin = "sha256:" + hex.EncodeToString(sum[:])
	pub, f.Signer, _ = ed25519.GenerateKey(rand.Reader)
	f.Trusted = map[string]ed25519.PublicKey{catalog.KeyID(pub): pub}
	f.KeysDir = t.TempDir()
	keyPEM, _ := catalog.MarshalPublicKey(pub)
	if err := os.WriteFile(filepath.Join(f.KeysDir, "signer.pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, "INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username,manual_roles) VALUES ('owner','fixture','owner','oidc','owner','{admin}'); INSERT INTO service_accounts(account_id,name,owner_user_id,roles) VALUES ('sa','fixture','owner','{admin}')"); err != nil {
		t.Fatal(err)
	}
	f.Token, _, err = authn.GenerateServiceToken(time.Now(), 1)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(f.Token))
	if _, err := db.Pool.Exec(ctx, "INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES ('token','sa',$1,now()+interval '1 hour')", tokenHash[:]); err != nil {
		t.Fatal(err)
	}
	for _, configure := range configure {
		configure(f)
	}
	f.A = f.start(t)
	f.B = f.start(t)
	actions := map[string]catalog.Action{}
	for _, a := range []catalog.Action{
		{Name: "typed", Description: "typed parameters", Risk: "read", Exec: []any{"/usr/bin/printf", "%s %s", "{number}", "{flag}"}, Params: map[string]params.Definition{"number": {Type: params.Int, Description: "integer", Min: proto.Int64(1), Max: 4}, "flag": {Type: params.Bool, Description: "boolean"}, "items": {Type: params.StringArray, Description: "array", MaxItems: 3, MaxLen: 20}}, Timeout: "5s", MaxOutput: 1024},
		{Name: "missing", Description: "unsupported executable", Risk: "read", Exec: []any{"/usr/bin/p6-does-not-exist"}, Timeout: "5s", MaxOutput: 1024},
		{Name: "stable", Description: "fixed output", Risk: "read", Exec: []any{"/usr/bin/printf", "same output"}, Timeout: "5s", MaxOutput: 16384},
		{Name: "fail", Description: "failure", Risk: "read", Exec: []any{"/usr/bin/false"}, Timeout: "5s", MaxOutput: 1024},
		{Name: "slow", Description: "slow local action", Risk: "read", Exec: []any{"/usr/bin/sleep", "2"}, Timeout: "5s", MaxOutput: 1024},
		{Name: "linger", Description: "long local action for instance failure", Risk: "read", Exec: []any{"/usr/bin/sleep", "20"}, Timeout: "30s", MaxOutput: 1024},
		{Name: "timeout", Description: "signed timeout", Risk: "read", Exec: []any{"/usr/bin/sleep", "2"}, Timeout: "100ms", MaxOutput: 1024},
		{Name: "large", Description: "large output", Risk: "read", Exec: []any{"/usr/bin/printf", "%10000s", "x"}, Timeout: "5s", MaxOutput: 16384},
		{Name: "steps", Description: "stop on error", Risk: "read", OnError: "stop", Steps: []catalog.Step{{Name: "first", Exec: []any{"/usr/bin/false"}}, {Name: "second", Exec: []any{"/usr/bin/printf", "not executed"}}}, Timeout: "5s", MaxOutput: 1024},
		{Name: "cancel_steps", Description: "cancel continuing steps", Risk: "read", OnError: "continue", Steps: []catalog.Step{{Name: "first", Exec: []any{"/usr/bin/sleep", "2"}}, {Name: "second", Exec: []any{"/usr/bin/printf", "not executed"}}}, Timeout: "5s", MaxOutput: 1024},
	} {
		actions[a.Name] = a
	}
	loaded, err := catalog.Load("../../../examples/catalog")
	if err != nil {
		t.Fatal(err)
	}
	actions["system_load"] = loaded.Actions["system_load"]
	f.Package, err = catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: "p6"}, Actions: actions}, catalog.BuildOptions{Now: time.Now(), TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := catalog.CanonicalJSON(f.Package)
	envelope, err := catalog.Sign(payload, catalog.SigningKey{PrivateKey: f.Signer})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(envelope)
	publication := &catalogsvc.Service{Store: db, Trusted: f.Trusted, MaxEnvelopeBytes: 64 << 20, MaxActionBytes: 256 << 10}
	if _, err := publication.Publish(ctx, raw); err != nil {
		t.Fatal(err)
	}
	for i, g := range []*gateway{f.A, f.B, f.B} {
		f.addAgent(t, g, []string{"a-host", "b-host", "c-host"}[i])
	}
	return f
}

// Construct traced dependencies during setup's configure phase. The services
// are not running yet, and fixture cleanup closes them before closing this pool.
func tracedJobStore(t *testing.T, db *store.Store, tracer pgx.QueryTracer) *store.Store {
	t.Helper()
	cfg := db.Pool.Config()
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	traced := *db
	traced.Pool = pool
	return &traced
}

// Isolated scenarios must finish their accepted output work before their agents
// and servers are cleaned up. A committed task terminal state precedes Put.
func awaitFixtureOutputs(t *testing.T, f *fixture) {
	t.Helper()
	eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var done bool
		err := f.DB.Pool.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM tasks WHERE output_state='pending')
          AND (SELECT count(*) FROM tasks WHERE output_state IN ('stored','failed'))
            = (SELECT count(*) FROM audit_events WHERE operation='store_output')`).Scan(&done)
		if err != nil {
			t.Fatal(err)
		}
		return done
	})
}

func bearer(token string) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
			r.Header().Set("Authorization", "Bearer "+token)
			return next(ctx, r)
		}
	})
}

func (f *fixture) start(t *testing.T) *gateway {
	t.Helper()
	ctx := context.Background()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	access, err := api.New(ctx, f.DB, api.Config{Origin: "https://" + listener.Addr().String()}, api.NewAuditor(audit.New(f.DB.Pool, audit.Config{})))
	if err != nil {
		t.Fatal(err)
	}
	c := hostconn.DefaultConfig()
	c.HeartbeatInterval = 100 * time.Millisecond
	c.HeartbeatTimeout = f.HeartbeatTimeout
	c.CleanupInterval = 100 * time.Millisecond
	hosts, err := hostconn.New(f.DB, f.CA, c, hostconn.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := job.New(f.DB, access, hosts, f.Storage, audit.New(f.DB.Pool, audit.Config{}), f.Trusted, job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	hooks := jobs.Hooks()
	onMessage := hooks.OnMessage
	hooks.OnMessage = func(ctx context.Context, e hostconn.Event) error {
		if f.BeforeMessage != nil {
			f.BeforeMessage(e)
		}
		err := onMessage(ctx, e)
		if err != nil {
			t.Logf("job event rejected: host=%s message=%T error=%v", e.HostID, e.Message.Message, err)
		}
		return err
	}
	hosts.Hooks = hooks
	if f.BeforeStart != nil {
		f.BeforeStart(hosts, jobs)
	}
	if err := hosts.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs.Start()
	srv := server.New(hosts, f.Certificate)
	srv.Jobs = jobs
	access.ConfigureJobDependencies(jobs, f.Storage.Storage.(api.ObjectStorageHealth))
	srv.UseIdentity(access)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.Roots, MinVersion: tls.VersionTLS13}}, Timeout: 20 * time.Second}
	g := &gateway{Host: hosts, Job: jobs, Server: srv, Address: listener.Addr().String(), HTTP: client}
	g.Client = rpc.NewJobServiceClient(client, "https://"+g.Address, connect.WithInterceptors(bearer(f.Token)))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
		jobs.Close()
		client.CloseIdleConnections()
	})
	return g
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	end := time.Now().Add(10 * time.Second)
	for time.Now().Before(end) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not satisfied within 10 seconds")
}
func (f *fixture) addAgent(t *testing.T, g *gateway, name string) {
	t.Helper()
	ctx := context.Background()
	token, err := g.Host.CreateJoinToken(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := agent.Config{Upstream: g.Address, CAPin: f.Pin}
	identity, err := agent.Join(ctx, cfg, token, name, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.DB.Pool.Exec(ctx, "UPDATE hosts SET authorization_labels='{"+`"env":"test"`+"}' WHERE host_id=$1", identity.HostID); err != nil {
		t.Fatal(err)
	}
	a, err := agent.New(cfg, agent.Options{DataDir: dir, KeysDir: f.KeysDir, KeyOwner: os.Getuid(), Version: g.Host.Config.Version})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- a.Run(runCtx) }()
	f.Stop = append(f.Stop, cancel)
	f.Hosts = append(f.Hosts, identity.HostID)
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("P3 agent did not stop")
		}
	})
	eventually(t, func() bool {
		report := g.Host.CatalogReport(identity.HostID, f.Package.CatalogID)
		return report != nil && report.Loaded
	})
}

func request(action string) *v1.RunJobRequest {
	return &v1.RunJobRequest{Action: action, Reason: "local P6 validation", Targets: &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "env=test"}}, ExpectedCount: proto.Uint64(3), WaitSeconds: proto.Uint32(5)}
}
func run(t *testing.T, g *gateway, r *v1.RunJobRequest) *v1.RunJobResponse {
	t.Helper()
	v, err := g.Client.RunJob(context.Background(), connect.NewRequest(r))
	if err != nil {
		t.Fatal(err)
	}
	return v.Msg
}
func get(t *testing.T, g *gateway, id string) *v1.GetJobResponse {
	t.Helper()
	v, err := g.Client.GetJob(context.Background(), connect.NewRequest(&v1.GetJobRequest{JobId: id, WaitSeconds: proto.Uint32(5)}))
	if err != nil {
		t.Fatal(err)
	}
	// wait_seconds bounds one RPC; callers of this helper assert a terminal job.
	eventually(t, func() bool {
		if v.Msg.Job.Status != v1.JobStatus_JOB_STATUS_QUEUED && v.Msg.Job.Status != v1.JobStatus_JOB_STATUS_RUNNING {
			return true
		}
		v, err = g.Client.GetJob(context.Background(), connect.NewRequest(&v1.GetJobRequest{JobId: id, WaitSeconds: proto.Uint32(0)}))
		if err != nil {
			t.Fatal(err)
		}
		return false
	})
	return v.Msg
}
func tasks(t *testing.T, g *gateway, id string) []*v1.Task {
	t.Helper()
	v, err := g.Client.ListTasks(context.Background(), connect.NewRequest(&v1.ListTasksRequest{JobId: id}))
	if err != nil {
		t.Fatal(err)
	}
	return v.Msg.Tasks
}

func TestTwoGatewaysRealAgentsAndSeaweedFS(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	t.Run("selector_expected_count", func(t *testing.T) {
		r := request("stable")
		r.ExpectedCount = proto.Uint64(2)
		_, err := f.A.Client.RunJob(ctx, connect.NewRequest(r))
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("mismatch error=%v", err)
		}
		var actual uint64
		for _, d := range err.(*connect.Error).Details() {
			m, _ := d.Value()
			if v, ok := m.(*v1.ErrorDetail); ok {
				actual = v.GetActualCount()
			}
		}
		if actual != 3 {
			t.Fatalf("actual count=%d want 3", actual)
		}
		r.ExpectedCount = nil
		_, err = f.A.Client.RunJob(ctx, connect.NewRequest(r))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("missing count=%v", err)
		}
	})
	t.Run("cross_instance_grouping_and_storage", func(t *testing.T) {
		v := run(t, f.A, request("stable"))
		if v.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED || len(v.Summary.Groups) != 1 || v.Summary.Groups[0].HostCount != 3 || len(v.Summary.Groups[0].Hosts) != 2 || v.Summary.Groups[0].Stdout != "same output" {
			t.Fatalf("response=%v", v)
		}
		if !strings.HasPrefix(v.Job.JobId, "job-") {
			t.Fatalf("job ID=%s", v.Job.JobId)
		}
		eventually(t, func() bool {
			list := tasks(t, f.B, v.Job.JobId)
			for _, task := range list {
				if !task.OutputStored {
					return false
				}
			}
			return true
		})
		r, err := f.B.Client.GetJobOutput(ctx, connect.NewRequest(&v1.GetJobOutputRequest{JobId: v.Job.JobId, Hostname: "a-host", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT}))
		if err != nil || !r.Msg.Eof || string(r.Msg.Data) != "same output" || !r.Msg.OutputStored {
			t.Fatalf("output=%v error=%v", r, err)
		}
		_, err = f.B.Client.GetJobOutput(ctx, connect.NewRequest(&v1.GetJobOutputRequest{JobId: v.Job.JobId, Hostname: "a-host", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT, Offset: 99}))
		if connect.CodeOf(err) != connect.CodeOutOfRange {
			t.Fatalf("offset error=%v", err)
		}
	})
	t.Run("deny_entire_job", func(t *testing.T) {
		if _, err := f.DB.Pool.Exec(ctx, "UPDATE hosts SET authorization_labels='{}' WHERE host_id=$1", f.Hosts[2]); err != nil {
			t.Fatal(err)
		}
		r := request("stable")
		r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host", "b-host", "c-host"}}}}
		_, err := f.A.Client.RunJob(ctx, connect.NewRequest(r))
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("deny error=%v", err)
		}
		var denied *v1.ErrorDetail
		for _, d := range err.(*connect.Error).Details() {
			v, _ := d.Value()
			if v, ok := v.(*v1.ErrorDetail); ok {
				denied = v
			}
		}
		if denied == nil || len(denied.DeniedHosts) != 1 || denied.DeniedHosts[0].Host != "c-host" {
			t.Fatalf("denials=%v", denied)
		}
		var n int
		f.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM tasks WHERE job_id=$1", denied.RequestId).Scan(&n)
		if n != 0 {
			t.Fatalf("denied job dispatched %d tasks", n)
		}
		if _, err := f.DB.Pool.Exec(ctx, "UPDATE hosts SET authorization_labels='{"+`"env":"test"`+"}' WHERE host_id=$1", f.Hosts[2]); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("batch_failure_stop", func(t *testing.T) {
		r := request("fail")
		r.BatchSize = proto.Uint32(1)
		r.MaxFailures = proto.Uint32(0)
		v := run(t, f.A, r)
		list := tasks(t, f.A, v.Job.JobId)
		if v.Job.Status != v1.JobStatus_JOB_STATUS_FAILED || list[0].Result.Status != v1.TaskStatus_TASK_STATUS_FAILED || list[1].Result.Status != v1.TaskStatus_TASK_STATUS_SKIPPED || list[2].Result.Status != v1.TaskStatus_TASK_STATUS_SKIPPED {
			t.Fatalf("job=%v tasks=%v", v.Job, list)
		}
	})
	t.Run("unsupported_stops_later_batch", func(t *testing.T) {
		r := request("missing")
		r.BatchSize = proto.Uint32(1)
		r.MaxFailures = proto.Uint32(0)
		v := run(t, f.A, r)
		list := tasks(t, f.A, v.Job.JobId)
		if list[0].Result.Status != v1.TaskStatus_TASK_STATUS_UNSUPPORTED || list[1].Result.Status != v1.TaskStatus_TASK_STATUS_SKIPPED {
			t.Fatalf("unsupported task results=%v", list)
		}
	})
	t.Run("timeout_counts_as_failure", func(t *testing.T) {
		r := request("timeout")
		r.BatchSize = proto.Uint32(1)
		r.MaxFailures = proto.Uint32(0)
		v := run(t, f.A, r)
		list := tasks(t, f.A, v.Job.JobId)
		if v.Job.Status != v1.JobStatus_JOB_STATUS_FAILED || list[0].Result.Status != v1.TaskStatus_TASK_STATUS_TIMEOUT || list[1].Result.Status != v1.TaskStatus_TASK_STATUS_SKIPPED {
			t.Fatalf("timeout job=%v tasks=%v", v.Job, list)
		}
	})
	t.Run("wait_timeout_keeps_job_id", func(t *testing.T) {
		r := request("slow")
		r.WaitSeconds = proto.Uint32(1)
		v := run(t, f.A, r)
		if v.Job.JobId == "" || v.Job.Status != v1.JobStatus_JOB_STATUS_RUNNING {
			t.Fatalf("wait timeout=%v", v)
		}
		completed := get(t, f.B, v.Job.JobId)
		if completed.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED {
			t.Fatalf("wait changed execution=%v", completed)
		}
	})
	t.Run("cancel_running_and_pending", func(t *testing.T) {
		r := request("slow")
		r.BatchSize = proto.Uint32(1)
		r.WaitSeconds = proto.Uint32(0)
		v := run(t, f.A, r)
		eventually(t, func() bool { return tasks(t, f.A, v.Job.JobId)[0].Result.Status == v1.TaskStatus_TASK_STATUS_RUNNING })
		_, err := f.B.Client.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: v.Job.JobId}))
		if err != nil {
			t.Fatal(err)
		}
		completed := get(t, f.A, v.Job.JobId)
		if completed.Job.Status != v1.JobStatus_JOB_STATUS_CANCELLED {
			t.Fatalf("cancel result=%v", completed)
		}
		for _, task := range tasks(t, f.A, v.Job.JobId) {
			if task.Result.Status != v1.TaskStatus_TASK_STATUS_CANCELLED {
				t.Fatalf("task=%v", task)
			}
		}
	})
	t.Run("cancel_completed_preserves_terminal", func(t *testing.T) {
		v := run(t, f.A, request("stable"))
		r, err := f.B.Client.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: v.Job.JobId}))
		if err != nil || r.Msg.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED {
			t.Fatalf("cancel completed=%v error=%v", r, err)
		}
	})
	t.Run("cancel_steps_continue", func(t *testing.T) {
		r := request("cancel_steps")
		r.WaitSeconds = proto.Uint32(0)
		v := run(t, f.A, r)
		eventually(t, func() bool {
			for _, task := range tasks(t, f.B, v.Job.JobId) {
				if task.Result.Status != v1.TaskStatus_TASK_STATUS_RUNNING {
					return false
				}
			}
			return true
		})
		if _, err := f.B.Client.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: v.Job.JobId})); err != nil {
			t.Fatal(err)
		}
		completed := get(t, f.A, v.Job.JobId)
		if completed.Job.Status != v1.JobStatus_JOB_STATUS_CANCELLED {
			t.Fatalf("cancel continuing steps=%v", completed)
		}
		task := tasks(t, f.B, v.Job.JobId)[0]
		steps, err := f.B.Client.ListTaskSteps(ctx, connect.NewRequest(&v1.ListTaskStepsRequest{JobId: v.Job.JobId, TaskId: task.TaskId}))
		if err != nil || len(steps.Msg.Steps) != 2 || steps.Msg.Steps[1].Result.Status != v1.TaskStatus_TASK_STATUS_SKIPPED {
			t.Fatalf("cancelled step results=%v error=%v", steps, err)
		}
	})
	t.Run("steps_first_failure_and_skipped", func(t *testing.T) {
		v := run(t, f.A, request("steps"))
		if v.Job.Status != v1.JobStatus_JOB_STATUS_FAILED {
			t.Fatalf("steps job=%v", v)
		}
		task := tasks(t, f.A, v.Job.JobId)[0]
		r, err := f.B.Client.ListTaskSteps(ctx, connect.NewRequest(&v1.ListTaskStepsRequest{JobId: v.Job.JobId, TaskId: task.TaskId}))
		if err != nil || len(r.Msg.Steps) != 2 || r.Msg.Steps[0].Result.GetExitCode() != 1 || r.Msg.Steps[1].Result.Status != v1.TaskStatus_TASK_STATUS_SKIPPED || task.Result.GetExitCode() != 1 {
			t.Fatalf("steps=%v task=%v error=%v", r, task, err)
		}
	})
	t.Run("group_preview_budget", func(t *testing.T) {
		v := run(t, f.A, request("large"))
		if len(v.Summary.Groups) != 1 || len(v.Summary.Groups[0].Stdout) > 4096 || !v.Summary.Groups[0].Truncated {
			t.Fatalf("preview=%v", v.Summary)
		}
		raw, _ := protojson.Marshal(v)
		if len(raw) > 32<<10 {
			t.Fatalf("response bytes=%d", len(raw))
		}
	})
	t.Run("write_failure_does_not_change_execution", func(t *testing.T) {
		f.Storage.Fail.Store(true)
		v := run(t, f.A, request("stable"))
		eventually(t, func() bool {
			var n int
			f.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM tasks WHERE job_id=$1 AND output_state='failed'", v.Job.JobId).Scan(&n)
			return n == 3
		})
		f.Storage.Fail.Store(false)
		if v.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED {
			t.Fatalf("storage changed job=%v", v.Job)
		}
		r, err := f.A.Client.GetJobOutput(ctx, connect.NewRequest(&v1.GetJobOutputRequest{JobId: v.Job.JobId, Hostname: "a-host", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT}))
		if connect.CodeOf(err) != connect.CodeNotFound || r != nil {
			t.Fatalf("failed store must not expose full memory output=%v error=%v", r, err)
		}
		preview := get(t, f.B, v.Job.JobId)
		if len(preview.Summary.Groups) != 1 || preview.Summary.Groups[0].Stdout != "same output" {
			t.Fatalf("failed store lost database preview=%v", preview)
		}
	})
	t.Run("concurrent_jobs_cluster_limit", func(t *testing.T) {
		ids := []string{}
		for i := 0; i < 5; i++ {
			r := request("linger")
			r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{[]string{"a-host", "b-host", "c-host"}[i%3]}}}}
			r.ExpectedCount = nil
			r.WaitSeconds = proto.Uint32(0)
			v := run(t, f.A, r)
			ids = append(ids, v.Job.JobId)
		}
		r := request("linger")
		r.WaitSeconds = proto.Uint32(0)
		_, err := f.B.Client.RunJob(ctx, connect.NewRequest(r))
		if connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Fatalf("sixth job error=%v", err)
		}
		for _, id := range ids {
			_, err := f.B.Client.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: id}))
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, id := range ids {
			get(t, f.B, id)
		}
	})
	t.Run("offline_does_not_count_toward_max_failures", func(t *testing.T) {
		if _, err := f.DB.Pool.Exec(ctx, "INSERT INTO hosts(host_id,hostname,authorization_labels,certificate_serial,certificate_expires_at) VALUES ('offline-fixture','0-offline','{\"env\":\"test\"}','offline-fixture',now()+interval '1 day')"); err != nil {
			t.Fatal(err)
		}
		r := request("stable")
		r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"0-offline", "a-host"}}}}
		r.ExpectedCount = nil
		r.BatchSize, r.MaxFailures = proto.Uint32(1), proto.Uint32(0)
		v := run(t, f.A, r)
		list := tasks(t, f.B, v.Job.JobId)
		if len(list) != 2 || list[0].Result.Status != v1.TaskStatus_TASK_STATUS_OFFLINE || list[1].Result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED {
			t.Fatalf("offline stopped next batch: %v", list)
		}
		if _, err := f.DB.Pool.Exec(ctx, "UPDATE hosts SET authorization_labels='{}' WHERE host_id='offline-fixture'"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("offline_during_execution_no_replay", func(t *testing.T) {
		r := request("slow")
		r.WaitSeconds = proto.Uint32(0)
		v := run(t, f.A, r)
		eventually(t, func() bool {
			for _, task := range tasks(t, f.A, v.Job.JobId) {
				if task.Result.Status != v1.TaskStatus_TASK_STATUS_RUNNING {
					return false
				}
			}
			return true
		})
		f.Stop[2]()
		completed := get(t, f.A, v.Job.JobId)
		if completed.Job.Status != v1.JobStatus_JOB_STATUS_PARTIALLY_FAILED {
			t.Fatalf("disconnect job=%v", completed.Job)
		}
		list := tasks(t, f.A, v.Job.JobId)
		if list[2].Result.Status != v1.TaskStatus_TASK_STATUS_OFFLINE {
			t.Fatalf("disconnected task=%v", list[2])
		}
		v = run(t, f.A, request("stable"))
		if v.Job.Status != v1.JobStatus_JOB_STATUS_PARTIALLY_FAILED {
			t.Fatalf("offline job=%v", v.Job)
		}
	})
	t.Run("system_counts_follow_job_visibility_and_storage_health", func(t *testing.T) {
		client := rpc.NewSystemServiceClient(f.A.HTTP, "https://"+f.A.Address, connect.WithInterceptors(bearer(f.Token)))
		r, err := client.GetSystemStatus(ctx, connect.NewRequest(&v1.GetSystemStatusRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		var failed uint64
		if err := f.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM jobs WHERE subject_id='sa' AND status IN (4,5) AND finished_at>=now()-interval '24 hours'").Scan(&failed); err != nil {
			t.Fatal(err)
		}
		if r.Msg.RunningJobs != 0 || r.Msg.FailedJobsLast_24Hours != failed || r.Msg.Status != v1.HealthStatus_HEALTH_STATUS_HEALTHY {
			t.Fatalf("visible job statistics=%v want failed=%d", r.Msg, failed)
		}
		token, record, err := authn.GenerateServiceToken(time.Now(), 1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.DB.Pool.Exec(ctx, "INSERT INTO service_accounts(account_id,name,owner_user_id,roles) VALUES ('other','other','owner','{admin}')"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.DB.Pool.Exec(ctx, "INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES ('other','other',$1,$2)", record.Hash[:], record.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		other := rpc.NewSystemServiceClient(f.B.HTTP, "https://"+f.B.Address, connect.WithInterceptors(bearer(token)))
		r, err = other.GetSystemStatus(ctx, connect.NewRequest(&v1.GetSystemStatusRequest{}))
		if err != nil || r.Msg.RunningJobs != 0 || r.Msg.FailedJobsLast_24Hours != 0 {
			t.Fatalf("other owner learned job counts=%v error=%v", r, err)
		}
		objects := f.Storage.Storage.(*output.S3)
		bad := &output.S3{Client: objects.Client, Bucket: "missing-fixture-bucket"}
		f.A.Job.Access.(*api.Service).ConfigureJobDependencies(f.A.Job, bad)
		r, err = client.GetSystemStatus(ctx, connect.NewRequest(&v1.GetSystemStatusRequest{}))
		if err != nil || r.Msg.Status != v1.HealthStatus_HEALTH_STATUS_DEGRADED || r.Msg.Dependencies[2].Status != v1.HealthStatus_HEALTH_STATUS_UNAVAILABLE {
			t.Fatalf("storage failure health=%v error=%v", r, err)
		}
		f.A.Job.Access.(*api.Service).ConfigureJobDependencies(f.A.Job, objects)
	})
}

func TestHeartbeatTimeoutMarksTaskOffline(t *testing.T) {
	var paused atomic.Bool
	f := setup(t, func(f *fixture) {
		f.HeartbeatTimeout = time.Second
		f.BeforeMessage = func(e hostconn.Event) {
			if e.Message.GetTaskStarted() != nil && paused.CompareAndSwap(false, true) {
				// Exceed the explicit short timeout while a task is in flight.
				time.Sleep(2 * time.Second)
			}
		}
	})
	r := request("stable")
	r.WaitSeconds = proto.Uint32(0)
	r.ExpectedCount = nil
	r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"b-host"}}}}
	started := run(t, f.A, r)
	completed := get(t, f.A, started.Job.JobId)
	list := tasks(t, f.B, started.Job.JobId)
	if !paused.Load() || completed.Job.Status != v1.JobStatus_JOB_STATUS_FAILED || len(list) != 1 || list[0].Result.Status != v1.TaskStatus_TASK_STATUS_OFFLINE {
		t.Fatalf("heartbeat timeout: paused=%t job=%v tasks=%v", paused.Load(), completed.Job, list)
	}
}
