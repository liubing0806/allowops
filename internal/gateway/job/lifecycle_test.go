package job_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(data)
}

func (b *lockedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

type sourceGateway struct {
	process *os.Process
	done    chan error
	client  rpc.JobServiceClient
	stopped bool
}

func startSource(t *testing.T, f *fixture) *sourceGateway {
	t.Helper()
	dir := t.TempDir()
	root, _ := filepath.Abs("../../..")
	binary := filepath.Join(dir, "gateway")
	build := exec.Command("go", "build", "-o", binary, "./cmd/allowops-gateway")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	command(t, build)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	var chain []byte
	for _, der := range f.Certificate.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, err := catalog.MarshalPrivateKey(f.Certificate.PrivateKey.(ed25519.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "tls.pem"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, chain, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	objects := f.Storage.Storage.(*output.S3)
	options := objects.Client.Options()
	credentials, err := options.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatal("fixture credentials unavailable")
	}
	configuration := map[string]any{"address": address, "tls_certificate": certPath, "tls_key": keyPath, "ca_certificate": filepath.Join(f.RootDir, "host-ca.pem"), "ca_key": filepath.Join(f.RootDir, "host-ca.key"), "catalog_keys": f.KeysDir, "gateway": hostconn.DefaultConfig(), "identity": map[string]any{"origin": "https://" + address}, "output": map[string]any{"bucket": objects.Bucket, "region": "us-east-1", "endpoint": *options.BaseEndpoint}}
	raw, _ := yaml.Marshal(configuration)
	configPath := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "serve", "--config", configPath)
	cmd.Env = append(os.Environ(), "ALLOWOPS_DATABASE_URL="+f.DSN, "AWS_ACCESS_KEY_ID="+credentials.AccessKeyID, "AWS_SECRET_ACCESS_KEY="+credentials.SecretAccessKey, "AWS_EC2_METADATA_DISABLED=true")
	logs := &lockedBuffer{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s := &sourceGateway{process: cmd.Process, done: make(chan error, 1), client: rpc.NewJobServiceClient(f.A.HTTP, "https://"+address, connect.WithInterceptors(bearer(f.Token)))}
	go func() { s.done <- cmd.Wait() }()
	t.Cleanup(func() {
		if !s.stopped {
			s.process.Kill()
			<-s.done
		}
	})
	eventually(t, func() bool { return strings.Contains(logs.String(), "gateway serving ") })
	return s
}

func TestGatewayDrainAndLostOriginRecovery(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for _, graceful := range []bool{true, false} {
		name := "forced_exit"
		if graceful {
			name = "graceful"
		}
		t.Run(name, func(t *testing.T) {
			s := startSource(t, f)
			action := "linger"
			if graceful {
				action = "slow"
			}
			r := request(action)
			r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"b-host", "c-host"}}}}
			r.ExpectedCount = nil
			r.BatchSize = proto.Uint32(1)
			r.WaitSeconds = proto.Uint32(0)
			response, err := s.client.RunJob(ctx, connect.NewRequest(r))
			if err != nil {
				t.Fatal(err)
			}
			id := response.Msg.Job.JobId
			eventually(t, func() bool { return tasks(t, f.B, id)[0].Result.Status == v1.TaskStatus_TASK_STATUS_RUNNING })
			if graceful {
				if err := s.process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := s.process.Kill(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-s.done:
				s.stopped = true
				if graceful && err != nil {
					t.Fatalf("graceful gateway exit=%v", err)
				}
				if !graceful && err == nil {
					t.Fatal("forced gateway unexpectedly exited successfully")
				}
			case <-time.After(15 * time.Second):
				t.Fatal("source gateway did not exit")
			}
			if !graceful {
				var origin string
				if err := f.DB.Pool.QueryRow(ctx, "SELECT origin_instance FROM jobs WHERE job_id=$1", id).Scan(&origin); err != nil {
					t.Fatal(err)
				}
				// Advance only the disposable origin heartbeat past the real threshold.
				if _, err := f.DB.Pool.Exec(ctx, "UPDATE gateway_instances SET last_seen=now()-interval '1 day' WHERE instance_id=$1", origin); err != nil {
					t.Fatal(err)
				}
				var wg sync.WaitGroup
				for _, g := range []*gateway{f.A, f.B} {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if err := g.Job.RecoverLostInstances(ctx); err != nil {
							t.Error(err)
						}
					}()
				}
				wg.Wait()
			}
			completed := get(t, f.B, id)
			list := tasks(t, f.B, id)
			if graceful {
				if list[0].Result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED || list[1].Result.Status != v1.TaskStatus_TASK_STATUS_SKIPPED || completed.Job.Status != v1.JobStatus_JOB_STATUS_PARTIALLY_FAILED {
					t.Fatalf("drain job=%v tasks=%v", completed.Job, list)
				}
			} else {
				if list[0].Result.Status != v1.TaskStatus_TASK_STATUS_FAILED || list[0].Result.Reason != "GATEWAY_INSTANCE_LOST" || list[1].Result.Status != v1.TaskStatus_TASK_STATUS_SKIPPED || completed.Job.Status != v1.JobStatus_JOB_STATUS_FAILED {
					t.Fatalf("lost source job=%v tasks=%v", completed.Job, list)
				}
				var count int
				if err := f.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE operation='recover_job' AND job_id=$1 AND reason='result'", id).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 1 {
					t.Fatalf("recovery result audits=%d want 1", count)
				}
				if err := f.B.Job.RecoverLostInstances(ctx); err != nil {
					t.Fatal(err)
				}
				f.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE operation='recover_job' AND job_id=$1 AND reason='result'", id).Scan(&count)
				if count != 1 {
					t.Fatalf("duplicate recovery audits=%d", count)
				}
			}
		})
	}
}
