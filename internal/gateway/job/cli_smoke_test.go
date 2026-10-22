package job_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/store/db"
	"github.com/liubing0806/allowops/internal/testpg"
	"github.com/liubing0806/allowops/internal/testseaweedfs"
	"google.golang.org/protobuf/encoding/protojson"
)

func command(t *testing.T, cmd *exec.Cmd) []byte {
	t.Helper()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", cmd.Path, err, out)
	}
	return out
}

// A slow catalog read also stalls Connect while it validates a load report.
// Real agents send periodic heartbeats, but that loop cannot acknowledge them
// during this pause. Keep it longer than the former three-second fixture limit.
type delayedCatalogQueries struct {
	db.DBTX
}

func (q delayedCatalogQueries) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.HasPrefix(sql, "-- name: GetCatalog :one") {
		time.Sleep(4 * time.Second)
	}
	return q.DBTX.QueryRow(ctx, sql, args...)
}

func TestCLISmokeAllowopsAgentProcesses(t *testing.T) {
	// setup creates the gateway and catalog. Stop its in-process agents so this
	// scenario selects exactly the two allowops processes below.
	f := setup(t, func(f *fixture) {
		f.DB.Queries = db.New(delayedCatalogQueries{DBTX: f.DB.Pool})
	})
	for _, stop := range f.Stop {
		stop()
	}
	ctx := context.Background()
	eventually(t, func() bool {
		var n int
		f.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM hosts WHERE instance_id IS NOT NULL").Scan(&n)
		return n == 0
	})
	if _, err := f.DB.Pool.Exec(ctx, "UPDATE hosts SET authorization_labels='{}'"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", filepath.Join(dir, "agent"), "./test/jobs/agent")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	command(t, build)
	build = exec.Command("go", "build", "-o", filepath.Join(dir, "allowops"), "./cmd/allowops")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	command(t, build)
	for _, pub := range f.Trusted {
		b, _ := catalog.MarshalPublicKey(pub)
		if err := os.WriteFile(filepath.Join(dir, "signer.pem"), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOARCH != "amd64" {
		t.Fatal("CLI smoke fixture currently requires amd64 Debian packages")
	}
	assets := filepath.Join(dir, "assets")
	if err := os.Mkdir(assets, 0700); err != nil {
		t.Fatal(err)
	}
	for _, pkg := range []string{"procps_4.0.2-3_amd64.deb", "libproc2-0_4.0.2-3_amd64.deb"} {
		archive := filepath.Join(dir, pkg)
		command(t, exec.Command("curl", "-fLsS", "--max-time", "30", "https://deb.debian.org/debian/pool/main/p/procps/"+pkg, "-o", archive))
		cmd := exec.Command("ar", "p", archive, "data.tar.xz")
		raw, err := cmd.Output()
		if err != nil {
			t.Fatal("extract Debian archive failed")
		}
		data := filepath.Join(dir, "data.tar.xz")
		if err := os.WriteFile(data, raw, 0600); err != nil {
			t.Fatal(err)
		}
		command(t, exec.Command("tar", "-xf", data, "-C", assets))
	}
	for _, file := range []struct{ source, name string }{{"usr/bin/uptime", "uptime"}, {"lib/x86_64-linux-gnu/libproc2.so.0.0.1", "libproc2.so.0"}} {
		raw, err := os.ReadFile(filepath.Join(assets, file.source))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, file.name), raw, 0755); err != nil {
			t.Fatal(err)
		}
	}
	dockerfile := `FROM debian:12
RUN useradd --system --user-group --home-dir /var/lib/allowops --shell /usr/sbin/nologin allowops && install -d -m 0700 -o allowops -g allowops /var/lib/allowops && install -d -m 0755 /etc/allowops/catalog-keys
COPY agent /usr/local/bin/agent
COPY signer.pem /etc/allowops/catalog-keys/signer.pem
COPY uptime /usr/bin/uptime
COPY libproc2.so.0 /usr/lib/x86_64-linux-gnu/libproc2.so.0
USER allowops
ENTRYPOINT ["/usr/local/bin/agent"]
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0600); err != nil {
		t.Fatal(err)
	}
	fixtureID := strings.ToLower(rand.Text())
	image := "allowops-p6-smoke:" + strings.ToLower(strings.ReplaceAll(t.Name(), "_", "-")) + "-" + fixtureID
	command(t, exec.Command("docker", "build", "-t", image, dir))
	t.Cleanup(func() { command(t, exec.Command("docker", "image", "rm", image)) })
	for i, g := range []*gateway{f.A, f.B} {
		name := []string{"smoke-a", "smoke-b"}[i]
		token, err := g.Host.CreateJoinToken(ctx, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		input, _ := json.Marshal(map[string]string{"Upstream": g.Address, "Pin": f.Pin, "Token": token, "Hostname": name})
		containerName := "p6-" + name + "-" + fixtureID
		cmd := exec.Command("docker", "run", "--rm", "--name", containerName, "--network", "host", "-i", image)
		cmd.Stdin = bytes.NewReader(input)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		t.Cleanup(func() {
			_ = exec.Command("docker", "stop", "-t", "3", containerName).Run()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("agent container exit: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("agent container did not stop")
			}
		})
		var hostID string
		eventually(t, func() bool {
			err := f.DB.Pool.QueryRow(ctx, "SELECT host_id FROM hosts WHERE hostname=$1", name).Scan(&hostID)
			if err != nil {
				return false
			}
			report := g.Host.CatalogReport(hostID, f.Package.CatalogID)
			return report != nil && report.Loaded
		})
		if _, err := f.DB.Pool.Exec(ctx, "UPDATE hosts SET authorization_labels='{"+`"env":"test"`+"}' WHERE host_id=$1", hostID); err != nil {
			t.Fatal(err)
		}
	}
	configDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(filepath.Join(configDir, "allowops"), 0700); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	caDER := f.Certificate.Certificate[len(f.Certificate.Certificate)-1]
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	credential, _ := json.Marshal(map[string]any{"gateway": "https://" + f.A.Address, "ca_file": caPath, "token": f.Token, "expires_at": time.Now().Add(time.Hour)})
	if err := os.WriteFile(filepath.Join(configDir, "allowops", "credentials"), credential, 0600); err != nil {
		t.Fatal(err)
	}
	cli := func(args ...string) []byte {
		cmd := exec.Command(filepath.Join(dir, "allowops"), args...)
		cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+configDir)
		return command(t, cmd)
	}
	raw := cli("run", "system_load", "--selector", "env=test", "--expected-count", "2", "--reason", "local CLI smoke", "--json")
	run := &v1.RunJobResponse{}
	if err := protojson.Unmarshal(raw, run); err != nil {
		t.Fatal(err)
	}
	if run.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED || run.Job.TotalTasks != 2 {
		t.Fatalf("CLI run=%s", raw)
	}
	raw = cli("jobs", "get", run.Job.JobId, "--json")
	got := &v1.GetJobResponse{}
	if err := protojson.Unmarshal(raw, got); err != nil || got.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED {
		t.Fatalf("CLI get=%s err=%v", raw, err)
	}
	eventually(t, func() bool {
		var n int
		f.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM tasks WHERE job_id=$1 AND output_stored", run.Job.JobId).Scan(&n)
		return n == 2
	})
	raw = cli("jobs", "output", run.Job.JobId, "--host", "smoke-b", "--json")
	gotOutput := &v1.GetJobOutputResponse{}
	if err := protojson.Unmarshal(raw, gotOutput); err != nil || !gotOutput.Eof || len(gotOutput.Data) == 0 || !gotOutput.OutputStored {
		t.Fatalf("CLI output bytes=%d err=%v", len(raw), err)
	}
	if raw := cli("jobs", "get", run.Job.JobId); !bytes.Contains(raw, []byte("succeeded")) {
		t.Fatalf("CLI table=%s", raw)
	}
	if raw := cli("jobs", "list", "--json"); !bytes.Contains(raw, []byte(run.Job.JobId)) {
		t.Fatalf("CLI list missing job: %s", raw)
	}
	raw = cli("run", "typed", "--selector", "env=test", "--expected-count", "2", "--reason", "typed CLI smoke", "--param", "number=2", "--param", "flag=true", "--param", `items=["one","two"]`, "--json")
	typed := &v1.RunJobResponse{}
	if err := protojson.Unmarshal(raw, typed); err != nil || typed.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED || len(typed.Summary.Groups) != 1 || typed.Summary.Groups[0].Stdout != "2 true" {
		t.Fatalf("CLI typed parameters=%s err=%v", raw, err)
	}
	cli("jobs", "cancel", run.Job.JobId, "--json")
	t.Logf("CLI run system_load expected_count=2 -> jobs get -> jobs output: succeeded; typed int/bool/string_array: succeeded; PostgreSQL=%s SeaweedFS=%s; two P3 processes run as allowops", testpg.Image, testseaweedfs.Image)
}
