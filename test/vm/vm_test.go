//go:build vm

package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/test/harness"
)

func TestMatrix(t *testing.T) {
	harness.Environment(t)
	distros := strings.Split(os.Getenv("VM_DISTROS"), ",")
	if distros[0] == "" {
		distros = []string{"ubuntu2404", "rocky9", "rocky8", "ubuntu2004", "debian12", "centos7"}
	}
	for _, distro := range distros {
		t.Run(distro, func(t *testing.T) {
			format := "deb"
			if strings.HasPrefix(distro, "rocky") || distro == "centos7" {
				format = "rpm"
			}
			packages, err := filepath.Glob("../../dist/*." + format)
			harness.Check(t, err)
			if len(packages) != 1 {
				t.Fatalf("expected one locally built %s in dist; build snapshot packages first", format)
			}
			pkg, err := filepath.Abs(packages[0])
			harness.Check(t, err)
			work := t.TempDir()
			t.Cleanup(func() {
				out, err := exec.Command("bash", "run.sh", "stop", work).CombinedOutput()
				if err != nil {
					t.Errorf("stop VM: %v %s", err, out)
				}
			})
			if !script(t, "start", work, nil, distro) {
				return
			}
			g := harness.New(t, 1)
			t.Cleanup(func() { g.Log(t) })
			_, port, err := net.SplitHostPort(g.Address)
			harness.Check(t, err)
			input, err := json.Marshal(map[string]string{"upstream": "https://10.0.2.2:" + port, "pin": g.Pin, "token": g.JoinToken})
			harness.Check(t, err)
			if !script(t, "configure", work, input, pkg, filepath.Join(g.Dir, "keys", "catalog.pem")) {
				return
			}
			deadline := time.Now().Add(time.Minute)
			var ready int
			for time.Now().Before(deadline) {
				err = g.DB.Pool.QueryRow(context.Background(), "SELECT count(*) FROM hosts h JOIN host_catalog_reports r USING(host_id) WHERE h.connection_id IS NOT NULL AND r.loaded AND r.catalog_id='p10a'").Scan(&ready)
				harness.Check(t, err)
				if ready == 1 {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if ready != 1 {
				t.Fatal("guest did not connect and load signed catalog")
			}
			_, err = g.DB.Pool.Exec(context.Background(), `UPDATE hosts SET authorization_labels='{"env":"p10a"}'`)
			harness.Check(t, err)
			var hostname string
			harness.Check(t, g.DB.Pool.QueryRow(context.Background(), "SELECT hostname FROM hosts WHERE connection_id IS NOT NULL").Scan(&hostname))
			for _, action := range []string{"system_load", "root_identity"} {
				r, elapsed, err := g.RunJob([]string{hostname}, action)
				harness.Check(t, err)
				if r.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED || r.Job.TotalTasks != 1 {
					t.Fatalf("action %s: %v", action, r)
				}
				var stdout []byte
				harness.Check(t, g.DB.Pool.QueryRow(context.Background(), "SELECT stdout_preview FROM tasks WHERE job_id=$1", r.Job.JobId).Scan(&stdout))
				if action == "root_identity" && string(stdout) != "0\n" {
					t.Fatalf("root uid output: got %q want 0\\n", stdout)
				}
				if len(stdout) == 0 {
					t.Fatalf("action %s returned empty output", action)
				}
				t.Logf("PASS action=%s job=%s elapsed=%s stdout=%q", action, r.Job.Status, elapsed, stdout)
			}
			script(t, "uninstall", work, nil)
		})
	}
}

func script(t *testing.T, op, work string, input []byte, args ...string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", append([]string{"run.sh", op, work}, args...)...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	t.Logf("%s: %s", op, out)
	if err != nil {
		t.Error(fmt.Errorf("VM %s failed: %w", op, err))
		return false
	}
	return true
}
