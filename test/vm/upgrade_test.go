//go:build vm

package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/liubing0806/allowops/test/harness"
)

// TestOnlineUpgrade upgrades a packaged agent through a signed catalog action.
// VM_UPGRADE_PACKAGES holds from/, to/ and newer/, each with one .deb and one
// .rpm; to/ must not be newer than the gateway and newer/ must be newer.
func TestOnlineUpgrade(t *testing.T) {
	harness.Environment(t)
	root := os.Getenv("VM_UPGRADE_PACKAGES")
	if root == "" {
		t.Fatal("VM_UPGRADE_PACKAGES required")
	}
	distros := strings.Split(os.Getenv("VM_DISTROS"), ",")
	if distros[0] == "" {
		distros = []string{"centos7", "ubuntu2004", "rocky9"}
	}
	content, err := os.ReadFile("agent-upgrade.sh")
	harness.Check(t, err)
	sum := sha256.Sum256(content)
	upgrade := catalog.Action{Name: "agent_upgrade", Description: "Install a staged agent package and restart the agent", Risk: "dangerous", RunAs: "root",
		Params:  map[string]params.Definition{"package": {Type: "enum", Values: []string{"to", "newer"}, Description: "Staged package"}},
		Script:  &catalog.Script{File: "agent-upgrade.sh", Interpreter: "/bin/sh", Content: content, SHA256: hex.EncodeToString(sum[:])},
		Args:    []any{"{package}"},
		Timeout: "300s", MaxOutput: 64 << 10}
	for _, distro := range distros {
		t.Run(distro, func(t *testing.T) {
			format := "deb"
			if strings.HasPrefix(distro, "rocky") || distro == "centos7" {
				format = "rpm"
			}
			pkg := map[string]string{}
			for _, stage := range []string{"from", "to", "newer"} {
				matches, err := filepath.Glob(filepath.Join(root, stage, "*."+format))
				harness.Check(t, err)
				if len(matches) != 1 {
					t.Fatalf("expected one %s package in %s", format, stage)
				}
				pkg[stage], err = filepath.Abs(matches[0])
				harness.Check(t, err)
			}
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
			g := harness.NewWithActions(t, 1, map[string]catalog.Action{"agent_upgrade": upgrade})
			t.Cleanup(func() { g.Log(t) })
			_, port, err := net.SplitHostPort(g.Address)
			harness.Check(t, err)
			input, err := json.Marshal(map[string]string{"upstream": "https://10.0.2.2:" + port, "pin": g.Pin, "token": g.JoinToken})
			harness.Check(t, err)
			if !script(t, "configure", work, input, pkg["from"], filepath.Join(g.Dir, "keys", "catalog.pem")) {
				return
			}
			// Staged files get stable names that the signed action's enum selects.
			staged := t.TempDir()
			for _, stage := range []string{"to", "newer"} {
				data, err := os.ReadFile(pkg[stage])
				harness.Check(t, err)
				harness.Check(t, os.WriteFile(filepath.Join(staged, stage+"."+format), data, 0600))
			}
			if !script(t, "stage", work, nil, filepath.Join(staged, "to."+format), filepath.Join(staged, "newer."+format)) {
				return
			}
			ctx := context.Background()
			type state struct{ version, connection string }
			current := func() state {
				var s state
				var connection *string
				harness.Check(t, g.DB.Pool.QueryRow(ctx, "SELECT agent_version, connection_id FROM hosts").Scan(&s.version, &connection))
				if connection != nil {
					s.connection = *connection
				}
				return s
			}
			wait := func(what string, ok func(state) bool) state {
				deadline := time.Now().Add(2 * time.Minute)
				for time.Now().Before(deadline) {
					var n int
					harness.Check(t, g.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM hosts").Scan(&n))
					if n == 1 {
						if s := current(); ok(s) {
							return s
						}
					}
					time.Sleep(500 * time.Millisecond)
				}
				t.Fatalf("timeout waiting for %s; last state %+v", what, current())
				return state{}
			}
			before := wait("initial connection", func(s state) bool { return s.connection != "" })
			_, err = g.DB.Pool.Exec(ctx, `UPDATE hosts SET authorization_labels='{"env":"p10a"}'`)
			harness.Check(t, err)
			var hostname string
			harness.Check(t, g.DB.Pool.QueryRow(ctx, "SELECT hostname FROM hosts").Scan(&hostname))
			t.Logf("before upgrade: %+v", before)
			systemd := func(label string) {
				cmd := exec.Command("bash", "run.sh", "shell", work)
				cmd.Stdin = strings.NewReader("systemctl --version | head -1; systemctl show allowops-agent -p MainPID -p ActiveEnterTimestamp -p NRestarts 2>/dev/null || systemctl show allowops-agent -p MainPID -p ActiveEnterTimestamp; systemctl list-units --all --no-pager 'run-*' ; journalctl --no-pager -n 25 -u allowops-agent\n")
				out, err := cmd.CombinedOutput()
				t.Logf("guest %s: %s", label, out)
				harness.Check(t, err)
			}
			systemd("before upgrade")
			run := func(stage string) {
				r, elapsed, err := g.RunJobWithParams([]string{hostname}, "agent_upgrade", map[string]any{"package": stage})
				harness.Check(t, err)
				var stdout, stderr []byte
				var finished time.Time
				harness.Check(t, g.DB.Pool.QueryRow(ctx, "SELECT stdout_preview, stderr_preview, finished_at FROM tasks WHERE job_id=$1", r.Job.JobId).Scan(&stdout, &stderr, &finished))
				t.Logf("upgrade %s: job=%s elapsed=%s finished_at=%s stdout=%q stderr=%q", stage, r.Job.Status, elapsed, finished.UTC().Format(time.RFC3339Nano), stdout, stderr)
				if r.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED || !strings.Contains(string(stdout), "restart scheduled") {
					t.Fatalf("upgrade %s did not report success before restart: %v", stage, r)
				}
			}
			run("to")
			after := wait("reconnect with upgraded version", func(s state) bool {
				return s.connection != "" && s.connection != before.connection && s.version != before.version
			})
			t.Logf("after supported upgrade: %+v", after)
			systemd("after supported upgrade")
			if r, _, err := g.RunJob([]string{hostname}, "root_identity"); err != nil || r.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED {
				t.Fatalf("upgraded agent cannot run actions: %v %v", r, err)
			}
			run("newer")
			// The newer agent must be refused; the row keeps the last accepted version.
			rejected := wait("disconnect of newer agent", func(s state) bool { return s.connection == "" })
			time.Sleep(20 * time.Second)
			final := current()
			t.Logf("after newer upgrade: %+v (first offline state %+v)", final, rejected)
			systemd("after newer upgrade")
			if final.connection != "" || final.version != after.version {
				t.Fatalf("newer agent was accepted: %+v", final)
			}
			// Operators must see why the host is offline on both sides.
			journal := exec.Command("bash", "run.sh", "shell", work)
			journal.Stdin = strings.NewReader("journalctl --no-pager -u allowops-agent | grep 'gateway rejected agent version'\n")
			out, err := journal.CombinedOutput()
			t.Logf("agent journal rejection: %s", out)
			if err != nil {
				t.Fatalf("agent journal lacks the rejection: %v", err)
			}
			gatewayLog, err := os.ReadFile(filepath.Join(g.Dir, "gateway.log"))
			harness.Check(t, err)
			var logged []string
			for _, line := range strings.Split(string(gatewayLog), "\n") {
				if strings.Contains(line, "agent version unsupported") && strings.Contains(line, hostname) {
					logged = append(logged, line)
				}
			}
			t.Logf("gateway rejection log: %q", logged)
			if len(logged) != 1 {
				t.Fatalf("gateway logged %d rejections for %s, want one", len(logged), hostname)
			}
			r, _, err := g.RunJob([]string{hostname}, "root_identity")
			if err == nil {
				t.Logf("job after rejection: status=%s", r.Job.Status)
				if r.Job.Status == v1.JobStatus_JOB_STATUS_SUCCEEDED {
					t.Fatal("job succeeded on a rejected agent")
				}
			} else {
				t.Logf("job after rejection: %v", err)
			}
		})
	}
}
