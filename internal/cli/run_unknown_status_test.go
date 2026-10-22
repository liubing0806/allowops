package cli

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
)

// RR-c-05: only SUCCEEDED exits 0. QUEUED/RUNNING keep the A51 behaviour
// (exit 0 plus a notice). UNSPECIFIED, statuses this CLI does not know, and a
// response without a Job exit nonzero and name the unknown status on stderr.
type unknownStatusGateway struct {
	rpc.UnimplementedJobServiceHandler
}

func (unknownStatusGateway) RunJob(_ context.Context, r *connect.Request[v1.RunJobRequest]) (*connect.Response[v1.RunJobResponse], error) {
	switch r.Msg.Action {
	case "unspecified":
		return connect.NewResponse(&v1.RunJobResponse{Job: &v1.Job{JobId: "job-unknown", Action: r.Msg.Action, Status: v1.JobStatus_JOB_STATUS_UNSPECIFIED}}), nil
	case "future_status":
		return connect.NewResponse(&v1.RunJobResponse{Job: &v1.Job{JobId: "job-unknown", Action: r.Msg.Action, Status: v1.JobStatus(99)}}), nil
	case "nil_job":
		return connect.NewResponse(&v1.RunJobResponse{}), nil
	case "succeeded":
		return connect.NewResponse(&v1.RunJobResponse{Job: &v1.Job{JobId: "job-ok", Action: r.Msg.Action, Status: v1.JobStatus_JOB_STATUS_SUCCEEDED}}), nil
	}
	return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unknown fixture action"))
}

func prepareUnknownStatusGateway(t *testing.T) {
	t.Helper()
	_, handler := rpc.NewJobServiceHandler(unknownStatusGateway{})
	s := httptest.NewTLSServer(handler)
	t.Cleanup(s.Close)
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveCredentials(credentials{Gateway: s.URL, CAFile: ca, Token: "synthetic-contract-token", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

func TestRunUnknownStatusExitsNonzero(t *testing.T) {
	prepareUnknownStatusGateway(t)
	for _, name := range []string{"unspecified", "future_status", "nil_job"} {
		for _, jsonOutput := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%t", name, jsonOutput), func(t *testing.T) {
				cmd := NewRunCmd()
				var out, stderr bytes.Buffer
				cmd.SetOut(&out)
				cmd.SetErr(&stderr)
				args := []string{name, "--hosts", "fixture-host", "--reason", "contract", "--wait-seconds", "0"}
				if jsonOutput {
					args = append(args, "--json")
				}
				cmd.SetArgs(args)
				var err error
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("run panicked: %v", r)
							err = fmt.Errorf("panic")
						}
					}()
					err = cmd.Execute()
				}()
				if err == nil {
					t.Errorf("%s returned nil; want nonzero exit", name)
				}
				if !strings.Contains(stderr.String(), "has unknown status") || strings.Contains(stderr.String(), "未知状态") {
					t.Errorf("stderr must say \"has unknown status\" in English only: %q", stderr.String())
				}
			})
		}
	}
}

func TestRunUnknownStatusProcessExit(t *testing.T) {
	prepareUnknownStatusGateway(t)
	binary := filepath.Join(t.TempDir(), "allowops")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "go", "build", "-o", binary, "../../cmd/allowops").CombinedOutput(); err != nil {
		t.Fatalf("CLI fixture build: %v\n%s", err, output)
	}
	for _, tc := range []struct {
		name string
		want int
	}{{"succeeded", 0}, {"unspecified", 1}, {"future_status", 1}, {"nil_job", 1}} {
		for _, jsonOutput := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%t", tc.name, jsonOutput), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				args := []string{"run", tc.name, "--hosts", "fixture-host", "--reason", "contract", "--wait-seconds", "0"}
				if jsonOutput {
					args = append(args, "--json")
				}
				cmd := exec.CommandContext(ctx, binary, args...)
				var out, stderr bytes.Buffer
				cmd.Stdout = &out
				cmd.Stderr = &stderr
				code := 0
				if err := cmd.Run(); err != nil {
					exit, ok := err.(*exec.ExitError)
					if !ok {
						t.Fatal(err)
					}
					code = exit.ExitCode()
				}
				if code != tc.want {
					t.Errorf("real CLI %s exit=%d want=%d stdout=%q stderr=%q", tc.name, code, tc.want, out.String(), stderr.String())
				}
				if tc.want != 0 && (!strings.Contains(stderr.String(), "has unknown status") || strings.Contains(stderr.String(), "未知状态")) {
					t.Errorf("stderr must say \"has unknown status\" in English only: %q", stderr.String())
				}
			})
		}
	}
}
