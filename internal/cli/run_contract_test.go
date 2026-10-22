package cli

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
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
	"google.golang.org/protobuf/encoding/protojson"
)

type contractRunGateway struct {
	rpc.UnimplementedJobServiceHandler
}

var contractRunStatuses = map[string]v1.JobStatus{
	"succeeded": v1.JobStatus_JOB_STATUS_SUCCEEDED, "failed": v1.JobStatus_JOB_STATUS_FAILED,
	"partially_failed": v1.JobStatus_JOB_STATUS_PARTIALLY_FAILED, "cancelled": v1.JobStatus_JOB_STATUS_CANCELLED,
	"denied": v1.JobStatus_JOB_STATUS_DENIED, "queued": v1.JobStatus_JOB_STATUS_QUEUED, "running": v1.JobStatus_JOB_STATUS_RUNNING,
}

func (contractRunGateway) RunJob(_ context.Context, r *connect.Request[v1.RunJobRequest]) (*connect.Response[v1.RunJobResponse], error) {
	if r.Msg.Action == "rpc_error" {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("synthetic server detail"))
	}
	status, ok := contractRunStatuses[r.Msg.Action]
	if !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unknown fixture action"))
	}
	return connect.NewResponse(&v1.RunJobResponse{Job: &v1.Job{JobId: "job-contract", Action: r.Msg.Action, Status: status, TotalTasks: 1}}), nil
}

func prepareContractRunGateway(t *testing.T) {
	t.Helper()
	_, handler := rpc.NewJobServiceHandler(contractRunGateway{})
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

func contractRunWantError(name string) bool {
	return name != "succeeded" && name != "queued" && name != "running"
}

func TestRunObservedOutcomeContract(t *testing.T) {
	prepareContractRunGateway(t)
	for name, status := range contractRunStatuses {
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
				err := cmd.Execute()
				if (err != nil) != contractRunWantError(name) {
					t.Errorf("observed %s command error=%v; want nonzero=%t", name, err, contractRunWantError(name))
				}
				if !strings.Contains(out.String(), "job-contract") {
					t.Errorf("job output lost: %q", out.String())
				}
				if jsonOutput {
					var response v1.RunJobResponse
					if err := protojson.Unmarshal(out.Bytes(), &response); err != nil || response.Job.GetStatus() != status {
						t.Errorf("JSON response=%q err=%v", out.String(), err)
					}
				}
				if (name == "queued" || name == "running") && !strings.Contains(stderr.String(), "not completed") {
					t.Errorf("pending job must explicitly say not completed: stderr=%q", stderr.String())
				}
			})
		}
	}
}

type contractBrokenWriter struct{ err error }

func (w contractBrokenWriter) Write([]byte) (int, error) { return 0, w.err }

func TestRunContractPreservesSubmissionAndOutputErrors(t *testing.T) {
	prepareContractRunGateway(t)
	for _, name := range []string{"rpc_error", "succeeded", "failed"} {
		for _, jsonOutput := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%t", name, jsonOutput), func(t *testing.T) {
				cmd := NewRunCmd()
				var stderr bytes.Buffer
				cmd.SetErr(&stderr)
				var out bytes.Buffer
				cmd.SetOut(&out)
				sentinel := errors.New("fixture output failure")
				if name != "rpc_error" {
					cmd.SetOut(contractBrokenWriter{sentinel})
				}
				args := []string{name, "--hosts", "fixture-host", "--reason", "contract"}
				if jsonOutput {
					args = append(args, "--json")
				}
				cmd.SetArgs(args)
				err := cmd.Execute()
				if err == nil {
					t.Fatal("submission/output failure returned nil")
				}
				if name != "rpc_error" && !errors.Is(err, sentinel) {
					t.Errorf("output error replaced: %v", err)
				}
			})
		}
	}
	cmd := NewRunCmd()
	cmd.SetArgs([]string{"succeeded", "--hosts", "fixture-host"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err == nil {
		t.Error("missing reason accepted")
	}
}

func TestRunProcessExitContract(t *testing.T) {
	prepareContractRunGateway(t)
	binary := filepath.Join(t.TempDir(), "allowops")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "go", "build", "-o", binary, "../../cmd/allowops").CombinedOutput(); err != nil {
		t.Fatalf("CLI fixture build: %v\n%s", err, output)
	}
	for _, name := range []string{"succeeded", "failed", "partially_failed", "cancelled", "denied", "queued", "running", "rpc_error"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "run", name, "--hosts", "fixture-host", "--reason", "contract", "--wait-seconds", "0", "--json")
			var out, stderr bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &stderr
			err := cmd.Run()
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			want := 0
			if contractRunWantError(name) {
				want = 1
			}
			if code != want {
				t.Errorf("real CLI %s exit=%d want=%d stdout=%q stderr=%q", name, code, want, out.String(), stderr.String())
			}
			if name != "rpc_error" {
				var response v1.RunJobResponse
				if err := protojson.Unmarshal(out.Bytes(), &response); err != nil || response.Job.GetStatus() != contractRunStatuses[name] {
					t.Errorf("output lost: %q err=%v", out.String(), err)
				}
			}
		})
	}
}
