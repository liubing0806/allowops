package cli

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestBrowserCommand(t *testing.T) {
	const loginURL = "https://gateway.example.org/auth/oidc/start?a=1&b=2"
	for _, tt := range []struct {
		goos string
		args []string
	}{
		{"darwin", []string{"open", loginURL}},
		{"windows", []string{"rundll32", "url.dll,FileProtocolHandler", loginURL}},
		{"linux", []string{"xdg-open", loginURL}},
	} {
		t.Run(tt.goos, func(t *testing.T) {
			if got := browserCommand(tt.goos, loginURL).Args; !slices.Equal(got, tt.args) {
				t.Fatalf("browser command = %q, want %q", got, tt.args)
			}
		})
	}
}

func useTestConfigDir(t *testing.T, dir string) string {
	t.Helper()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("APPDATA", dir)
	case "darwin":
		t.Setenv("HOME", dir)
		return filepath.Join(dir, "Library", "Application Support")
	default:
		t.Setenv("XDG_CONFIG_HOME", dir)
	}
	return dir
}

func TestCredentials(t *testing.T) {
	configDir := useTestConfigDir(t, t.TempDir())
	path := filepath.Join(configDir, "allowops", "credentials")
	if _, err := loadCredentials(); err == nil || err.Error() != "login required" {
		t.Fatalf("missing credentials error = %v", err)
	}

	want := credentials{
		Gateway:   "https://gateway.example.org",
		CAFile:    "ca.pem",
		ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second),
	}
	for _, token := range []string{"first-session", "replacement-session"} {
		want.Token = token
		if err := saveCredentials(want); err != nil {
			t.Fatal(err)
		}
		got, err := loadCredentials()
		if err != nil || got != want {
			t.Fatalf("loadCredentials() = %+v, %v, want %+v", got, err, want)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm() != 0600 {
			t.Fatalf("credentials permissions = %04o, want 0600", info.Mode().Perm())
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCredentials(); err == nil || !strings.Contains(err.Error(), "permissions 0600") {
			t.Fatalf("0644 credentials error = %v", err)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredentials(); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory credentials error = %v", err)
	}
}

func TestRPCErrorReportsPossibleCommitWithoutEchoingServerSecrets(t *testing.T) {
	err := connect.NewError(connect.CodeUnavailable, errors.New("provider-password-must-not-leak"))
	detail, detailErr := connect.NewErrorDetail(&v1.ErrorDetail{Reason: "AUDIT_RESULT_UNAVAILABLE"})
	if detailErr != nil {
		t.Fatal(detailErr)
	}
	err.AddDetail(detail)
	message := rpcError(err).Error()
	if !strings.Contains(message, "may have committed") || strings.Contains(message, "provider-password") {
		t.Fatalf("CLI audit failure message=%q", message)
	}
}

// The CLI cancels the command context on SIGINT instead of exiting, so the
// password prompt must end with it and restore terminal echo.
func TestPasswordPromptEndsWithCommandContext(t *testing.T) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	defer master.Close()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	ctx, cancel := context.WithCancel(context.Background())
	c := &cobra.Command{}
	c.SetContext(ctx)
	c.SetIn(terminal)
	c.SetErr(io.Discard)
	done := make(chan error, 1)
	go func() {
		_, err := readPassword(c, false)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled prompt returned a password")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("password prompt kept waiting after the command context ended")
	}
	state, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if state.Lflag&unix.ECHO == 0 {
		t.Error("terminal echo was not restored")
	}
}

func TestRPCErrorReportsPolicyEvaluationLimit(t *testing.T) {
	err := connect.NewError(connect.CodeResourceExhausted, errors.New("private gateway details"))
	detail, detailErr := connect.NewErrorDetail(&v1.ErrorDetail{Reason: "POLICY_EVALUATION_LIMIT_EXCEEDED"})
	if detailErr != nil {
		t.Fatal(detailErr)
	}
	err.AddDetail(detail)
	message := rpcError(err).Error()
	if !strings.Contains(message, "--cases") || !strings.Contains(message, "identity.max_test_evaluations") || strings.Contains(message, "private gateway details") {
		t.Fatalf("CLI policy limit message=%q", message)
	}
}

type policyCasesGateway struct {
	rpc.UnimplementedPolicyServiceHandler
	wantCases []*v1.PolicyTestCase
}

func (g policyCasesGateway) GetPolicy(context.Context, *connect.Request[v1.GetPolicyRequest]) (*connect.Response[v1.GetPolicyResponse], error) {
	return connect.NewResponse(&v1.GetPolicyResponse{Policy: &v1.PolicyVersion{Version: 7, Rules: &v1.PolicyRules{}}}), nil
}

func (g policyCasesGateway) TestPolicy(_ context.Context, r *connect.Request[v1.TestPolicyRequest]) (*connect.Response[v1.TestPolicyResponse], error) {
	want := &v1.TestPolicyRequest{BaseVersion: 7, Candidate: &v1.TestPolicyRequest_Rules{Rules: &v1.PolicyRules{}}, Cases: g.wantCases}
	if !proto.Equal(r.Msg, want) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unexpected policy test request"))
	}
	return connect.NewResponse(&v1.TestPolicyResponse{Test: &v1.PolicyTest{TestId: "pt-explicit"}}), nil
}

func (g policyCasesGateway) GetPolicyTestChanges(_ context.Context, r *connect.Request[v1.GetPolicyTestChangesRequest]) (*connect.Response[v1.GetPolicyTestChangesResponse], error) {
	if r.Msg.TestId != "pt-explicit" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("unexpected policy test ID"))
	}
	return connect.NewResponse(&v1.GetPolicyTestChangesResponse{Changes: []*v1.PolicyChange{{Host: "host-a"}}}), nil
}

func (g policyCasesGateway) SavePolicy(_ context.Context, r *connect.Request[v1.SavePolicyRequest]) (*connect.Response[v1.SavePolicyResponse], error) {
	want := &v1.SavePolicyRequest{BaseVersion: 7, Rules: &v1.PolicyRules{}, TestId: "pt-explicit", Reason: "fixture change"}
	if !proto.Equal(r.Msg, want) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unexpected policy save request"))
	}
	return connect.NewResponse(&v1.SavePolicyResponse{Policy: &v1.PolicyVersion{Version: 8, Reason: "saved fixture policy"}}), nil
}

func TestPolicyCommandsSendCases(t *testing.T) {
	at := timestamppb.New(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	_, handler := rpc.NewPolicyServiceHandler(policyCasesGateway{wantCases: []*v1.PolicyTestCase{
		{SubjectId: "operator", Operation: "execute_action", Action: "restart", SourceIp: "192.0.2.1", At: at,
			Targets: &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"host-a"}}}}},
		{SubjectId: "viewer", Operation: "view_jobs", Targets: &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "env=prod"}}},
	}})
	s := httptest.NewTLSServer(handler)
	t.Cleanup(s.Close)
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ca := write("ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})))
	if err := saveCredentials(credentials{Gateway: s.URL, CAFile: ca, Token: "fixture-token", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	yamlCases := write("cases.yaml", `- subject_id: operator
  operation: execute_action
  action: restart
  source_ip: 192.0.2.1
  at: 2026-01-02T03:04:05Z
  targets:
    hosts:
      names: [host-a]
- subject_id: viewer
  operation: view_jobs
  targets:
    selector: env=prod
`)
	jsonCases := write("cases.json", `[
  {"subjectId":"operator","operation":"execute_action","action":"restart","sourceIp":"192.0.2.1","at":"2026-01-02T03:04:05Z","targets":{"hosts":{"names":["host-a"]}}},
  {"subjectId":"viewer","operation":"view_jobs","targets":{"selector":"env=prod"}}
]`)
	rules := write("rules.yaml", "rules: []\n")
	for _, args := range [][]string{{"test", "--cases", yamlCases}, {"apply", "-f", rules, "--cases", jsonCases, "--reason", "fixture change"}} {
		t.Run(args[0], func(t *testing.T) {
			cmd := NewPolicyCmd()
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if text := output.String(); !strings.Contains(text, "pt-explicit") || !strings.Contains(text, "host-a") ||
				strings.Contains(text, "saved fixture policy") != (args[0] == "apply") {
				t.Fatalf("%s output=%q", args[0], text)
			}
		})
	}
	t.Run("empty case list", func(t *testing.T) {
		cmd := NewPolicyCmd()
		cmd.SetArgs([]string{"test", "--cases", write("empty.yaml", "[]\n")})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "at least one policy test case") {
			t.Fatalf("empty case file error=%v", err)
		}
	})
}
