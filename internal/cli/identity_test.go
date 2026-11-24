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
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type policyYAMLFixture struct {
	rpc.UnimplementedPolicyServiceHandler
	rules *v1.PolicyRules
}

func (f policyYAMLFixture) GetPolicy(context.Context, *connect.Request[v1.GetPolicyRequest]) (*connect.Response[v1.GetPolicyResponse], error) {
	return connect.NewResponse(&v1.GetPolicyResponse{Policy: &v1.PolicyVersion{Version: 1, Rules: f.rules}}), nil
}

func TestPolicyGetApprovalRulesYAMLRoundTrip(t *testing.T) {
	rules, err := readRules("../../examples/policy/hitl-approval.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]*v1.PolicyApprovalConfig{
		"java-arthas-l2":                {ApproverRoles: []string{"java-approver"}, MinApprovals: 1, TtlSeconds: 900},
		"operations-write-or-dangerous": {ApproverRoles: []string{"ops-approver"}, MinApprovals: 2, TtlSeconds: 1800},
	}
	for _, rule := range rules.Rules {
		if approval, ok := want[rule.Name]; ok {
			if rule.Effect != v1.PolicyEffect_POLICY_EFFECT_REQUIRE_APPROVAL || !proto.Equal(rule.Approval, approval) {
				t.Fatalf("parsed approval rule = %v, want approval %v", rule, approval)
			}
			delete(want, rule.Name)
		}
	}
	if len(want) > 0 {
		t.Fatalf("missing approval rules: %v", want)
	}

	_, handler := rpc.NewPolicyServiceHandler(policyYAMLFixture{rules: rules})
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveCredentials(credentials{Gateway: server.URL, CAFile: ca, Token: "synthetic-policy-token", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	cmd := NewPolicyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"get"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"effect: require_approval", "approval:", "approver_roles:", "min_approvals:", "ttl_seconds:"} {
		if !strings.Contains(out.String(), field) {
			t.Errorf("exported YAML missing %q:\n%s", field, out.String())
		}
	}
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := readRules(path)
	if err != nil || !proto.Equal(reloaded, rules) {
		t.Fatalf("reloaded YAML rules = %v, err=%v; want %v", reloaded, err, rules)
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
