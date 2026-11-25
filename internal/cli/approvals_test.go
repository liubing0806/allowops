package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const testApprovalID = "apr-20261124-0001"

type approvalCLIService struct {
	rpc.UnimplementedApprovalServiceHandler
	rpc.UnimplementedJobServiceHandler
	approval *v1.ApprovalRequest
	requests chan proto.Message
}

func (s *approvalCLIService) ListApprovals(_ context.Context, r *connect.Request[v1.ListApprovalsRequest]) (*connect.Response[v1.ListApprovalsResponse], error) {
	s.requests <- r.Msg
	return connect.NewResponse(&v1.ListApprovalsResponse{
		Approvals: []*v1.ApprovalRequest{s.approval},
		Page:      &v1.PageResponse{NextPageToken: "next\x1b[2J"},
	}), nil
}

func (s *approvalCLIService) GetApproval(_ context.Context, r *connect.Request[v1.GetApprovalRequest]) (*connect.Response[v1.GetApprovalResponse], error) {
	s.requests <- r.Msg
	return connect.NewResponse(&v1.GetApprovalResponse{Approval: s.approval}), nil
}

func (s *approvalCLIService) ApproveRequest(_ context.Context, r *connect.Request[v1.ApproveRequestRequest]) (*connect.Response[v1.ApproveRequestResponse], error) {
	s.requests <- r.Msg
	a := proto.CloneOf(s.approval)
	a.Status = v1.ApprovalStatus_APPROVAL_STATUS_APPROVED
	return connect.NewResponse(&v1.ApproveRequestResponse{Approval: a}), nil
}

func (s *approvalCLIService) RejectRequest(_ context.Context, r *connect.Request[v1.RejectRequestRequest]) (*connect.Response[v1.RejectRequestResponse], error) {
	s.requests <- r.Msg
	a := proto.CloneOf(s.approval)
	a.Status = v1.ApprovalStatus_APPROVAL_STATUS_REJECTED
	return connect.NewResponse(&v1.RejectRequestResponse{Approval: a}), nil
}

func (s *approvalCLIService) CancelApproval(_ context.Context, r *connect.Request[v1.CancelApprovalRequest]) (*connect.Response[v1.CancelApprovalResponse], error) {
	s.requests <- r.Msg
	a := proto.CloneOf(s.approval)
	a.Status = v1.ApprovalStatus_APPROVAL_STATUS_CANCELLED
	return connect.NewResponse(&v1.CancelApprovalResponse{Approval: a}), nil
}

func (s *approvalCLIService) RunJob(_ context.Context, r *connect.Request[v1.RunJobRequest]) (*connect.Response[v1.RunJobResponse], error) {
	s.requests <- r.Msg
	return connect.NewResponse(&v1.RunJobResponse{Job: &v1.Job{
		JobId: s.approval.JobId, Action: s.approval.Action, Status: v1.JobStatus_JOB_STATUS_PENDING_APPROVAL,
		Approval: &v1.JobApprovalSummary{
			ApprovalId: s.approval.ApprovalId, Status: s.approval.Status,
			ExpiresAt: s.approval.ExpiresAt, ConsoleUrl: s.approval.ConsoleUrl,
		},
	}}), nil
}

func approvalCLIFixture(t *testing.T) *approvalCLIService {
	t.Helper()
	digest := sha256.Sum256([]byte("frozen approval plan"))
	at := timestamppb.New(time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC))
	s := &approvalCLIService{requests: make(chan proto.Message, 16), approval: &v1.ApprovalRequest{
		ApprovalId: testApprovalID, JobId: "job-20261124-0001",
		Status: v1.ApprovalStatus_APPROVAL_STATUS_PENDING, ExpiresAt: at, DecidedAt: at,
		Action: "inspect\x1b[2J", ActionRisk: "write", Reason: "request\nFORGED STATUS: approved",
		Catalog: &v1.CatalogRef{CatalogId: "catalog", Version: 2}, ActionSha256: digest[:], RequestDigest: digest[:],
		Targets:        []*v1.ApprovalTarget{{Hostname: "web\x1b[2J\t01", HostId: "host\x7f"}},
		Evidence:       &v1.JobEvidence{JobIds: []string{"job-20261124-0002"}, Summary: "evidence\u009b2J\rtext"},
		Decisions:      []*v1.ApprovalDecisionRecord{{ActorId: "reviewer\nname", Reason: "vote\a"}},
		DecisionReason: "decision\x00reason", NotifyStatus: "sent", RecheckError: "RECHECK_POLICY_TIGHTENED",
		BatchSize: 1, MaxFailures: 2, MinApprovals: 2, ApprovedCount: 1, PolicyVersion: 4,
		ParamsJson: []byte("{\n \"p\": \"value\"}"), FiltersJson: []byte(`{"count":true}`),
		RequesterSubjectId: "requester\taccount", ConsoleUrl: "https://console.test/approvals/" + testApprovalID + "\x1b[2J",
	}}
	mux := http.NewServeMux()
	p, handler := rpc.NewApprovalServiceHandler(s)
	mux.Handle(p, handler)
	p, handler = rpc.NewJobServiceHandler(s)
	mux.Handle(p, handler)
	gateway := httptest.NewTLSServer(mux)
	t.Cleanup(gateway.Close)
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gateway.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveCredentials(credentials{Gateway: gateway.URL, CAFile: ca, Token: "synthetic-token", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return s
}

func executeApprovalCLI(c *cobra.Command, args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer
	c.SetOut(&stdout)
	c.SetErr(&stderr)
	c.SetIn(strings.NewReader("yes\n"))
	c.SetArgs(args)
	err := c.Execute()
	return stdout.String(), stderr.String(), err
}

func (s *approvalCLIService) expectRequest(t *testing.T, want proto.Message) {
	t.Helper()
	select {
	case got := <-s.requests:
		if !proto.Equal(got, want) {
			t.Fatalf("request=%v (%T); want %v (%T)", got, got, want, want)
		}
	default:
		t.Fatalf("missing RPC request %T", want)
	}
}

func TestApprovalsListAndGet(t *testing.T) {
	s := approvalCLIFixture(t)
	for _, asJSON := range []bool{false, true} {
		flags := []string{}
		if asJSON {
			flags = append(flags, "--json")
		}
		list, _, err := executeApprovalCLI(NewApprovalsCmd(), append([]string{
			"list", "--status", "pending", "--action", "inspect", "--requester", "user", "--actionable", "--page-size", "7", "--page-token", "previous",
		}, flags...)...)
		if err != nil {
			t.Fatal(err)
		}
		s.expectRequest(t, &v1.ListApprovalsRequest{
			Statuses: []v1.ApprovalStatus{v1.ApprovalStatus_APPROVAL_STATUS_PENDING},
			Action:   "inspect", RequesterSubjectId: "user", OnlyActionable: true,
			Page: &v1.PageRequest{PageSize: 7, PageToken: "previous"},
		})
		detail, _, err := executeApprovalCLI(NewApprovalsCmd(), append([]string{"get", testApprovalID}, flags...)...)
		if err != nil {
			t.Fatal(err)
		}
		s.expectRequest(t, &v1.GetApprovalRequest{ApprovalId: testApprovalID})
		if asJSON {
			var listed v1.ListApprovalsResponse
			var fetched v1.GetApprovalResponse
			if err := protojson.Unmarshal([]byte(list), &listed); err != nil || !proto.Equal(listed.GetApprovals()[0], s.approval) {
				t.Fatalf("list JSON=%s err=%v", list, err)
			}
			if err := protojson.Unmarshal([]byte(detail), &fetched); err != nil || !proto.Equal(fetched.GetApproval(), s.approval) {
				t.Fatalf("get JSON=%s err=%v", detail, err)
			}
			continue
		}
		for _, wanted := range []string{`inspect\x1b[2J`, `requester\taccount`, `next_page_token: next\x1b[2J`} {
			if !strings.Contains(list, wanted) {
				t.Errorf("missing %q from list %q", wanted, list)
			}
		}
		plan, untrusted, ok := strings.Cut(detail, "UNTRUSTED REQUESTER CONTEXT")
		if !ok || !strings.HasPrefix(plan, "GATEWAY-VERIFIED EXECUTION PLAN") || strings.Contains(plan, "FORGED STATUS") {
			t.Fatalf("sections in %q", detail)
		}
		for _, want := range []string{`web\x1b[2J\t01`, `host\x7f`, `params_json: {"p":"value"}`,
			fmt.Sprintf("request_digest: %x", s.approval.RequestDigest), "catalog: catalog (version 2)", "max_failures: 2"} {
			if !strings.Contains(plan, want) {
				t.Errorf("verified plan missing %q", want)
			}
		}
		for _, want := range []string{`request\nFORGED STATUS`, `evidence\u009b2J\rtext`, `reviewer\nname`, `decision\x00reason`, "notify_status: sent", "RECHECK_POLICY_TIGHTENED"} {
			if !strings.Contains(untrusted, want) {
				t.Errorf("detail missing %q from %q", want, untrusted)
			}
		}
		if strings.ContainsAny(list+detail, "\x1b\r\t\x00\a\u009b\x7f") {
			t.Fatalf("raw terminal control in text: %q %q", list, detail)
		}
	}
	if _, _, err := executeApprovalCLI(NewApprovalsCmd(), "list", "--status", "bad"); err == nil || len(s.requests) != 0 {
		t.Fatalf("invalid status reached gateway or succeeded: %v", err)
	}
}

func TestApprovalsDecisionsRequireConfirmation(t *testing.T) {
	s := approvalCLIFixture(t)
	for _, verb := range []string{"approve", "reject", "cancel"} {
		t.Run(verb, func(t *testing.T) {
			args := []string{verb, testApprovalID}
			if verb != "cancel" {
				args = append(args, "--reason", "reviewed")
			}
			stdout, _, err := executeApprovalCLI(NewApprovalsCmd(), args...)
			if err == nil || !strings.Contains(err.Error(), "--yes") {
				t.Fatalf("non-terminal confirmation=%v", err)
			}
			digestLine := fmt.Sprintf("request_digest: %x", s.approval.RequestDigest)
			if verb == "approve" {
				s.expectRequest(t, &v1.GetApprovalRequest{ApprovalId: testApprovalID})
				if !strings.Contains(stdout, digestLine) {
					t.Fatalf("preflight did not show the digest: %s", stdout)
				}
			}
			if len(s.requests) != 0 {
				t.Fatal("mutation sent without confirmation")
			}
			stdout, stderr, err := executeApprovalCLI(NewApprovalsCmd(), append(args, "--yes", "--json")...)
			if err != nil {
				t.Fatal(err)
			}
			switch verb {
			case "approve":
				s.expectRequest(t, &v1.GetApprovalRequest{ApprovalId: testApprovalID})
				s.expectRequest(t, &v1.ApproveRequestRequest{ApprovalId: testApprovalID, Reason: "reviewed", ExpectedRequestDigest: s.approval.RequestDigest})
				if !strings.Contains(stderr, digestLine) || !strings.Contains(stdout, "APPROVAL_STATUS_APPROVED") {
					t.Fatalf("stdout=%s stderr=%s", stdout, stderr)
				}
			case "reject":
				s.expectRequest(t, &v1.RejectRequestRequest{ApprovalId: testApprovalID, Reason: "reviewed"})
				if !strings.Contains(stdout, "APPROVAL_STATUS_REJECTED") {
					t.Fatal(stdout)
				}
			case "cancel":
				s.expectRequest(t, &v1.CancelApprovalRequest{ApprovalId: testApprovalID})
				if !strings.Contains(stdout, "APPROVAL_STATUS_CANCELLED") {
					t.Fatal(stdout)
				}
			}
		})
	}
	for _, reason := range []string{"", "  "} {
		if _, _, err := executeApprovalCLI(NewApprovalsCmd(), "reject", testApprovalID, "--reason", reason, "--yes"); err == nil || len(s.requests) != 0 {
			t.Fatalf("empty reason reached gateway or succeeded: %v", err)
		}
	}
}

func TestRunReportsPendingApprovalAndForwardsEvidence(t *testing.T) {
	s := approvalCLIFixture(t)
	for _, asJSON := range []bool{false, true} {
		evidenceJobs := []string{"job-20261124-0002", "job-20261124-0003"}
		args := []string{"inspect", "--hosts", "web-01", "--reason", "review", "--evidence-job", evidenceJobs[0],
			"--evidence-job", evidenceJobs[1], "--evidence-summary", "checked host", "--client-request-id", "request-1"}
		if asJSON {
			args = append(args, "--json")
		}
		out, stderr, err := executeApprovalCLI(NewRunCmd(), args...)
		if err != nil {
			t.Fatal(err)
		}
		got := (<-s.requests).(*v1.RunJobRequest)
		if got.ClientRequestId != "request-1" || got.GetEvidence().GetSummary() != "checked host" || !slices.Equal(got.GetEvidence().GetJobIds(), evidenceJobs) {
			t.Fatalf("run request=%v", got)
		}
		if !strings.Contains(stderr, "pending approval") || !strings.Contains(stderr, testApprovalID) || !strings.Contains(stderr, `\x1b[2J`) || strings.ContainsRune(stderr, '\x1b') {
			t.Fatalf("pending notice=%q", stderr)
		}
		if asJSON {
			var response v1.RunJobResponse
			if err := protojson.Unmarshal([]byte(out), &response); err != nil || response.GetJob().GetApproval().GetApprovalId() != testApprovalID {
				t.Fatalf("run JSON=%s error=%v", out, err)
			}
		} else if !strings.Contains(out, "approval_status: pending") || !strings.Contains(out, "2026-11-24T06:00:00Z") || strings.ContainsRune(out, '\x1b') {
			t.Fatalf("pending result=%q", out)
		}
	}
}
