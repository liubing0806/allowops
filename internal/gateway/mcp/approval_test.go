package mcp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestApprovalResultsFitWireBudget(t *testing.T) {
	a := &v1.JobApprovalSummary{
		ApprovalId: "apr-20261124-0001", Status: v1.ApprovalStatus_APPROVAL_STATUS_PENDING,
		ExpiresAt:    timestamppb.New(time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)),
		MinApprovals: 2, ApprovedCount: 1, ConsoleUrl: "https://console.test/approvals/apr-20261124-0001",
	}
	for i := 0; i < 128; i++ {
		a.RequiredApproverRoleSets = append(a.RequiredApproverRoleSets, &v1.PolicyApprovalRoleSet{
			Roles: []string{strings.Repeat("role-", 64)},
		})
	}
	job := &v1.Job{JobId: "job-20261124-0001", Action: "gated_write", Status: v1.JobStatus_JOB_STATUS_PENDING_APPROVAL, Approval: a, TotalTasks: 1}
	data := jobMetadata(job)
	_, fullSize, err := toolResult(data)
	if err != nil || fullSize <= resultByteLimit {
		t.Fatalf("test receipt is not oversized: bytes=%d err=%v", fullSize, err)
	}
	pending, err := pendingApprovalResult(job, false)
	pendingData := assertApprovalBudget(t, pending, err)
	if pendingData["status"] != "pending_approval" || !strings.Contains(pendingData["hint"].(string), "Do not retry") {
		t.Fatalf("pending receipt=%v", pendingData)
	}
	preTrimmed := &v1.Job{
		JobId: "job-20261124-0001", Action: "gated_write", Status: v1.JobStatus_JOB_STATUS_PENDING_APPROVAL, TotalTasks: 1,
		Approval: &v1.JobApprovalSummary{
			ApprovalId: "apr-20261124-0001", Status: v1.ApprovalStatus_APPROVAL_STATUS_PENDING,
			ExpiresAt: a.ExpiresAt, MinApprovals: 2, ApprovedCount: 1, ConsoleUrl: a.ConsoleUrl,
		},
	}
	trimmedPending, err := pendingApprovalResult(preTrimmed, true)
	trimmedData := assertApprovalBudget(t, trimmedPending, err)
	if _, hasRoles := trimmedData["approval"].(map[string]any)["required_approver_role_sets"]; hasRoles {
		t.Fatalf("pre-trimmed pending receipt should omit required_approver_role_sets: %v", trimmedData)
	}
	metadata, err := jobMetadataResult(job)
	assertApprovalBudget(t, metadata, err)

	job.Status = v1.JobStatus_JOB_STATUS_DENIED
	a.Status = v1.ApprovalStatus_APPROVAL_STATUS_EXECUTION_DENIED
	a.DecidedAt = timestamppb.New(a.ExpiresAt.AsTime().Add(-time.Minute))
	a.DecisionReason = "Policy changed while waiting"
	a.RecheckError = "RECHECK_POLICY_TIGHTENED"
	final, err := nativeSummaryResult("actor", job, &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED}, "concise", "")
	finalApproval := assertApprovalBudget(t, final, err)["approval"].(map[string]any)
	if finalApproval["status"] != "execution_denied" || finalApproval["decision_reason"] != a.DecisionReason ||
		finalApproval["recheck_error"] != a.RecheckError || finalApproval["decided_at"] != "2026-11-24T05:59:00Z" {
		t.Fatalf("final approval=%v", finalApproval)
	}
}

func assertApprovalBudget(t *testing.T, result *ToolResult, err error) map[string]any {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > resultByteLimit || result.IsError {
		t.Fatalf("approval result bytes=%d error=%v IsError=%t", len(raw), err, result.IsError)
	}
	data := result.StructuredContent.(map[string]any)
	approval := data["approval"].(map[string]any)
	if data["details_truncated"] != true || data["output_trust"] != "untrusted" || data["job_id"] != "job-20261124-0001" ||
		approval["approval_id"] != "apr-20261124-0001" || approval["expires_at"] != "2026-11-24T06:00:00Z" ||
		approval["console_url"] != "https://console.test/approvals/apr-20261124-0001" || approval["status"] == "" {
		t.Fatalf("receipt lost core fields: %v", data)
	}
	return data
}

// The enclosing test uses the real MCP transport, database, job service and host agents.
func testMCPApprovalLifecycle(t *testing.T, f *transportFixture, flat *sdk.ClientSession, transport http.RoundTripper, gateway, evidenceID string) {
	t.Helper()
	ctx := t.Context()
	requester := f.mint(t, "approval-requester", "requester")
	exec := func(sql string, values ...any) {
		t.Helper()
		if _, err := f.db.Pool.Exec(ctx, sql, values...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username,email,manual_roles)
		VALUES ('approver','test','approver','ldap','approver','approver@example.test',ARRAY['admin'])`)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	approverToken := "aops_cli_" + base64.RawURLEncoding.EncodeToString(secret)
	hash := sha256.Sum256([]byte(approverToken))
	exec(`INSERT INTO identity_sessions(session_id,user_id,token_hash,client,expires_at)
		VALUES ('approver','approver',$1,'cli',clock_timestamp()+interval '1 hour')`, hash[:])

	policy, err := f.identity.GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	rules := policy.Msg.Policy.Rules
	rules.Rules = append(rules.Rules,
		&v1.PolicyRule{Name: "gated-view", Roles: []string{"requester"}, Operations: []string{"view_hosts", "view_jobs", "view_output"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW},
		&v1.PolicyRule{Name: "gated-actions", Roles: []string{"admin", "requester"}, Operations: []string{"execute_action"},
			Actions: []string{"gated_write", "gated_dangerous"}, HostLabels: map[string]string{"env": "test"},
			Effect: v1.PolicyEffect_POLICY_EFFECT_REQUIRE_APPROVAL, Approval: &v1.PolicyApprovalConfig{MinApprovals: 1, ApproverRoles: []string{"admin"}}},
	)
	ruleJSON, err := protojson.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO policy_versions(version,rules,created_by) VALUES (2,$1,'fixture')`, ruleJSON)

	progressiveClient := sdk.NewClient(&sdk.Implementation{Name: "approval-mcp-fixture"}, nil)
	progressive, err := progressiveClient.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint: gateway + "/mcp", DisableStandaloneSSE: true,
		HTTPClient: &http.Client{Transport: headerTransport{
			base:    &bearerTransport{base: transport, token: requester},
			headers: map[string]string{"X-Allowops-MCP-Mode": "progressive"},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer progressive.Close()
	found := call(t, progressive, "actions_search", map[string]any{"hostname": "web-01"})
	discovery := content(t, found)
	if found.IsError || discovery["total"] != float64(2) {
		t.Fatalf("require_approval-only discovery=%v", discovery)
	}
	for _, item := range discovery["actions"].([]any) {
		if a := item.(map[string]any); a["requires_approval"] != true {
			t.Fatalf("missing host-specific approval requirement: %v", a)
		}
	}
	if names := toolNames(t, flat); !slices.Contains(names, "gated_write") {
		t.Fatalf("flat action missing: %v", names)
	}

	submission := func(key string) map[string]any {
		return map[string]any{"targets": map[string]any{"hosts": []string{"web-01"}}, "reason": "Review gated execution", "client_request_id": key}
	}
	args := submission("flat.1")
	args["evidence"] = map[string]any{"job_ids": []string{evidenceID}, "summary": "Checked the previous run"}
	pending := assertMCPApproval(t, call(t, flat, "gated_write", args), "pending_approval", "pending")
	jobID, approvalID := pending["job_id"].(string), pending["approval"].(map[string]any)["approval_id"].(string)
	receipt := pending["approval"].(map[string]any)
	if receipt["console_url"] != "https://console.test/approvals/"+approvalID || receipt["expires_at"] == "" ||
		receipt["min_approvals"] != float64(1) || receipt["approved_count"] != float64(0) ||
		receipt["required_approver_role_sets"].([]any)[0].([]any)[0] != "admin" ||
		!strings.Contains(pending["hint"].(string), "jobs_get(job_id, wait_seconds=30)") ||
		!strings.Contains(pending["hint"].(string), "jobs_cancel(job_id)") {
		t.Fatalf("pending approval receipt=%v", pending)
	}
	duplicate := assertMCPApproval(t, call(t, flat, "gated_write", args), "pending_approval", "pending")
	if duplicate["job_id"] != jobID || duplicate["approval"].(map[string]any)["approval_id"] != approvalID {
		t.Fatalf("idempotency created another receipt: %v", duplicate)
	}
	conflicting := submission("flat.1")
	conflicting["targets"] = map[string]any{"hosts": []string{"web-02"}}
	conflict := call(t, flat, "gated_write", conflicting)
	if !conflict.IsError || content(t, conflict)["reason"] != "CLIENT_REQUEST_ID_CONFLICT" {
		t.Fatalf("changed plan reused client_request_id: %v", content(t, conflict))
	}
	badEvidence := submission("foreign-evidence")
	badEvidence["action"] = "gated_write"
	badEvidence["evidence"] = map[string]any{"job_ids": []string{evidenceID}}
	denied := call(t, progressive, "actions_invoke_write", badEvidence)
	if !denied.IsError || content(t, denied)["reason"] != "INVALID_EVIDENCE_JOB" || content(t, denied)["job_id"] != nil {
		t.Fatalf("foreign evidence accepted or disclosed: %v", content(t, denied))
	}
	jobArgs := map[string]any{"job_id": jobID}
	assertMCPApproval(t, call(t, flat, "jobs_get", jobArgs), "pending_approval", "pending")
	current := call(t, flat, "jobs_list", nil)
	listed := content(t, current)
	if current.IsError || len(listed["jobs"].([]any)) != 1 {
		t.Fatalf("jobs_list=%v", listed)
	}
	entry := listed["jobs"].([]any)[0].(map[string]any)
	if entry["job_id"] != jobID || entry["status"] != "pending_approval" || entry["approval"].(map[string]any)["approval_id"] != approvalID {
		t.Fatalf("pending jobs_list entry=%v", entry)
	}
	diff := call(t, flat, "jobs_diff", map[string]any{"base_job_id": jobID, "target_job_id": jobID})
	if !diff.IsError || content(t, diff)["reason"] != "DIFF_JOB_NOT_FINISHED" {
		t.Fatalf("pending jobs_diff=%v", content(t, diff))
	}
	host := call(t, flat, "jobs_get", map[string]any{"job_id": jobID, "host": "web-01", "wait_seconds": 0})
	if !host.IsError || content(t, host)["reason"] != "JOB_PENDING_APPROVAL" {
		t.Fatalf("pending host output=%v", content(t, host))
	}
	var pendingAudits int
	if err := f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events
		WHERE operation IN ('mcp/gated_write','mcp/jobs_get') AND job_id=$1 AND decision='require_approval'`, jobID).Scan(&pendingAudits); err != nil || pendingAudits != 3 {
		t.Fatalf("pending result audit count=%d error=%v", pendingAudits, err)
	}

	approvals := rpc.NewApprovalServiceClient(&http.Client{
		Transport: &bearerTransport{base: transport, token: approverToken},
	}, gateway)
	detail, err := approvals.GetApproval(ctx, connect.NewRequest(&v1.GetApprovalRequest{ApprovalId: approvalID}))
	if err != nil {
		t.Fatal(err)
	}
	if evidence := detail.Msg.Approval.Evidence; !slices.Equal(evidence.GetJobIds(), []string{evidenceID}) ||
		evidence.GetSummary() != "Checked the previous run" {
		t.Fatalf("approval evidence=%v", evidence)
	}
	if _, err := approvals.ApproveRequest(ctx, connect.NewRequest(&v1.ApproveRequestRequest{
		ApprovalId: approvalID, ExpectedRequestDigest: detail.Msg.Approval.RequestDigest, Reason: "Reviewed the plan",
	})); err != nil {
		t.Fatal(err)
	}
	executed := assertMCPApproval(t, call(t, flat, "jobs_get", map[string]any{"job_id": jobID, "wait_seconds": 30}), "succeeded", "approved")
	groups := executed["groups"].([]any)
	if len(groups) != 1 || groups[0].(map[string]any)["stdout"] != "approval execution verified" ||
		executed["approval"].(map[string]any)["decision_reason"] != "Reviewed the plan" {
		t.Fatalf("approved execution=%v", executed)
	}

	for _, outcome := range []string{"rejected", "expired", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			risk := "dangerous"
			if outcome == "rejected" {
				risk = "write"
			}
			args := submission(outcome)
			args["action"] = "gated_" + risk
			data := assertMCPApproval(t, call(t, progressive, "actions_invoke_"+risk, args), "pending_approval", "pending")
			id := data["job_id"].(string)
			apr := data["approval"].(map[string]any)["approval_id"].(string)
			switch outcome {
			case "rejected":
				if _, err := approvals.RejectRequest(ctx, connect.NewRequest(&v1.RejectRequestRequest{
					ApprovalId: apr, Reason: "Declined the plan",
				})); err != nil {
					t.Fatal(err)
				}
			case "expired":
				exec(`UPDATE approval_requests SET created_at=clock_timestamp()-interval '1 minute',
					expires_at=clock_timestamp()-interval '1 second' WHERE approval_id=$1`, apr)
			case "cancelled":
				assertMCPApproval(t, call(t, progressive, "jobs_cancel", map[string]any{"job_id": id}), "cancelled", "cancelled")
			}
			status := "cancelled"
			if outcome == "rejected" || outcome == "expired" {
				status = "denied"
			}
			final := assertMCPApproval(t, call(t, progressive, "jobs_get", map[string]any{"job_id": id, "wait_seconds": 30}), status, outcome)
			if approval := final["approval"].(map[string]any); approval["decided_at"] == nil || outcome == "rejected" && approval["decision_reason"] != "Declined the plan" {
				t.Fatalf("terminal metadata=%v", final)
			}
		})
	}
}

func assertMCPApproval(t *testing.T, result *sdk.CallToolResult, jobStatus, approvalStatus string) map[string]any {
	t.Helper()
	data := content(t, result)
	approval, _ := data["approval"].(map[string]any)
	if result.IsError || data["status"] != jobStatus || approval["status"] != approvalStatus ||
		data["output_trust"] != "untrusted" || data["job_id"] == nil || approval["approval_id"] == nil {
		t.Fatalf("job/approval=%v, want statuses %s/%s", data, jobStatus, approvalStatus)
	}
	return data
}
