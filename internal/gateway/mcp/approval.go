package mcp

import (
	"strings"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func pendingApprovalResult(job *v1.Job) (*ToolResult, error) {
	if job.Approval == nil {
		return nil, accessError(connect.CodeUnavailable, "job approval receipt unavailable")
	}
	data := jobMetadata(job)
	data["hint"] = "Do not retry submitting this action. Share the approval_id and console_url with the user. Poll with jobs_get(job_id, wait_seconds=30), or withdraw with jobs_cancel(job_id)."
	return boundedJobResult(data, data)
}

func approvalMetadata(approval *v1.JobApprovalSummary) map[string]any {
	roleSets := make([][]string, 0, len(approval.RequiredApproverRoleSets))
	for _, set := range approval.RequiredApproverRoleSets {
		roleSets = append(roleSets, set.GetRoles())
	}
	data := map[string]any{
		"approval_id":                 approval.ApprovalId,
		"status":                      strings.ToLower(strings.TrimPrefix(approval.Status.String(), "APPROVAL_STATUS_")),
		"expires_at":                  approvalTimestamp(approval.ExpiresAt),
		"min_approvals":               approval.MinApprovals,
		"approved_count":              approval.ApprovedCount,
		"required_approver_role_sets": roleSets,
		"console_url":                 approval.ConsoleUrl,
	}
	if approval.DecidedAt != nil {
		data["decided_at"] = approvalTimestamp(approval.DecidedAt)
	}
	if approval.DecisionReason != "" {
		data["decision_reason"] = approval.DecisionReason
	}
	if approval.RecheckError != "" {
		data["recheck_error"] = approval.RecheckError
	}
	return data
}

func approvalTimestamp(t *timestamppb.Timestamp) string {
	if t == nil {
		return ""
	}
	return t.AsTime().Format(time.RFC3339Nano)
}

// Role requirements can be arbitrarily larger than an MCP result. Measure the
// entire envelope, then omit those details if the receipt or page exceeds it.
func toolResultWithApprovals(value any, jobs ...map[string]any) (*ToolResult, int, error) {
	result, size, err := toolResult(value)
	if err != nil || size <= resultByteLimit {
		return result, size, err
	}
	trimmed := false
	for _, job := range jobs {
		approval, _ := job["approval"].(map[string]any)
		if roles, _ := approval["required_approver_role_sets"].([][]string); len(roles) > 0 {
			delete(approval, "required_approver_role_sets")
			job["details_truncated"] = true
			trimmed = true
		}
	}
	if !trimmed {
		return result, size, nil
	}
	return toolResult(value)
}

func boundedJobResult(value any, jobs ...map[string]any) (*ToolResult, error) {
	result, size, err := toolResultWithApprovals(value, jobs...)
	if err != nil {
		return nil, err
	}
	if size > resultByteLimit {
		return nil, accessError(connect.CodeResourceExhausted, "job metadata exceeds 32KB")
	}
	return result, nil
}
