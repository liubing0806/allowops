package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

var shortJobID = regexp.MustCompile(`^job-[0-9]{8}-[0-9]{1,20}$`)

type callState struct{ jobID string }

func (s *Service) call(ctx context.Context, r *sdk.CallToolRequest, available map[string]bool) (*sdk.CallToolResult, error) {
	state := &callState{}
	result, err := s.execute(ctx, r, available, state)
	var ce *connect.Error
	if errors.As(err, &ce) {
		for _, detail := range ce.Details() {
			value, e := detail.Value()
			if e == nil {
				if d, ok := value.(*v1.ErrorDetail); ok && shortJobID.MatchString(d.RequestId) {
					state.jobID = d.RequestId
				}
			}
		}
	}
	event := reqctx.RequestAuditInfo(ctx)
	event.Operation = "mcp/unknown_tool"
	if available[r.Params.Name] {
		event.Operation = "mcp/" + r.Params.Name
	}
	event.Phase = "result"
	event.Outcome = "allow"
	event.JobID = state.jobID
	if err != nil {
		event.Outcome = "deny"
	}
	// The job module owns the audit written before a write (design P6, G28). This result covers early parameter
	// failures and unknown/denied tools without duplicating the authorized event (design G49).
	if auditErr := s.identity.AppendResultAudit(ctx, event); auditErr != nil {
		message := "result audit unavailable"
		if state.jobID != "" && (r.Params.Name == "jobs_cancel" || !strings.HasPrefix(r.Params.Name, "jobs_") && r.Params.Name != "hosts_search") {
			message += "; operation may have committed"
		}
		err = accessError(connect.CodeUnavailable, message)
		result = nil
	}
	if err != nil {
		return toolError(err, state), nil
	}
	return sdkResult(result), nil
}

func sdkResult(result *ToolResult) *sdk.CallToolResult {
	content := make([]sdk.Content, len(result.Content))
	for i, c := range result.Content {
		content[i] = &sdk.TextContent{Text: c.Text}
	}
	return &sdk.CallToolResult{Meta: sdk.Meta(result.Meta), Content: content, StructuredContent: result.StructuredContent, IsError: result.IsError}
}

func toolError(err error, state *callState) *sdk.CallToolResult {
	data := map[string]any{"error": "tool unavailable", "output_trust": "untrusted"}
	var ce *connect.Error
	if errors.As(err, &ce) {
		// Connect messages from the trusted local service boundary contain stable
		// reasons only. No request values, output or provider errors are copied.
		switch ce.Code() {
		case connect.CodeInvalidArgument, connect.CodeFailedPrecondition, connect.CodePermissionDenied, connect.CodeNotFound, connect.CodeUnavailable:
			data["error"] = ce.Message()
		}
		for _, detail := range ce.Details() {
			value, e := detail.Value()
			if e != nil {
				continue
			}
			if d, ok := value.(*v1.ErrorDetail); ok {
				data["reason"] = d.Reason
				if d.ActualCount != nil {
					data["actual_count"] = *d.ActualCount
				}
				if len(d.DeniedHosts) > 0 {
					data["denied_hosts"] = d.DeniedHosts
					data["denied_count"] = len(d.DeniedHosts)
				}
				if len(d.Violations) > 0 {
					data["violations"] = d.Violations
				}
				if shortJobID.MatchString(d.RequestId) {
					state.jobID = d.RequestId
				}
			}
		}
	}
	if state.jobID != "" {
		data["job_id"] = state.jobID
	}
	encode := func() (*ToolResult, int) {
		result, _, _ := toolResult(data)
		result.IsError = true
		encoded, _ := json.Marshal(result)
		return result, len(encoded)
	}
	result, size := encode()
	if size > resultByteLimit {
		data["details_truncated"] = true
		delete(data, "violations")
		if denied, ok := data["denied_hosts"].([]*v1.HostDenial); ok {
			// Retain the largest complete prefix that fits, including rules (design G54).
			low, high := 0, len(denied)
			for low < high {
				mid := low + (high-low+1)/2
				data["denied_hosts"] = denied[:mid]
				_, candidateSize := encode()
				if candidateSize <= resultByteLimit {
					low = mid
				} else {
					high = mid - 1
				}
			}
			data["denied_hosts"] = denied[:low]
		}
		result, size = encode()
		if size > resultByteLimit {
			count, hasDenials := data["denied_count"]
			data = map[string]any{"error": "tool error details exceed 32KB", "output_trust": "untrusted", "details_truncated": true}
			if hasDenials {
				data["denied_count"] = count
				data["denied_hosts"] = []*v1.HostDenial{}
			}
			if state.jobID != "" {
				data["job_id"] = state.jobID
			}
			result, _ = encode()
		}
	}
	return sdkResult(result)
}

func (s *Service) execute(ctx context.Context, r *sdk.CallToolRequest, available map[string]bool, state *callState) (*ToolResult, error) {
	if !available[r.Params.Name] {
		return nil, accessError(connect.CodeNotFound, "tool removed or unavailable for this identity; call tools/list to refresh")
	}
	if r.Params.Name == "hosts_search" {
		return s.searchHosts(ctx, r.Params.Arguments)
	}
	if s.jobs == nil {
		return nil, accessError(connect.CodeUnavailable, "job service unavailable")
	}
	switch r.Params.Name {
	case "jobs_get":
		return s.getJob(ctx, r, state)
	case "jobs_list":
		return s.listJobs(ctx, r.Params.Arguments)
	case "jobs_cancel":
		args, err := fixedArguments(r.Params.Arguments, "job_id")
		if err != nil {
			return nil, err
		}
		id, err := jobArgument(args)
		if err != nil {
			return nil, err
		}
		state.jobID = id
		response, err := s.jobs.CancelJob(ctx, &v1.CancelJobRequest{JobId: id})
		if err != nil {
			return nil, err
		}
		if response == nil || response.Job == nil {
			return nil, accessError(connect.CodeUnavailable, "job response unavailable")
		}
		return jobMetadataResult(response.Job)
	default:
		action, err := s.currentAction(ctx, r.Params.Name)
		if err != nil {
			return nil, err
		}
		if unsupportedActionSchema(action) {
			return nil, accessError(connect.CodeFailedPrecondition, errUnsupportedActionSchema.Error())
		}
		request, format, err := actionRequest(action, r.Params.Arguments)
		if err != nil {
			return nil, invalidArguments(err)
		}
		request.ResponseFormat = format
		var response *v1.RunJobResponse
		err = s.withProgress(ctx, r, func() error { var e error; response, e = s.jobs.RunJob(ctx, request); return e })
		if response != nil && response.Job != nil && shortJobID.MatchString(response.Job.JobId) {
			state.jobID = response.Job.JobId
		}
		if err != nil {
			return nil, err
		}
		if state.jobID == "" {
			return nil, accessError(connect.CodeUnavailable, "invalid job response")
		}
		return nativeSummaryResult(reqctx.RequestAuditInfo(ctx).ActorID, response.Job, response.Summary, format, "")
	}
}

func fixedArguments(raw json.RawMessage, allowed ...string) (map[string]json.RawMessage, error) {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	args, err := argumentObject(raw)
	if err != nil {
		return nil, invalidArguments(err)
	}
	for name := range args {
		if !slices.Contains(allowed, name) {
			return nil, accessError(connect.CodeInvalidArgument, "unknown argument; allowed: "+strings.Join(allowed, ", "))
		}
		if slices.Contains([]string{"hostname", "selector", "host", "next_cursor"}, name) {
			var value string
			if json.Unmarshal(args[name], &value) != nil || value == "" {
				return nil, accessError(connect.CodeInvalidArgument, name+" allowed: nonempty string; omit optional fields to use defaults")
			}
		}
	}
	return args, nil
}

func jobArgument(args map[string]json.RawMessage) (string, error) {
	var id string
	if decodeField(args, "job_id", &id, true) != nil || !shortJobID.MatchString(id) {
		return "", accessError(connect.CodeInvalidArgument, "job_id allowed: short ID returned by action tools, such as job-20261014-0001")
	}
	return id, nil
}

func (s *Service) getJob(ctx context.Context, r *sdk.CallToolRequest, state *callState) (*ToolResult, error) {
	args, err := fixedArguments(r.Params.Arguments, "job_id", "host", "wait_seconds", "response_format", "next_cursor", "stream", "offset", "step_index")
	if err != nil {
		return nil, err
	}
	id, err := jobArgument(args)
	if err != nil {
		return nil, err
	}
	state.jobID = id
	wait := uint32(defaultWaitSeconds)
	if decodeField(args, "wait_seconds", &wait, false) != nil || wait > maxWaitSeconds {
		return nil, accessError(connect.CodeInvalidArgument, "wait_seconds allowed: integer in [0,120]")
	}
	format := "concise"
	if decodeField(args, "response_format", &format, false) != nil || !slices.Contains([]string{"concise", "detailed"}, format) {
		return nil, accessError(connect.CodeInvalidArgument, "response_format allowed: concise, detailed")
	}
	var host, cursor string
	if err = decodeField(args, "host", &host, false); err != nil {
		return nil, invalidArguments(err)
	}
	if err = decodeField(args, "next_cursor", &cursor, false); err != nil {
		return nil, invalidArguments(err)
	}
	if host == "" && (args["offset"] != nil || args["stream"] != nil) {
		return nil, accessError(connect.CodeInvalidArgument, "offset and stream require host")
	}
	if host != "" && cursor != "" {
		return nil, accessError(connect.CodeInvalidArgument, "host output uses offset; next_cursor is for summary pages")
	}
	stream := "stdout"
	if decodeField(args, "stream", &stream, false) != nil || !slices.Contains([]string{"stdout", "stderr"}, stream) {
		return nil, accessError(connect.CodeInvalidArgument, "stream allowed: stdout, stderr")
	}
	offset := uint64(0)
	if err = decodeField(args, "offset", &offset, false); err != nil {
		return nil, invalidArguments(err)
	}
	step, err := outputStepArgument(args, host)
	if err != nil {
		return nil, err
	}
	var response *v1.GetJobResponse
	err = s.withProgress(ctx, r, func() error {
		var e error
		response, e = s.jobs.GetJob(ctx, &v1.GetJobRequest{JobId: id, WaitSeconds: &wait, ResponseFormat: format})
		return e
	})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Job == nil {
		return nil, accessError(connect.CodeUnavailable, "job response unavailable")
	}
	if host == "" {
		return nativeSummaryResult(reqctx.RequestAuditInfo(ctx).ActorID, response.Job, response.Summary, format, cursor)
	}
	outputStream := v1.OutputStream_OUTPUT_STREAM_STDOUT
	if stream == "stderr" {
		outputStream = v1.OutputStream_OUTPUT_STREAM_STDERR
	}
	output, err := s.jobs.GetJobOutput(ctx, &v1.GetJobOutputRequest{JobId: id, Hostname: host, Stream: outputStream, Offset: offset, LimitBytes: 16 << 10, StepIndex: step})
	if err != nil {
		return nil, outputStepError(step, err)
	}
	return outputPageResult(id, host, outputStream, offset, output, step)
}

func (s *Service) listJobs(ctx context.Context, raw json.RawMessage) (*ToolResult, error) {
	args, err := fixedArguments(raw, "next_cursor")
	if err != nil {
		return nil, err
	}
	var cursor string
	if err = decodeField(args, "next_cursor", &cursor, false); err != nil {
		return nil, invalidArguments(err)
	}
	actor := reqctx.RequestAuditInfo(ctx).ActorID
	// One backend item per page ensures metadata is measured before it reaches
	// MCP; the backend's opaque cursor retains its scope/snapshot binding.
	response, err := s.jobs.ListJobs(ctx, &v1.ListJobsRequest{SubjectId: actor, Page: &v1.PageRequest{PageSize: 1, PageToken: cursor}})
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, accessError(connect.CodeUnavailable, "job response unavailable")
	}
	jobs := []map[string]any{}
	for _, job := range response.Jobs {
		if job.SubjectId != actor {
			return nil, accessError(connect.CodePermissionDenied, "job list contains another identity")
		}
		jobs = append(jobs, jobMetadata(job))
	}
	result, size, err := toolResult(map[string]any{"jobs": jobs, "next_cursor": response.Page.GetNextPageToken(), "output_trust": "untrusted"})
	if size > resultByteLimit {
		return nil, errors.New("job metadata exceeds 32KB")
	}
	return result, err
}

func jobMetadata(job *v1.Job) map[string]any {
	counts := map[string]uint64{}
	for _, c := range job.Counts {
		counts[taskStatus(c.Status)] = c.Count
	}
	return map[string]any{"counts": counts, "job_id": job.JobId, "action": job.Action, "status": strings.ToLower(strings.TrimPrefix(job.Status.String(), "JOB_STATUS_")), "total": job.TotalTasks, "output_trust": "untrusted"}
}

func jobMetadataResult(job *v1.Job) (*ToolResult, error) {
	result, size, err := toolResult(jobMetadata(job))
	if size > resultByteLimit {
		return nil, errors.New("job metadata exceeds 32KB")
	}
	return result, err
}

func invalidArguments(err error) error {
	if err == nil {
		return nil
	}
	return accessError(connect.CodeInvalidArgument, err.Error())
}
