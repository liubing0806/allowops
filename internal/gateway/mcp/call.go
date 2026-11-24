package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

var shortJobID = regexp.MustCompile(`^job-[0-9]{8}-[0-9]{1,20}$`)

// callState collects what the result audit needs. operation, when set,
// replaces the audited tool name with the validated action name; mutating
// marks calls that may have changed hosts once a job ID is known.
type callState struct {
	jobID     string
	operation string
	mutating  bool
}

func (s *Service) call(ctx context.Context, r *sdk.CallToolRequest, scope *serverScope) (*sdk.CallToolResult, error) {
	state := &callState{}
	result, err := s.execute(ctx, r, scope, state)
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
	// Only registered tools and visible actions are audited by name (design G49).
	event.Operation = "mcp/unknown_tool"
	if state.operation != "" {
		event.Operation = state.operation
	} else if scope.known(r.Params.Name) {
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
		if state.jobID != "" && state.mutating {
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
		if errors.Is(err, errActionEntryTooLarge) {
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

func (s *Service) execute(ctx context.Context, r *sdk.CallToolRequest, scope *serverScope, state *callState) (*ToolResult, error) {
	name := r.Params.Name
	if !scope.tools[name] {
		if _, visible := scope.allAvailable[name]; !visible {
			return nil, accessError(connect.CodeNotFound, "tool removed or unavailable for this identity; call tools/list to refresh")
		}
		if scope.unsupported[name] {
			return nil, accessError(connect.CodeFailedPrecondition, errUnsupportedActionSchema.Error())
		}
		// A visible action that is not registered: progressive mode (design 6.3).
		return nil, accessError(connect.CodeFailedPrecondition, "action is not directly exposed in progressive mode; call the matching "+invokeToolName(scope.allAvailable[name].Risk)+" tool")
	}
	switch name {
	case "hosts_search":
		return s.searchHosts(ctx, r.Params.Arguments)
	case "entities_search":
		return s.searchEntities(ctx, r.Params.Arguments, scope.visible)
	case "changes_list":
		return s.listChanges(ctx, r.Params.Arguments)
	case "runbooks_search":
		return s.searchRunbooks(ctx, r.Params.Arguments)
	case "runbooks_read":
		return s.readRunbook(ctx, r.Params.Arguments)
	case "actions_search":
		if scope.metaTools[name] {
			return s.searchActions(ctx, r.Params.Arguments, scope)
		}
	}
	if s.jobs == nil {
		return nil, accessError(connect.CodeUnavailable, "job service unavailable")
	}
	switch name {
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
		state.mutating = true
		response, err := s.jobs.CancelJob(ctx, &v1.CancelJobRequest{JobId: id})
		if err != nil {
			return nil, err
		}
		if response == nil || response.Job == nil {
			return nil, accessError(connect.CodeUnavailable, "job response unavailable")
		}
		return jobMetadataResult(response.Job)
	case "actions_invoke_read":
		if scope.metaTools[name] {
			return s.invokeAction(ctx, r, scope, "read", state)
		}
	case "actions_invoke_write":
		if scope.metaTools[name] {
			return s.invokeAction(ctx, r, scope, "write", state)
		}
	case "actions_invoke_dangerous":
		if scope.metaTools[name] {
			return s.invokeAction(ctx, r, scope, "dangerous", state)
		}
	}
	state.mutating = true
	action, err := s.currentAction(ctx, name)
	if err != nil {
		return nil, err
	}
	return s.runAction(ctx, r, action, r.Params.Arguments, nil, state)
}

// runAction validates the arguments against the verified action and runs the
// job. extraAllowed names arguments the calling tool already consumed, so
// that unknown argument errors list them too.
func (s *Service) runAction(ctx context.Context, r *sdk.CallToolRequest, action catalog.Action, raw json.RawMessage, extraAllowed []string, state *callState) (*ToolResult, error) {
	if unsupportedActionSchema(action) {
		return nil, accessError(connect.CodeFailedPrecondition, errUnsupportedActionSchema.Error())
	}
	request, format, err := actionRequest(action, raw, s.config.Jobs, extraAllowed...)
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

// invokeAction runs one visible action through actions_invoke_<risk>. The
// action's current signed risk must equal the tool's risk, so a client that
// approves one risk level never runs another (design 6.2).
func (s *Service) invokeAction(ctx context.Context, r *sdk.CallToolRequest, scope *serverScope, risk string, state *callState) (*ToolResult, error) {
	raw := r.Params.Arguments
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	args, err := argumentObject(raw)
	if err != nil {
		return nil, invalidArguments(err)
	}
	var name string
	if decodeField(args, "action", &name, true) != nil || !actionName.MatchString(name) || slices.Contains(fixedReservedToolNames, name) {
		return nil, accessError(connect.CodeInvalidArgument, "action required; allowed: action name returned by actions_search")
	}
	if _, visible := scope.allAvailable[name]; !visible {
		if slices.Contains(progressiveMetaToolNames, name) {
			return nil, accessError(connect.CodeInvalidArgument, "action required; allowed: action name returned by actions_search")
		}
		return nil, accessError(connect.CodeNotFound, "tool removed or unavailable for this identity; call actions_search to refresh")
	}
	state.operation = "mcp/" + name
	if scope.unsupported[name] {
		return nil, accessError(connect.CodeFailedPrecondition, errUnsupportedActionSchema.Error())
	}
	state.mutating = true
	action, err := s.currentAction(ctx, name)
	if err != nil {
		return nil, err
	}
	if action.Risk != risk {
		return nil, accessError(connect.CodeFailedPrecondition, "action risk does not match invocation tool; call the matching "+invokeToolName(action.Risk)+" tool")
	}
	delete(args, "action")
	rest, err := json.Marshal(args)
	if err != nil {
		return nil, invalidArguments(err)
	}
	return s.runAction(job.WithExpectedRisk(ctx, risk), r, action, rest, []string{"action"}, state)
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
	args, err := fixedArguments(r.Params.Arguments, "job_id", "host", "wait_seconds", "response_format", "next_cursor", "stream", "offset", "step_index", "encoding")
	if err != nil {
		return nil, err
	}
	id, err := jobArgument(args)
	if err != nil {
		return nil, err
	}
	state.jobID = id
	// An omitted wait_seconds stays nil so the job layer applies the gateway default.
	var wait uint32
	if decodeField(args, "wait_seconds", &wait, false) != nil || wait > s.config.Jobs.MaxWaitSeconds {
		return nil, accessError(connect.CodeInvalidArgument, fmt.Sprintf("wait_seconds allowed: integer in [0,%d]", s.config.Jobs.MaxWaitSeconds))
	}
	var waitSeconds *uint32
	if _, present := args["wait_seconds"]; present {
		waitSeconds = &wait
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
	if host == "" && (args["offset"] != nil || args["stream"] != nil || args["encoding"] != nil) {
		return nil, accessError(connect.CodeInvalidArgument, "offset, stream and encoding require host")
	}
	if host != "" && cursor != "" {
		return nil, accessError(connect.CodeInvalidArgument, "host output uses offset; next_cursor is for summary pages")
	}
	stream := "stdout"
	if decodeField(args, "stream", &stream, false) != nil || !slices.Contains([]string{"stdout", "stderr"}, stream) {
		return nil, accessError(connect.CodeInvalidArgument, "stream allowed: stdout, stderr")
	}
	encoding := "base64"
	if decodeField(args, "encoding", &encoding, false) != nil || !slices.Contains([]string{"base64", "text"}, encoding) {
		return nil, accessError(connect.CodeInvalidArgument, "encoding allowed: base64, text")
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
		response, e = s.jobs.GetJob(ctx, &v1.GetJobRequest{JobId: id, WaitSeconds: waitSeconds, ResponseFormat: format})
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
	return outputPageResult(id, host, outputStream, offset, output, step, encoding == "text")
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
