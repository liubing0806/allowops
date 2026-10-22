package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type stepErrorJobs struct {
	JobService
	err  error
	step *uint32
}

func (j *stepErrorJobs) GetJob(_ context.Context, r *v1.GetJobRequest) (*v1.GetJobResponse, error) {
	return &v1.GetJobResponse{Job: &v1.Job{JobId: r.JobId}}, nil
}
func (j *stepErrorJobs) GetJobOutput(_ context.Context, r *v1.GetJobOutputRequest) (*v1.GetJobOutputResponse, error) {
	j.step = r.StepIndex
	return &v1.GetJobOutputResponse{Data: []byte("single"), NextOffset: 6, Eof: true, OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED}, j.err
}

func TestA33OmittedCompositeStepIsParameterErrorWithReadingHint(t *testing.T) {
	for _, test := range []struct {
		name, reason string
		code         connect.Code
		step         *uint32
		hint         bool
	}{
		{name: "composite step omitted", reason: "INVALID_OUTPUT_STEP", code: connect.CodeInvalidArgument, hint: true},
		{name: "explicit invalid step", reason: "INVALID_OUTPUT_STEP", code: connect.CodeInvalidArgument, step: new(uint32)},
		{name: "permission denied", reason: "OUTPUT_DENIED", code: connect.CodePermissionDenied},
		{name: "other parameter error", reason: "OUTPUT_PAGE_LIMIT", code: connect.CodeInvalidArgument},
		{name: "single action without step"},
	} {
		t.Run(test.name, func(t *testing.T) {
			jobs := &stepErrorJobs{}
			if test.reason != "" {
				backend := connect.NewError(test.code, errors.New(test.reason))
				detail, err := connect.NewErrorDetail(&v1.ErrorDetail{Reason: test.reason})
				if err != nil {
					t.Fatal(err)
				}
				backend.AddDetail(detail)
				jobs.err = backend
			}
			args := map[string]any{"job_id": "job-20261014-0001", "host": "web-01", "wait_seconds": 0}
			if test.step != nil {
				args["step_index"] = *test.step
			}
			raw, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			state := &callState{}
			service := &Service{jobs: jobs}
			result, err := service.getJob(context.Background(), &sdk.CallToolRequest{Params: &sdk.CallToolParamsRaw{Name: "jobs_get", Arguments: raw}}, state)
			if (jobs.step == nil) != (test.step == nil) || jobs.step != nil && *jobs.step != *test.step {
				t.Fatalf("step forwarded=%v want=%v", jobs.step, test.step)
			}
			if test.reason == "" {
				if err != nil || result == nil {
					t.Fatalf("single-action output=%v error=%v", result, err)
				}
				return
			}
			if connect.CodeOf(err) != test.code {
				t.Fatalf("code=%v want=%v error=%v", connect.CodeOf(err), test.code, err)
			}
			tool := toolError(err, state)
			data := tool.StructuredContent.(map[string]any)
			if !tool.IsError || data["reason"] != test.reason || data["job_id"] != args["job_id"] {
				t.Fatalf("parameter error details=%v", data)
			}
			message, _ := data["error"].(string)
			if test.hint {
				if !strings.Contains(message, "step_index") || !strings.Contains(message, "one step at a time") {
					t.Fatalf("missing step parameter and reading hint: %v", data)
				}
			} else if err != jobs.err {
				t.Fatalf("unrelated backend error changed: %v", err)
			}
		})
	}
}
