package mcp

import (
	"context"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

// JobService is the job module's boundary (design P6). Messages retain protobuf presence and types.
// Each method derives identity from the request context set by the identity middleware and owns authorization and audit,
// including direct in-process calls. RunJob/CancelJob write the authorized audit event
// before any write (design G28); MCP records only its tool-level result (design G49). Do not retry RunJob after
// an indeterminate response. Output must already be redacted and authorized.
type JobService interface {
	RunJob(context.Context, *v1.RunJobRequest) (*v1.RunJobResponse, error)
	GetJob(context.Context, *v1.GetJobRequest) (*v1.GetJobResponse, error)
	ListJobs(context.Context, *v1.ListJobsRequest) (*v1.ListJobsResponse, error)
	ListTasks(context.Context, *v1.ListTasksRequest) (*v1.ListTasksResponse, error)
	CancelJob(context.Context, *v1.CancelJobRequest) (*v1.CancelJobResponse, error)
	GetJobOutput(context.Context, *v1.GetJobOutputRequest) (*v1.GetJobOutputResponse, error)
}
