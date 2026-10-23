package job

import (
	"context"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

// Client is the in-process P6M boundary. The context must come from the shared
// Access.Middleware authentication. Each operation performs authorization
// and audit itself, including when called without a Connect transport.
// Callers must not retry RunJob automatically after an indeterminate result.
type Client interface {
	RunJob(context.Context, *v1.RunJobRequest) (*v1.RunJobResponse, error)
	GetJob(context.Context, *v1.GetJobRequest) (*v1.GetJobResponse, error)
	ListJobs(context.Context, *v1.ListJobsRequest) (*v1.ListJobsResponse, error)
	ListTasks(context.Context, *v1.ListTasksRequest) (*v1.ListTasksResponse, error)
	ListTaskSteps(context.Context, *v1.ListTaskStepsRequest) (*v1.ListTaskStepsResponse, error)
	CancelJob(context.Context, *v1.CancelJobRequest) (*v1.CancelJobResponse, error)
	GetJobOutput(context.Context, *v1.GetJobOutputRequest) (*v1.GetJobOutputResponse, error)
}
