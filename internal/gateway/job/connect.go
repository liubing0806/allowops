package job

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
)

type ConnectService struct{ Client Client }

func (s *Service) Handler() http.Handler {
	_, handler := rpc.NewJobServiceHandler(&ConnectService{Client: s}, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(ResponseBytes))
	return s.Access.Middleware(handler)
}

func (c *ConnectService) RunJob(ctx context.Context, r *connect.Request[v1.RunJobRequest]) (*connect.Response[v1.RunJobResponse], error) {
	v, e := c.Client.RunJob(ctx, r.Msg)
	if e != nil {
		return nil, e
	}
	return connect.NewResponse(v), nil
}
func (c *ConnectService) GetJob(ctx context.Context, r *connect.Request[v1.GetJobRequest]) (*connect.Response[v1.GetJobResponse], error) {
	v, e := c.Client.GetJob(ctx, r.Msg)
	if e != nil {
		return nil, e
	}
	return connect.NewResponse(v), nil
}
func (c *ConnectService) ListJobs(ctx context.Context, r *connect.Request[v1.ListJobsRequest]) (*connect.Response[v1.ListJobsResponse], error) {
	v, e := c.Client.ListJobs(ctx, r.Msg)
	if e != nil {
		return nil, e
	}
	return connect.NewResponse(v), nil
}
func (c *ConnectService) ListTasks(ctx context.Context, r *connect.Request[v1.ListTasksRequest]) (*connect.Response[v1.ListTasksResponse], error) {
	v, e := c.Client.ListTasks(ctx, r.Msg)
	if e != nil {
		return nil, e
	}
	return connect.NewResponse(v), nil
}
func (c *ConnectService) ListTaskSteps(ctx context.Context, r *connect.Request[v1.ListTaskStepsRequest]) (*connect.Response[v1.ListTaskStepsResponse], error) {
	v, e := c.Client.ListTaskSteps(ctx, r.Msg)
	if e != nil {
		return nil, e
	}
	return connect.NewResponse(v), nil
}
func (c *ConnectService) CancelJob(ctx context.Context, r *connect.Request[v1.CancelJobRequest]) (*connect.Response[v1.CancelJobResponse], error) {
	v, e := c.Client.CancelJob(ctx, r.Msg)
	if e != nil {
		return nil, e
	}
	return connect.NewResponse(v), nil
}
func (c *ConnectService) GetJobOutput(ctx context.Context, r *connect.Request[v1.GetJobOutputRequest]) (*connect.Response[v1.GetJobOutputResponse], error) {
	v, e := c.Client.GetJobOutput(ctx, r.Msg)
	if e != nil {
		return nil, e
	}
	return connect.NewResponse(v), nil
}
