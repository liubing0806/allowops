package mcp

import (
	"context"
	"errors"
	"google.golang.org/protobuf/proto"
	"strings"
	"sync"
	"testing"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

type boundaryJobs struct {
	mu                           sync.Mutex
	summary                      *v1.JobSummary
	readJob                      *v1.Job
	lastRunFormat, lastGetFormat string
	taskCalls                    int
	JobService
	getCalls, cancelCalls int
	runErr, tasksErr      error
}

func (j *boundaryJobs) GetJob(_ context.Context, r *v1.GetJobRequest) (*v1.GetJobResponse, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.getCalls++
	j.lastGetFormat = r.ResponseFormat
	if j.readJob != nil {
		return &v1.GetJobResponse{Job: proto.Clone(j.readJob).(*v1.Job), Summary: proto.Clone(j.summary).(*v1.JobSummary)}, nil
	}
	return nil, errors.New("backend internal failure")
}
func (j *boundaryJobs) CancelJob(_ context.Context, r *v1.CancelJobRequest) (*v1.CancelJobResponse, error) {
	j.cancelCalls++
	return &v1.CancelJobResponse{Job: &v1.Job{JobId: r.JobId, Status: v1.JobStatus_JOB_STATUS_CANCELLED}}, nil
}
func (j *boundaryJobs) RunJob(ctx context.Context, r *v1.RunJobRequest) (*v1.RunJobResponse, error) {
	if j.runErr != nil {
		return nil, j.runErr
	}
	j.mu.Lock()
	j.lastRunFormat = r.ResponseFormat
	j.mu.Unlock()
	response, err := j.JobService.RunJob(ctx, r)
	if err == nil && j.summary != nil {
		response.Summary = proto.Clone(j.summary).(*v1.JobSummary)
	}
	return response, err
}

func TestSDKReadArgumentsBeforeBackendAndCancelDelegation(t *testing.T) {
	f := newTransportFixture(t)
	jobs := &boundaryJobs{JobService: f.jobs}
	f.service.jobs = jobs
	c, _ := f.client(t, f.admin, nil)
	for _, args := range []map[string]any{
		{"job_id": "job-20261014-0001", "host": ""},
		{"job_id": "job-20261014-0001", "next_cursor": ""},
		{"job_id": "job-20261014-0001", "offset": 1},
		{"job_id": "job-20261014-0001", "host": "web-01", "stream": "invalid"},
		{"job_id": "job-20261014-0001", "host": "web-01", "offset": -1},
		{"job_id": "job-20261014-0001", "host": "web-01", "next_cursor": "invalid"},
	} {
		if !call(t, c, "jobs_get", args).IsError {
			t.Fatal("accepted invalid output arguments")
		}
	}
	if jobs.getCalls != 0 {
		t.Fatalf("invalid parameters reached GetJob: calls=%d", jobs.getCalls)
	}
	result := call(t, c, "jobs_cancel", map[string]any{"job_id": "job-20261014-0001"})
	if result.IsError || jobs.cancelCalls != 1 || jobs.getCalls != 0 {
		t.Fatalf("cancel=%+v cancel calls=%d GetJob calls=%d", result, jobs.cancelCalls, jobs.getCalls)
	}
}

func TestSDKBackendFailureDoesNotExposeInternalError(t *testing.T) {
	f := newTransportFixture(t)
	f.service.jobs = &boundaryJobs{JobService: f.jobs, runErr: errors.New("fixture sensitive backend details")}
	c, _ := f.client(t, f.admin, nil)
	result := call(t, c, "logs_read", actionArgs())
	if !result.IsError || strings.Contains(content(t, result)["error"].(string), "sensitive") {
		t.Fatalf("internal error exposed: %+v", result)
	}
}

func (j *boundaryJobs) ListTasks(ctx context.Context, r *v1.ListTasksRequest) (*v1.ListTasksResponse, error) {
	j.mu.Lock()
	j.taskCalls++
	j.mu.Unlock()
	if j.tasksErr != nil {
		return nil, j.tasksErr
	}
	return j.JobService.ListTasks(ctx, r)
}
func TestSDKUsesNativeSummaryWithoutAdditionalReads(t *testing.T) {
	f := newTransportFixture(t)
	backend := &boundaryJobs{JobService: f.jobs, tasksErr: errors.New("extra task reads forbidden"), summary: &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED, Truncated: true, OfflineHosts: []string{"offline-host"}, Groups: []*v1.OutputGroup{{HostCount: 2, Hosts: []string{"web-01", "web-02"}, Stdout: "native backend summary", ExitCode: proto.Int32(0), Truncated: true}}}}
	f.service.jobs = backend
	c, _ := f.client(t, f.admin, nil)
	args := actionArgs()
	args["response_format"] = "detailed"
	result := call(t, c, "logs_read", args)
	m := content(t, result)
	if result.IsError || m["truncated"] != true || m["offline_hosts"] == nil || m["groups"] == nil {
		t.Fatalf("native summary=%v", m)
	}
	groups := m["groups"].([]any)
	if len(groups) != 1 || groups[0].(map[string]any)["stdout"] != "native backend summary" {
		t.Fatalf("groups=%v", groups)
	}
	backend.mu.Lock()
	backend.readJob = &v1.Job{JobId: m["job_id"].(string), Status: v1.JobStatus_JOB_STATUS_SUCCEEDED, TotalTasks: 2}
	backend.mu.Unlock()
	get := call(t, c, "jobs_get", map[string]any{"job_id": m["job_id"], "wait_seconds": 0, "response_format": "detailed"})
	if get.IsError || content(t, get)["truncated"] != true {
		t.Fatalf("get=%+v", get)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.taskCalls != 0 || backend.lastRunFormat != "detailed" || backend.lastGetFormat != "detailed" {
		t.Fatalf("task reads=%d RunJob format=%s GetJob format=%s", backend.taskCalls, backend.lastRunFormat, backend.lastGetFormat)
	}
}
