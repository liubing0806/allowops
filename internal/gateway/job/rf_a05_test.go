package job_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"google.golang.org/protobuf/proto"
)

type rfOutputDeadline struct {
	output.Storage
	deadline bool
	once     sync.Once
	done     chan time.Duration
}

func (s *rfOutputDeadline) Put(ctx context.Context, _ string, _ []byte) error {
	if !s.deadline {
		return errors.New("fixture object write failed")
	}
	started := time.Now()
	<-ctx.Done()
	s.once.Do(func() { s.done <- time.Since(started) })
	return ctx.Err()
}

func TestRFA05OutputStateAfterPersistenceFailure(t *testing.T) {
	for _, mode := range []string{"actual_shared_30s_deadline", "state_update_connection_failure"} {
		t.Run(mode, func(t *testing.T) {
			var storage *rfOutputDeadline
			tracer := &rfSQLFault{errors: make(chan error, 1), injectionErrors: make(chan error, 1), match: func(sql string) bool {
				return mode == "state_update_connection_failure" && strings.HasPrefix(sql, "UPDATE tasks SET output_stored=")
			}}
			f := setup(t, func(f *fixture) {
				storage = &rfOutputDeadline{Storage: f.Storage, deadline: mode == "actual_shared_30s_deadline", done: make(chan time.Duration, 1)}
				tracer.admin = f.DB.Pool
				traced := tracedJobStore(t, f.DB, tracer)
				f.BeforeStart = func(_ *hostconn.Service, jobs *job.Service) {
					if f.A == nil {
						jobs.Store = traced
						jobs.Storage = storage
					}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			r := request("stable")
			r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host"}}}}
			r.ExpectedCount = nil
			r.WaitSeconds = proto.Uint32(0)
			id := run(t, f.A, r).Job.JobId
			if storage.deadline {
				select {
				case elapsed := <-storage.done:
					t.Logf("actual Put context exhausted after %s", elapsed)
					if elapsed < 29*time.Second || elapsed > 35*time.Second {
						t.Fatalf("upload did not exhaust original 30s deadline: %s", elapsed)
					}
				case <-ctx.Done():
					t.Fatal("Put never exhausted actual shared deadline")
				}
			} else {
				select {
				case err := <-tracer.injectionErrors:
					t.Fatalf("fixture injection failed: %v", err)
				case err := <-tracer.errors:
					if err == nil {
						t.Fatal("no actual state update failure")
					}
					t.Logf("state update error=%v", err)
				case <-ctx.Done():
					t.Fatal("state UPDATE not reached")
				}
			}
			var state string
			var stored bool
			var status int16
			end := time.Now().Add(3 * time.Second)
			for time.Now().Before(end) {
				if err := f.DB.Pool.QueryRow(ctx, "SELECT output_state,output_stored,status FROM tasks WHERE job_id=$1", id).Scan(&state, &stored, &status); err != nil {
					t.Fatal(err)
				}
				if state != "pending" {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if state != "failed" || stored || status != int16(v1.TaskStatus_TASK_STATUS_SUCCEEDED) {
				t.Errorf("output_state=%s output_stored=%t execution=%d; want failed,false,SUCCEEDED(3)", state, stored, status)
			}
			_, err := f.B.Client.GetJobOutput(ctx, connect.NewRequest(&v1.GetJobOutputRequest{JobId: id, Hostname: "a-host", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT}))
			var detail *v1.ErrorDetail
			if rpcErr, ok := err.(*connect.Error); ok {
				for _, item := range rpcErr.Details() {
					value, _ := item.Value()
					if d, ok := value.(*v1.ErrorDetail); ok {
						detail = d
					}
				}
			}
			if connect.CodeOf(err) != connect.CodeNotFound || detail == nil || detail.Reason != "OUTPUT_UNAVAILABLE" || detail.RetryAfter != nil {
				t.Errorf("output read error=%v detail=%v; want NOT_FOUND/OUTPUT_UNAVAILABLE without retry", err, detail)
			}
		})
	}
}
