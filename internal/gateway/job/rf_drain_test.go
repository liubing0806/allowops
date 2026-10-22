package job_test

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/store"
	"google.golang.org/protobuf/proto"
)

type rfDrainTracer struct {
	entered chan struct{}
	once    sync.Once
}

func (p *rfDrainTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if d.SQL == "SELECT count(*) FROM tasks t JOIN hosts h ON h.host_id=t.host_id WHERE t.status IN (1,2) AND t.dispatched AND h.instance_id=$1 AND h.connection_id=t.connection_id" {
		p.once.Do(func() { close(p.entered) })
	}
	return ctx
}
func (*rfDrainTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestRFDrainAllowsExistingCancellation(t *testing.T) {
	for _, local := range []bool{true, false} {
		name := "remote_sender"
		if local {
			name = "draining_sender"
		}
		t.Run(name, func(t *testing.T) {
			tracer := &rfDrainTracer{entered: make(chan struct{})}
			f := setup(t, func(f *fixture) {
				traced := tracedJobStore(t, f.DB, tracer)
				f.BeforeStart = func(_ *hostconn.Service, jobs *job.Service) {
					if f.A == nil {
						jobs.Store = traced
					}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			r := request("linger")
			r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host"}}}}
			r.ExpectedCount = nil
			r.WaitSeconds = proto.Uint32(0)
			id := run(t, f.B, r).Job.JobId
			eventually(t, func() bool {
				var status int16
				err := f.DB.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE job_id=$1", id).Scan(&status)
				return err == nil && status == 2
			})
			drained := make(chan error, 1)
			go func() { drained <- f.A.Host.Drain(ctx) }()
			eventually(t, func() bool {
				var draining bool
				err := f.DB.Pool.QueryRow(ctx, "SELECT draining FROM gateway_instances WHERE instance_id=$1", f.A.Host.InstanceID).Scan(&draining)
				return err == nil && draining
			})
			// This real SQL starts only after job Drain has stopped admission.
			select {
			case <-tracer.entered:
			case <-ctx.Done():
				t.Fatal("job Drain hook not entered")
			}
			// Wait for the real job Drain hook's admission boundary as well as P4 state.
			r.Action = "stable"
			_, err := f.A.Client.RunJob(ctx, connect.NewRequest(r))
			if connect.CodeOf(err) != connect.CodeUnavailable {
				t.Fatalf("new RunJob during Drain=%v; want UNAVAILABLE", err)
			}
			var host, connection string
			if err := f.DB.Pool.QueryRow(ctx, "SELECT host_id,connection_id FROM tasks WHERE job_id=$1", id).Scan(&host, &connection); err != nil {
				t.Fatal(err)
			}
			_, err = f.A.Host.SendToConnection(ctx, host, connection, &v1.ConnectResponse{Message: &v1.ConnectResponse_Task{Task: &v1.TaskAssignment{TaskId: "new-during-drain"}}})
			if !errors.Is(err, store.ErrOffline) {
				t.Errorf("new task dispatch during Drain=%v; want rejection", err)
			}
			sender := f.B
			if local {
				sender = f.A
			}
			if _, err := sender.Client.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: id})); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-drained:
				if err != nil {
					t.Errorf("Drain=%v", err)
				}
			case <-ctx.Done():
				t.Fatal("existing cancellation did not allow Drain to finish")
			}
			eventually(t, func() bool {
				var status int16
				err := f.DB.Pool.QueryRow(ctx, "SELECT status FROM jobs WHERE job_id=$1", id).Scan(&status)
				return err == nil && status > 2
			})
			list := tasks(t, f.B, id)
			job := get(t, f.B, id)
			t.Logf("sender=%s real task=%s job=%s", name, list[0].Result.Status, job.Job.Status)
			if list[0].Result.Status != v1.TaskStatus_TASK_STATUS_CANCELLED || job.Job.Status != v1.JobStatus_JOB_STATUS_CANCELLED {
				t.Errorf("explicit cancellation during Drain task=%s job=%s; want CANCELLED,CANCELLED", list[0].Result.Status, job.Job.Status)
			}
		})
	}
}
