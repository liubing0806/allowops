package job_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"google.golang.org/protobuf/proto"
)

type rfSQLFault struct {
	admin           *pgxpool.Pool
	match           func(string) bool
	hit             atomic.Bool
	errors          chan error
	injectionErrors chan error
}

type rfFaultQuery struct{}

func (p *rfSQLFault) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if p.match(d.SQL) && p.hit.CompareAndSwap(false, true) {
		control, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var killed bool
		if err := p.admin.QueryRow(control, "SELECT pg_terminate_backend($1)", c.PgConn().PID()).Scan(&killed); err != nil || !killed {
			if err == nil {
				err = errors.New("own query backend was not terminated")
			}
			select {
			case p.injectionErrors <- fmt.Errorf("inject query connection failure: %w", err):
			default:
			}
		}
		return context.WithValue(ctx, rfFaultQuery{}, true)
	}
	return ctx
}

func (p *rfSQLFault) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if ctx.Value(rfFaultQuery{}) == true {
		select {
		case p.errors <- d.Err:
		default:
		}
	}
}

func TestRFA03SchedulerRetainsOwnerAfterSQLFailure(t *testing.T) {
	for _, mode := range []string{"second_batch_read", "finish_job", "required_terminal_write", "cancel_worker_read"} {
		t.Run(mode, func(t *testing.T) {
			var reads atomic.Int32
			tracer := &rfSQLFault{errors: make(chan error, 1), injectionErrors: make(chan error, 1)}
			tracer.match = func(sql string) bool {
				switch mode {
				case "second_batch_read":
					return sql == "SELECT cancel_requested FROM jobs WHERE job_id=$1" && reads.Add(1) == 2
				case "cancel_worker_read":
					return strings.HasPrefix(sql, "SELECT task_id,host_id,COALESCE(connection_id,''),status FROM tasks WHERE job_id=")
				case "finish_job":
					return sql == "SELECT cancel_requested,status FROM jobs WHERE job_id=$1 FOR UPDATE"
				default:
					return strings.HasPrefix(sql, "UPDATE tasks SET status=$3,result=$4,finished_at=")
				}
			}
			var mu sync.Mutex
			starts := map[string]int{}
			f := setup(t, func(f *fixture) {
				tracer.admin = f.DB.Pool
				traced := tracedJobStore(t, f.DB, tracer)
				f.BeforeMessage = func(e hostconn.Event) {
					if m := e.Message.GetTaskStarted(); m != nil {
						mu.Lock()
						starts[m.TaskId]++
						mu.Unlock()
					}
				}
				f.BeforeStart = func(hosts *hostconn.Service, jobs *job.Service) {
					if f.A == nil {
						jobs.Store = traced
						if mode == "required_terminal_write" {
							hosts.Config.MailboxRows = 0
						}
					}
				}
			})
			t.Cleanup(func() { awaitFixtureOutputs(t, f) })
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			r := request("stable")
			if mode == "cancel_worker_read" {
				r.Action = "slow"
			}
			r.BatchSize = proto.Uint32(1)
			r.WaitSeconds = proto.Uint32(0)
			r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host", "b-host"}}}}
			r.ExpectedCount = nil
			response, err := f.A.Client.RunJob(ctx, connect.NewRequest(r))
			if err != nil {
				t.Fatal(err)
			}
			id := response.Msg.Job.JobId
			// Cleanup only our unfinished fixture rows after product assertions.
			defer func() {
				cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
				defer done()
				_, _ = f.DB.Pool.Exec(cleanup, "UPDATE tasks SET status=7 WHERE job_id=$1 AND status IN (1,2)", id)
				_, _ = f.DB.Pool.Exec(cleanup, "UPDATE jobs SET status=4 WHERE job_id=$1 AND status IN (1,2)", id)
			}()
			if mode == "cancel_worker_read" {
				eventually(t, func() bool {
					var n int
					err := f.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM tasks WHERE job_id=$1 AND status=2", id).Scan(&n)
					return err == nil && n == 1
				})
				if _, err := f.A.Client.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: id})); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-tracer.injectionErrors:
				t.Fatalf("fixture injection failed: %v", err)
			case err := <-tracer.errors:
				if err == nil {
					t.Fatal("fault did not cause actual SQL error")
				}
				t.Logf("injected %s error=%v", mode, err)
			case <-ctx.Done():
				t.Fatal("target SQL fault was not reached")
			}
			var status int16
			eventually(t, func() bool {
				if err := f.DB.Pool.QueryRow(ctx, "SELECT status FROM jobs WHERE job_id=$1", id).Scan(&status); err != nil {
					t.Fatal(err)
				}
				return status > 2
			})
			want := v1.JobStatus_JOB_STATUS_SUCCEEDED
			if mode == "required_terminal_write" {
				want = v1.JobStatus_JOB_STATUS_FAILED
			}
			if mode == "cancel_worker_read" {
				want = v1.JobStatus_JOB_STATUS_CANCELLED
			}
			if status != int16(want) {
				t.Errorf("%s recovered database job status=%d; want %s(%d)", mode, status, want, want)
			}
			var healthy bool
			if err := f.DB.Pool.QueryRow(ctx, "SELECT last_seen>now()-$2*interval '1 second' FROM gateway_instances WHERE instance_id=$1", f.A.Host.InstanceID, hostconn.InstanceLostAfter(f.A.Host.Config).Seconds()).Scan(&healthy); err != nil || !healthy {
				t.Errorf("source owner health=%t error=%v", healthy, err)
			}
			var one int
			if err := f.A.Job.Store.Pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
				t.Fatalf("query pool recovered=%d error=%v", one, err)
			}
			ts := tasks(t, f.B, id)
			mu.Lock()
			defer mu.Unlock()
			for _, task := range ts {
				if mode == "cancel_worker_read" && task.Result.Status != v1.TaskStatus_TASK_STATUS_CANCELLED {
					t.Errorf("running cancellation task %s status=%s; want CANCELLED", task.TaskId, task.Result.Status)
				}
				expected := 1
				if mode == "required_terminal_write" {
					expected = 0
				}
				if mode == "cancel_worker_read" && task.Hostname == "b-host" {
					expected = 0
				}
				if starts[task.TaskId] != expected {
					t.Errorf("task %s real starts=%d; want %d without replay", task.TaskId, starts[task.TaskId], expected)
				}
			}
		})
	}
}
