package job_test

import (
	"context"
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
	"google.golang.org/protobuf/proto"
)

func TestVFX6LateStartCancelOnRealOwnerLoop(t *testing.T) {
	type outcome struct {
		status  v1.TaskStatus
		elapsed time.Duration
	}
	started := make(chan time.Time, 1)
	completed := make(chan outcome, 1)
	cancelErr := make(chan error, 1)
	var once atomic.Bool
	var startNanos atomic.Int64
	f := setup(t, func(f *fixture) {
		f.BeforeMessage = func(e hostconn.Event) {
			if m := e.Message.GetTaskStarted(); m != nil && once.CompareAndSwap(false, true) {
				ctx, done := context.WithTimeout(context.Background(), 3*time.Second)
				_, err := f.B.Client.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: m.JobId}))
				done()
				cancelErr <- err
				now := time.Now()
				startNanos.Store(now.UnixNano())
				started <- now
			}
			if m := e.Message.GetTaskCompleted(); m != nil {
				completed <- outcome{m.Result.Status, time.Since(time.Unix(0, startNanos.Load()))}
			}
		}
	})
	r := request("slow")
	r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host"}}}}
	r.ExpectedCount = nil
	r.WaitSeconds = proto.Uint32(0)
	response := run(t, f.A, r)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("TaskStarted not observed")
	}
	if err := <-cancelErr; err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-completed:
		var state int16
		if err := f.DB.Pool.QueryRow(context.Background(), "SELECT status FROM tasks WHERE job_id=$1", response.Job.JobId).Scan(&state); err != nil {
			t.Fatal(err)
		}
		t.Logf("real owner: host completed=%s after %s; database terminal=%d; action was /usr/bin/sleep 2", got.status, got.elapsed, state)
		if got.status != v1.TaskStatus_TASK_STATUS_CANCELLED || got.elapsed > 3*time.Second {
			t.Errorf("late-start CancelTask failed to stop host: got %s after %s; want CANCELLED within 3s", got.status, got.elapsed)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("owner did not process TaskCompleted within 15s")
	}
}

// Pause the real owner's write after its mailbox lookup has succeeded. The
// message is already queued, but the production stream.Send has not run.
type fx6MailboxTracer struct {
	paused  chan struct{}
	release chan struct{}
	once    atomic.Bool
}

type fx6MailboxQuery struct{}

func (p *fx6MailboxTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(d.SQL, "SELECT EXISTS(SELECT 1 FROM gateway_messages WHERE message_id=") && p.once.CompareAndSwap(false, true) {
		return context.WithValue(ctx, fx6MailboxQuery{}, true)
	}
	return ctx
}

func (p *fx6MailboxTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if ctx.Value(fx6MailboxQuery{}) == true && d.Err == nil {
		close(p.paused)
		<-p.release
	}
}

func TestVFX6CrossInstanceStopsQueuedAssignment(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		name := "cancel"
		if recovery {
			name = "recovery"
		}
		t.Run(name, func(t *testing.T) {
			tracer := &fx6MailboxTracer{paused: make(chan struct{}), release: make(chan struct{})}
			// Always release before fixture teardown, including on a failed assertion.
			var release sync.Once
			starts := make(chan struct{}, 1)
			f := setup(t, func(f *fixture) {
				cfg := f.DB.Pool.Config()
				cfg.ConnConfig.Tracer = tracer
				pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(pool.Close)
				db := *f.DB
				db.Pool = pool
				f.DB = &db
				f.BeforeMessage = func(e hostconn.Event) {
					if e.Message.GetTaskStarted() != nil {
						starts <- struct{}{}
					}
				}
			})
			defer release.Do(func() { close(tracer.release) })
			r := request("stable")
			r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host"}}}}
			r.ExpectedCount = nil
			r.WaitSeconds = proto.Uint32(0)
			response := run(t, f.A, r)
			select {
			case <-tracer.paused:
			case <-time.After(5 * time.Second):
				t.Fatal("assignment did not reach owner mailbox write")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			want := v1.TaskStatus_TASK_STATUS_CANCELLED
			if recovery {
				if _, err := f.DB.Pool.Exec(ctx, "UPDATE gateway_instances SET last_seen=now()-interval '1 hour' WHERE instance_id=$1", f.A.Host.InstanceID); err != nil {
					t.Fatal(err)
				}
				if err := f.B.Job.RecoverLostInstances(ctx); err != nil {
					t.Fatal(err)
				}
				want = v1.TaskStatus_TASK_STATUS_SKIPPED
			} else if _, err := f.B.Client.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: response.Job.JobId})); err != nil {
				t.Fatal(err)
			}
			var state int16
			if err := f.DB.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE job_id=$1", response.Job.JobId).Scan(&state); err != nil || state != int16(want) {
				t.Fatalf("remote terminal status=%d want=%d error=%v", state, want, err)
			}
			release.Do(func() { close(tracer.release) })
			// The dispatch sender deletes its mailbox only after the real owner has
			// rejected the message or processed TaskCompleted. TaskStarted precedes
			// TaskCompleted on the same real agent stream, so this is a joined check.
			eventually(t, func() bool {
				var n int
				err := f.DB.Pool.QueryRow(context.Background(), "SELECT count(*) FROM gateway_messages").Scan(&n)
				return (err == nil && n == 0) || len(starts) > 0
			})
			select {
			case <-starts:
				t.Error("TaskAssignment reached real agent after remote terminal commit")
			default:
			}
		})
	}
}
