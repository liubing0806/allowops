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
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"google.golang.org/protobuf/proto"
)

type rfA06Storage struct {
	output.Storage
	once        sync.Once
	entered     chan struct{}
	release     chan struct{}
	finished    chan time.Time
	returned    chan time.Time
	observation *rfA06Observation
	calls       atomic.Int32
}

func (s *rfA06Storage) Put(ctx context.Context, key string, data []byte) (err error) {
	call := s.calls.Add(1)
	s.observation.mark(fmt.Sprintf("put_%d_admitted", call), nil)
	defer func() {
		s.observation.mark(fmt.Sprintf("put_%d_return_ctx_%v", call, ctx.Err()), err)
		s.returned <- time.Now()
	}()
	first := false
	s.once.Do(func() { first = true; close(s.entered) })
	if first {
		select {
		case <-s.release:
		case <-ctx.Done():
		}
		s.observation.mark("first_put_released_or_cancelled", ctx.Err())
		s.finished <- time.Now()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.observation.mark(fmt.Sprintf("actual_put_%d_start", call), nil)
	cancelled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		s.observation.mark(fmt.Sprintf("actual_put_%d_context_done", call), ctx.Err())
		close(cancelled)
	})
	err = s.Storage.Put(ctx, key, data)
	if !stop() {
		<-cancelled
	}
	s.observation.mark(fmt.Sprintf("actual_put_%d_return", call), err)
	return err
}

type rfA06Commit struct{}
type rfA06Query struct{}

type rfA06Tracer struct {
	mu                 sync.Mutex
	terminal           map[uint32]bool
	committed, release chan struct{}
	once               sync.Once
	observation        *rfA06Observation
}

func (p *rfA06Tracer) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := c.PgConn().PID()
	if strings.HasPrefix(d.SQL, "UPDATE tasks SET status=$3,result=$4,finished_at=now(),stdout_preview=") {
		p.terminal[id] = true
		p.observation.mark("terminal_update_start", nil)
		ctx = context.WithValue(ctx, rfA06Query{}, "terminal_update")
	}
	if d.SQL == "commit" && p.terminal[id] {
		delete(p.terminal, id)
		p.observation.mark("terminal_commit_start_after_admission_registration", nil)
		return context.WithValue(ctx, rfA06Commit{}, true)
	}
	if strings.HasPrefix(d.SQL, "UPDATE tasks SET output_stored=") {
		p.observation.mark("output_state_sql_start", nil)
		ctx = context.WithValue(ctx, rfA06Query{}, "output_state_sql")
	}
	return ctx
}

func (p *rfA06Tracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if phase, ok := ctx.Value(rfA06Query{}).(string); ok {
		p.observation.mark(phase+"_return", d.Err)
	}
	if ctx.Value(rfA06Commit{}) == true && d.Err == nil {
		p.observation.mark("terminal_commit_visible", nil)
		p.once.Do(func() {
			close(p.committed)
			select {
			case <-p.release:
			case <-time.After(5 * time.Second):
			}
		})
		p.observation.mark("terminal_commit_callback_return", nil)
	}
}

func TestRFA06ShutdownWaitsAcceptedPersistenceWithinDrainBudget(t *testing.T) {
	for _, mode := range []string{"release_within_budget", "deadline_cancels_upload", "terminal_commit_admission_window"} {
		t.Run(mode, func(t *testing.T) {
			var observation *rfA06Observation
			if mode == "terminal_commit_admission_window" {
				observation = &rfA06Observation{start: time.Now()}
				t.Cleanup(func() { observation.dump(t) })
			}
			var storage *rfA06Storage
			var release, releaseCommit, drainOnce sync.Once
			tracer := &rfA06Tracer{terminal: map[uint32]bool{}, committed: make(chan struct{}), release: make(chan struct{}), observation: observation}
			type drainResult struct {
				at  time.Time
				err error
			}
			drained := make(chan drainResult, 1)
			f := setup(t, func(f *fixture) {
				storage = &rfA06Storage{Storage: f.Storage, entered: make(chan struct{}), release: make(chan struct{}), finished: make(chan time.Time, 1), returned: make(chan time.Time, 2), observation: observation}
				db := f.DB
				if mode == "terminal_commit_admission_window" {
					db = tracedJobStore(t, f.DB, tracer)
					f.Storage.Storage = rfA06ObserveS3(f.Storage.Storage.(*output.S3), observation)
				}
				f.BeforeStart = func(hosts *hostconn.Service, jobs *job.Service) {
					if f.A == nil {
						jobs.Storage = storage
						jobs.Store = db
						if observation != nil {
							jobs.Audit = rfA06Audit{Appender: jobs.Audit, observation: observation}
						}
						original := hosts.Hooks.Drain
						hosts.Hooks.Drain = func(ctx context.Context) error {
							observation.mark("job_drain_start", nil)
							err := original(ctx)
							observation.mark("job_drain_return", err)
							drainOnce.Do(func() { drained <- drainResult{time.Now(), err} })
							return err
						}
					}
				}
			})
			defer release.Do(func() { close(storage.release) })
			defer releaseCommit.Do(func() { close(tracer.release) })
			r := request("stable")
			r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host"}}}}
			r.ExpectedCount = nil
			r.WaitSeconds = proto.Uint32(0)
			id := run(t, f.B, r).Job.JobId
			if mode == "terminal_commit_admission_window" {
				select {
				case <-tracer.committed:
				case <-time.After(5 * time.Second):
					t.Fatal("terminal COMMIT did not succeed")
				}
			} else {
				select {
				case <-storage.entered:
				case <-time.After(5 * time.Second):
					t.Fatal("real task persistence not entered")
				}
			}
			// A is the real connection/output owner; B is the source scheduler.
			var status int16
			if err := f.DB.Pool.QueryRow(context.Background(), "SELECT status FROM tasks WHERE job_id=$1", id).Scan(&status); err != nil || status != 3 {
				t.Fatalf("visible committed execution status=%d error=%v", status, err)
			}
			budget := 3 * time.Second
			if mode == "deadline_cancels_upload" {
				budget = 500 * time.Millisecond
			}
			shutdown, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			deadline, _ := shutdown.Deadline()
			done := make(chan error, 1)
			go func() {
				observation.mark("server_shutdown_start", nil)
				err := f.A.Server.Shutdown(shutdown)
				observation.mark("server_shutdown_return", err)
				observation.mark("job_close_start", nil)
				f.A.Job.Close()
				observation.mark("job_close_return", nil)
				done <- err
			}()
			if mode != "deadline_cancels_upload" {
				// Release accepted output while the existing Drain budget is still available.
				timer := time.AfterFunc(200*time.Millisecond, func() {
					observation.mark("test_release", nil)
					releaseCommit.Do(func() { close(tracer.release) })
					release.Do(func() { close(storage.release) })
				})
				defer timer.Stop()
			}
			var shutdownErr error
			select {
			case shutdownErr = <-done:
			case <-time.After(8 * time.Second):
				t.Fatal("Shutdown+Close exceeded drain plus bounded cleanup")
			}
			var actualFinished time.Time
			if observation != nil {
				// Close has joined persistence, so this is the final call count.
				// Observe every underlying Put return rather than its release gate.
				for i := int32(0); i < storage.calls.Load(); i++ {
					select {
					case at := <-storage.returned:
						if at.After(actualFinished) {
							actualFinished = at
						}
					case <-time.After(time.Second):
						t.Fatal("actual Put did not return before Shutdown+Close joined")
					}
				}
				if actualFinished.IsZero() {
					t.Fatal("no actual Put return observed")
				}
			}
			d := <-drained
			var finished time.Time
			select {
			case finished = <-storage.finished:
			case <-time.After(time.Second):
				t.Fatal("persistence worker did not join")
			}
			t.Logf("mode=%s Drain_return=%s Put_release_or_cancel=%s deadline=%s Shutdown_error=%v", mode, d.at.Format(time.RFC3339Nano), finished.Format(time.RFC3339Nano), deadline.Format(time.RFC3339Nano), shutdownErr)
			if observation != nil {
				finished = actualFinished
				t.Logf("last actual Put return=%s", finished.Format(time.RFC3339Nano))
			}
			if mode == "deadline_cancels_upload" {
				if !errors.Is(d.err, context.DeadlineExceeded) || !errors.Is(shutdownErr, context.DeadlineExceeded) {
					t.Errorf("Drain=%v Shutdown=%v; want deadline exceeded while upload pending", d.err, shutdownErr)
				}
				if finished.Before(deadline.Add(-20*time.Millisecond)) || finished.After(deadline.Add(5*time.Second)) {
					t.Errorf("upload cancellation outside existing drain deadline plus 5s cleanup: %s", finished)
				}
			} else if d.at.Before(finished) || shutdownErr != nil {
				t.Errorf("Drain returned before accepted upload finished: drain=%s upload=%s error=%v", d.at, finished, shutdownErr)
			}
			var state string
			if err := f.DB.Pool.QueryRow(context.Background(), "SELECT status,output_state FROM tasks WHERE job_id=$1", id).Scan(&status, &state); err != nil {
				t.Fatal(err)
			}
			want := "stored"
			if mode == "deadline_cancels_upload" {
				want = "failed"
			}
			if status != 3 || state != want {
				t.Errorf("execution=%d output_state=%s; want SUCCEEDED(3),%s", status, state, want)
			}
			if mode == "deadline_cancels_upload" {
				// RR-a-02: a cancelled upload still leaves a deny store_output audit event.
				var denied int
				if err := f.DB.Pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_events WHERE operation='store_output' AND decision='deny' AND job_id=$1", id).Scan(&denied); err != nil {
					t.Fatal(err)
				}
				if denied != 1 {
					t.Errorf("store_output deny audit events=%d for failed output_state; want 1", denied)
				}
			}
			if want == "stored" {
				value, err := f.B.Client.GetJobOutput(context.Background(), connect.NewRequest(&v1.GetJobOutputRequest{JobId: id, Hostname: "a-host", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT}))
				if err != nil || string(value.Msg.Data) != "same output" {
					t.Errorf("accepted upload readback=%v error=%v", value, err)
				}
			}
		})
	}
}
