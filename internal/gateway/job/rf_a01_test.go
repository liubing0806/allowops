package job_test

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/agent"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/executor"
	"google.golang.org/protobuf/proto"
)

type rfDelayedCancellation struct {
	cancelled chan struct{}
	release   chan struct{}
}

func (r *rfDelayedCancellation) Run(ctx context.Context, a catalog.Action, input, filters map[string]any, id string, version int64, callbacks executor.Callbacks) (executor.Result, error) {
	result, err := (agent.LocalRunner{}).Run(ctx, a, input, filters, id, version, callbacks)
	if errors.Is(err, context.Canceled) {
		close(r.cancelled)
		// Only the runner's final return is delayed. The owner stream stays writable.
		select {
		case <-r.release:
		case <-time.After(8 * time.Second):
		}
	}
	return result, err
}

type rfA01Query struct{ cancel, capacity bool }
type rfA01Tracer struct{ cancels, capacity atomic.Int32 }

func (p *rfA01Tracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	q := rfA01Query{capacity: strings.HasPrefix(d.SQL, "UPDATE gateway_messages SET failure='capacity'")}
	if strings.HasPrefix(d.SQL, "INSERT INTO gateway_messages(") {
		m := &v1.ConnectResponse{}
		if b, ok := d.Args[4].([]byte); ok && proto.Unmarshal(b, m) == nil && m.GetCancel() != nil {
			q.cancel = true
		}
	}
	return context.WithValue(ctx, rfA01Query{}, q)
}
func (p *rfA01Tracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if q, ok := ctx.Value(rfA01Query{}).(rfA01Query); ok && d.Err == nil {
		if q.cancel {
			p.cancels.Add(1)
		}
		if q.capacity {
			p.capacity.Add(1)
		}
	}
}

func TestRFA01RepeatedCrossInstanceCancellation(t *testing.T) {
	t.Logf("actual Go runtime GOMAXPROCS=%d GOFLAGS=%s", runtime.GOMAXPROCS(0), os.Getenv("GOFLAGS"))
	tracer := &rfA01Tracer{}
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
	})
	runner := &rfDelayedCancellation{cancelled: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(runner.release) })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	token, err := f.A.Host.CreateJoinToken(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := agent.Config{Upstream: f.A.Address, CAPin: f.Pin}
	identity, err := agent.Join(ctx, cfg, token, "rf-a01-host", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.DB.Pool.Exec(ctx, `UPDATE hosts SET authorization_labels='{"env":"test"}' WHERE host_id=$1`, identity.HostID); err != nil {
		t.Fatal(err)
	}
	a, err := agent.New(cfg, agent.Options{DataDir: dir, KeysDir: f.KeysDir, KeyOwner: os.Getuid(), Version: f.A.Host.Config.Version, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	agentCtx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(agentCtx) }()
	defer func() {
		release.Do(func() { close(runner.release) })
		stop()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("own agent did not stop")
		}
	}()
	eventually(t, func() bool {
		report := f.A.Host.CatalogReport(identity.HostID, f.Package.CatalogID)
		return report != nil && report.Loaded
	})
	r := request("linger")
	r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"rf-a01-host"}}}}
	r.ExpectedCount = nil
	r.WaitSeconds = proto.Uint32(0)
	response := run(t, f.B, r)
	id := response.Job.JobId
	eventually(t, func() bool {
		var status int16
		err := f.DB.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE job_id=$1", id).Scan(&status)
		return err == nil && status == 2
	})
	if _, err := f.B.Client.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: id})); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runner.cancelled:
	case <-ctx.Done():
		t.Fatal("LocalRunner did not finish real process cancellation")
	}
	var pending int
	if err := f.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM gateway_messages WHERE host_id=$1 AND response IS NULL AND failure=''", identity.HostID).Scan(&pending); err != nil || pending != 2 {
		t.Fatalf("first assignment+cancel pending=%d error=%v; want 2", pending, err)
	}
	if _, err := f.A.Client.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: id})); err != nil {
		t.Fatal(err)
	}
	// On old code wait for its actual capacity write, while a deduplicated second
	// request has no worker to wait for. Final join below verifies total admissions.
	end := time.Now().Add(300 * time.Millisecond)
	for tracer.capacity.Load() == 0 && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	var before int16
	end = time.Now().Add(time.Second)
	for {
		if err := f.DB.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE job_id=$1", id).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if tracer.capacity.Load() == 0 || before > 2 || time.Now().After(end) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	t.Logf("before result: task status=%d cancel mailbox admissions=%d capacity UPDATEs=%d", before, tracer.cancels.Load(), tracer.capacity.Load())
	if before != 2 {
		t.Errorf("online task status=%d before real agent final result; want RUNNING(2)", before)
	}
	release.Do(func() { close(runner.release) })
	eventually(t, func() bool {
		var status int16
		err := f.DB.Pool.QueryRow(ctx, "SELECT status FROM jobs WHERE job_id=$1", id).Scan(&status)
		return err == nil && status > 2
	})
	f.A.Job.Close()
	f.B.Job.Close()
	got := tasks(t, f.B, id)
	job := get(t, f.B, id)
	t.Logf("joined workers: task=%s job=%s cancel admissions=%d capacity=%d", got[0].Result.Status, job.Job.Status, tracer.cancels.Load(), tracer.capacity.Load())
	if got[0].Result.Status != v1.TaskStatus_TASK_STATUS_CANCELLED || job.Job.Status != v1.JobStatus_JOB_STATUS_CANCELLED {
		t.Errorf("real cancelled task=%s job=%s; want CANCELLED,CANCELLED", got[0].Result.Status, job.Job.Status)
	}
	if tracer.cancels.Load() != 1 || tracer.capacity.Load() != 0 {
		t.Errorf("duplicate cancellation admissions=%d capacity=%d; want 1,0", tracer.cancels.Load(), tracer.capacity.Load())
	}
}
