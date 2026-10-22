package job_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"google.golang.org/protobuf/proto"
)

type rrA05Finish struct{}

// rrA05Tracer counts rejected job finish statements. Both the scheduler and the
// cancellation worker issue one; each receives a non-retryable SQLSTATE and stops.
type rrA05Tracer struct{ rejected atomic.Int32 }

func (p *rrA05Tracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(d.SQL, "UPDATE jobs SET status=$2,finished_at=now()") {
		return context.WithValue(ctx, rrA05Finish{}, true)
	}
	return ctx
}
func (p *rrA05Tracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	var pgerr *pgconn.PgError
	if ctx.Value(rrA05Finish{}) == true && errors.As(d.Err, &pgerr) && pgerr.Code == "P0001" {
		p.rejected.Add(1)
	}
}

// RR-a-05: a repeated CancelJob must restart the cancellation worker when the
// worker this instance started stopped on an unrecoverable SQL error.
func TestRRA05RepeatedCancelRestartsStoppedWorker(t *testing.T) {
	tracer := &rrA05Tracer{}
	f := setup(t, func(f *fixture) {
		traced := tracedJobStore(t, f.DB, tracer)
		f.BeforeStart = func(_ *hostconn.Service, jobs *job.Service) {
			if f.A == nil {
				jobs.Store = traced
			}
		}
	})
	t.Cleanup(func() { awaitFixtureOutputs(t, f) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := request("linger")
	r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host"}}}}
	r.ExpectedCount = nil
	r.WaitSeconds = proto.Uint32(0)
	response, err := f.A.Client.RunJob(ctx, connect.NewRequest(r))
	if err != nil {
		t.Fatal(err)
	}
	id := response.Msg.Job.JobId
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		_, _ = f.DB.Pool.Exec(cleanup, "UPDATE tasks SET status=7 WHERE job_id=$1 AND status IN (1,2)", id)
		_, _ = f.DB.Pool.Exec(cleanup, "UPDATE jobs SET status=4 WHERE job_id=$1 AND status IN (1,2)", id)
	}()
	eventually(t, func() bool {
		var n int
		err := f.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM tasks WHERE job_id=$1 AND status=2", id).Scan(&n)
		return err == nil && n == 1
	})
	// Reject the final job status write with a non-retryable SQLSTATE (P0001).
	for _, statement := range []string{
		`CREATE FUNCTION rr_a05_reject_finish() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture finish rejected'; END $$`,
		`CREATE TRIGGER rr_a05_reject_finish BEFORE UPDATE OF status ON jobs FOR EACH ROW WHEN (OLD.status IN (1,2) AND NEW.status > 2) EXECUTE FUNCTION rr_a05_reject_finish()`,
	} {
		if _, err := f.DB.Pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	cancelJob := func() {
		t.Helper()
		if _, err := f.A.Client.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: id})); err != nil {
			t.Fatal(err)
		}
	}
	cancelJob()
	// The scheduler and the cancellation worker each stop on their rejected finish.
	eventually(t, func() bool { return tracer.rejected.Load() >= 2 })
	if _, err := f.DB.Pool.Exec(ctx, "DROP TRIGGER rr_a05_reject_finish ON jobs"); err != nil {
		t.Fatal(err)
	}
	// A client retry may arrive before the failed worker has unregistered; retry until
	// a request is admitted after it stopped.
	var status int16
	end := time.Now().Add(10 * time.Second)
	for {
		cancelJob()
		if err := f.DB.Pool.QueryRow(ctx, "SELECT status FROM jobs WHERE job_id=$1", id).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status > 2 || time.Now().After(end) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status != int16(v1.JobStatus_JOB_STATUS_CANCELLED) {
		t.Errorf("job status=%d after repeated CancelJob; want CANCELLED(%d) once the stopped worker is restarted", status, v1.JobStatus_JOB_STATUS_CANCELLED)
	}
}
