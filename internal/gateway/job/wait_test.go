package job

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

type jobWaitTracer struct {
	reads  int
	onRead func(context.Context, int)
}

func (tr *jobWaitTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasSuffix(data.SQL, "FROM jobs WHERE job_id=$1") {
		tr.reads++
		if tr.onRead != nil {
			tr.onRead(ctx, tr.reads)
		}
	}
	return ctx
}

func (*jobWaitTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestWaitPollsWithBackoff(t *testing.T) {
	s := concurrencyFixture(t)
	original := s.Store
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tracer := &jobWaitTracer{}
	cfg := original.Pool.Config()
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	traced := *original
	traced.Pool = pool
	s.Store = &traced

	t.Run("running until wait deadline", func(t *testing.T) {
		job, err := s.wait(ctx, "job", 1)
		if err != nil || job.GetStatus() != v1.JobStatus_JOB_STATUS_RUNNING {
			t.Fatalf("wait status=%v err=%v, want running", job.GetStatus(), err)
		}
		if tracer.reads < 6 || tracer.reads > 10 {
			t.Errorf("job reads in one second=%d, want 6 to 10 with backoff capped at 250ms", tracer.reads)
		}
	})
	t.Run("finished on second read", func(t *testing.T) {
		tracer.reads = 0
		tracer.onRead = func(ctx context.Context, read int) {
			if read == 2 {
				if _, err := original.Pool.Exec(ctx, "UPDATE jobs SET status=3,finished_at=now() WHERE job_id='job'"); err != nil {
					t.Error(err)
				}
			}
		}
		started := time.Now()
		job, err := s.wait(ctx, "job", 1)
		if err != nil || job.GetStatus() != v1.JobStatus_JOB_STATUS_SUCCEEDED {
			t.Fatalf("wait status=%v err=%v, want succeeded", job.GetStatus(), err)
		}
		if elapsed := time.Since(started); tracer.reads != 2 || elapsed >= 250*time.Millisecond {
			t.Errorf("short job returned after %s and %d reads, want two reads within 250ms", elapsed, tracer.reads)
		}
	})
}
