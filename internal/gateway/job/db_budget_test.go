package job_test

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
	"google.golang.org/protobuf/proto"
)

type jobQueryCounts struct {
	total, jobReads, taskCounts, mailboxReads, writes, txControl int
	duringHold                                                   int
	peakConns                                                    int32
}

type queryBudgetTracer struct {
	mu        sync.Mutex
	pool      *pgxpool.Pool // non-nil during the measured workload
	holdUntil time.Time
	counts    jobQueryCounts
}

func (q *queryBudgetTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pool == nil {
		return ctx
	}
	sql := strings.TrimSpace(data.SQL)
	if strings.HasPrefix(sql, "-- name:") { // sqlc prepends a query name.
		_, sql, _ = strings.Cut(sql, "\n")
	}
	sql = strings.ToLower(strings.Join(strings.Fields(sql), " "))
	c := &q.counts
	c.total++
	if time.Now().Before(q.holdUntil) {
		c.duringHold++
	}
	c.peakConns = max(c.peakConns, q.pool.Stat().TotalConns())
	switch {
	case strings.HasPrefix(sql, "select job_id,") && strings.HasSuffix(sql, " from jobs where job_id=$1"):
		c.jobReads++
	case strings.HasPrefix(sql, "select ") && strings.HasSuffix(sql, " from tasks where job_id=$1 group by status order by status"):
		c.taskCounts++
	case strings.HasPrefix(sql, "select response,") && strings.HasSuffix(sql, " from gateway_messages where message_id=$1"):
		c.mailboxReads++
	case strings.HasPrefix(sql, "insert "), strings.HasPrefix(sql, "update "), strings.HasPrefix(sql, "delete "):
		c.writes++
	case strings.HasPrefix(sql, "begin"), sql == "commit", sql == "rollback":
		c.txControl++
	}
	return ctx
}

func (*queryBudgetTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestRunJobDatabaseBudget(t *testing.T) {
	const hosts = 3
	const hold = 300 * time.Millisecond
	var tracer queryBudgetTracer
	var observer *fixture
	var completed atomic.Int32
	held, release := context.WithCancel(t.Context())
	defer release()
	f := setup(t, func(f *fixture) {
		// Both gateways use this pool for hand-written and sqlc statements.
		// Keep its capacity independent of the CI worker's CPU count and
		// above the connection budget so the peak assertion can fail.
		observer = &fixture{DB: f.DB}
		cfg := f.DB.Pool.Config()
		cfg.MaxConns = 24
		cfg.ConnConfig.Tracer = &tracer
		pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		f.DB = &store.Store{Pool: pool, Queries: db.New(pool)}
		f.BeforeMessage = func(e hostconn.Event) {
			if e.Message.GetTaskCompleted() == nil {
				return
			}
			// All three real agents must be in flight together. Hold their
			// completions while RunJob and all three dispatchers are waiting.
			if completed.Add(1) == hosts {
				tracer.mu.Lock()
				tracer.holdUntil = time.Now().Add(hold)
				tracer.mu.Unlock()
				time.Sleep(hold)
				release()
			}
			<-held.Done()
		}
	})
	r := request("stable")
	r.BatchSize = proto.Uint32(hosts)
	r.WaitSeconds = proto.Uint32(15)

	tracer.mu.Lock()
	tracer.pool = f.DB.Pool
	tracer.counts.peakConns = tracer.pool.Stat().TotalConns()
	start := time.Now()
	tracer.mu.Unlock()
	resp := run(t, f.A, r)
	if got := resp.GetJob(); got.GetStatus() != v1.JobStatus_JOB_STATUS_SUCCEEDED || got.GetTotalTasks() != hosts || completed.Load() != hosts {
		t.Fatalf("job status=%s total_tasks=%d agent_completions=%d; want succeeded on %d hosts", got.GetStatus(), got.GetTotalTasks(), completed.Load(), hosts)
	}
	// Output persistence can finish after the RPC returns. Wait for its
	// audit commits through the untraced observer so its polling costs zero
	// statements in the measurement.
	awaitFixtureOutputs(t, observer)
	tracer.mu.Lock()
	elapsed := time.Since(start)
	stat := tracer.pool.Stat()
	c := tracer.counts
	c.peakConns = max(c.peakConns, stat.TotalConns())
	tracer.pool = nil
	tracer.mu.Unlock()

	polls := c.jobReads + c.taskCounts + c.mailboxReads
	other := c.total - polls - c.writes - c.txControl
	t.Logf("hosts=%d elapsed=%s sql_total=%d poll_total=%d poll_jobs=%d poll_task_counts=%d poll_mailbox=%d writes=%d tx_control=%d other=%d hold=%s sql_during_hold=%d pool_peak_total_conns=%d pool_max_conns=%d",
		hosts, elapsed, c.total, polls, c.jobReads, c.taskCounts, c.mailboxReads, c.writes, c.txControl, other, hold, c.duringHold, c.peakConns, stat.MaxConns())

	// Three -race runs on bc694a1 used 329–343 statements (106–114 poll
	// reads) and 5–6 connections. Allow fixed lifecycle costs plus extra
	// ticks on slow CI workers. The 300ms hold has its own absolute ceiling:
	// about 75 reads (job, counts, three mailboxes every 20ms) plus gateway
	// maintenance. After #12, remeasure and lower the hold and poll budgets.
	const maxDuringHold = 130
	ticks := 1 + int(elapsed/(20*time.Millisecond))
	maxPolls := 10 + 6*ticks
	maxStatements := 275 + 8*ticks
	maxWrites := 65 + 2*(1+int(elapsed/(100*time.Millisecond))) // two gateways clean expired messages every 100ms
	const maxPeakConns = 14
	if c.total == 0 || c.writes == 0 || c.peakConns == 0 {
		t.Fatal("missing SQL or connections for a completed job")
	}
	if c.duringHold > maxDuringHold || polls > maxPolls || c.total > maxStatements || c.writes > maxWrites || c.peakConns > maxPeakConns {
		t.Errorf("database budget exceeded: hold_statements=%d/%d polls=%d/%d statements=%d/%d writes=%d/%d peak_conns=%d/%d", c.duringHold, maxDuringHold, polls, maxPolls, c.total, maxStatements, c.writes, maxWrites, c.peakConns, maxPeakConns)
	}
}
