package job_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"google.golang.org/protobuf/proto"
)

type rfP6Value struct{}

type rfP6Audit struct {
	audit.Appender
	pool                                *pgxpool.Pool
	cancel                              context.CancelFunc
	cancelResult, block, authorizedFail bool
	value                               any
	remaining                           time.Duration
	payload                             audit.Payload
}

func (s *rfP6Audit) Append(ctx context.Context, p audit.Payload) (audit.Event, error) {
	if p.Reason == "authorized" && s.authorizedFail {
		return audit.Event{}, errors.New("fixture authorized audit failure")
	}
	if p.Reason != "result" {
		return s.Appender.Append(ctx, p)
	}
	s.payload = p
	s.value = ctx.Value(rfP6Value{})
	s.remaining = -1
	if deadline, ok := ctx.Deadline(); ok {
		s.remaining = time.Until(deadline)
	}
	if s.cancelResult {
		s.cancel()
	}
	if s.block {
		control, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		tx, err := s.pool.Begin(control)
		if err != nil {
			return audit.Event{}, err
		}
		if _, err := tx.Exec(control, "SELECT pg_advisory_xact_lock(418007)"); err != nil {
			tx.Rollback(context.Background())
			return audit.Event{}, err
		}
		var once sync.Once
		release := func() {
			once.Do(func() {
				cleanup, done := context.WithTimeout(context.Background(), time.Second)
				defer done()
				_ = tx.Rollback(cleanup)
			})
		}
		timer := time.AfterFunc(6*time.Second, release)
		defer func() { timer.Stop(); release() }()
	}
	return s.Appender.Append(ctx, p)
}

func TestRFB01P6CancelledResultsPersist(t *testing.T) {
	for _, mode := range []string{"committed_write", "read", "deny", "bounded_result_failure", "authorized_failure"} {
		t.Run(mode, func(t *testing.T) {
			requestBase, cancelRequest := context.WithCancel(context.Background())
			defer cancelRequest()
			var spy *rfP6Audit
			tracer := &rfA02Tracer{}
			if mode == "committed_write" {
				tracer.cancel = cancelRequest
			}
			f := setup(t, func(f *fixture) {
				spy = &rfP6Audit{Appender: audit.New(f.DB.Pool, audit.Config{}), pool: f.DB.Pool, cancel: cancelRequest, cancelResult: mode == "read" || mode == "deny", block: mode == "bounded_result_failure", authorizedFail: mode == "authorized_failure"}
				tracer.admin = f.DB.Pool
				traced := tracedJobStore(t, f.DB, tracer)
				f.BeforeStart = func(_ *hostconn.Service, jobs *job.Service) {
					if f.A == nil {
						jobs.Store = traced
						jobs.Audit = spy
					}
				}
			})
			t.Cleanup(func() {
				if mode != "bounded_result_failure" {
					awaitFixtureOutputs(t, f)
					return
				}
				// This case deliberately blocks P7, including unrelated output
				// audits. Join output state writes without requiring those
				// deliberately unavailable audits to have succeeded.
				eventually(t, func() bool {
					cleanup, done := context.WithTimeout(context.Background(), time.Second)
					defer done()
					var pending int
					if err := f.DB.Pool.QueryRow(cleanup, "SELECT count(*) FROM tasks WHERE output_state='pending'").Scan(&pending); err != nil {
						t.Fatal(err)
					}
					return pending == 0
				})
			})
			defer func() {
				var last uint64
				if err := f.DB.Pool.QueryRow(context.Background(), "SELECT max(seq) FROM audit_events").Scan(&last); err != nil {
					t.Error(err)
					return
				}
				verification, err := audit.New(f.DB.Pool, audit.Config{}).Verify(context.Background(), audit.VerifyOptions{From: 1, To: last})
				if err != nil || !verification.Valid {
					t.Errorf("real P7 chain verification=%+v error=%v", verification, err)
				}
			}()
			id := run(t, f.B, request("stable")).Job.JobId
			ctx, cancel := context.WithTimeout(requestBase, 15*time.Second)
			defer cancel()
			ctx = context.WithValue(ctx, rfP6Value{}, "retained-request-value")
			req := httptest.NewRequest(http.MethodPost, "https://"+f.A.Address+"/mcp", nil).WithContext(context.WithValue(ctx, rfA02Request{}, true))
			req.TLS = &tls.ConnectionState{}
			req.RemoteAddr = "192.0.2.37:1234"
			req.Header.Set("Authorization", "Bearer "+f.Token)
			var callErr error
			started := time.Now()
			f.A.Job.Access.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				if mode == "read" {
					_, callErr = f.A.Job.GetJob(r.Context(), &v1.GetJobRequest{JobId: id, WaitSeconds: proto.Uint32(0)})
				} else if mode == "deny" {
					_, callErr = f.A.Job.GetJob(r.Context(), &v1.GetJobRequest{JobId: "unknown-rf-p6"})
				} else {
					runRequest := request("stable")
					runRequest.Reason = "rf-p6-" + mode
					runRequest.WaitSeconds = proto.Uint32(0)
					_, callErr = f.A.Job.RunJob(r.Context(), runRequest)
				}
			})).ServeHTTP(httptest.NewRecorder(), req)
			elapsed := time.Since(started)
			t.Logf("mode=%s response=%v result deadline remaining=%s elapsed=%s", mode, callErr, spy.remaining, elapsed)
			if mode == "authorized_failure" {
				var n int
				if err := f.DB.Pool.QueryRow(context.Background(), "SELECT count(*) FROM jobs WHERE reason=$1", "rf-p6-"+mode).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n != 0 || spy.payload.Operation != "" || connect.CodeOf(callErr) != connect.CodeUnavailable {
					t.Errorf("authorized failure jobs=%d result=%s response=%v", n, spy.payload.Operation, callErr)
				}
				return
			}
			if spy.value != "retained-request-value" || spy.payload.SubjectID != "sa" || spy.payload.SourceIP != "192.0.2.37" {
				t.Errorf("result context/payload lost attribution: value=%v subject=%s source=%s", spy.value, spy.payload.SubjectID, spy.payload.SourceIP)
			}
			if spy.remaining <= 0 || spy.remaining > 5*time.Second {
				t.Errorf("result audit deadline remaining=%s; want independent deadline within 5s", spy.remaining)
			}
			if mode == "bounded_result_failure" {
				detail := ""
				if rpc, ok := callErr.(*connect.Error); ok {
					for _, d := range rpc.Details() {
						v, _ := d.Value()
						if value, ok := v.(*v1.ErrorDetail); ok {
							detail = value.Reason
						}
					}
				}
				if elapsed > 6*time.Second || detail != "AUDIT_RESULT_UNAVAILABLE" {
					t.Errorf("bounded committed result failure elapsed=%s detail=%s; want <=6s AUDIT_RESULT_UNAVAILABLE", elapsed, detail)
				}
				return
			}
			var count int
			if err := f.DB.Pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_events WHERE operation=$1 AND reason='result' AND job_id=$2 AND subject_id='sa' AND source_ip='192.0.2.37'", spy.payload.Operation, spy.payload.JobID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Errorf("persisted P6 result audits=%d for %s job=%s; want 1 after client cancellation", count, mode, spy.payload.JobID)
			}
			if mode == "read" && callErr != nil {
				t.Errorf("read response=%v; want original successful read", callErr)
			}
			if mode == "deny" && connect.CodeOf(callErr) != connect.CodeNotFound {
				t.Errorf("deny response=%v; want original NOT_FOUND", callErr)
			}
			if mode == "committed_write" && !tracer.committed.Load() {
				t.Fatal("write was not actually committed")
			}
		})
	}
}
