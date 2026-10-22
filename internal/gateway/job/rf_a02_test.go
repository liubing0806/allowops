package job_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"google.golang.org/protobuf/proto"
)

type rfA02Request struct{}
type rfA02Commit struct{}
type rfA02Tracer struct {
	admin           *pgxpool.Pool
	cancel          context.CancelFunc
	kill            bool
	committed       atomic.Bool
	fault           atomic.Bool
	injectionErrors chan error
}

func (p *rfA02Tracer) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if ctx.Value(rfA02Request{}) == nil {
		return ctx
	}
	if d.SQL == "commit" {
		return context.WithValue(ctx, rfA02Commit{}, true)
	}
	if p.kill && p.committed.Load() && strings.HasPrefix(d.SQL, "SELECT job_id,action,catalog_id,") && p.fault.CompareAndSwap(false, true) {
		control, done := context.WithTimeout(context.Background(), 2*time.Second)
		defer done()
		var killed bool
		if err := p.admin.QueryRow(control, "SELECT pg_terminate_backend($1)", c.PgConn().PID()).Scan(&killed); err != nil || !killed {
			if err == nil {
				err = errors.New("own post-commit backend was not terminated")
			}
			select {
			case p.injectionErrors <- fmt.Errorf("inject post-commit connection failure: %w", err):
			default:
			}
		}
	}
	return ctx
}
func (p *rfA02Tracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if ctx.Value(rfA02Commit{}) == true && d.Err == nil {
		p.committed.Store(true)
		if p.cancel != nil {
			p.cancel()
		}
	}
}
func TestRFA02CommittedJobRetainsScheduler(t *testing.T) {
	for _, mode := range []string{"request_cancelled_after_commit", "postcommit_get_connection_failure", "commit_rejected"} {
		t.Run(mode, func(t *testing.T) {
			requestBase, cancelRequest := context.WithCancel(context.Background())
			defer cancelRequest()
			tracer := &rfA02Tracer{kill: mode == "postcommit_get_connection_failure", injectionErrors: make(chan error, 1)}
			if mode == "request_cancelled_after_commit" {
				tracer.cancel = cancelRequest
			}
			f := setup(t, func(f *fixture) {
				tracer.admin = f.DB.Pool
				traced := tracedJobStore(t, f.DB, tracer)
				f.BeforeStart = func(_ *hostconn.Service, jobs *job.Service) {
					if f.A == nil {
						jobs.Store = traced
					}
				}
			})
			t.Cleanup(func() { awaitFixtureOutputs(t, f) })
			ctx, cancel := context.WithTimeout(requestBase, 15*time.Second)
			defer cancel()
			if _, err := f.DB.Pool.Exec(context.Background(), `CREATE OR REPLACE FUNCTION rf_reject_create() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
   IF NEW.reason='rf-commit_rejected' THEN RAISE EXCEPTION 'fixture deferred create rejection'; END IF; RETURN NULL; END $$;`); err != nil {
				t.Fatal(err)
			}
			if mode == "commit_rejected" {
				if _, err := f.DB.Pool.Exec(context.Background(), `CREATE CONSTRAINT TRIGGER rf_reject_create AFTER INSERT ON jobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rf_reject_create()`); err != nil {
					t.Fatal(err)
				}
			}
			req := httptest.NewRequest(http.MethodPost, "https://"+f.A.Address+"/mcp", nil).WithContext(context.WithValue(ctx, rfA02Request{}, true))
			req.TLS = &tls.ConnectionState{}
			req.Header.Set("Authorization", "Bearer "+f.Token)
			r := request("stable")
			r.Reason = "rf-" + mode
			r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host"}}}}
			r.ExpectedCount = nil
			r.WaitSeconds = proto.Uint32(0)
			var callErr error
			f.A.Job.Access.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) { _, callErr = f.A.Job.RunJob(req.Context(), r) })).ServeHTTP(httptest.NewRecorder(), req)
			select {
			case err := <-tracer.injectionErrors:
				t.Fatalf("fixture injection failed: %v", err)
			default:
			}
			t.Logf("production RunJob response error=%v committed=%t injected_read_fault=%t", callErr, tracer.committed.Load(), tracer.fault.Load())
			if callErr == nil {
				t.Fatal("fixture did not provoke expected RPC failure")
			}
			var id string
			err := f.DB.Pool.QueryRow(context.Background(), "SELECT job_id FROM jobs WHERE reason=$1", r.Reason).Scan(&id)
			if mode == "commit_rejected" {
				if err != pgx.ErrNoRows || tracer.committed.Load() {
					t.Fatalf("failed commit retained job id=%s error=%v", id, err)
				}
				return
			}
			if err != nil || !tracer.committed.Load() {
				t.Fatalf("no committed job id=%s error=%v", id, err)
			}
			var status int16
			eventually(t, func() bool {
				if err := f.DB.Pool.QueryRow(context.Background(), "SELECT status FROM jobs WHERE job_id=$1", id).Scan(&status); err != nil {
					t.Fatal(err)
				}
				return status > 2
			})
			var healthy bool
			if err := f.DB.Pool.QueryRow(context.Background(), "SELECT last_seen>now()-$2*interval '1 second' FROM gateway_instances WHERE instance_id=$1", f.A.Host.InstanceID, api.InstanceLostAfter(f.A.Host.Config).Seconds()).Scan(&healthy); err != nil {
				t.Fatal(err)
			}
			if status != int16(v1.JobStatus_JOB_STATUS_SUCCEEDED) || !healthy {
				t.Errorf("committed job status=%d owner_healthy=%t; want SUCCEEDED(3),true", status, healthy)
			}
		})
	}
}
