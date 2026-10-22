package job

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
)

// terminateTaskRead ends the backend that runs the first task event read, as a
// database restart or failover would.
type terminateTaskRead struct {
	admin      *pgxpool.Pool
	terminated atomic.Bool
	err        error
}

func (p *terminateTaskRead) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(d.SQL, "SELECT j.action_definition,") && p.terminated.CompareAndSwap(false, true) {
		var killed bool
		if p.err = p.admin.QueryRow(context.Background(), "SELECT pg_terminate_backend($1)", c.PgConn().PID()).Scan(&killed); p.err == nil && !killed {
			p.err = pgx.ErrNoRows
		}
	}
	return ctx
}
func (p *terminateTaskRead) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestOnMessageRetriesTransientDatabaseError(t *testing.T) {
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO gateway_instances(instance_id) VALUES ('fixture');
 INSERT INTO hosts(host_id,hostname,certificate_serial,certificate_expires_at) VALUES ('host','host','serial',now()+interval '1 hour');
 INSERT INTO jobs(job_id,created_at,subject_id,origin_instance,action,action_definition,catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures)
 VALUES ('job',now(),'sa','fixture','action',convert_to('{"max_output":1024}','UTF8'),'catalog',1,decode(repeat('00',32),'hex'),1,'test',2,1,0);
 CREATE TABLE tasks_fixture PARTITION OF tasks DEFAULT;
 INSERT INTO tasks(job_id,task_id,created_at,host_id,hostname,position,connection_id,dispatched,status,result)
 SELECT job_id,'task',created_at,'host','host',0,'connection',true,1,decode('0801','hex') FROM jobs WHERE job_id='job';`); err != nil {
		t.Fatal(err)
	}
	tracer := &terminateTaskRead{admin: db.Pool}
	cfg := db.Pool.Config()
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	traced := *db
	traced.Pool = pool
	s := &Service{Store: &traced, outputs: map[string]*taskOutput{}}
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.Close()

	started := hostconn.Event{HostID: "host", ConnectionID: "connection", Message: &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: "task"}}}}
	if err := s.OnMessage(ctx, started); err != nil {
		t.Fatalf("TaskStarted after a terminated database connection: %v", err)
	}
	if !tracer.terminated.Load() || tracer.err != nil {
		t.Fatalf("fixture did not terminate the task read connection: %v", tracer.err)
	}
	var status int16
	if err := db.Pool.QueryRow(ctx, "SELECT status FROM tasks WHERE task_id='task'").Scan(&status); err != nil || status != int16(v1.TaskStatus_TASK_STATUS_RUNNING) {
		t.Fatalf("task status=%d error=%v, want running", status, err)
	}

	unknown := hostconn.Event{HostID: "host", ConnectionID: "connection", Message: &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: "job", TaskId: "missing"}}}}
	if err := s.OnMessage(ctx, unknown); err == nil || err.Error() != "UNKNOWN_TASK_EVENT" {
		t.Fatalf("unknown task event error=%v, want UNKNOWN_TASK_EVENT", err)
	}
}
