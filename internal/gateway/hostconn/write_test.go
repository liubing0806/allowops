package hostconn

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgconn"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"google.golang.org/protobuf/proto"
)

func TestTaskWriteReleasesLifecycleLocks(t *testing.T) {
	dsn := testpg.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO gateway_instances(instance_id) VALUES ('fixture');
 INSERT INTO hosts(host_id,hostname,certificate_serial,certificate_expires_at,instance_id,connection_id)
 VALUES ('host','host','serial',now()+interval '1 hour','fixture','old');
 INSERT INTO jobs(job_id,created_at,subject_id,origin_instance,action,action_definition,catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures)
 VALUES ('job',now(),'sa','fixture','action',convert_to('{}','UTF8'),'catalog',1,decode(repeat('00',32),'hex'),1,'test',2,1,0);
 CREATE TABLE tasks_fixture PARTITION OF tasks DEFAULT;
 INSERT INTO tasks(job_id,task_id,created_at,host_id,hostname,position,connection_id,dispatched,status,result)
 SELECT job_id,'task',created_at,'host','host',0,'old',true,1,decode('0801','hex') FROM jobs;`); err != nil {
		t.Fatal(err)
	}
	message := &v1.ConnectResponse{Message: &v1.ConnectResponse_Task{Task: &v1.TaskAssignment{JobId: "job", TaskId: "task"}}}
	raw, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, "INSERT INTO gateway_messages(message_id,origin_instance,host_id,connection_id,request,expires_at) VALUES ('mail','fixture','host','old',$1,now()+interval '1 minute')", raw); err != nil {
		t.Fatal(err)
	}
	s := &Service{Store: db, Config: DefaultConfig()}
	c := &connection{identity: Identity{HostID: "host"}, id: "old", pending: map[string][]string{}, maxInflight: 1}
	item := outbound{message: message, mailbox: "mail"}
	// Every query runs in a separate transaction. NOWAIT directly establishes
	// whether the writer still owns the row locks, without timing assumptions.
	checkLocks := func(t *testing.T, held bool) {
		t.Helper()
		for _, query := range []string{
			"SELECT 1 FROM hosts WHERE host_id='host' FOR UPDATE NOWAIT",
			"SELECT 1 FROM jobs WHERE job_id='job' FOR UPDATE NOWAIT",
			"SELECT 1 FROM tasks WHERE job_id='job' AND task_id='task' FOR UPDATE NOWAIT",
		} {
			tx, err := db.Pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, query)
			tx.Rollback(ctx)
			var pgerr *pgconn.PgError
			if held {
				if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
					t.Errorf("writer lock missing for %s: %v", query, err)
				}
			} else if err != nil {
				t.Errorf("writer left a lock after returning for %s: %v", query, err)
			}
		}
	}
	// P4 also routes assignments independently of persisted P6 jobs. Exercise
	// real HTTP/2 streams through production write, including the denied cases.
	for _, test := range []struct {
		name, jobID, taskID, setup string
		allowed                    bool
	}{
		{"empty_job", "", "standalone-empty", "", true},
		{"unknown_job", "standalone-job", "standalone-nonempty", "", true},
		{"reserved_task", "job", "task", "", true},
		{"canceled_job", "job", "task", "UPDATE jobs SET cancel_requested=true", false},
		{"recovered_job", "job", "task", "UPDATE jobs SET status=5; UPDATE tasks SET status=7", false},
		{"missing_task", "job", "missing", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.setup != "" {
				if _, err := db.Pool.Exec(ctx, test.setup); err != nil {
					t.Fatal(err)
				}
			}
			defer func() {
				if _, err := db.Pool.Exec(ctx, "UPDATE jobs SET status=2,cancel_requested=false; UPDATE tasks SET status=1"); err != nil {
					t.Error(err)
				}
			}()
			assignment := &v1.ConnectResponse{Message: &v1.ConnectResponse_Task{Task: &v1.TaskAssignment{JobId: test.jobID, TaskId: test.taskID}}}
			raw, err := proto.Marshal(assignment)
			if err != nil {
				t.Fatal(err)
			}
			mailbox := "mail-" + test.name
			if _, err := db.Pool.Exec(ctx, "INSERT INTO gateway_messages(message_id,origin_instance,host_id,connection_id,request,expires_at) VALUES ($1,'fixture','host','old',$2,now()+interval '1 minute')", mailbox, raw); err != nil {
				t.Fatal(err)
			}
			written := make(chan error, 1)
			handler := connect.NewBidiStreamHandler("/test.Writer/Write", func(ctx context.Context, stream *connect.BidiStream[v1.ConnectRequest, v1.ConnectResponse]) error {
				if _, err := stream.Receive(); err != nil {
					written <- err
					return err
				}
				connection := &connection{identity: Identity{HostID: "host"}, id: "old", ctx: ctx, pending: map[string][]string{}, maxInflight: 1}
				err := s.write(connection, stream, outbound{message: assignment, mailbox: mailbox})
				written <- err
				return err
			})
			server := httptest.NewUnstartedServer(handler)
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			client := connect.NewClient[v1.ConnectRequest, v1.ConnectResponse](server.Client(), server.URL+"/test.Writer/Write", connect.WithGRPC())
			stream := client.CallBidiStream(ctx)
			defer stream.CloseResponse()
			if err := stream.Send(&v1.ConnectRequest{}); err != nil {
				t.Fatal(err)
			}
			defer stream.CloseRequest()
			response, receiveErr := stream.Receive()
			if test.allowed {
				if receiveErr != nil || !proto.Equal(response.GetTask(), assignment.GetTask()) {
					t.Errorf("standalone assignment jobID=%q receive=%v error=%v; want original TaskAssignment", test.jobID, response, receiveErr)
				}
			} else if receiveErr == nil || response.GetTask() != nil {
				t.Errorf("inactive or unreserved task reached stream: response=%v error=%v", response, receiveErr)
			}
			if err := <-written; err != nil {
				t.Errorf("write returned %v", err)
			}
		})
	}

	t.Run("write_error", func(t *testing.T) {
		writeErr := errors.New("fixture stream write deadline failure")
		c.ctx = WithWriteDeadline(ctx, func(time.Time) error {
			checkLocks(t, true)
			return writeErr
		})
		// The production write reaches send with all locks held. Its actual
		// write-deadline error path returns before dereferencing the nil stream.
		if err := s.write(c, nil, item); !errors.Is(err, writeErr) {
			t.Fatalf("write error=%v want %v", err, writeErr)
		}
		checkLocks(t, false)
	})
	t.Run("connection_replaced", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, "UPDATE hosts SET connection_id='replacement' WHERE host_id='host'"); err != nil {
			t.Fatal(err)
		}
		c.ctx = ctx
		if err := s.write(c, nil, item); !errors.Is(err, store.ErrOffline) {
			t.Fatalf("replaced connection write error=%v want offline", err)
		}
		checkLocks(t, false)
		if _, err := db.Pool.Exec(ctx, "UPDATE hosts SET connection_id='old' WHERE host_id='host'"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("terminal_mailbox_update_error", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `UPDATE jobs SET cancel_requested=true;
 CREATE FUNCTION reject_mailbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture mailbox update rejected'; END $$;
 CREATE TRIGGER reject_mailbox BEFORE UPDATE ON gateway_messages FOR EACH ROW EXECUTE FUNCTION reject_mailbox();`); err != nil {
			t.Fatal(err)
		}
		if err := s.write(c, nil, item); err == nil {
			t.Fatal("expected mailbox SQL error")
		}
		checkLocks(t, false)
	})
}
