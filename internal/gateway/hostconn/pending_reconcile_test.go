package hostconn

import (
	"context"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/store"
)

var tickSeq int

// runMaintenance starts the production maintenance loop with a short cleanup tick
// and returns a function that waits until two further full ticks have completed.
func runMaintenance(ctx context.Context, t *testing.T, s *Service, db *store.Store) (waitTicks func()) {
	t.Helper()
	s.Config.CleanupInterval = 20 * time.Millisecond
	run, stop := context.WithCancel(ctx)
	s.ctx = run
	done := make(chan struct{})
	go func() { s.maintenance(); close(done) }()
	t.Cleanup(func() { stop(); <-done })
	return func() {
		t.Helper()
		// An expired row is deleted by the cleanup step of a tick, so its removal
		// proves that a tick started after the row was inserted. The step that
		// reconciles runs in the same tick, before the next one can begin.
		for range 2 {
			tickSeq++
			id := "tick-" + strconv.Itoa(tickSeq)
			if _, err := db.Pool.Exec(ctx, "INSERT INTO gateway_messages(message_id,origin_instance,host_id,connection_id,request,expires_at) VALUES ($1,'fixture','host','old','',now()-interval '1 second')", id); err != nil {
				t.Fatal(err)
			}
			end := time.Now().Add(5 * time.Second)
			for {
				var n int
				if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM gateway_messages WHERE message_id=$1", id).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n == 0 {
					break
				}
				if time.Now().After(end) {
					t.Fatal("maintenance cleanup did not run")
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
	}
}

func pendingOf(c *connection, task string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.pending[task])
}

func insertTask(ctx context.Context, t *testing.T, db *store.Store, taskID string, status int, connection string) {
	t.Helper()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO jobs(job_id,created_at,subject_id,origin_instance,action,action_definition,catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures)
 VALUES ('job-'||$1::text,now(),'sa','fixture','action',convert_to('{}','UTF8'),'catalog',1,decode(repeat('00',32),'hex'),1,'test',2,1,0)`, taskID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO tasks(job_id,task_id,created_at,host_id,hostname,position,connection_id,dispatched,status,result)
 SELECT job_id,$1::text,created_at,'host','host',0,$3::text,true,$2::smallint,'' FROM jobs WHERE job_id='job-'||$1::text`, taskID, status, connection); err != nil {
		t.Fatal(err)
	}
}

func taskFixture(ctx context.Context, t *testing.T, db *store.Store) {
	t.Helper()
	if _, err := db.Pool.Exec(ctx, "CREATE TABLE tasks_fixture PARTITION OF tasks DEFAULT"); err != nil {
		t.Fatal(err)
	}
}

// A mailbox row deleted by a sender on another instance leaves the owner's pending
// entry behind; only the owner can drop it. Without that, the entry counts against
// MaxInflight until reconnect.
func TestMaintenanceDropsPendingMailboxOfFinishedTask(t *testing.T) {
	s, db, ctx := newMailboxFixture(t)
	taskFixture(ctx, t, db)
	insertTask(ctx, t, db, "finished", 3, "old")
	c := &connection{identity: Identity{HostID: "host"}, id: "old", pending: map[string][]string{"finished": {"gone-1"}, "unknown": {"gone-2"}}}
	s.connections["host"] = c
	runMaintenance(ctx, t, s, db)()
	for _, task := range []string{"finished", "unknown"} {
		if got := pendingOf(c, task); len(got) != 0 {
			t.Errorf("pending[%s]=%v after maintenance; want the mailbox without a row to be dropped", task, got)
		}
	}
}

// A task that is still executing keeps occupying its slot even when the sender of
// its assignment is gone, and a mailbox that still has a row is never dropped.
func TestMaintenanceKeepsPendingMailboxOfRunningTask(t *testing.T) {
	s, db, ctx := newMailboxFixture(t)
	taskFixture(ctx, t, db)
	insertTask(ctx, t, db, "running", 2, "old")
	insertTask(ctx, t, db, "answered", 3, "old")
	if _, err := db.Pool.Exec(ctx, "INSERT INTO gateway_messages(message_id,origin_instance,host_id,connection_id,request,expires_at) VALUES ('live','fixture','host','old','',now()+interval '1 hour')"); err != nil {
		t.Fatal(err)
	}
	c := &connection{identity: Identity{HostID: "host"}, id: "old", pending: map[string][]string{"running": {"gone-assignment"}, "answered": {"live"}}}
	s.connections["host"] = c
	runMaintenance(ctx, t, s, db)()
	if got := pendingOf(c, "running"); !slices.Equal(got, []string{"gone-assignment"}) {
		t.Errorf("pending[running]=%v; want the executing task to keep its slot", got)
	}
	if got := pendingOf(c, "answered"); !slices.Equal(got, []string{"live"}) {
		t.Errorf("pending[answered]=%v; want a mailbox with a row to be kept", got)
	}
}

// A cancel appended behind the assignment of a running task is dropped once its
// row is gone, so a retry of the cancel is not rejected for capacity; the
// assignment keeps the slot.
func TestMaintenanceDropsStaleCancelBehindRunningTask(t *testing.T) {
	s, db, ctx := newMailboxFixture(t)
	taskFixture(ctx, t, db)
	insertTask(ctx, t, db, "running", 2, "old")
	c := &connection{identity: Identity{HostID: "host"}, id: "old", pending: map[string][]string{"running": {"gone-assignment", "gone-cancel"}}}
	s.connections["host"] = c
	runMaintenance(ctx, t, s, db)()
	if got := pendingOf(c, "running"); !slices.Equal(got, []string{"gone-assignment"}) {
		t.Errorf("pending[running]=%v; want [gone-assignment]", got)
	}
}

// Two instances: instance A cancels through instance B's connection and its caller
// times out. A deletes the row but has no connection, so B must reconcile.
func TestCrossInstanceSenderTimeoutIsReconciledByOwner(t *testing.T) {
	owner, db, ctx := newMailboxFixture(t)
	sender := &Service{Store: db, Config: DefaultConfig(), InstanceID: "sender", ctx: ctx, connections: map[string]*connection{}}
	if _, err := db.Pool.Exec(ctx, "INSERT INTO gateway_instances(instance_id) VALUES ('sender')"); err != nil {
		t.Fatal(err)
	}
	c := &connection{identity: Identity{HostID: "host"}, id: "old", pending: map[string][]string{}}
	owner.connections["host"] = c
	caller, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := sender.sendToConnection(caller, "host", "old", cancelMessage("task")); done <- err }()
	var mailbox string
	end := time.Now().Add(5 * time.Second)
	for mailbox == "" {
		if err := db.Pool.QueryRow(ctx, "SELECT COALESCE(max(message_id),'') FROM gateway_messages WHERE origin_instance='sender'").Scan(&mailbox); err != nil {
			t.Fatal(err)
		}
		if mailbox == "" && time.Now().After(end) {
			t.Fatal("sender did not insert its mailbox row")
		}
		time.Sleep(time.Millisecond)
	}
	// The owner's write path records the delivered cancel.
	c.mu.Lock()
	c.pending["task"] = []string{mailbox}
	c.mu.Unlock()
	if err := <-done; err == nil {
		t.Fatal("unanswered cancel returned no error")
	}
	if got := pendingOf(c, "task"); !slices.Equal(got, []string{mailbox}) {
		t.Fatalf("sender instance changed the owner's pending: %v", got)
	}
	runMaintenance(ctx, t, owner, db)()
	if got := pendingOf(c, "task"); len(got) != 0 {
		t.Errorf("owner pending[task]=%v after maintenance; want the cancel of an absent task dropped", got)
	}
}
