package hostconn

import (
	"context"
	"errors"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
)

// newMailboxFixture returns a Service with an active host owned by connection "old"
// and no running listener, so a mailbox row is never delivered or answered.
func newMailboxFixture(t *testing.T) (*Service, *store.Store, context.Context) {
	t.Helper()
	dsn := testpg.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if _, err := db.Pool.Exec(ctx, `INSERT INTO gateway_instances(instance_id) VALUES ('fixture');
 INSERT INTO hosts(host_id,hostname,certificate_serial,certificate_expires_at,instance_id,connection_id)
 VALUES ('host','host','serial',now()+interval '1 hour','fixture','old')`); err != nil {
		t.Fatal(err)
	}
	return &Service{Store: db, Config: DefaultConfig(), InstanceID: "fixture", ctx: ctx, connections: map[string]*connection{}}, db, ctx
}

func cancelMessage(task string) *v1.ConnectResponse {
	return &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{JobId: "job", TaskId: task, Reason: "CANCELLED"}}}
}

// lateDoneContext reports a deadline but never closes Done: the state in which the
// mailbox poll tick runs after the deadline and before the context's own timer.
type lateDoneContext struct {
	context.Context
	deadline time.Time
}

func (c lateDoneContext) Deadline() (time.Time, bool) { return c.deadline, true }

// RR-a-03: a mailbox that expires at the caller's own deadline is the caller's
// timeout, not evidence that the host is offline.
func TestMailboxExpiryAtCallerDeadlineIsNotOffline(t *testing.T) {
	s, _, ctx := newMailboxFixture(t)
	caller := lateDoneContext{Context: ctx, deadline: time.Now().Add(500 * time.Millisecond)}
	_, err := s.sendToConnection(caller, "host", "old", cancelMessage("task"))
	if errors.Is(err, store.ErrOffline) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("send error=%v; want context deadline exceeded, not %v", err, store.ErrOffline)
	}
}

// RR-a-03 reverse cases: only a mailbox that expires at the caller's own deadline
// is the caller's timeout. A mailbox whose TTL ends before the caller's deadline,
// or a caller without any deadline, means the host did not answer in time and the
// host is reported offline. A fix that returns DeadlineExceeded for every expiry
// fails these tests.
func TestMailboxExpiryBeforeCallerDeadlineIsOffline(t *testing.T) {
	s, _, _ := newMailboxFixture(t)
	s.Config.MailboxTTL = 200 * time.Millisecond
	caller, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	_, err := s.sendToConnection(caller, "host", "old", cancelMessage("task"))
	if !errors.Is(err, store.ErrOffline) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("send error=%v; want %v when the mailbox TTL ends before the caller deadline", err, store.ErrOffline)
	}
}

func TestMailboxExpiryWithoutCallerDeadlineIsOffline(t *testing.T) {
	s, _, _ := newMailboxFixture(t)
	s.Config.MailboxTTL = 200 * time.Millisecond
	caller, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if _, ok := caller.Deadline(); ok {
		t.Fatal("fixture caller context must have no deadline")
	}
	_, err := s.sendToConnection(caller, "host", "old", cancelMessage("task"))
	if !errors.Is(err, store.ErrOffline) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("send error=%v; want %v when the caller has no deadline", err, store.ErrOffline)
	}
}
