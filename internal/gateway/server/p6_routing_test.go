package server_test

import (
	"context"
	"errors"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store"
)

func TestGenerationBoundTasksOutliveMailboxTTL(t *testing.T) {
	f := setup(t)
	f.a.service.Config.MailboxTTL = 50 * time.Millisecond
	// Model a delayed mailbox commit: an unbound message may expire before
	// NOTIFY can deliver it, while a generation-bound task must remain live.
	if _, err := f.store.Pool.Exec(context.Background(), `
		CREATE FUNCTION delay_mailbox_insert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN PERFORM pg_sleep(0.12); RETURN NEW; END $$;
		CREATE TRIGGER delay_mailbox_insert BEFORE INSERT ON gateway_messages
		FOR EACH ROW EXECUTE FUNCTION delay_mailbox_insert()`); err != nil {
		t.Fatal(err)
	}
	host, cert := f.join(t, f.a, "p6-long-task")
	stream, hello := open(t, f.b, cert, "2.3.4")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, bound := range []bool{false, true} {
		id := "original"
		if bound {
			id = "bound"
		}
		message := &v1.ConnectResponse{Message: &v1.ConnectResponse_Task{Task: &v1.TaskAssignment{JobId: "job-test", TaskId: id}}}
		result := make(chan error, 1)
		go func() {
			var err error
			if bound {
				_, err = f.a.service.SendToConnection(ctx, host.HostId, hello.ConnectionId, message)
			} else {
				_, err = f.a.service.Send(ctx, host.HostId, message)
			}
			result <- err
		}()
		// The original Send may expire before delivery; only the bound task
		// promises to survive the delayed commit and await TaskCompleted.
		if bound {
			if m := receive(t, stream); m.GetTask().GetTaskId() != id {
				t.Fatalf("task=%v want %s", m, id)
			}
			select {
			case err := <-result:
				t.Fatalf("bound task returned before completion: %v", err)
			case <-time.After(2 * f.a.service.Config.MailboxTTL):
			}
			if err := stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_TaskCompleted{TaskCompleted: &v1.TaskCompleted{JobId: "job-test", TaskId: id}}}); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case err := <-result:
			if bound && err != nil {
				t.Fatalf("bound task exceeded mailbox TTL: %v", err)
			}
			if !bound && !errors.Is(err, store.ErrOffline) {
				t.Fatalf("original Send=%v want offline at mailbox TTL", err)
			}
		case <-ctx.Done():
			t.Fatal("router result deadline")
		}
	}
	if _, err := f.a.service.SendToConnection(ctx, host.HostId, "obsolete", &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{TaskId: "obsolete"}}}); !errors.Is(err, store.ErrOffline) {
		t.Fatalf("obsolete generation=%v", err)
	}
}
