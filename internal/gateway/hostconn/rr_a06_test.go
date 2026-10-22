package hostconn

import (
	"context"
	"slices"
	"testing"
	"time"
)

// RR-a-06: when the sender gives up and deletes its mailbox row, the connection
// must no longer count that row as an in-flight message for the task.
func TestSenderTimeoutForgetsPendingMailbox(t *testing.T) {
	s, db, ctx := newMailboxFixture(t)
	c := &connection{identity: Identity{HostID: "host"}, id: "old", pending: map[string][]string{"task": {"assignment"}}}
	s.connections["host"] = c
	caller, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := s.sendToConnection(caller, "host", "old", cancelMessage("task")); done <- err }()
	var mailbox string
	end := time.Now().Add(5 * time.Second)
	for mailbox == "" {
		if err := db.Pool.QueryRow(ctx, "SELECT COALESCE(max(message_id),'') FROM gateway_messages WHERE host_id='host'").Scan(&mailbox); err != nil {
			t.Fatal(err)
		}
		if mailbox == "" && time.Now().After(end) {
			t.Fatal("sender did not insert its mailbox row")
		}
		time.Sleep(time.Millisecond)
	}
	// The owner's write path records the delivered message before the sender gives up.
	c.mu.Lock()
	c.pending["task"] = append(c.pending["task"], mailbox)
	c.mu.Unlock()
	if err := <-done; err == nil {
		t.Fatal("unanswered cancel returned no error")
	}
	var rows int
	if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM gateway_messages WHERE message_id=$1", mailbox).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("mailbox rows after sender timeout=%d error=%v; want 0", rows, err)
	}
	c.mu.Lock()
	got := slices.Clone(c.pending["task"])
	c.mu.Unlock()
	if !slices.Equal(got, []string{"assignment"}) {
		t.Errorf("pending[task]=%v after sender deleted %s; want [assignment]", got, mailbox)
	}
}
