package hostconn

import (
	"context"
	"errors"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jackc/pgx/v5"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
	"google.golang.org/protobuf/proto"
)

type mailboxPollDB struct {
	db.DBTX
	started time.Time
	reads   []time.Duration
	replyAt time.Duration
	reply   []byte
}

func (d *mailboxPollDB) QueryRow(context.Context, string, ...any) pgx.Row {
	elapsed := time.Since(d.started)
	d.reads = append(d.reads, elapsed)
	if elapsed >= d.replyAt {
		return mailboxPollRow{d.reply}
	}
	return mailboxPollRow{}
}

type mailboxPollRow struct{ reply []byte }

func (r mailboxPollRow) Scan(dest ...any) error {
	*dest[0].(*[]byte) = r.reply
	*dest[1].(*string) = ""
	return nil
}

func TestMailboxResultPollsWithBackoff(t *testing.T) {
	reply, err := proto.Marshal(&v1.TaskCompleted{TaskId: "task"})
	if err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		reader := &mailboxPollDB{started: start, replyAt: 10 * time.Millisecond, reply: reply}
		ctx := context.Background()
		s := &Service{Store: &store.Store{Queries: db.New(reader)}, ctx: ctx}
		got, err := s.awaitMailboxResult(ctx, "message", start.Add(time.Second))
		if err != nil || got.GetTaskId() != "task" || !slices.Equal(reader.reads, []time.Duration{20 * time.Millisecond}) {
			t.Errorf("short mailbox task=%q err=%v reads=%v, want reply at 20ms", got.GetTaskId(), err, reader.reads)
		}

		start = time.Now()
		reader.started = start
		reader.replyAt = 2 * time.Second
		reader.reads = nil
		expiry := 813 * time.Millisecond
		_, err = s.awaitMailboxResult(ctx, "message", start.Add(expiry))
		want := []time.Duration{20, 60, 140, 300, 550, 800}
		for i := range want {
			want[i] *= time.Millisecond
		}
		if !slices.Equal(reader.reads, want) {
			t.Errorf("unanswered mailbox reads=%v, want %v", reader.reads, want)
		}
		if !errors.Is(err, store.ErrOffline) || time.Since(start) != expiry {
			t.Errorf("mailbox expired after %s with %v, want %s and offline", time.Since(start), err, expiry)
		}
	})
}
