package audit

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	dbstore "github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
)

func migratedAuditPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testpg.Start(t)
	if err := dbstore.Migrate(t.Context(), dsn); err != nil {
		t.Fatal(err)
	}
	owner, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	return owner
}

func auditWriter(t *testing.T, owner *pgxpool.Pool, now func() time.Time) *Store {
	t.Helper()
	config := owner.Config()
	config.ConnConfig.RuntimeParams["role"] = "allowops_audit_writer"
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return New(pool, Config{Now: now})
}

// Migration 2 creates the partitions and records its timestamp in the same
// transaction. That UTC month stays unambiguous even across midnight on month end.
func auditMigrationMonth(t *testing.T, owner *pgxpool.Pool) time.Time {
	t.Helper()
	var month time.Time
	err := owner.QueryRow(t.Context(), "SELECT date_trunc('month', tstamp::timestamptz, 'UTC') FROM goose_db_version WHERE version_id=2 AND is_applied").Scan(&month)
	if err != nil {
		t.Fatal(err)
	}
	return month.UTC()
}

func TestAuditPartitionTimeTravelRollover(t *testing.T) {
	ctx := t.Context()
	owner := migratedAuditPool(t)
	first := auditMigrationMonth(t, owner)
	var now time.Time
	writer := auditWriter(t, owner, func() time.Time { return now })
	payload := Payload{Operation: "monthly_event"}
	previous := make([]byte, 32)
	for month := 0; month < 6; month++ {
		now = first.AddDate(0, month, 0)
		if month == 3 {
			_, err := writer.Append(ctx, payload)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.TableName != "audit_events" || !strings.Contains(pgErr.Message, "no partition") {
				t.Fatalf("append at %s: got %v, want missing partition for audit_events (23514)", now, err)
			}
			if _, err := owner.Exec(ctx, "SELECT audit_create_partitions($1, 3)", now); err != nil {
				t.Fatalf("create partitions from %s: %v", now, err)
			}
		}
		event, err := writer.Append(ctx, payload)
		if err != nil {
			t.Fatalf("append at %s: %v", now, err)
		}
		if event.Seq != uint64(month+1) || !bytes.Equal(event.PrevHash, previous) {
			t.Fatalf("month +%d: seq=%d prev_hash=%x, want %d and %x", month, event.Seq, event.PrevHash, month+1, previous)
		}
		var partition string
		err = writer.Pool.QueryRow(ctx, "SELECT tableoid::regclass::text FROM audit_events WHERE seq=$1 AND at=$2", event.Seq, now).Scan(&partition)
		if want := now.Format("audit_events_200601"); err != nil || partition != want {
			t.Fatalf("seq %d: partition=%q err=%v, want %q", event.Seq, partition, err, want)
		}
		previous = event.Hash
	}
	result, err := writer.Verify(ctx, VerifyOptions{From: 1, To: 6, ExpectedFinalHash: previous})
	if err != nil || !result.Valid || result.CheckedCount != 6 {
		t.Fatalf("verify six monthly partitions: %+v err=%v", result, err)
	}
}

func TestAuditExporterStorageFaultAndRecovery(t *testing.T) {
	ctx := t.Context()
	writer := auditWriter(t, migratedAuditPool(t), nil)
	var mu sync.Mutex
	var attempts int
	var committed []uint64
	storage := storageFunc(func(_ context.Context, events []Event) error {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts <= 2 {
			return syscall.EIO
		}
		for _, event := range events {
			committed = append(committed, event.Seq)
		}
		return nil
	})
	exporter := Exporter{Store: writer, Storage: storage, Cursor: "storage_recovery"}
	var last Event
	for range 5 {
		event, err := writer.Append(ctx, Payload{Operation: "export_event"})
		if err != nil {
			t.Fatal(err)
		}
		last = event
	}
	checkCursor := func(wantNext uint64, wantHash []byte) {
		t.Helper()
		var next uint64
		var preceding []byte
		err := writer.Pool.QueryRow(ctx, "SELECT next_seq, preceding_hash FROM audit_export_cursors WHERE name=$1", exporter.Cursor).Scan(&next, &preceding)
		if err != nil || next != wantNext || !bytes.Equal(preceding, wantHash) {
			t.Fatalf("cursor next_seq=%d preceding_hash=%x err=%v, want %d and %x", next, preceding, err, wantNext, wantHash)
		}
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if n, err := exporter.Once(ctx); n != 0 || !errors.Is(err, syscall.EIO) {
			t.Fatalf("attempt %d: exported=%d err=%v, want 0 and EIO", attempt, n, err)
		}
		checkCursor(1, make([]byte, 32))
	}
	for _, want := range []uint64{5, 0} {
		if n, err := exporter.Once(ctx); n != want || err != nil {
			t.Fatalf("recovery: exported=%d err=%v, want %d", n, err, want)
		}
		checkCursor(last.Seq+1, last.Hash)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []uint64{1, 2, 3, 4, 5}; attempts != 3 || !slices.Equal(committed, want) {
		t.Fatalf("Commit calls=%d committed seqs=%v, want 3 calls and %v", attempts, committed, want)
	}
}

func TestAuditCheckpointsClockAndCancel(t *testing.T) {
	owner := migratedAuditPool(t)
	ctx, stop := context.WithTimeout(t.Context(), 15*time.Second)
	defer stop()
	// Noon on the first UTC day stays inside the partition when the clock moves back.
	start := auditMigrationMonth(t, owner).Add(12 * time.Hour)
	now := start
	clock := func() time.Time { return now }
	first, second := auditWriter(t, owner, clock), auditWriter(t, owner, clock)

	var group sync.WaitGroup
	begin := make(chan struct{})
	for _, instance := range []*Store{first, second} {
		group.Go(func() {
			<-begin
			if _, err := instance.Checkpoint(ctx); err != nil {
				t.Errorf("concurrent checkpoint: %v", err)
			}
		})
	}
	close(begin)
	group.Wait()
	now = start.Add(5*time.Minute - time.Microsecond)
	if event, err := first.Checkpoint(ctx); err != nil || event.Seq != 0 {
		t.Fatalf("checkpoint inside five minutes: seq=%d err=%v, want no new event", event.Seq, err)
	}
	now = start.Add(5 * time.Minute)
	before, err := second.Append(ctx, Payload{Operation: "before_clock_rollback"})
	if err != nil || before.Seq != 2 || !before.At.Equal(now) {
		t.Fatalf("after concurrent checkpoints: seq=%d at=%s err=%v, want seq 2 at %s", before.Seq, before.At, err, now)
	}
	now = now.Add(-time.Hour)
	after, err := first.Append(ctx, Payload{Operation: "after_clock_rollback"})
	if err != nil || after.Seq != 3 || after.At.Before(before.At) {
		t.Fatalf("clock rollback: seq=%d at=%s err=%v, want seq 3 at or after %s", after.Seq, after.At, err, before.At)
	}

	now = start.Add(5 * time.Minute)
	entered := make(chan struct{})
	signalStart := sync.OnceFunc(func() { close(entered) })
	first.Config.Now = func() time.Time {
		signalStart()
		return now
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- first.RunCheckpoints(runCtx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("RunCheckpoints returned %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("RunCheckpoints did not return after cancellation")
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("RunCheckpoints did not start its initial checkpoint")
	}
	// The clock callback runs under the append lock. The other instance sees
	// the committed checkpoint when it acquires the lock.
	if event, err := second.Checkpoint(ctx); err != nil || event.Seq != 0 {
		t.Fatalf("second instance after RunCheckpoints: seq=%d err=%v, want no new event", event.Seq, err)
	}
	// Read on RunCheckpoints' own single-connection pool so cancellation
	// cannot race the client's receipt of its initial COMMIT response.
	events, err := first.Events(ctx, 1, 4)
	if err != nil || len(events) != 4 {
		t.Fatalf("stored events=%d err=%v, want 4", len(events), err)
	}
	if events[0].Operation != "audit_checkpoint" || !events[0].At.Equal(start) || events[2].At.Before(events[1].At) {
		t.Fatalf("first checkpoint at %s, timestamps across rollback %s -> %s", events[0].At, events[1].At, events[2].At)
	}
	last := events[3]
	if last.Operation != "audit_checkpoint" || !last.At.Equal(now) || last.CheckpointSeq == nil || *last.CheckpointSeq != after.Seq || !bytes.Equal(last.CheckpointHash, after.Hash) {
		t.Fatalf("five-minute checkpoint=%+v, want anchor at seq %d", last, after.Seq)
	}
}
