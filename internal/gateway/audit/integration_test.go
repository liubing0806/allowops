package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	dbstore "github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPostgresAudit(t *testing.T) {
	dsn := testpg.Start(t)
	ctx := context.Background()
	if err := dbstore.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	a := New(pool, Config{CursorKey: bytes.Repeat([]byte{1}, 32)})
	reset := func(t *testing.T) {
		t.Helper()
		if _, err := pool.Exec(ctx, "TRUNCATE audit_events; DELETE FROM audit_export_cursors; UPDATE audit_boundary SET seq=0,hash=decode(repeat('00',32),'hex')"); err != nil {
			t.Fatal(err)
		}
		a = New(pool, Config{CursorKey: bytes.Repeat([]byte{1}, 32)})
	}
	appendN := func(t *testing.T, n int) []Event {
		t.Helper()
		var events []Event
		for i := 0; i < n; i++ {
			e, err := a.Append(ctx, Payload{SubjectID: "user", Operation: "execute_action", Resource: "host", Decision: "allow", Reason: "test", SourceIP: "192.0.2.1", MatchedRules: []string{"a", "b"}})
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, e)
		}
		return events
	}
	valid := func(t *testing.T, from, to uint64) {
		t.Helper()
		v, err := a.Verify(ctx, VerifyOptions{From: from, To: to})
		if err != nil || !v.Valid || v.CheckedCount != to-from+1 {
			var invalidSeq uint64
			if v.FirstInvalidSeq != nil {
				invalidSeq = *v.FirstInvalidSeq
			}
			t.Fatalf("verify valid=%t checked_count=%d first_invalid_seq=%d reason=%q err=%v; want valid and checked_count=%d", v.Valid, v.CheckedCount, invalidSeq, v.Reason, err, to-from+1)
		}
	}
	t.Run("concurrent_instances", func(t *testing.T) {
		reset(t)
		otherConfig, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		// Append must choose its isolation explicitly. A waiting advisory-lock
		// query must not freeze a snapshot before the preceding writer commits.
		otherConfig.ConnConfig.RuntimeParams["default_transaction_isolation"] = "repeatable read"
		otherPool, err := pgxpool.NewWithConfig(ctx, otherConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer otherPool.Close()
		other := New(otherPool, Config{})
		var wg sync.WaitGroup
		for i := 0; i < 128; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				s := a
				if i%2 == 1 {
					s = other
				}
				if _, err := s.Append(ctx, Payload{Operation: "concurrent", SubjectID: fmt.Sprint(i)}); err != nil {
					t.Errorf("append=%v", err)
				}
			}(i)
		}
		wg.Wait()
		valid(t, 1, 128)
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(DISTINCT seq) FROM audit_events").Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 128 {
			t.Fatalf("distinct seq=%d want 128", count)
		}
	})
	for _, tc := range []struct {
		name, sql string
		seq       uint64
	}{
		{"field", "UPDATE audit_events SET reason='tampered' WHERE seq=2", 2},
		{"malformed_outputs", "UPDATE audit_events SET outputs='{}'::jsonb WHERE seq=2", 2},
		{"missing_before_malformed", "DELETE FROM audit_events WHERE seq=1; UPDATE audit_events SET outputs='{}'::jsonb WHERE seq=2", 1},
		{"malformed_checkpoint", "UPDATE audit_events SET checkpoint_seq=-1,checkpoint_hash=hash WHERE seq=2", 2},
		{"rules_order", "UPDATE audit_events SET matched_rules=ARRAY['b','a'] WHERE seq=2", 2},
		{"delete", "DELETE FROM audit_events WHERE seq=2", 2},
		{"delete_last", "DELETE FROM audit_events WHERE seq=4", 4},
		{"hash", "UPDATE audit_events SET hash=decode(repeat('01',32),'hex') WHERE seq=2", 2},
		{"previous_hash", "UPDATE audit_events SET prev_hash=decode(repeat('01',32),'hex') WHERE seq=2", 2},
		{"insert", `INSERT INTO audit_events (` + columns + `) SELECT seq,at+interval '1 microsecond',subject_id,operation,resource,decision,reason,matched_rules,source_ip,hostname,action,job_id,task_id,policy_version,outputs,checkpoint_seq,checkpoint_hash,hash_input,prev_hash,hash FROM audit_events WHERE seq=2`, 2},
		{"reorder", "UPDATE audit_events SET seq=9 WHERE seq=2", 2},
		{"bytes", "UPDATE audit_events SET hash_input=hash_input || decode('20','hex') WHERE seq=2", 2},
	} {
		t.Run("tamper_"+tc.name, func(t *testing.T) {
			reset(t)
			appendN(t, 4)
			if _, err := pool.Exec(ctx, tc.sql); err != nil {
				t.Fatal(err)
			}
			v, err := a.Verify(ctx, VerifyOptions{From: 1, To: 4})
			if err != nil || v.Valid || v.FirstInvalidSeq == nil || *v.FirstInvalidSeq != tc.seq {
				t.Fatalf("verify=%+v err=%v want invalid seq %d", v, err, tc.seq)
			}
		})
	}
	t.Run("low_privileges", func(t *testing.T) {
		reset(t)
		if _, err := pool.Exec(ctx, `CREATE ROLE audit_fixture LOGIN PASSWORD 'local-fixture-only'; GRANT allowops_audit_writer TO audit_fixture`); err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.UserPassword("audit_fixture", "local-fixture-only")
		low, err := pgxpool.New(ctx, u.String())
		if err != nil {
			t.Fatal("low privilege pool unavailable")
		}
		defer low.Close()
		lowAudit := New(low, Config{})
		if _, err := lowAudit.Append(ctx, Payload{Operation: "low"}); err != nil {
			t.Fatal(err)
		}
		if _, err := (&Exporter{Store: lowAudit, Cursor: "low", Storage: FileStorage{Directory: t.TempDir(), MaxBytes: 1 << 20}}).Once(ctx); err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{"UPDATE audit_events SET reason='changed'", "DELETE FROM audit_events", "TRUNCATE audit_events", "UPDATE " + time.Now().UTC().Format("audit_events_200601") + " SET reason='changed'", "SELECT audit_create_partitions(now(),1)"} {
			_, err := low.Exec(ctx, sql)
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
				t.Fatalf("%s error=%v; want permission denied (42501)", sql, err)
			}
		}
	})
	t.Run("checkpoints", func(t *testing.T) {
		reset(t)
		now := time.Now().UTC()
		a.Config.Now = func() time.Time { return now }
		appendN(t, 2)
		e, err := a.Checkpoint(ctx)
		if err != nil || e.CheckpointSeq == nil || *e.CheckpointSeq != 2 {
			t.Fatalf("checkpoint=%+v err=%v", e, err)
		}
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if e, err := a.Checkpoint(ctx); err != nil || e.Seq != 0 {
					t.Errorf("duplicate checkpoint=%d err=%v", e.Seq, err)
				}
			}()
		}
		wg.Wait()
		now = now.Add(5 * time.Minute)
		e, err = a.Checkpoint(ctx)
		if err != nil || e.Seq != 4 || *e.CheckpointSeq != 3 {
			t.Fatalf("five minute checkpoint=%+v err=%v", e, err)
		}
		valid(t, 1, 4)
	})
	t.Run("outputs_and_rollback", func(t *testing.T) {
		reset(t)
		now := time.Now().UTC()
		a.Config.Now = func() time.Time { return now }
		step := uint32(0)
		output := Output{ObjectPath: "outputs/fixture.stdout.zst", SHA256: bytes.Repeat([]byte{7}, 32), Stream: 1, StepIndex: &step}
		e, err := a.Append(ctx, Payload{Operation: "output_stored", Outputs: []Output{output}, PolicyVersion: 9007199254740993})
		if err != nil {
			t.Fatal(err)
		}
		stored, err := a.Events(ctx, 1, 1)
		if err != nil || len(stored) != 1 || stored[0].PolicyVersion != 9007199254740993 || !bytes.Equal(stored[0].Outputs[0].SHA256, output.SHA256) {
			t.Fatalf("stored output=%+v err=%v", stored, err)
		}
		if !stored[0].At.Equal(e.At) || stored[0].At.Location() != time.UTC {
			t.Fatalf("stored timestamp=%v, want UTC %v", stored[0].At, e.At)
		}
		if _, err := a.Append(ctx, Payload{Operation: strings.Repeat("x", a.Config.PayloadBytes)}); !errors.Is(err, ErrLimit) {
			t.Fatalf("oversized append=%v", err)
		}
		now = now.Add(-time.Minute)
		next, err := a.Append(ctx, Payload{Operation: "after_rollback"})
		if err != nil || next.Seq != 2 || !next.At.Equal(e.At) {
			t.Fatalf("rollback and clock regression seq=%d at=%v err=%v", next.Seq, next.At, err)
		}
		valid(t, 1, 2)
		if _, err := pool.Exec(ctx, `UPDATE audit_events SET outputs=jsonb_set(outputs,'{0,unexpected}', '"tampered"') WHERE seq=1`); err != nil {
			t.Fatal(err)
		}
		v, err := a.Verify(ctx, VerifyOptions{From: 1, To: 2})
		if err != nil || v.Valid || v.FirstInvalidSeq == nil || *v.FirstInvalidSeq != 1 {
			t.Fatalf("unknown output field=%+v err=%v", v, err)
		}
	})
	t.Run("export_rotation_restart", func(t *testing.T) {
		reset(t)
		events := appendN(t, 8)
		line, _ := Line(events[0])
		dir := t.TempDir()
		x := &Exporter{Store: a, Cursor: "restart", BatchSize: 3, Storage: FileStorage{Directory: dir, MaxBytes: int64(len(line) * 2)}}
		if n, err := x.Once(ctx); err != nil || n != 3 {
			t.Fatalf("first export=%d err=%v", n, err)
		}
		x = &Exporter{Store: New(pool, Config{}), Cursor: "restart", BatchSize: 3, Storage: FileStorage{Directory: dir, MaxBytes: int64(len(line) * 2)}}
		for _, want := range []uint64{3, 2, 0} {
			if n, err := x.Once(ctx); err != nil || n != want {
				t.Fatalf("resumed export=%d want %d err=%v", n, want, err)
			}
		}
		files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) < 4 {
			t.Fatalf("rotated files=%d want at least 4", len(files))
		}
		var joined []byte
		for _, file := range files {
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(b)) > int64(len(line)*2) || len(b) == 0 || b[len(b)-1] != '\n' {
				t.Fatalf("rotation size=%d", len(b))
			}
			joined = append(joined, b...)
		}
		v, err := VerifyReader(bytes.NewReader(joined), VerifyOptions{From: 1, To: 8}, Config{})
		if err != nil || !v.Valid {
			t.Fatalf("rotated chain=%+v err=%v", v, err)
		}
		var next uint64
		if err := pool.QueryRow(ctx, "SELECT next_seq FROM audit_export_cursors WHERE name='restart'").Scan(&next); err != nil {
			t.Fatal(err)
		}
		if next != 9 {
			t.Fatalf("cursor=%d want 9", next)
		}
	})
	t.Run("durability_failure_and_single_owner", func(t *testing.T) {
		reset(t)
		appendN(t, 3)
		entered := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		sink := storageFunc(func(context.Context, []Event) error {
			close(entered)
			<-release
			return fmt.Errorf("fixture storage failure")
		})
		x := &Exporter{Store: a, Cursor: "lock", Storage: sink}
		go func() { _, err := x.Once(ctx); done <- err }()
		<-entered
		other := &Exporter{Store: a, Cursor: "lock", Storage: FileStorage{Directory: t.TempDir(), MaxBytes: 1 << 20}}
		if _, err := other.Once(ctx); !errors.Is(err, ErrBusy) {
			t.Fatalf("second owner=%v want busy", err)
		}
		close(release)
		if err := <-done; err == nil {
			t.Fatal("storage failure ignored")
		}
		var next uint64
		if err := pool.QueryRow(ctx, "SELECT next_seq FROM audit_export_cursors WHERE name='lock'").Scan(&next); err != nil {
			t.Fatal(err)
		}
		if next != 1 {
			t.Fatalf("failed durability advanced cursor=%d", next)
		}
		if n, err := other.Once(ctx); err != nil || n != 3 {
			t.Fatalf("retry=%d err=%v", n, err)
		}
		// Reproduce a crash after durable publication but before cursor commit.
		dir := t.TempDir()
		replay := &Exporter{Store: a, Cursor: "replay", Storage: storageFunc(func(ctx context.Context, es []Event) error {
			if err := (FileStorage{Directory: dir, MaxBytes: 1 << 20}).Commit(ctx, es); err != nil {
				return err
			}
			return fmt.Errorf("fixture crash before cursor")
		})}
		if _, err := replay.Once(ctx); err == nil {
			t.Fatal("fixture crash ignored")
		}
		replay.Storage = FileStorage{Directory: dir, MaxBytes: 1 << 20}
		if n, err := replay.Once(ctx); err != nil || n != 3 {
			t.Fatalf("crash replay=%d %v", n, err)
		}
		files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
		if len(files) != 2 {
			t.Fatalf("replayed files=%d want 2", len(files))
		}
	})
	t.Run("exporter_holds_leadership_while_idle", func(t *testing.T) {
		reset(t)
		appendN(t, 2)
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		x := &Exporter{Store: a, Cursor: "leader", Storage: FileStorage{Directory: t.TempDir(), MaxBytes: 1 << 20}}
		go func() { done <- x.Run(runCtx, time.Hour) }()
		defer func() {
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Errorf("exporter stop=%v", err)
			}
		}()
		deadline := time.Now().Add(time.Second)
		for {
			var ready bool
			if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT FROM audit_export_cursors WHERE name='leader' AND next_seq=3)").Scan(&ready); err != nil {
				t.Fatal(err)
			}
			if ready {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("leader did not export first batch")
			}
			time.Sleep(10 * time.Millisecond)
		}
		probe, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { probe.Conn().Close(ctx); probe.Release() }()
		var acquired bool
		if err := probe.QueryRow(ctx, "SELECT pg_try_advisory_lock(418009)").Scan(&acquired); err != nil {
			t.Fatal(err)
		}
		if acquired {
			t.Fatal("idle exporter leadership lock held=false, want true")
		}
		maintenance, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		if _, err := a.Prune(maintenance, RetentionOptions{}); err != nil {
			t.Fatalf("leader blocked retention maintenance: %v", err)
		}
	})
	t.Run("exporter_stops_when_leadership_connection_is_lost", func(t *testing.T) {
		reset(t)
		appendN(t, 2)
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		stopped := false
		x := &Exporter{Store: a, Cursor: "lost-leader", Storage: FileStorage{Directory: t.TempDir(), MaxBytes: 1 << 20}}
		go func() { done <- x.Run(runCtx, 10*time.Millisecond) }()
		defer func() {
			cancel()
			if !stopped {
				<-done
			}
		}()
		deadline := time.Now().Add(time.Second)
		for {
			var ready bool
			if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT FROM audit_export_cursors WHERE name='lost-leader' AND next_seq=3)").Scan(&ready); err != nil {
				t.Fatal(err)
			}
			if ready {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("leader did not finish batch")
			}
			time.Sleep(10 * time.Millisecond)
		}
		var terminated bool
		if err := pool.QueryRow(ctx, "SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=418009 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())").Scan(&terminated); err != nil || !terminated {
			t.Fatalf("terminate fixture leadership connection: terminated=%t err=%v", terminated, err)
		}
		select {
		case err := <-done:
			stopped = true
			if err == nil {
				t.Fatal("connection loss did not report failure")
			}
		case <-time.After(time.Second):
			t.Fatal("exporter kept running after its leadership connection was terminated")
		}
	})
	t.Run("exporter_warns_on_conflicting_instance", func(t *testing.T) {
		reset(t)
		lock, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { lock.Conn().Close(ctx); lock.Release() }()
		if _, err := lock.Exec(ctx, "SELECT pg_advisory_lock(418009),pg_advisory_lock($1)", exportLock); err != nil {
			t.Fatal(err)
		}
		var logs auditLogBuffer
		originalOutput, originalFlags := log.Writer(), log.Flags()
		original := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		defer func() { slog.SetDefault(original); log.SetOutput(originalOutput); log.SetFlags(originalFlags) }()
		deadline, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		runCtx, cancel := context.WithCancel(deadline)
		defer cancel()
		// A successful conflict probe may take longer than the old 150ms
		// observation window when other race-enabled packages are running.
		probes := &conflictProbeTracer{cancel: cancel}
		config := pool.Config()
		config.ConnConfig.Tracer = probes
		dial := config.ConnConfig.DialFunc
		config.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dial(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return delayedConflictConn{conn}, nil
		}
		probePool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer probePool.Close()
		x := &Exporter{Store: New(probePool, Config{}), Cursor: "conflicting-instance", Storage: FileStorage{Directory: t.TempDir(), MaxBytes: 1 << 20}}
		if err := x.Run(runCtx, 10*time.Millisecond); !errors.Is(err, context.Canceled) {
			t.Fatalf("conflicting exporter stopped=%v", err)
		}
		if probes.completed < 3 {
			t.Fatalf("completed conflict probes=%d, want at least 3", probes.completed)
		}
		if got := strings.Count(logs.String(), "level=WARN"); got != 1 {
			t.Fatalf("conflict warnings=%d, want 1 per conflict; logs=%q", got, logs.String())
		}
		var cursors int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_export_cursors").Scan(&cursors); err != nil || cursors != 0 {
			t.Fatalf("conflicting exporter cursors=%d err=%v", cursors, err)
		}
	})
	t.Run("api", func(t *testing.T) { reset(t); appendN(t, 4); testAPI(t, a) })
	t.Run("partition_retention", func(t *testing.T) {
		reset(t)
		now := time.Now().UTC()
		old := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -13, 0)
		if err := a.CreatePartitions(ctx, old, 1); err != nil {
			t.Fatal(err)
		}
		if err := a.CreatePartitions(ctx, now.AddDate(0, 4, 0), 2); err != nil {
			t.Fatal(err)
		}
		a.Config.Now = func() time.Time { return old }
		removed := appendN(t, 2)
		a.Config.Now = func() time.Time { return now }
		retained := appendN(t, 2)
		if _, err := a.Prune(ctx, RetentionOptions{RequireExternalCheckpoint: true}); err == nil {
			t.Fatal("pruned without required external checkpoint")
		}
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_events").Scan(&count); err != nil || count != 4 {
			t.Fatalf("failed prune count=%d err=%v", count, err)
		}
		if _, err := pool.Exec(ctx, "INSERT INTO audit_export_cursors VALUES ('pending',1,decode(repeat('00',32),'hex'))"); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Prune(ctx, RetentionOptions{}); err == nil {
			t.Fatal("pruned unexported events")
		}
		if _, err := pool.Exec(ctx, "DELETE FROM audit_export_cursors"); err != nil {
			t.Fatal(err)
		}
		boundary, err := a.Prune(ctx, RetentionOptions{})
		if err != nil || boundary.Seq != 2 || !bytes.Equal(boundary.Hash, removed[1].Hash) {
			t.Fatalf("boundary=%+v err=%v", boundary, err)
		}
		valid(t, 3, 4)
		internal, err := a.Verify(ctx, VerifyOptions{From: 3, To: 4})
		if err != nil || !internal.Valid || internal.ExternallyAnchored {
			t.Fatalf("default retained verification=%+v err=%v", internal, err)
		}
		v, err := a.Verify(ctx, VerifyOptions{From: 1, To: 4})
		if err != nil || v.Valid || v.FirstInvalidSeq == nil || *v.FirstInvalidSeq != 1 {
			t.Fatalf("deleted history=%+v err=%v", v, err)
		}
		v, err = a.Verify(ctx, VerifyOptions{From: 3, To: 4, ExpectedPrecedingHash: removed[1].Hash, ExpectedFinalHash: retained[1].Hash})
		if err != nil || !v.Valid || !v.ExternallyAnchored {
			t.Fatalf("retained external=%+v err=%v", v, err)
		}
		var exists bool
		if err := pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", old.Format("audit_events_200601")).Scan(&exists); err != nil || exists {
			t.Fatalf("expired partition exists=%t err=%v", exists, err)
		}
		// The same maintenance interface supports the owner selecting A19=true.
		reset(t)
		if err := a.CreatePartitions(ctx, old, 1); err != nil {
			t.Fatal(err)
		}
		a.Config.Now = func() time.Time { return old }
		removed = appendN(t, 2)
		a.Config.Now = func() time.Time { return now }
		appendN(t, 1)
		external := &Anchor{Seq: 2, Hash: removed[1].Hash}
		if _, err := a.Prune(ctx, RetentionOptions{RequireExternalCheckpoint: true, ExternalCheckpoint: external}); err != nil {
			t.Fatal(err)
		}
		valid(t, 3, 3)
	})
}

type storageFunc func(context.Context, []Event) error

func (f storageFunc) Commit(ctx context.Context, es []Event) error { return f(ctx, es) }

type accessStub struct{}

func (accessStub) Authorize(_ context.Context, h http.Header, operation string) (string, error) {
	if operation != "view_audit" {
		return "", fmt.Errorf("unexpected operation")
	}
	subject := h.Get("X-Fixture-Subject")
	if subject == "" {
		return "", connect.NewError(connect.CodePermissionDenied, fmt.Errorf("fixture denied"))
	}
	return subject, nil
}

func testAPI(t *testing.T, a *Store) {
	t.Helper()
	ctx := context.Background()
	s := &Service{Store: a, Access: accessStub{}}
	_, handler := allowopsv1connect.NewAuditServiceHandler(s, connect.WithReadMaxBytes(1<<20), connect.WithSendMaxBytes(1<<20))
	server := httptest.NewServer(handler)
	defer server.Close()
	client := allowopsv1connect.NewAuditServiceClient(server.Client(), server.URL)
	request := func(subject string) *connect.Request[v1.ListAuditEventsRequest] {
		r := connect.NewRequest(&v1.ListAuditEventsRequest{Query: &v1.AuditQuery{SubjectId: "user"}, Page: &v1.PageRequest{PageSize: 2}})
		r.Header().Set("X-Fixture-Subject", subject)
		return r
	}
	if _, err := client.ListAuditEvents(ctx, request("")); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("unauthorized error=%v", err)
	}
	r := request("auditor")
	first, err := client.ListAuditEvents(ctx, r)
	if err != nil || len(first.Msg.Events) != 2 || first.Msg.Page.NextPageToken == "" {
		t.Fatalf("first page=%v err=%v", first, err)
	}
	e, _ := a.Events(ctx, 1, 1)
	if !bytes.Equal(first.Msg.Events[0].HashInput, e[0].HashInput) {
		t.Fatal("RPC changed persisted hash_input")
	}
	r = request("auditor")
	r.Msg.Page.PageToken = first.Msg.Page.NextPageToken
	second, err := client.ListAuditEvents(ctx, r)
	if err != nil || len(second.Msg.Events) != 2 || second.Msg.Events[0].Seq != 3 {
		t.Fatalf("second page=%v err=%v", second, err)
	}
	r = request("different-user")
	r.Msg.Page.PageToken = first.Msg.Page.NextPageToken
	if _, err := client.ListAuditEvents(ctx, r); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("cross-user cursor=%v", err)
	}
	r = request("auditor")
	r.Msg.Page.PageToken = first.Msg.Page.NextPageToken
	r.Msg.Query.Operation = "changed"
	if _, err := client.ListAuditEvents(ctx, r); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("changed query=%v", err)
	}
	lines, _ := Line(e[0])
	er := connect.NewRequest(&v1.ExportAuditRequest{LimitBytes: uint32(len(lines) * 2)})
	er.Header().Set("X-Fixture-Subject", "auditor")
	exp, err := client.ExportAudit(ctx, er)
	if err != nil || exp.Msg.NextPageToken == "" || exp.Msg.SnapshotLastSeq != 4 {
		t.Fatalf("export page=%v err=%v", exp, err)
	}
	if _, err := a.Append(ctx, Payload{Operation: "after_snapshot"}); err != nil {
		t.Fatal(err)
	}
	for exp.Msg.NextPageToken != "" {
		er.Msg.PageToken = exp.Msg.NextPageToken
		exp, err = client.ExportAudit(ctx, er)
		if err != nil {
			t.Fatal(err)
		}
		if exp.Msg.SnapshotLastSeq != 4 || exp.Msg.LastSeq > 4 {
			t.Fatalf("snapshot last=%d row=%d; want frozen seq 4", exp.Msg.SnapshotLastSeq, exp.Msg.LastSeq)
		}
	}
	if exp.Msg.LastSeq != 4 {
		t.Fatalf("export last_seq=%d, want 4", exp.Msg.LastSeq)
	}
	er.Msg.Time = &v1.TimeRange{From: timestamppb.New(time.Now().Add(-time.Hour))}
	if _, err := client.ExportAudit(ctx, er); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("changed export range=%v", err)
	}
	vr := connect.NewRequest(&v1.VerifyAuditRequest{FromSeq: 1, ToSeq: 4})
	vr.Header().Set("X-Fixture-Subject", "auditor")
	v, err := client.VerifyAudit(ctx, vr)
	if err != nil || !v.Msg.Valid || v.Msg.ExternallyAnchored {
		t.Fatalf("verify RPC=%v err=%v", v, err)
	}
	vr.Msg.ToSeq = uint64(a.Config.VerifyRows) + 1
	if _, err := client.VerifyAudit(ctx, vr); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("verify count limit=%v", err)
	}
	s.Access = nil
	if _, err := client.VerifyAudit(ctx, vr); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("missing P5 access=%v", err)
	}
	// Runtime limits can be tightened without changing protocol defaults.
	s.Access = accessStub{}
	a.Config.PayloadBytes = 128
	if _, err := a.Append(ctx, Payload{Operation: strings.Repeat("x", 129)}); !errors.Is(err, ErrLimit) {
		t.Fatalf("payload limit=%v", err)
	}
}

// Delay the first lock-query write after pgx has installed its context watcher.
// This models descheduling during network I/O without delaying authentication.
type delayedConflictConn struct{ net.Conn }

func (c delayedConflictConn) Write(b []byte) (int, error) {
	if bytes.Contains(b, []byte("pg_try_advisory_lock")) {
		time.Sleep(200 * time.Millisecond)
	}
	return c.Conn.Write(b)
}

type conflictProbeTracer struct {
	completed int
	cancel    context.CancelFunc
}

func (p *conflictProbeTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}

func (p *conflictProbeTracer) TraceQueryEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if data.Err == nil {
		p.completed++
		// Stop between queries after repeated conflict observations, so the
		// warning assertion does not race a deadline against network I/O.
		if p.completed == 3 {
			p.cancel()
		}
	}
}

// Both slog and the PostgreSQL fixture's standard logger may write concurrently.
type auditLogBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *auditLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}
func (b *auditLogBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.data.String() }
