package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	dbstore "github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
)

func TestExporterUnlocksBeforeReturning(t *testing.T) {
	dsn := testpg.Start(t)
	ctx := context.Background()
	if err := dbstore.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	probe, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if _, err := New(probe, Config{}).Append(ctx, Payload{Operation: "unlock-test"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		instance bool
		cancel   bool
	}{
		{name: "batch_failure"},
		{name: "instance_cancelled", instance: true, cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := delayedTerminationPool(t, dsn)
			runCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			storageErr := errors.New("fixture crash before cursor")
			if tc.cancel {
				storageErr = context.Canceled
			}
			x := &Exporter{Store: New(pool, Config{}), Cursor: tc.name, Storage: storageFunc(func(context.Context, []Event) error {
				if tc.cancel {
					cancel()
				}
				return storageErr
			})}
			if tc.instance {
				err = x.Run(runCtx, time.Hour)
			} else {
				_, err = x.Once(runCtx)
			}
			if !errors.Is(err, storageErr) {
				t.Fatalf("storage failure=%v, want %v", err, storageErr)
			}
			// Keep the old backend alive after local Close returns. This models
			// PostgreSQL processing Terminate after an immediate crash replay.
			var locks int
			if err := probe.QueryRow(ctx, "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid IN (418008,418009) AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())").Scan(&locks); err != nil {
				t.Fatal(err)
			}
			if locks != 0 {
				t.Errorf("exporter returned while terminated backend still holds %d advisory locks; want 0", locks)
			}
			x.Store = New(probe, Config{})
			x.Storage = FileStorage{Directory: t.TempDir(), MaxBytes: 1 << 20}
			if n, err := x.Once(ctx); err != nil || n != 1 {
				t.Fatalf("crash replay=%d %v, want 1 and nil", n, err)
			}
		})
	}
	t.Run("instance_retries_and_releases_failed_session_locks", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		pool := delayedTerminationPool(t, dsn)
		logs := captureAuditLogs(t)
		storage := FileStorage{Directory: t.TempDir(), MaxBytes: 1 << 20}
		const locks = " FROM pg_locks WHERE locktype='advisory' AND classid=0 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())"
		const privatePath = "/fixture-private-audit-directory"
		var oldOwner, oldBatch int32
		x := &Exporter{Store: New(pool, Config{}), Cursor: "instance-retry", Storage: storageFunc(func(ctx context.Context, events []Event) error {
			if oldOwner == 0 {
				if err := probe.QueryRow(ctx, "SELECT max(pid) FILTER (WHERE objid=418009),max(pid) FILTER (WHERE objid=418008)"+locks).Scan(&oldOwner, &oldBatch); err != nil {
					return err
				}
				return &os.PathError{Op: "write", Path: privatePath, Err: os.ErrPermission}
			}
			var count int
			if err := probe.QueryRow(ctx, "SELECT count(*)"+locks+" AND pid IN ($1,$2) AND objid IN (418008,418009)", oldOwner, oldBatch).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Errorf("failed session backends still hold %d export locks on retry", count)
				return fmt.Errorf("failed export session still holds locks")
			}
			return storage.Commit(ctx, events)
		})}
		done, stop := startAuditTestWorker(t, ctx, func(ctx context.Context) error { return x.Run(ctx, time.Hour) })
		waitForAuditProgress(t, ctx, done, "the export cursor to advance after the storage error", func() bool {
			var ready bool
			if err := probe.QueryRow(ctx, "SELECT EXISTS(SELECT FROM audit_export_cursors WHERE name=$1 AND next_seq=2)", x.Cursor).Scan(&ready); err != nil {
				t.Fatal(err)
			}
			return ready
		})
		stopAuditTestWorker(t, stop, done)
		files, err := filepath.Glob(filepath.Join(storage.Directory, "*.jsonl"))
		if err != nil || len(files) != 1 {
			t.Fatalf("retried export files=%v err=%v; want one file", files, err)
		}
		if got := logs.String(); !strings.Contains(got, "level=ERROR") || !strings.Contains(got, "error_type=*fs.PathError") || strings.Contains(got, privatePath) {
			t.Fatalf("export failure logs=%q, want error type without path", got)
		}
	})
}

// delayedTerminationConn holds only the final PostgreSQL Terminate message and
// socket close. All SQL and server responses use the real local PostgreSQL.
// Tests release the underlying socket after checking the return-time contract.
type delayedTerminationConn struct {
	net.Conn
	mu      sync.Mutex
	delayed bool
}

func (c *delayedTerminationConn) Write(b []byte) (int, error) {
	if bytes.Equal(b, []byte{'X', 0, 0, 0, 4}) {
		c.mu.Lock()
		c.delayed = true
		c.mu.Unlock()
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func (c *delayedTerminationConn) Close() error {
	c.mu.Lock()
	delayed := c.delayed
	c.mu.Unlock()
	if delayed {
		return nil
	}
	return c.Conn.Close()
}

func delayedTerminationPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var connections []*delayedTerminationConn
	dial := config.ConnConfig.DialFunc
	config.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		wrapped := &delayedTerminationConn{Conn: conn}
		mu.Lock()
		connections = append(connections, wrapped)
		mu.Unlock()
		return wrapped, nil
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range connections {
			_ = conn.Conn.Close()
		}
	})
	return pool
}
