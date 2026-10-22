package audit

import (
	"bytes"
	"context"
	"errors"
	"net"
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
		{name: "instance_failure", instance: true},
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
