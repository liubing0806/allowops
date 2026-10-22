package store

import (
	"context"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/testpg"
)

// A pool from OpenPool has its own connection limit and never waits for the
// connections of another pool on the same database.
func TestOpenPoolIsIndependentOfBusinessPool(t *testing.T) {
	dsn := testpg.Start(t)
	ctx := context.Background()
	business, err := Open(ctx, dsn+"&pool_max_conns=1")
	if err != nil {
		t.Fatal(err)
	}
	defer business.Close()
	extra, err := OpenPool(ctx, dsn+"&pool_max_conns=1", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	if got := extra.Config().MaxConns; got != 3 {
		t.Fatalf("MaxConns=%d want 3", got)
	}
	held, err := business.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	short, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var one int
	if err := extra.QueryRow(short, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("query on separate pool while the business pool is exhausted: %v", err)
	}
	if _, err := OpenPool(ctx, dsn, 0); err == nil {
		t.Fatal("zero connection limit accepted")
	}
}
