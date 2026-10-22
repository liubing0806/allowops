package hostconn

import (
	"context"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
)

func TestListenersDoNotStarveTransactionalRequests(t *testing.T) {
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	// Match the default pool capacity on a four-CPU host, independently of
	// the CPU count of the machine running this regression test.
	db, err := store.Open(ctx, dsn+"&pool_max_conns=4")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	for range 3 {
		cfg := DefaultConfig()
		cfg.FlushInterval = time.Hour
		cfg.CleanupInterval = time.Hour
		s, err := New(db, nil, cfg, Hooks{})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Start(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	// Management requests reload policy and append authorization audit while
	// holding a transaction. Both must still be able to acquire a connection.
	var version int64
	if err := db.Pool.QueryRow(ctx, "SELECT COALESCE(max(version),0) FROM policy_versions").Scan(&version); err != nil {
		t.Fatalf("policy query while transaction held: %v", err)
	}
	chain := audit.New(db.Pool, audit.Config{})
	if _, err := chain.Append(ctx, audit.Payload{SubjectID: "fixture", Operation: "manage_hosts", Decision: "allow", Reason: "authorized"}); err != nil {
		t.Fatalf("authorization audit while transaction held: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
