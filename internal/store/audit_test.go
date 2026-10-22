package store

import (
	"context"
	"testing"

	"github.com/liubing0806/allowops/internal/testpg"
)

func TestAuditMigration(t *testing.T) {
	dsn := testpg.Start(t)
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var count int
	if err := s.Pool.QueryRow(ctx, "SELECT count(*) FROM pg_partitioned_table p JOIN pg_class c ON c.oid=p.partrelid WHERE c.relname='audit_events'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("partitioned audit_events tables=%d, want 1", count)
	}
}
