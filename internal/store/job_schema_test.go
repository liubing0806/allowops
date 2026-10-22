package store

import (
	"context"
	"testing"

	"github.com/liubing0806/allowops/internal/testpg"
)

func TestJobSchemaAndMonthlyTasks(t *testing.T) {
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, name := range []string{"jobs", "tasks", "task_steps"} {
		var exists bool
		if err := s.Pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", name).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("missing P6 relation %s", name)
		}
	}
	var strategy string
	if err := s.Pool.QueryRow(ctx, "SELECT partstrat FROM pg_partitioned_table WHERE partrelid='tasks'::regclass").Scan(&strategy); err != nil {
		t.Fatal(err)
	}
	if strategy != "r" {
		t.Fatalf("tasks partition strategy=%q; want range", strategy)
	}
}
