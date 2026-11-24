package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/store"
)

func TestEnsurePartitionsArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		dsn  string
		want string
	}{
		{name: "default months", dsn: "private-dsn", want: "configure PostgreSQL"},
		{name: "minimum months", args: []string{"--months", "1"}, dsn: "private-dsn", want: "configure PostgreSQL"},
		{name: "maximum months", args: []string{"--months=120"}, dsn: "private-dsn", want: "configure PostgreSQL"},
		{name: "below minimum", args: []string{"--months", "0"}, want: "--months must be between 1 and 120"},
		{name: "above maximum", args: []string{"--months", "121"}, want: "--months must be between 1 and 120"},
		{name: "invalid months", args: []string{"--months", "private-dsn"}, want: "usage: allowops-gateway ensure-partitions [--months 3]"},
		{name: "unexpected argument", args: []string{"private-dsn"}, want: "usage: allowops-gateway ensure-partitions [--months 3]"},
		{name: "missing DSN", want: "ALLOWOPS_DATABASE_URL required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ALLOWOPS_DATABASE_URL", tc.dsn)
			err := run(append([]string{"ensure-partitions"}, tc.args...))
			if err == nil || err.Error() != tc.want {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func testEnsurePartitionsPostgres(t *testing.T, binary, dsn string) {
	t.Helper()
	ctx := t.Context()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	setup := func(sql string) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	invoke := func(args ...string) (string, error) {
		command := exec.CommandContext(ctx, binary, append([]string{"ensure-partitions"}, args...)...)
		command.Env = append(os.Environ(), "ALLOWOPS_DATABASE_URL="+dsn)
		out, err := command.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	partitionCount := func() int {
		t.Helper()
		var count int
		if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_partitions").Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}

	taskPartitionCount := func() int {
		t.Helper()
		var count int
		if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM pg_inherits WHERE inhparent='tasks'::regclass").Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}

	// Default migrated schema has both audit_create_partitions and tasks_create_partitions.
	for range 2 {
		out, err := invoke("--months", "4")
		if err != nil || out != "ensured partitions for 4 UTC months in audit_events and tasks" {
			t.Fatalf("audit and tasks maintenance: exit=%v output=%q", err, out)
		}
	}
	if count := partitionCount(); count != 4 {
		t.Fatalf("audit partition count = %d, want 4", count)
	}
	if count := taskPartitionCount(); count != 4 {
		t.Fatalf("tasks partition count = %d, want 4", count)
	}

	// When tasks_create_partitions(timestamptz, integer) is absent on search_path,
	// unrelated overloads and schemas must not be invoked.
	setup(`DROP FUNCTION tasks_create_partitions(timestamptz, integer);
		CREATE FUNCTION tasks_create_partitions(timestamptz, bigint) RETURNS void
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'wrong overload'; END; $$;
		CREATE SCHEMA unrelated;
		CREATE FUNCTION unrelated.tasks_create_partitions(timestamptz, integer) RETURNS void
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'wrong schema'; END; $$`)
	out, err := invoke("--months", "4")
	if err != nil || out != "ensured partitions for 4 UTC months in audit_events" {
		t.Fatalf("audit-only maintenance: exit=%v output=%q", err, out)
	}

	setup(`CREATE FUNCTION tasks_create_partitions(timestamptz, integer) RETURNS void
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private database error'; END; $$`)
	out, err = invoke("--months", "5")
	if err == nil || out != "ensure tasks partitions failed" {
		t.Fatalf("tasks maintenance failure: exit=%v output=%q", err, out)
	}
	if count := partitionCount(); count != 4 {
		t.Fatalf("audit partition count after rollback = %d, want 4", count)
	}

	if out, err := invoke("--months", "private-dsn"); err == nil || out != "usage: allowops-gateway ensure-partitions [--months 3]" {
		t.Fatalf("invalid flag value: exit=%v output=%q", err, out)
	}
}
