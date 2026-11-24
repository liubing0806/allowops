package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/liubing0806/allowops/internal/testpg"
)

func TestIdentityUpgradePreservesP7Schema(t *testing.T) {
	dsn := testpg.Start(t)
	ctx := context.Background()
	provider, closeDB, err := migrationProvider(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	if _, err := provider.UpTo(ctx, 2); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Pool.Exec(ctx, "INSERT INTO audit_export_cursors(name,next_seq,preceding_hash) VALUES ('upgrade',1,decode(repeat('00',32),'hex'))"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	if err := db.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
	var version, cursor, roles int
	if err := db.Pool.QueryRow(ctx, "SELECT (SELECT max(version_id) FROM goose_db_version WHERE is_applied),(SELECT next_seq FROM audit_export_cursors WHERE name='upgrade'),(SELECT count(*) FROM roles)").Scan(&version, &cursor, &roles); err != nil {
		t.Fatal(err)
	}
	if int64(version) != SchemaVersion || cursor != 1 || roles != 5 {
		t.Fatalf("identity upgrade: schema=%d P7 cursor=%d roles=%d", version, cursor, roles)
	}
}

func TestTasksPartitionUpgrade(t *testing.T) {
	dsn := testpg.Start(t)
	ctx := context.Background()
	provider, closeDB, err := migrationProvider(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	if _, err := provider.UpTo(ctx, 9); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CheckSchema(ctx); err == nil {
		t.Fatal("accepted schema version 9")
	}

	now := time.Now().UTC()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	current := month.Format("tasks_200601")
	legacyDDL := fmt.Sprintf("CREATE TABLE %s PARTITION OF tasks FOR VALUES FROM ('%s') TO ('%s')",
		pgx.Identifier{current}.Sanitize(), month.Format(time.RFC3339), month.AddDate(0, 1, 0).Format(time.RFC3339))
	if _, err := s.Pool.Exec(ctx, legacyDDL); err != nil {
		t.Fatal(err)
	}
	var legacyOID uint32
	if err := s.Pool.QueryRow(ctx, "SELECT $1::regclass::oid", current).Scan(&legacyOID); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
	for offset := range 3 {
		name := month.AddDate(0, offset, 0).Format("tasks_200601")
		var oid uint32
		var canRead, canInsert, canUpdate bool
		err := s.Pool.QueryRow(ctx, `
			SELECT inhrelid, has_table_privilege('allowops_job_writer', inhrelid, 'SELECT'),
			    has_table_privilege('allowops_job_writer', inhrelid, 'INSERT'),
			    has_table_privilege('allowops_job_writer', inhrelid, 'UPDATE')
			FROM pg_inherits WHERE inhparent='tasks'::regclass AND inhrelid=$1::regclass
		`, name).Scan(&oid, &canRead, &canInsert, &canUpdate)
		if err != nil || !canRead || !canInsert || !canUpdate {
			t.Fatalf("%s: SELECT=%t INSERT=%t UPDATE=%t err=%v", name, canRead, canInsert, canUpdate, err)
		}
		if offset == 0 && oid != legacyOID {
			t.Fatalf("%s replaced on upgrade: oid=%d; want %d", name, oid, legacyOID)
		}
	}
}

func TestPostgresRegistration(t *testing.T) {
	dsn := testpg.Start(t)
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CheckSchema(ctx); err == nil {
		t.Fatal("accepted unmigrated database")
	}
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
	sign := func(string) (string, time.Time, error) { return "serial", time.Now().Add(time.Hour), nil }
	token, err := s.CreateJoinToken(ctx, 5, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Register(ctx, token, rand.Text(), sign); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrCredential) {
				t.Errorf("registration: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 5 {
		t.Fatalf("successful joins=%d, want 5", successes.Load())
	}
	token, err = s.CreateJoinToken(ctx, 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(ctx, token, "same", sign); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(ctx, token, "same", sign); !errors.Is(err, ErrHostname) {
		t.Fatalf("duplicate=%v, want hostname conflict", err)
	}
	if _, err := s.Register(ctx, token, "remaining", sign); err != nil {
		t.Fatalf("duplicate consumed token: %v", err)
	}
	token, err = s.CreateJoinToken(ctx, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeJoinToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(ctx, token, "revoked", sign); !errors.Is(err, ErrCredential) {
		t.Fatalf("revoked=%v", err)
	}
	if _, err := s.Pool.Exec(ctx, "INSERT INTO goose_db_version(version_id,is_applied) VALUES ($1,true)", SchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckSchema(ctx); err == nil {
		t.Fatal("accepted future schema")
	}
}
