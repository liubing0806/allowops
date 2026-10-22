package store

import (
	"context"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/testpg"
)

func TestManagementUpgradePreservesUnknownTimes(t *testing.T) {
	ctx := context.Background()
	dsn := testpg.Start(t)
	p, closeDB, err := migrationProvider(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	if _, err = p.UpTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	token, err := s.CreateJoinToken(ctx, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Register(ctx, token, "old", func(string) (string, time.Time, error) { return "old", time.Now().Add(time.Hour), nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Pool.Exec(ctx, "INSERT INTO catalog_versions(catalog_id,version,dsse,digest,expires_at,action_names) VALUES ('old',1,$1,$2,now()+interval '1 hour',ARRAY['old'])", []byte("fixture"), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	var hostUnknown, joinUnknown, catalogUnknown bool
	if err = s.Pool.QueryRow(ctx, `SELECT (SELECT registered_at IS NULL FROM hosts WHERE hostname='old'),(SELECT created_at IS NULL AND revoked_at IS NULL FROM join_tokens),(SELECT published_at IS NULL FROM catalog_versions WHERE catalog_id='old')`).Scan(&hostUnknown, &joinUnknown, &catalogUnknown); err != nil {
		t.Fatal(err)
	}
	if !hostUnknown || !joinUnknown || !catalogUnknown {
		t.Fatalf("historical timestamps unknown: host=%t join=%t catalog=%t; want all true", hostUnknown, joinUnknown, catalogUnknown)
	}
	token, err = s.CreateJoinToken(ctx, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Register(ctx, token, "new", func(string) (string, time.Time, error) { return "new", time.Now().Add(time.Hour), nil }); err != nil {
		t.Fatal(err)
	}
	var recorded bool
	if err = s.Pool.QueryRow(ctx, "SELECT registered_at IS NOT NULL FROM hosts WHERE hostname='new'").Scan(&recorded); err != nil || !recorded {
		t.Fatal("new registration timestamp absent", err)
	}
}
