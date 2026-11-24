package store

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/liubing0806/allowops/internal/store/db"
	"github.com/liubing0806/allowops/internal/testpg"
)

func TestPluginChangeHistory(t *testing.T) {
	dsn := testpg.Start(t)
	ctx := t.Context()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	if _, err := s.Pool.Exec(ctx, `
INSERT INTO catalog_versions(catalog_id,version,dsse,digest,expires_at,action_names,published_at)
SELECT id, version, decode('ff','hex'), decode(repeat('00',32),'hex'), $2::timestamptz,
       array_fill('action'::text, ARRAY[version::int]), published_at
FROM (VALUES ('b', 1, $2::timestamptz), ('a', 1, $2), ('a', 2, $2), ('a', 3, $1::timestamptz),
             ('early', 1, $1 - interval '1 microsecond'), ('late', 1, $2 + interval '1 microsecond'),
             ('unpublished', 1, NULL)) AS fixture(id, version, published_at)`, from, to); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `
INSERT INTO policy_versions(version,rules,created_at,created_by,reason,rolled_back_from)
VALUES (201, '{}', $1, 'alice', 'first policy', NULL),
       (202, '{}', $2, 'bob', 'update', NULL),
       (203, '{}', $2, 'carol', 'rollback', 202),
       (204, '{}', $1::timestamptz - interval '1 microsecond', 'alice', '', NULL),
       (205, '{}', $2::timestamptz + interval '1 microsecond', 'bob', '', NULL)`, from, to); err != nil {
		t.Fatal(err)
	}
	start := pgtype.Timestamptz{Time: from, Valid: true}
	end := pgtype.Timestamptz{Time: to, Valid: true}

	t.Run("catalog", func(t *testing.T) {
		query := db.ListCatalogChangeHistoryParams{PublishedAt: start, PublishedAt_2: end, Limit: 5}
		rows, err := s.Queries.ListCatalogChangeHistory(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		want := []struct {
			id      string
			version int64
			at      time.Time
		}{{"a", 2, to}, {"a", 1, to}, {"b", 1, to}, {"a", 3, from}}
		if len(rows) != len(want) || len(rows) >= int(query.Limit) {
			t.Fatalf("catalog rows = %v, want %d rows with no next item", rows, len(want))
		}
		for i, row := range rows {
			w := want[i]
			if row.CatalogID != w.id || row.Version != w.version || row.ActionCount != int32(w.version) || !row.PublishedAt.Valid || !row.PublishedAt.Time.Equal(w.at) {
				t.Fatalf("catalog row %d = %+v, want %+v and %d actions", i, row, w, w.version)
			}
		}
		const limit = 2
		query.Limit = limit + 1
		rows, err = s.Queries.ListCatalogChangeHistory(ctx, query)
		if err != nil || len(rows) != limit+1 || rows[limit].CatalogID != "b" {
			t.Fatalf("catalog limit+1 = %v, err = %v, want b as the next item", rows, err)
		}
	})

	t.Run("policy", func(t *testing.T) {
		query := db.ListPolicyChangeHistoryParams{CreatedAt: start, CreatedAt_2: end, Limit: 4}
		rows, err := s.Queries.ListPolicyChangeHistory(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		want := []struct {
			version  int64
			at       time.Time
			actor    string
			reason   string
			rollback int64
		}{{203, to, "carol", "rollback", 202}, {202, to, "bob", "update", 0}, {201, from, "alice", "first policy", 0}}
		if len(rows) != len(want) || len(rows) >= int(query.Limit) {
			t.Fatalf("policy rows = %v, want %d rows with no next item", rows, len(want))
		}
		for i, row := range rows {
			w := want[i]
			if row.Version != w.version || row.CreatedBy != w.actor || row.Reason != w.reason || row.RolledBackFrom != w.rollback || !row.CreatedAt.Valid || !row.CreatedAt.Time.Equal(w.at) {
				t.Fatalf("policy row %d = %+v, want %+v", i, row, w)
			}
		}
		const limit = 1
		query.Limit = limit + 1
		rows, err = s.Queries.ListPolicyChangeHistory(ctx, query)
		if err != nil || len(rows) != limit+1 || rows[limit].Version != 202 {
			t.Fatalf("policy limit+1 = %v, err = %v, want v202 as the next item", rows, err)
		}
	})
}
