package hostconn

import (
	"context"
	"testing"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store"
	"google.golang.org/protobuf/proto"
)

const rejectReportTrigger = `CREATE FUNCTION reject_report() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture report insert rejected'; END $$;
 CREATE TRIGGER reject_report BEFORE INSERT OR UPDATE ON host_catalog_reports FOR EACH ROW EXECUTE FUNCTION reject_report()`

func finalReport(version uint64) *v1.CatalogLoadReport {
	return &v1.CatalogLoadReport{Catalog: &v1.CatalogRef{CatalogId: "catalog", Version: version}, ReportId: "report", Loaded: true, FinalPage: true}
}

// reportFixture returns a mailbox fixture with catalog versions 1 and 2 and a
// connection "old" that owns the host.
func reportFixture(t *testing.T) (*Service, *connection, *store.Store, context.Context) {
	t.Helper()
	s, db, ctx := newMailboxFixture(t)
	if _, err := db.Pool.Exec(ctx, `INSERT INTO catalog_versions(catalog_id,version,dsse,digest,expires_at,action_names)
 SELECT 'catalog',v,'\x00',decode(repeat('00',32),'hex'),now()+interval '1 hour','{}' FROM generate_series(1,2) v`); err != nil {
		t.Fatal(err)
	}
	c := &connection{identity: Identity{HostID: "host"}, id: "old", ctx: ctx, pending: map[string][]string{}, loaded: map[string]*v1.CatalogLoadReport{}}
	s.connections["host"] = c
	return s, c, db, ctx
}

func reportVersion(ctx context.Context, t *testing.T, db *store.Store) (version int64, found bool) {
	t.Helper()
	rows, err := db.Pool.Query(ctx, "SELECT version FROM host_catalog_reports WHERE host_id='host' AND catalog_id='catalog'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&version); err != nil {
			t.Fatal(err)
		}
		found = true
	}
	return version, found
}

// A report whose write failed is the only copy of that load result in the database
// views, so the owner retries it instead of waiting for the next catalog push.
func TestFailedCatalogReportIsRetriedByMaintenance(t *testing.T) {
	s, c, db, ctx := reportFixture(t)
	if _, err := db.Pool.Exec(ctx, rejectReportTrigger); err != nil {
		t.Fatal(err)
	}
	if err := s.catalogReport(c, finalReport(1)); err != nil {
		t.Fatalf("a failed snapshot write must not fail the connection: %v", err)
	}
	if _, found := reportVersion(ctx, t, db); found {
		t.Fatal("fixture trigger did not reject the first write")
	}
	if _, err := db.Pool.Exec(ctx, "DROP TRIGGER reject_report ON host_catalog_reports"); err != nil {
		t.Fatal(err)
	}
	runMaintenance(ctx, t, s, db)()
	if version, found := reportVersion(ctx, t, db); !found || version != 1 {
		t.Errorf("host_catalog_reports version=%d found=%v after maintenance; want the failed report written as version 1", version, found)
	}
}

// The retry carries the connection guard of the original write: a host whose
// connection was replaced keeps what the new connection reports.
func TestFailedCatalogReportIsNotRetriedAfterReplacement(t *testing.T) {
	s, c, db, ctx := reportFixture(t)
	if _, err := db.Pool.Exec(ctx, rejectReportTrigger); err != nil {
		t.Fatal(err)
	}
	if err := s.catalogReport(c, finalReport(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, "DROP TRIGGER reject_report ON host_catalog_reports; UPDATE hosts SET connection_id='new' WHERE host_id='host'"); err != nil {
		t.Fatal(err)
	}
	runMaintenance(ctx, t, s, db)()
	if version, found := reportVersion(ctx, t, db); found {
		t.Errorf("host_catalog_reports has version %d written by a replaced connection", version)
	}
}

// A report that arrived after the failed one supersedes it; the retry must not
// write the older version over it.
func TestFailedCatalogReportDoesNotOverwriteNewerReport(t *testing.T) {
	s, c, db, ctx := reportFixture(t)
	if _, err := db.Pool.Exec(ctx, rejectReportTrigger); err != nil {
		t.Fatal(err)
	}
	if err := s.catalogReport(c, finalReport(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, "DROP TRIGGER reject_report ON host_catalog_reports"); err != nil {
		t.Fatal(err)
	}
	second := proto.Clone(finalReport(2)).(*v1.CatalogLoadReport)
	second.ReportId = "report-2"
	if err := s.catalogReport(c, second); err != nil {
		t.Fatal(err)
	}
	runMaintenance(ctx, t, s, db)()
	if version, found := reportVersion(ctx, t, db); !found || version != 2 {
		t.Errorf("host_catalog_reports version=%d found=%v; want the newer version 2", version, found)
	}
}
