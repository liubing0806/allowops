package api

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

// Reads decode only the rows they return: a corrupt envelope of an unrelated
// historical version must not fail reads of other versions or other pages.
func TestCatalogReadsDecodeOnlyRequestedRows(t *testing.T) {
	f, key := catalogFixture(t)
	client := catalogClient(f, f.adminToken)
	ctx := context.Background()
	now := time.Now()
	versions := []uint64{}
	for i := range 4 {
		id := uploadTestCatalog(t, client, signedTestCatalog(t, key, "one", "status", now.Add(time.Duration(i)*time.Second)))
		r, err := client.PublishCatalog(ctx, connect.NewRequest(&v1.PublishCatalogRequest{UploadId: id}))
		if err != nil {
			t.Fatal(err)
		}
		versions = append(versions, r.Msg.Catalog.Catalog.Version)
	}
	// versions is ascending; list order is newest first.
	oldest := versions[0]
	if _, err := f.db.Pool.Exec(ctx, "UPDATE catalog_versions SET dsse='\\x7b7d'::bytea WHERE catalog_id='one' AND version=$1", int64(oldest)); err != nil {
		t.Fatal(err)
	}
	for _, v := range []uint64{0, versions[3], versions[1]} {
		r, err := client.GetCatalog(ctx, connect.NewRequest(&v1.GetCatalogRequest{Catalog: &v1.CatalogRef{CatalogId: "one", Version: v}}))
		if err != nil {
			t.Fatalf("GetCatalog(version=%d) failed because of an unrelated corrupt version: %v", v, err)
		}
		if v != 0 && r.Msg.Catalog.Catalog.Version != v {
			t.Fatalf("GetCatalog(version=%d) returned version %d", v, r.Msg.Catalog.Catalog.Version)
		}
		if v == 0 && (!r.Msg.Catalog.Current || r.Msg.Catalog.Catalog.Version != versions[3]) {
			t.Fatalf("GetCatalog(current) returned %v", r.Msg.Catalog)
		}
	}
	_, err := client.GetCatalog(ctx, connect.NewRequest(&v1.GetCatalogRequest{Catalog: &v1.CatalogRef{CatalogId: "one", Version: oldest}}))
	code(t, err, connect.CodeInternal)
	_, err = client.GetCatalog(ctx, connect.NewRequest(&v1.GetCatalogRequest{Catalog: &v1.CatalogRef{CatalogId: "one", Version: versions[3] + 100}}))
	code(t, err, connect.CodeNotFound)

	first, err := client.ListCatalogs(ctx, connect.NewRequest(&v1.ListCatalogsRequest{CatalogId: "one", Page: &v1.PageRequest{PageSize: 2}}))
	if err != nil {
		t.Fatalf("first page failed because of an unrelated corrupt version: %v", err)
	}
	if len(first.Msg.Catalogs) != 2 || first.Msg.Catalogs[0].Catalog.Version != versions[3] || first.Msg.Catalogs[1].Catalog.Version != versions[2] || !first.Msg.Catalogs[0].Current || first.Msg.Catalogs[1].Current || first.Msg.Page.GetNextPageToken() == "" {
		t.Fatalf("first page = %v cursor=%q", first.Msg.Catalogs, first.Msg.Page.GetNextPageToken())
	}
	// The next page holds the corrupt row and is the only page that fails.
	_, err = client.ListCatalogs(ctx, connect.NewRequest(&v1.ListCatalogsRequest{CatalogId: "one", Page: &v1.PageRequest{PageSize: 2, PageToken: first.Msg.Page.NextPageToken}}))
	code(t, err, connect.CodeInternal)
}
