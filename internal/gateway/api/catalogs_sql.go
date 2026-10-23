package api

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/liubing0806/allowops/internal/store/db"
)

// Catalog and system status data access. See sql.go for the statements kept
// hand-written.

// catalogRow is one stored catalog envelope with its publication time and
// whether it is the newest version of its catalog.
type catalogRow struct {
	raw       []byte
	published pgtype.Timestamptz
	current   bool
}

// storedCatalogRows lists catalog versions ordered by catalog and newest
// version first. catalogID filters to one catalog when not empty and current
// keeps only each catalog's newest version. The optional filter makes the
// statement text dynamic.
func storedCatalogRows(ctx context.Context, q querier, catalogID string, current bool) ([]catalogRow, error) {
	sql := `SELECT c.dsse,c.published_at,c.version=(SELECT max(version) FROM catalog_versions WHERE catalog_id=c.catalog_id) FROM catalog_versions c WHERE ($1='' OR c.catalog_id=$1)`
	if current {
		sql += ` AND c.version=(SELECT max(version) FROM catalog_versions WHERE catalog_id=c.catalog_id)`
	}
	sql += " ORDER BY c.catalog_id,c.version DESC"
	rows, err := q.Query(ctx, sql, catalogID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []catalogRow{}
	for rows.Next() {
		var r catalogRow
		if err = rows.Scan(&r.raw, &r.published, &r.current); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func purgeCatalogUploads(ctx context.Context, q querier) error {
	return db.New(q).DeleteExpiredCatalogUploads(ctx)
}

func insertCatalogUpload(ctx context.Context, q querier, id, actor string, size uint64, digest []byte, expires time.Time) error {
	// The declared size is bounded by the envelope byte limit.
	return db.New(q).InsertCatalogUpload(ctx, db.InsertCatalogUploadParams{UploadID: id, ActorID: actor, EnvelopeSize: int64(size), EnvelopeSha256: digest, ExpiresAt: timestamptz(expires)})
}

// uploadRow is a stored catalog upload.
type uploadRow struct {
	actor     string
	expires   time.Time
	size      uint64
	digest    []byte
	data      []byte
	published []byte
	chunkEnds []byte
}

// lockCatalogUpload reads and row-locks an upload.
func lockCatalogUpload(ctx context.Context, q querier, id string) (uploadRow, error) {
	r, err := db.New(q).LockCatalogUpload(ctx, id)
	return uploadRow{r.ActorID, r.ExpiresAt.Time, uint64(r.EnvelopeSize), r.EnvelopeSha256, r.Data, r.PublishedCatalog, r.ChunkEnds}, err
}

// appendCatalogChunk appends a chunk and replaces the packed chunk end offsets.
func appendCatalogChunk(ctx context.Context, q querier, id string, chunk, chunkEnds []byte) error {
	return db.New(q).AppendCatalogUploadChunk(ctx, db.AppendCatalogUploadChunkParams{Chunk: chunk, ChunkEnds: chunkEnds, UploadID: id})
}

func setCatalogUploadPublished(ctx context.Context, q querier, id string, published []byte) error {
	return db.New(q).SetCatalogUploadPublished(ctx, db.SetCatalogUploadPublishedParams{UploadID: id, PublishedCatalog: published})
}

// catalogPublishedAt returns the publication time of a catalog version.
func catalogPublishedAt(ctx context.Context, q querier, catalogID string, version int64) (time.Time, error) {
	t, err := db.New(q).GetCatalogPublishedAt(ctx, db.GetCatalogPublishedAtParams{CatalogID: catalogID, Version: version})
	return t.Time, err
}

func countExpiringCatalogs(ctx context.Context, q querier) (uint64, error) {
	n, err := db.New(q).CountExpiringCatalogs(ctx)
	return uint64(n), err
}

func countExpiringAccountTokens(ctx context.Context, q querier) (uint64, error) {
	n, err := db.New(q).CountExpiringServiceAccountTokens(ctx)
	return uint64(n), err
}

// instanceRow is a gateway instance with the number of connected hosts among
// the given host IDs.
type instanceRow = db.ListGatewayInstanceHostsRow

func gatewayInstanceRows(ctx context.Context, q querier, hostIDs []string) ([]instanceRow, error) {
	return db.New(q).ListGatewayInstanceHosts(ctx, hostIDs)
}
