package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"sort"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
)

type storedCatalog struct {
	meta *v1.CatalogVersion
	pkg  *catalog.Package
	raw  []byte
}

func catalogMeta(p *catalog.Package, raw []byte, published time.Time, current bool) *v1.CatalogVersion {
	meta := &v1.CatalogVersion{Catalog: &v1.CatalogRef{CatalogId: p.CatalogID, Version: uint64(p.Version)}, SchemaVersion: uint32(p.SchemaVersion), CreatedAt: stamp(p.CreatedAt), ExpiresAt: stamp(p.ExpiresAt), GitCommit: p.GitCommit, EnvelopeSha256: hash(string(raw)), EnvelopeSizeBytes: uint64(len(raw)), ActionCount: uint32(len(p.Actions)), Current: current}
	if !published.IsZero() {
		meta.PublishedAt = stamp(published)
	}
	return meta
}
func storedPackage(raw []byte) (*catalog.Package, error) {
	e, err := catalog.ParseEnvelope(raw)
	if err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, err
	}
	return catalog.ParsePackage(payload)
}

// catalogQuery selects catalog rows in SQL so only the rows a caller returns are
// decoded: one corrupt historical envelope must not fail reads of other
// versions. version 0 matches every version; limit 0 means no limit.
type catalogQuery struct {
	id      string
	version int64
	current bool
	offset  int
	limit   int
}

// storedCatalogs decodes at most q.limit rows. The row after them is never
// decoded; it only reports whether more rows follow.
func (s *Service) storedCatalogs(ctx context.Context, q catalogQuery) ([]storedCatalog, bool, error) {
	sql := `SELECT c.dsse,c.published_at,c.version=(SELECT max(version) FROM catalog_versions WHERE catalog_id=c.catalog_id) FROM catalog_versions c WHERE ($1='' OR c.catalog_id=$1) AND ($2::bigint=0 OR c.version=$2::bigint)`
	if q.current {
		sql += ` AND c.version=(SELECT max(version) FROM catalog_versions WHERE catalog_id=c.catalog_id)`
	}
	sql += " ORDER BY c.catalog_id,c.version DESC OFFSET $3::bigint LIMIT $4::bigint"
	var limit *int
	if q.limit > 0 {
		limit = new(q.limit + 1)
	}
	rows, err := s.Store.Pool.Query(ctx, sql, q.id, q.version, q.offset, limit)
	if err != nil {
		return nil, false, dbError(err)
	}
	defer rows.Close()
	out := []storedCatalog{}
	for rows.Next() {
		if q.limit > 0 && len(out) == q.limit {
			return out, true, nil
		}
		var raw []byte
		var published pgtype.Timestamptz
		var isCurrent bool
		if err = rows.Scan(&raw, &published, &isCurrent); err != nil {
			return nil, false, dbError(err)
		}
		p, err := storedPackage(raw)
		if err != nil {
			return nil, false, failure(connect.CodeInternal, "stored catalog invalid")
		}
		out = append(out, storedCatalog{catalogMeta(p, raw, published.Time, isCurrent), p, raw})
	}
	return out, false, dbError(rows.Err())
}
func (s *Service) getCatalog(ctx context.Context, ref *v1.CatalogRef) (storedCatalog, error) {
	if ref == nil || ref.CatalogId == "" || ref.Version > 1<<63-1 {
		return storedCatalog{}, failure(connect.CodeInvalidArgument, "catalog reference required")
	}
	all, _, err := s.storedCatalogs(ctx, catalogQuery{id: ref.CatalogId, version: int64(ref.Version), current: ref.Version == 0, limit: 1})
	if err != nil {
		return storedCatalog{}, err
	}
	if len(all) == 0 {
		return storedCatalog{}, failure(connect.CodeNotFound, "catalog not found")
	}
	return all[0], nil
}
func (s *Service) BeginCatalogUpload(ctx context.Context, req *connect.Request[v1.BeginCatalogUploadRequest]) (*connect.Response[v1.BeginCatalogUploadResponse], error) {
	cfg := s.gatewayConfig()
	if req.Msg.EnvelopeSizeBytes == 0 || len(req.Msg.EnvelopeSha256) != 32 {
		return nil, failure(connect.CodeInvalidArgument, "envelope size and SHA-256 required")
	}
	if req.Msg.EnvelopeSizeBytes > uint64(cfg.EnvelopeBytes) {
		return nil, failure(connect.CodeResourceExhausted, "envelope byte limit exceeded")
	}
	id := secret("cup_")
	expires := time.Now().Add(s.management.config.UploadTTL)
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "DELETE FROM catalog_uploads WHERE expires_at<=now()"); err != nil {
		return nil, dbError(err)
	}
	if _, err = tx.Exec(ctx, "INSERT INTO catalog_uploads(upload_id,actor_id,envelope_size,envelope_sha256,expires_at) VALUES ($1,$2,$3,$4,$5)", id, actorID(ctx), req.Msg.EnvelopeSizeBytes, req.Msg.EnvelopeSha256, expires); err != nil {
		return nil, dbError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.BeginCatalogUploadResponse{UploadId: id, MaxChunkBytes: uint32(cfg.ChunkBytes), ExpiresAt: stamp(expires)}), nil
}

type upload struct {
	size                    uint64
	digest, data, published []byte
	chunkEnds               []byte
}

// Packed uint32 end offsets retain the original retry boundaries without
// retaining another copy of each chunk or storing per-chunk JSON.
func (u *upload) repeatedChunk(offset uint64, data []byte) bool {
	if len(u.chunkEnds)%4 != 0 {
		return false
	}
	count := len(u.chunkEnds) / 4
	i := sort.Search(count, func(i int) bool { return uint64(binary.BigEndian.Uint32(u.chunkEnds[i*4:])) > offset })
	if i == count {
		return false
	}
	start := uint64(0)
	if i > 0 {
		start = uint64(binary.BigEndian.Uint32(u.chunkEnds[(i-1)*4:]))
	}
	end := uint64(binary.BigEndian.Uint32(u.chunkEnds[i*4:]))
	return start == offset && end == offset+uint64(len(data)) && end <= uint64(len(u.data)) && bytes.Equal(data, u.data[start:end])
}

func (s *Service) upload(ctx context.Context, tx pgx.Tx, id string) (*upload, error) {
	u := &upload{}
	var actor string
	var expires time.Time
	err := tx.QueryRow(ctx, "SELECT actor_id,envelope_size,envelope_sha256,data,expires_at,published_catalog,chunk_ends FROM catalog_uploads WHERE upload_id=$1 FOR UPDATE", id).Scan(&actor, &u.size, &u.digest, &u.data, &expires, &u.published, &u.chunkEnds)
	if err != nil {
		return nil, dbError(err)
	}
	if actor != actorID(ctx) {
		return nil, failure(connect.CodePermissionDenied, "upload belongs to another caller")
	}
	if !time.Now().Before(expires) {
		return nil, failure(connect.CodeFailedPrecondition, "upload expired; begin again")
	}
	return u, nil
}
func (s *Service) UploadCatalogChunk(ctx context.Context, req *connect.Request[v1.UploadCatalogChunkRequest]) (*connect.Response[v1.UploadCatalogChunkResponse], error) {
	if len(req.Msg.Data) == 0 {
		return nil, failure(connect.CodeInvalidArgument, "chunk data required")
	}
	if len(req.Msg.Data) > s.gatewayConfig().ChunkBytes {
		return nil, failure(connect.CodeResourceExhausted, "chunk byte limit exceeded")
	}
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	u, err := s.upload(ctx, tx, req.Msg.UploadId)
	if err != nil {
		return nil, err
	}
	offset := req.Msg.Offset
	next := uint64(len(u.data))
	if offset < next && u.repeatedChunk(offset, req.Msg.Data) {
		return connect.NewResponse(&v1.UploadCatalogChunkResponse{NextOffset: next}), nil
	}
	if offset != next || len(u.published) > 0 {
		return nil, failure(connect.CodeAborted, "upload offset or content changed")
	}
	if next+uint64(len(req.Msg.Data)) > u.size {
		return nil, failure(connect.CodeInvalidArgument, "chunk exceeds declared envelope size")
	}
	if _, err = tx.Exec(ctx, "UPDATE catalog_uploads SET data=data||$2::bytea,chunk_ends=$3 WHERE upload_id=$1", req.Msg.UploadId, req.Msg.Data, binary.BigEndian.AppendUint32(u.chunkEnds, uint32(next+uint64(len(req.Msg.Data))))); err != nil {
		return nil, dbError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.UploadCatalogChunkResponse{NextOffset: next + uint64(len(req.Msg.Data))}), nil
}
func (s *Service) PublishCatalog(ctx context.Context, req *connect.Request[v1.PublishCatalogRequest]) (*connect.Response[v1.PublishCatalogResponse], error) {
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	u, err := s.upload(ctx, tx, req.Msg.UploadId)
	if err != nil {
		return nil, err
	}
	if len(u.published) > 0 {
		meta := &v1.CatalogVersion{}
		if decode(u.published, meta) != nil {
			return nil, failure(connect.CodeInternal, "stored publication invalid")
		}
		return connect.NewResponse(&v1.PublishCatalogResponse{Catalog: meta}), nil
	}
	if uint64(len(u.data)) != u.size || !bytes.Equal(hash(string(u.data)), u.digest) {
		return nil, failure(connect.CodeFailedPrecondition, "upload length or digest mismatch")
	}
	if s.management.catalogs == nil {
		return nil, failure(connect.CodeUnavailable, "catalog verifier unavailable")
	}
	p, err := s.management.catalogs.Verify(u.data)
	if err != nil {
		return nil, failure(connect.CodeInvalidArgument, "catalog signature, schema or validity rejected")
	}
	names := []string{}
	for name := range p.Actions {
		names = append(names, name)
	}
	slices.Sort(names)
	err = s.Store.PublishTx(ctx, tx, db.InsertCatalogParams{CatalogID: p.CatalogID, Version: p.Version, Dsse: u.data, Digest: u.digest, ExpiresAt: store.Timestamp(p.ExpiresAt), ActionNames: names})
	if errors.Is(err, store.ErrRollback) || errors.Is(err, store.ErrActionConflict) {
		return nil, failure(connect.CodeAborted, err.Error())
	}
	if err != nil {
		return nil, dbError(err)
	}
	var published time.Time
	if err = tx.QueryRow(ctx, "SELECT published_at FROM catalog_versions WHERE catalog_id=$1 AND version=$2", p.CatalogID, p.Version).Scan(&published); err != nil {
		return nil, dbError(err)
	}
	meta := catalogMeta(p, u.data, published, true)
	b, err := encode(meta)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, "UPDATE catalog_uploads SET published_catalog=$2 WHERE upload_id=$1", req.Msg.UploadId, b); err != nil {
		return nil, dbError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.PublishCatalogResponse{Catalog: meta}), nil
}
func (s *Service) ListCatalogs(ctx context.Context, req *connect.Request[v1.ListCatalogsRequest]) (*connect.Response[v1.ListCatalogsResponse], error) {
	size, offset, binding, err := pageCursor(ctx, s.Config, "catalogs:"+req.Msg.CatalogId, req.Msg.Page)
	if err != nil {
		return nil, err
	}
	all, more, err := s.storedCatalogs(ctx, catalogQuery{id: req.Msg.CatalogId, offset: offset, limit: size})
	if err != nil {
		return nil, err
	}
	if len(all) == 0 && offset > 0 {
		var total int
		if err = s.Store.Pool.QueryRow(ctx, "SELECT count(*) FROM catalog_versions WHERE ($1='' OR catalog_id=$1)", req.Msg.CatalogId).Scan(&total); err != nil {
			return nil, dbError(err)
		}
		if offset > total {
			return nil, failure(connect.CodeInvalidArgument, "invalid page cursor")
		}
	}
	items := []*v1.CatalogVersion{}
	for _, c := range all {
		items = append(items, c.meta)
	}
	items, cursor, err := pageWindow(s.Config, binding, offset, size, items, more)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.ListCatalogsResponse{Catalogs: items, Page: cursor}), nil
}
func (s *Service) GetCatalog(ctx context.Context, req *connect.Request[v1.GetCatalogRequest]) (*connect.Response[v1.GetCatalogResponse], error) {
	c, err := s.getCatalog(ctx, req.Msg.Catalog)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.GetCatalogResponse{Catalog: c.meta}), nil
}
func actionSummary(a catalog.Action, digest string) *v1.ActionSummary {
	sum, _ := hex.DecodeString(digest)
	mode := "exec"
	if len(a.Steps) > 0 {
		mode = "steps"
	}
	if a.Script != nil {
		mode = "script"
	}
	if a.Builtin != "" {
		mode = "builtin"
	}
	return &v1.ActionSummary{Name: a.Name, Description: a.Description, Risk: a.Risk, Idempotent: a.Idempotent != nil && *a.Idempotent, ExecutionMode: mode, Builtin: a.Builtin, ActionSha256: sum}
}
func (s *Service) actionCatalogs(ctx context.Context, ref *v1.CatalogRef) ([]storedCatalog, error) {
	if ref == nil {
		all, _, err := s.storedCatalogs(ctx, catalogQuery{current: true})
		return all, err
	}
	c, err := s.getCatalog(ctx, ref)
	if err != nil {
		return nil, err
	}
	return []storedCatalog{c}, nil
}
func (s *Service) ListActions(ctx context.Context, req *connect.Request[v1.ListActionsRequest]) (*connect.Response[v1.ListActionsResponse], error) {
	all, err := s.actionCatalogs(ctx, req.Msg.Catalog)
	if err != nil {
		return nil, err
	}
	items := []*v1.ActionSummary{}
	for _, c := range all {
		for name, a := range c.pkg.Actions {
			ok, err := s.can(ctx, authz.ViewCatalog, authz.Action{Name: name, Risk: a.Risk}, authz.Host{})
			if err != nil {
				return nil, err
			}
			if ok {
				items = append(items, actionSummary(a, c.pkg.Digests[name]))
			}
		}
	}
	if len(items) == 0 {
		if _, err = s.Require(ctx, authz.ViewCatalog, authz.Action{}, authz.Host{}); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(items, func(a, b *v1.ActionSummary) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	binding, _ := encode(req.Msg.Catalog)
	items, cursor, err := page(ctx, s.Config, "actions:"+string(binding), req.Msg.Page, items)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.ListActionsResponse{Actions: items, Page: cursor}), nil
}
func (s *Service) GetAction(ctx context.Context, req *connect.Request[v1.GetActionRequest]) (*connect.Response[v1.GetActionResponse], error) {
	if req.Msg.Action == "" {
		return nil, failure(connect.CodeInvalidArgument, "action name required")
	}
	all, err := s.actionCatalogs(ctx, req.Msg.Catalog)
	if err != nil {
		return nil, err
	}
	for _, c := range all {
		a, ok := c.pkg.Actions[req.Msg.Action]
		if !ok {
			continue
		}
		if _, err = s.Require(ctx, authz.ViewCatalog, authz.Action{Name: a.Name, Risk: a.Risk}, authz.Host{}); err != nil {
			return nil, err
		}
		definition, err := catalog.CanonicalJSON(a)
		if err != nil {
			return nil, err
		}
		return connect.NewResponse(&v1.GetActionResponse{Action: actionSummary(a, c.pkg.Digests[a.Name]), DefinitionJson: definition, Catalog: c.meta.Catalog}), nil
	}
	return nil, failure(connect.CodeNotFound, "action not found")
}
func (s *Service) GetCatalogDistribution(ctx context.Context, req *connect.Request[v1.GetCatalogDistributionRequest]) (*connect.Response[v1.GetCatalogDistributionResponse], error) {
	if req.Msg.CatalogId == "" {
		return nil, failure(connect.CodeInvalidArgument, "catalog ID required")
	}
	if _, err := s.Require(ctx, authz.ViewCatalog, authz.Action{}, authz.Host{}); err != nil {
		return nil, err
	}
	all, err := s.hosts(ctx, s.Store.Pool, false)
	if err != nil {
		return nil, err
	}
	visible, err := s.visibleHosts(ctx, all)
	if err != nil {
		return nil, err
	}
	counts := map[uint64]uint64{}
	missing := uint64(0)
	for _, h := range visible {
		loaded := false
		for _, c := range h.LoadedCatalogs {
			if c.CatalogId == req.Msg.CatalogId {
				counts[c.Version]++
				loaded = true
			}
		}
		if !loaded {
			missing++
		}
	}
	versions := []uint64{}
	for v := range counts {
		versions = append(versions, v)
	}
	slices.Sort(versions)
	items := []*v1.CatalogDistribution{}
	for _, v := range versions {
		items = append(items, &v1.CatalogDistribution{Catalog: &v1.CatalogRef{CatalogId: req.Msg.CatalogId, Version: v}, HostCount: counts[v]})
	}
	items, cursor, err := page(ctx, s.Config, "distribution:"+req.Msg.CatalogId, req.Msg.Page, items)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.GetCatalogDistributionResponse{Versions: items, NotLoadedHostCount: missing, Page: cursor}), nil
}
