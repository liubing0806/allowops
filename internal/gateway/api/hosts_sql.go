package api

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store/db"
	"google.golang.org/protobuf/proto"
)

// Host, host import preview and join token data access. See sql.go for the
// statements kept hand-written.

// hostColumns selects a host with its online state. $1 is the heartbeat window
// as interval text, so the statements below are composed here.
const hostColumns = `h.host_id,h.hostname,h.authorization_labels,h.reported_labels,
 (h.instance_id IS NOT NULL AND EXISTS(SELECT 1 FROM gateway_instances i WHERE i.instance_id=h.instance_id AND i.last_seen>now()-$1::interval)),
 h.agent_version,h.capabilities,h.last_seen,h.registered_at,h.revision,
 COALESCE((SELECT jsonb_agg(jsonb_build_object('catalog_id',r.catalog_id,'version',r.version) ORDER BY r.catalog_id) FROM host_catalog_reports r WHERE r.host_id=h.host_id AND r.loaded),'[]'::jsonb)`

func scanHost(row pgx.Row) (*v1.Host, error) {
	h := &v1.Host{}
	var auth, reported, caps, loaded []byte
	var last, registered pgtype.Timestamptz
	var revision int64
	err := row.Scan(&h.HostId, &h.Hostname, &auth, &reported, &h.Online, &h.AgentVersion, &caps, &last, &registered, &revision, &loaded)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(auth, &h.AuthorizationLabels); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(reported, &h.ReportedLabels); err != nil {
		return nil, err
	}
	if len(caps) > 0 {
		h.Capabilities = &v1.AgentCapabilities{}
		if err = proto.Unmarshal(caps, h.Capabilities); err != nil {
			return nil, err
		}
	}
	if err = json.Unmarshal(loaded, &h.LoadedCatalogs); err != nil {
		return nil, err
	}
	h.LastSeen = nullable(last)
	h.RegisteredAt = nullable(registered)
	h.Revision = strconv.FormatInt(revision, 10)
	return h, nil
}

// activeHosts lists active hosts by ID, locking the rows when lock is set.
// window is the heartbeat window as interval text.
func activeHosts(ctx context.Context, q querier, window string, lock bool) ([]*v1.Host, error) {
	sql := "SELECT " + hostColumns + " FROM hosts h WHERE certificate_status='active' ORDER BY host_id"
	if lock {
		sql += " FOR UPDATE OF h"
	}
	rows, err := q.Query(ctx, sql, window)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*v1.Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// activeHostByName reads one active host by hostname.
func activeHostByName(ctx context.Context, q querier, window, hostname string) (*v1.Host, error) {
	return scanHost(q.QueryRow(ctx, "SELECT "+hostColumns+" FROM hosts h WHERE hostname=$2 AND certificate_status='active'", window, hostname))
}

// lockActiveHost reads and row-locks one active host by ID.
func lockActiveHost(ctx context.Context, q querier, window, id string) (*v1.Host, error) {
	return scanHost(q.QueryRow(ctx, "SELECT "+hostColumns+" FROM hosts h WHERE host_id=$2 AND certificate_status='active' FOR UPDATE OF h", window, id))
}

// setHostLabels replaces the authorization labels (JSON) of a host.
func setHostLabels(ctx context.Context, q querier, id string, labels []byte) error {
	return db.New(q).UpdateHostLabels(ctx, db.UpdateHostLabelsParams{HostID: id, AuthorizationLabels: labels})
}

// previewRow is a stored host import preview.
type previewRow struct {
	actor         string
	digest        []byte
	rows, targets []byte
	invalid       int64
	expires       time.Time
	updated       pgtype.Int8
}

func purgeImportPreviews(ctx context.Context, q querier) error {
	return db.New(q).DeleteExpiredHostImportPreviews(ctx)
}

func insertImportPreview(ctx context.Context, q querier, id, actor string, digest, rows, targets []byte, invalid uint64, expires time.Time) error {
	// The invalid count is bounded by the CSV row limit.
	return db.New(q).InsertHostImportPreview(ctx, db.InsertHostImportPreviewParams{PreviewID: id, ActorID: actor, CsvSha256: digest, Rows: rows, Targets: targets, InvalidCount: int64(invalid), ExpiresAt: timestamptz(expires)})
}

// importPreview reads a preview and row-locks it when lock is set.
func importPreview(ctx context.Context, q querier, id string, lock bool) (previewRow, error) {
	if lock {
		r, err := db.New(q).LockHostImportPreview(ctx, id)
		return previewRow{r.ActorID, r.CsvSha256, r.Rows, r.Targets, r.InvalidCount, r.ExpiresAt.Time, r.UpdatedCount}, err
	}
	r, err := db.New(q).GetHostImportPreview(ctx, id)
	return previewRow{r.ActorID, r.CsvSha256, r.Rows, r.Targets, r.InvalidCount, r.ExpiresAt.Time, r.UpdatedCount}, err
}

func setImportPreviewUpdated(ctx context.Context, q querier, id string, count int) error {
	return db.New(q).SetHostImportPreviewUpdated(ctx, db.SetHostImportPreviewUpdatedParams{PreviewID: id, UpdatedCount: pgtype.Int8{Int64: int64(count), Valid: true}})
}

func joinFromRow(r db.ListJoinTokensRow) *v1.JoinToken {
	return &v1.JoinToken{TokenId: r.TokenID, MaxUses: uint32(r.MaxUses), UsedCount: uint32(r.UsedCount), ExpiresAt: stamp(r.ExpiresAt.Time), CreatedAt: nullable(r.CreatedAt), RevokedAt: nullable(r.RevokedAt)}
}

func joinTokenByHash(ctx context.Context, q querier, tokenHash []byte) (*v1.JoinToken, error) {
	r, err := db.New(q).GetJoinTokenByHash(ctx, tokenHash)
	if err != nil {
		return &v1.JoinToken{}, err
	}
	return joinFromRow(db.ListJoinTokensRow(r)), nil
}

func listJoinTokens(ctx context.Context, q querier) ([]*v1.JoinToken, error) {
	rows, err := db.New(q).ListJoinTokens(ctx)
	if err != nil {
		return nil, err
	}
	tokens := []*v1.JoinToken{}
	for _, r := range rows {
		tokens = append(tokens, joinFromRow(r))
	}
	return tokens, nil
}

// revokeJoinToken revokes a join token and reports the number of rows matched.
func revokeJoinToken(ctx context.Context, q querier, id string) (int64, error) {
	return db.New(q).RevokeJoinToken(ctx, id)
}
