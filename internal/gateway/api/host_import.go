package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"maps"
	"strings"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
)

type importTarget struct {
	HostID, Revision, Hostname string
	After                      map[string]string
}
type storedPreview struct {
	meta    *v1.HostImportPreview
	rows    []*v1.HostImportRow
	targets []importTarget
	updated pgtype.Int8
}

func violation(row *v1.HostImportRow, field, description string) {
	row.Violations = append(row.Violations, &v1.FieldViolation{Field: field, Description: description})
}
func (s *Service) PreviewHostImport(ctx context.Context, req *connect.Request[v1.PreviewHostImportRequest]) (*connect.Response[v1.PreviewHostImportResponse], error) {
	cfg := s.management.config
	if len(req.Msg.Csv) > cfg.MaxCSVBytes {
		return nil, failure(connect.CodeResourceExhausted, "CSV byte limit exceeded")
	}
	if !utf8.Valid(req.Msg.Csv) {
		return nil, failure(connect.CodeInvalidArgument, "CSV must be UTF-8")
	}
	reader := csv.NewReader(bytes.NewReader(req.Msg.Csv))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil || len(header) < 2 || header[0] != "hostname" {
		return nil, failure(connect.CodeInvalidArgument, "CSV header must start with hostname")
	}
	headerErrors := []string{}
	keys := map[string]bool{}
	for _, column := range header[1:] {
		verb, key, ok := strings.Cut(column, ":")
		if !ok || key == "" || (verb != "set" && verb != "remove") || keys[key] {
			headerErrors = append(headerErrors, "invalid, duplicate or conflicting column")
		}
		keys[key] = true
	}
	tx, err := s.Store.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	hosts, err := s.hosts(ctx, tx, false)
	if err != nil {
		return nil, err
	}
	byName := map[string]*v1.Host{}
	for _, h := range hosts {
		byName[h.Hostname] = h
	}
	rows := []*v1.HostImportRow{}
	targets := []importTarget{}
	seen := map[string]bool{}
	invalid := uint64(0)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, failure(connect.CodeInvalidArgument, "malformed RFC 4180 CSV")
		}
		if len(rows) >= cfg.MaxCSVRows {
			return nil, failure(connect.CodeResourceExhausted, "CSV row limit exceeded")
		}
		line, _ := reader.FieldPos(0)
		row := &v1.HostImportRow{Line: uint32(line), Hostname: record[0]}
		for _, e := range headerErrors {
			violation(row, "header", e)
		}
		h := byName[row.Hostname]
		if h == nil {
			violation(row, "hostname", "host not found")
		} else {
			if _, err = s.Require(ctx, authz.ManageHosts, authz.Action{}, hostAttributes(h)); err != nil {
				return nil, err
			}
			row.Before = maps.Clone(h.AuthorizationLabels)
			row.After = maps.Clone(row.Before)
		}
		if seen[row.Hostname] {
			violation(row, "hostname", "duplicate hostname")
		}
		seen[row.Hostname] = true
		if len(record) != len(header) {
			violation(row, "row", "column count does not match header")
		} else {
			changes := &v1.LabelChanges{Set: map[string]string{}}
			for i, column := range header[1:] {
				verb, key, _ := strings.Cut(column, ":")
				value := record[i+1]
				if verb == "set" {
					changes.Set[key] = value
				} else if value == "true" {
					changes.Remove = append(changes.Remove, key)
				} else if value != "" {
					violation(row, column, "remove value must be true or empty")
				}
			}
			if len(changes.Set)+len(changes.Remove) > 0 {
				after, e := s.changedLabels(row.Before, changes)
				if e != nil {
					violation(row, "labels", "invalid label changes")
				} else {
					row.After = after
				}
			}
		}
		if len(row.Violations) > 0 {
			invalid++
		}
		if h != nil {
			targets = append(targets, importTarget{h.HostId, h.Revision, h.Hostname, row.After})
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, failure(connect.CodeInvalidArgument, "CSV rows required")
	}
	if len(targets) == 0 {
		if _, err = s.Require(ctx, authz.ManageHosts, authz.Action{}, authz.Host{}); err != nil {
			return nil, err
		}
	}
	if err = s.authorizeWrite(ctx); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, "DELETE FROM host_import_previews WHERE expires_at<=now()"); err != nil {
		return nil, dbError(err)
	}
	expires := time.Now().Add(cfg.PreviewTTL)
	id := secret("hip_")
	rawRows, _ := json.Marshal(rows)
	rawTargets, _ := json.Marshal(targets)
	digest := hash(string(req.Msg.Csv))
	if _, err = tx.Exec(ctx, "INSERT INTO host_import_previews(preview_id,actor_id,csv_sha256,rows,targets,invalid_count,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)", id, reqctx.ActorID(ctx), digest, rawRows, rawTargets, invalid, expires); err != nil {
		return nil, dbError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.PreviewHostImportResponse{Preview: &v1.HostImportPreview{PreviewId: id, CsvSha256: digest, RowCount: uint64(len(rows)), InvalidRowCount: invalid, ExpiresAt: stamp(expires)}}), nil
}
func (s *Service) preview(ctx context.Context, q querier, id string, lock bool) (*storedPreview, error) {
	sql := "SELECT actor_id,csv_sha256,rows,targets,invalid_count,expires_at,updated_count FROM host_import_previews WHERE preview_id=$1"
	if lock {
		sql += " FOR UPDATE"
	}
	p := &storedPreview{meta: &v1.HostImportPreview{PreviewId: id}}
	var actor string
	var rows, targets []byte
	var expires time.Time
	err := q.QueryRow(ctx, sql, id).Scan(&actor, &p.meta.CsvSha256, &rows, &targets, &p.meta.InvalidRowCount, &expires, &p.updated)
	if err != nil {
		return nil, dbError(err)
	}
	if actor != reqctx.ActorID(ctx) {
		return nil, failure(connect.CodePermissionDenied, "preview belongs to another caller")
	}
	if !time.Now().Before(expires) {
		return nil, failure(connect.CodeFailedPrecondition, "preview expired; preview again")
	}
	if json.Unmarshal(rows, &p.rows) != nil || json.Unmarshal(targets, &p.targets) != nil {
		return nil, failure(connect.CodeInternal, "invalid stored preview")
	}
	p.meta.RowCount = uint64(len(p.rows))
	p.meta.ExpiresAt = stamp(expires)
	return p, nil
}
func (s *Service) previewTargets(ctx context.Context, q querier, p *storedPreview, lock, checkRevision bool) ([]*v1.Host, error) {
	all, err := s.hosts(ctx, q, lock)
	if err != nil {
		return nil, err
	}
	byID := map[string]*v1.Host{}
	for _, h := range all {
		byID[h.HostId] = h
	}
	out := []*v1.Host{}
	for _, target := range p.targets {
		h := byID[target.HostID]
		if h == nil || h.Hostname != target.Hostname {
			return nil, failure(connect.CodeAborted, "preview target changed; preview again")
		}
		if _, err = s.Require(ctx, authz.ManageHosts, authz.Action{}, hostAttributes(h)); err != nil {
			return nil, err
		}
		if checkRevision && h.Revision != target.Revision {
			return nil, failure(connect.CodeAborted, "preview target revision changed; preview again")
		}
		out = append(out, h)
	}
	if len(p.targets) == 0 {
		if _, err = s.Require(ctx, authz.ManageHosts, authz.Action{}, authz.Host{}); err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (s *Service) GetHostImportPreview(ctx context.Context, req *connect.Request[v1.GetHostImportPreviewRequest]) (*connect.Response[v1.GetHostImportPreviewResponse], error) {
	p, err := s.preview(ctx, s.Store.Pool, req.Msg.PreviewId, false)
	if err != nil {
		return nil, err
	}
	if _, err = s.previewTargets(ctx, s.Store.Pool, p, false, false); err != nil {
		return nil, err
	}
	cfg := s.Config
	cfg.MessageBytes -= 256
	rows, cursor, err := page(ctx, cfg, "import:"+p.meta.PreviewId, req.Msg.Page, p.rows)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.GetHostImportPreviewResponse{Preview: p.meta, Rows: rows, Page: cursor}), nil
}
func (s *Service) ExecuteHostImport(ctx context.Context, req *connect.Request[v1.ExecuteHostImportRequest]) (*connect.Response[v1.ExecuteHostImportResponse], error) {
	tx, err := s.Store.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	p, err := s.preview(ctx, tx, req.Msg.PreviewId, true)
	if err != nil {
		return nil, err
	}
	if p.meta.InvalidRowCount > 0 {
		return nil, failure(connect.CodeInvalidArgument, "preview contains invalid rows")
	}
	targets, err := s.previewTargets(ctx, tx, p, true, !p.updated.Valid)
	if err != nil {
		return nil, err
	}
	if err = s.authorizeWrite(ctx); err != nil {
		return nil, err
	}
	hostAuditTargets(ctx, targets)
	if p.updated.Valid {
		return connect.NewResponse(&v1.ExecuteHostImportResponse{UpdatedCount: uint64(p.updated.Int64)}), nil
	}
	for _, target := range p.targets {
		b, _ := json.Marshal(target.After)
		if _, err = tx.Exec(ctx, "UPDATE hosts SET authorization_labels=$2,revision=revision+1 WHERE host_id=$1", target.HostID, b); err != nil {
			return nil, dbError(err)
		}
	}
	count := len(p.targets)
	if _, err = tx.Exec(ctx, "UPDATE host_import_previews SET updated_count=$2 WHERE preview_id=$1", p.meta.PreviewId, count); err != nil {
		return nil, dbError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.ExecuteHostImportResponse{UpdatedCount: uint64(count)}), nil
}
