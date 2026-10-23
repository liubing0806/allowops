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

// importHeader reads and validates the CSV header. headerErrors holds one
// message per invalid, duplicate or conflicting column.
func importHeader(csvBytes []byte, cfg ManagementConfig) (reader *csv.Reader, header, headerErrors []string, err error) {
	if len(csvBytes) > cfg.MaxCSVBytes {
		return nil, nil, nil, failure(connect.CodeResourceExhausted, "CSV byte limit exceeded")
	}
	if !utf8.Valid(csvBytes) {
		return nil, nil, nil, failure(connect.CodeInvalidArgument, "CSV must be UTF-8")
	}
	reader = csv.NewReader(bytes.NewReader(csvBytes))
	reader.FieldsPerRecord = -1
	header, err = reader.Read()
	if err != nil || len(header) < 2 || header[0] != "hostname" {
		return nil, nil, nil, failure(connect.CodeInvalidArgument, "CSV header must start with hostname")
	}
	headerErrors = []string{}
	keys := map[string]bool{}
	for _, column := range header[1:] {
		verb, key, ok := strings.Cut(column, ":")
		if !ok || key == "" || (verb != "set" && verb != "remove") || keys[key] {
			headerErrors = append(headerErrors, "invalid, duplicate or conflicting column")
		}
		keys[key] = true
	}
	return reader, header, headerErrors, nil
}

// importRowLabels applies the label columns of one record to row.After and
// records a violation for each rejected value.
func (s *Service) importRowLabels(row *v1.HostImportRow, header, record []string) {
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

// importRow validates one CSV record against the host it names.
func (s *Service) importRow(ctx context.Context, header, headerErrors, record []string, line int, h *v1.Host, seen map[string]bool) (*v1.HostImportRow, error) {
	row := &v1.HostImportRow{Line: uint32(line), Hostname: record[0]}
	for _, e := range headerErrors {
		violation(row, "header", e)
	}
	if h == nil {
		violation(row, "hostname", "host not found")
	} else {
		if _, err := s.Require(ctx, authz.ManageHosts, authz.Action{}, hostAttributes(h)); err != nil {
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
		s.importRowLabels(row, header, record)
	}
	return row, nil
}

// importRows reads every remaining CSV record and returns the preview rows,
// the targets of the rows naming an existing host and the invalid row count.
func (s *Service) importRows(ctx context.Context, reader *csv.Reader, header, headerErrors []string, hosts []*v1.Host) ([]*v1.HostImportRow, []importTarget, uint64, error) {
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
			return nil, nil, 0, failure(connect.CodeInvalidArgument, "malformed RFC 4180 CSV")
		}
		if len(rows) >= s.management.config.MaxCSVRows {
			return nil, nil, 0, failure(connect.CodeResourceExhausted, "CSV row limit exceeded")
		}
		line, _ := reader.FieldPos(0)
		h := byName[record[0]]
		row, err := s.importRow(ctx, header, headerErrors, record, line, h, seen)
		if err != nil {
			return nil, nil, 0, err
		}
		if len(row.Violations) > 0 {
			invalid++
		}
		if h != nil {
			targets = append(targets, importTarget{h.HostId, h.Revision, h.Hostname, row.After})
		}
		rows = append(rows, row)
	}
	return rows, targets, invalid, nil
}

func (s *Service) PreviewHostImport(ctx context.Context, req *connect.Request[v1.PreviewHostImportRequest]) (*connect.Response[v1.PreviewHostImportResponse], error) {
	cfg := s.management.config
	reader, header, headerErrors, err := importHeader(req.Msg.Csv, cfg)
	if err != nil {
		return nil, err
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
	rows, targets, invalid, err := s.importRows(ctx, reader, header, headerErrors, hosts)
	if err != nil {
		return nil, err
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
	if err = purgeImportPreviews(ctx, tx); err != nil {
		return nil, dbError(err)
	}
	expires := time.Now().Add(cfg.PreviewTTL)
	id := secret("hip_")
	rawRows, _ := json.Marshal(rows)
	rawTargets, _ := json.Marshal(targets)
	digest := hash(string(req.Msg.Csv))
	if err = insertImportPreview(ctx, tx, id, reqctx.ActorID(ctx), digest, rawRows, rawTargets, invalid, expires); err != nil {
		return nil, dbError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.PreviewHostImportResponse{Preview: &v1.HostImportPreview{PreviewId: id, CsvSha256: digest, RowCount: uint64(len(rows)), InvalidRowCount: invalid, ExpiresAt: stamp(expires)}}), nil
}

func (s *Service) preview(ctx context.Context, q querier, id string, lock bool) (*storedPreview, error) {
	p := &storedPreview{meta: &v1.HostImportPreview{PreviewId: id}}
	r, err := importPreview(ctx, q, id, lock)
	if err != nil {
		return nil, dbError(err)
	}
	p.meta.CsvSha256, p.meta.InvalidRowCount, p.updated = r.digest, uint64(r.invalid), r.updated
	rows, targets, expires := r.rows, r.targets, r.expires
	if r.actor != reqctx.ActorID(ctx) {
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
		if err = setHostLabels(ctx, tx, target.HostID, b); err != nil {
			return nil, dbError(err)
		}
	}
	count := len(p.targets)
	if err = setImportPreviewUpdated(ctx, tx, p.meta.PreviewId, count); err != nil {
		return nil, dbError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.ExecuteHostImportResponse{UpdatedCount: uint64(count)}), nil
}
