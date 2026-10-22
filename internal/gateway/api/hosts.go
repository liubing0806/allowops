package api

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/store"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

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
func (s *Service) hosts(ctx context.Context, q querier, lock bool) ([]*v1.Host, error) {
	return s.hostsWhere(ctx, q, "", lock)
}

// hostsWhere reads active hosts in host_id order. where is an extra condition
// over h whose placeholders start at $2 ($1 is the heartbeat window). With lock,
// only the selected rows are locked, in that order.
func (s *Service) hostsWhere(ctx context.Context, q querier, where string, lock bool, args ...any) ([]*v1.Host, error) {
	sql := "SELECT " + hostColumns + " FROM hosts h WHERE certificate_status='active'" + where + " ORDER BY host_id"
	if lock {
		sql += " FOR UPDATE OF h"
	}
	rows, err := q.Query(ctx, sql, append([]any{max(2*s.gatewayConfig().FlushInterval, s.gatewayConfig().HeartbeatTimeout).String()}, args...)...)
	if err != nil {
		return nil, dbError(err)
	}
	defer rows.Close()
	out := []*v1.Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, dbError(err)
		}
		out = append(out, h)
	}
	return out, dbError(rows.Err())
}
func hostAttributes(h *v1.Host) authz.Host {
	return authz.Host{ID: h.HostId, Labels: h.AuthorizationLabels}
}

type labelCondition struct {
	key, value string
	reported   bool
}

func parseSelector(selector string, empty bool) ([]labelCondition, error) {
	if selector == "" && empty {
		return nil, nil
	}
	out := []labelCondition{}
	seen := map[string]string{}
	for _, part := range strings.Split(selector, ",") {
		if strings.Count(part, "=") != 1 {
			return nil, failure(connect.CodeInvalidArgument, "selector requires key=value conjunctions")
		}
		key, value, _ := strings.Cut(part, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		previous, repeated := seen[key]
		if key == "" || value == "" || !utf8.ValidString(part) || repeated && previous != value {
			return nil, failure(connect.CodeInvalidArgument, "invalid or repeated selector condition")
		}
		seen[key] = value
		c := labelCondition{key: key, value: value}
		if strings.HasPrefix(key, "reported.") {
			c.reported = true
			c.key = strings.TrimPrefix(key, "reported.")
			if c.key == "" {
				return nil, failure(connect.CodeInvalidArgument, "reported label key required")
			}
		}
		out = append(out, c)
	}
	return out, nil
}
func matches(h *v1.Host, conditions []labelCondition) bool {
	for _, c := range conditions {
		labels := h.AuthorizationLabels
		if c.reported {
			labels = h.ReportedLabels
		}
		v, ok := labels[c.key]
		if !ok || v != c.value {
			return false
		}
	}
	return true
}

// lockTargets resolves the request's targets and locks only those host rows, in
// host_id order, so a write does not block routing reads of unrelated hosts.
// Selector targets are chosen first, then locked and matched again against the
// locked rows; a host that changed in between is the same aborted outcome as a
// changed target count.
func (s *Service) lockTargets(ctx context.Context, tx pgx.Tx, targets *v1.HostTargets) ([]*v1.Host, error) {
	if targets == nil {
		return nil, failure(connect.CodeInvalidArgument, "targets required")
	}
	switch t := targets.Selection.(type) {
	case *v1.HostTargets_Selector:
		c, err := parseSelector(t.Selector, false)
		if err != nil {
			return nil, err
		}
		authorization, reported := map[string]string{}, map[string]string{}
		for _, condition := range c {
			if condition.reported {
				reported[condition.key] = condition.value
			} else {
				authorization[condition.key] = condition.value
			}
		}
		a, _ := json.Marshal(authorization)
		r, _ := json.Marshal(reported)
		rows, err := tx.Query(ctx, "SELECT host_id FROM hosts WHERE certificate_status='active' AND authorization_labels @> $1::jsonb AND reported_labels @> $2::jsonb ORDER BY host_id", a, r)
		if err != nil {
			return nil, dbError(err)
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return nil, dbError(err)
		}
		locked, err := s.hostsWhere(ctx, tx, " AND h.host_id = ANY($2)", true, ids)
		if err != nil {
			return nil, err
		}
		if len(locked) != len(ids) {
			return nil, failure(connect.CodeAborted, "target hosts changed")
		}
		for _, h := range locked {
			if !matches(h, c) {
				return nil, failure(connect.CodeAborted, "target hosts changed")
			}
		}
		return locked, nil
	case *v1.HostTargets_Hosts:
		if t.Hosts == nil || len(t.Hosts.Names) == 0 {
			return nil, failure(connect.CodeInvalidArgument, "hostnames required")
		}
		names := map[string]bool{}
		for _, name := range t.Hosts.Names {
			if name == "" || names[name] {
				return nil, failure(connect.CodeInvalidArgument, "invalid or repeated hostname")
			}
			names[name] = true
		}
		out, err := s.hostsWhere(ctx, tx, " AND h.hostname = ANY($2)", true, t.Hosts.Names)
		if err != nil {
			return nil, err
		}
		if len(out) != len(names) {
			return nil, failure(connect.CodeNotFound, "target host not found")
		}
		return out, nil
	}
	return nil, failure(connect.CodeInvalidArgument, "targets required")
}
func (s *Service) visibleHosts(ctx context.Context, hosts []*v1.Host) ([]*v1.Host, error) {
	out := []*v1.Host{}
	for _, h := range hosts {
		ok, err := s.can(ctx, authz.ViewHosts, authz.Action{}, hostAttributes(h))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		if _, err := s.Require(ctx, authz.ViewHosts, authz.Action{}, authz.Host{}); err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (s *Service) ListHosts(ctx context.Context, req *connect.Request[v1.ListHostsRequest]) (*connect.Response[v1.ListHostsResponse], error) {
	query := req.Msg.GetQuery()
	conditions, err := parseSelector(query.GetSelector(), true)
	if err != nil {
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
	out := []*v1.Host{}
	buckets := map[[2]string]*v1.LabelCount{}
	for _, h := range visible {
		if !matches(h, conditions) || query.GetHostname() != "" && h.Hostname != query.Hostname || query != nil && query.Online != nil && h.Online != *query.Online || query.GetAgentVersion() != "" && query.AgentVersion != h.AgentVersion {
			continue
		}
		if query.GetLoadedCatalog() != nil {
			found := false
			for _, c := range h.LoadedCatalogs {
				if proto.Equal(c, query.LoadedCatalog) {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		out = append(out, h)
		for key, value := range h.AuthorizationLabels {
			id := [2]string{key, value}
			if buckets[id] == nil {
				buckets[id] = &v1.LabelCount{Key: key, Value: value}
			}
			buckets[id].Count++
		}
	}
	keys := slices.Collect(maps.Keys(buckets))
	slices.SortFunc(keys, func(a, b [2]string) int {
		if n := strings.Compare(a[0], b[0]); n != 0 {
			return n
		}
		return strings.Compare(a[1], b[1])
	})
	counts := []*v1.LabelCount{}
	for _, key := range keys[:min(len(keys), s.management.config.LabelCountBuckets)] {
		counts = append(counts, buckets[key])
	}
	b, _ := encode(req.Msg.Query)
	cfg := s.Config
	// Reserve the exact encoded statistics and response metadata before paging.
	for {
		metadata, _ := protojson.Marshal(&v1.ListHostsResponse{TotalCount: uint64(len(out)), AuthorizationLabelCounts: counts, LabelCountsTruncated: len(counts) < len(buckets)})
		cfg.MessageBytes = s.Config.MessageBytes - len(metadata) - 64
		if cfg.MessageBytes >= s.Config.MessageBytes/2 || len(counts) == 0 {
			break
		}
		counts = counts[:len(counts)-1]
	}
	paged, cursor, err := page(ctx, cfg, "hosts:"+string(b), req.Msg.Page, out)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.ListHostsResponse{Hosts: paged, Page: cursor, TotalCount: uint64(len(out)), AuthorizationLabelCounts: counts, LabelCountsTruncated: len(counts) < len(buckets)}), nil
}
func (s *Service) GetHost(ctx context.Context, req *connect.Request[v1.GetHostRequest]) (*connect.Response[v1.GetHostResponse], error) {
	h, err := scanHost(s.Store.Pool.QueryRow(ctx, "SELECT "+hostColumns+" FROM hosts h WHERE hostname=$2 AND certificate_status='active'", max(2*s.gatewayConfig().FlushInterval, s.gatewayConfig().HeartbeatTimeout).String(), req.Msg.Hostname))
	if err != nil {
		return nil, dbError(err)
	}
	if _, err = s.Require(ctx, authz.ViewHosts, authz.Action{}, hostAttributes(h)); err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.GetHostResponse{Host: h}), nil
}
func (s *Service) changedLabels(before map[string]string, changes *v1.LabelChanges) (map[string]string, error) {
	if changes == nil || len(changes.Set)+len(changes.Remove) == 0 {
		return nil, failure(connect.CodeInvalidArgument, "label changes required")
	}
	out := maps.Clone(before)
	if out == nil {
		out = map[string]string{}
	}
	seen := map[string]bool{}
	for _, key := range changes.Remove {
		if _, ok := changes.Set[key]; ok || seen[key] {
			return nil, failure(connect.CodeInvalidArgument, "conflicting label changes")
		}
		seen[key] = true
		delete(out, key)
	}
	for key, value := range changes.Set {
		out[key] = value
	}
	cfg := s.management.config
	for key := range seen {
		if key == "" || len(key) > cfg.LabelKeyBytes || !utf8.ValidString(key) {
			return nil, failure(connect.CodeInvalidArgument, "invalid label key")
		}
	}
	if len(out) > cfg.LabelCount {
		return nil, failure(connect.CodeInvalidArgument, "too many labels")
	}
	for key, value := range out {
		if key == "" || len(key) > cfg.LabelKeyBytes || len(value) > cfg.LabelValueBytes || !utf8.ValidString(key) || !utf8.ValidString(value) {
			return nil, failure(connect.CodeInvalidArgument, "invalid label")
		}
	}
	return out, nil
}
func (s *Service) SetHostLabels(ctx context.Context, req *connect.Request[v1.SetHostLabelsRequest]) (*connect.Response[v1.SetHostLabelsResponse], error) {
	ctx, err := s.pinPolicy(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := s.Store.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	targets, err := s.lockTargets(ctx, tx, req.Msg.Targets)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 || uint64(len(targets)) != req.Msg.ExpectedCount {
		return nil, failure(connect.CodeAborted, "target count changed")
	}
	revisions := map[string]string{}
	for _, r := range req.Msg.ExpectedRevisions {
		if r == nil || r.HostId == "" || r.Revision == "" || revisions[r.HostId] != "" {
			return nil, failure(connect.CodeInvalidArgument, "exact target revisions required")
		}
		revisions[r.HostId] = r.Revision
	}
	if len(revisions) != len(targets) {
		return nil, failure(connect.CodeAborted, "target revisions changed")
	}
	updated := map[string]map[string]string{}
	for _, h := range targets {
		if _, err = s.Require(ctx, authz.ManageHosts, authz.Action{}, hostAttributes(h)); err != nil {
			return nil, err
		}
		if revisions[h.HostId] != h.Revision {
			return nil, failure(connect.CodeAborted, "host revision changed")
		}
		labels, err := s.changedLabels(h.AuthorizationLabels, req.Msg.Changes)
		if err != nil {
			return nil, err
		}
		updated[h.HostId] = labels
	}
	hostAuditTargets(ctx, targets)
	if err = s.authorizeWrite(ctx); err != nil {
		return nil, err
	}
	for _, h := range targets {
		b, _ := json.Marshal(updated[h.HostId])
		if _, err = tx.Exec(ctx, "UPDATE hosts SET authorization_labels=$2,revision=revision+1 WHERE host_id=$1", h.HostId, b); err != nil {
			return nil, dbError(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.SetHostLabelsResponse{UpdatedCount: uint64(len(targets))}), nil
}
func (s *Service) DeleteHost(ctx context.Context, req *connect.Request[v1.DeleteHostRequest]) (*connect.Response[v1.DeleteHostResponse], error) {
	if req.Msg.HostId == "" || req.Msg.ExpectedRevision == "" {
		return nil, failure(connect.CodeInvalidArgument, "host ID and revision required")
	}
	ctx, err := s.pinPolicy(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	h, err := scanHost(tx.QueryRow(ctx, "SELECT "+hostColumns+" FROM hosts h WHERE host_id=$2 AND certificate_status='active' FOR UPDATE OF h", max(2*s.gatewayConfig().FlushInterval, s.gatewayConfig().HeartbeatTimeout).String(), req.Msg.HostId))
	if err != nil {
		return nil, dbError(err)
	}
	if _, err = s.Require(ctx, authz.ManageHosts, authz.Action{}, hostAttributes(h)); err != nil {
		return nil, err
	}
	hostAuditTargets(ctx, []*v1.Host{h})
	if h.Revision != req.Msg.ExpectedRevision {
		return nil, failure(connect.CodeAborted, "host revision changed")
	}
	if err = s.authorizeWrite(ctx); err != nil {
		return nil, err
	}
	if err = store.DeleteHostTx(ctx, tx, h.HostId); err != nil {
		return nil, dbError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.DeleteHostResponse{}), nil
}
