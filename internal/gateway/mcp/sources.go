package mcp

import (
	"context"
	"crypto/sha256"
	"errors"
	"maps"
	"slices"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/store/db"
)

func (s *Service) currentAction(ctx context.Context, name string) (catalog.Action, error) {
	current, err := s.identity.Database().Queries.CurrentCatalogs(ctx)
	if err != nil {
		return catalog.Action{}, accessError(connect.CodeUnavailable, "catalog unavailable")
	}
	for _, c := range current {
		if time.Now().After(c.ExpiresAt.Time.Add(catalog.ClockSkew)) {
			continue
		}
		stored, err := s.identity.Database().Queries.GetCatalog(ctx, db.GetCatalogParams{CatalogID: c.CatalogID, Version: c.Version})
		if err != nil {
			return catalog.Action{}, accessError(connect.CodeUnavailable, "catalog unavailable")
		}
		digest := sha256.Sum256(stored.Dsse)
		if c.EnvelopeSizeBytes > int64(s.catalogs.MaxEnvelopeBytes) || !slices.Equal(digest[:], c.Digest) {
			return catalog.Action{}, accessError(connect.CodeUnavailable, "catalog integrity check failed")
		}
		pkg, err := s.catalogs.Verify(stored.Dsse)
		if err != nil {
			return catalog.Action{}, accessError(connect.CodeUnavailable, "catalog verification failed")
		}
		if pkg.CatalogID != c.CatalogID || pkg.Version != c.Version {
			return catalog.Action{}, accessError(connect.CodeUnavailable, "catalog reference mismatch")
		}
		if action, ok := pkg.Actions[name]; ok {
			return action, nil
		}
	}
	return catalog.Action{}, accessError(connect.CodeNotFound, "action removed or expired; call tools/list to refresh")
}
func (s *Service) searchHosts(ctx context.Context, raw []byte) (*ToolResult, error) {
	args, err := fixedArguments(raw, "hostname", "selector", "next_cursor")
	if err != nil {
		return nil, err
	}
	var hostname, selector, cursor string
	for _, field := range []struct {
		name  string
		value *string
	}{{"hostname", &hostname}, {"selector", &selector}, {"next_cursor", &cursor}} {
		if err = decodeField(args, field.name, field.value, false); err != nil {
			return nil, invalidArguments(err)
		}
	}
	if err = validateHostSearchSelection(hostname, selector); err != nil {
		return nil, invalidArguments(err)
	}
	response, err := s.identity.ListHosts(ctx, connect.NewRequest(&v1.ListHostsRequest{Query: &v1.HostQuery{Hostname: hostname, Selector: selector}, Page: &v1.PageRequest{PageSize: 1, PageToken: cursor}}))
	if err != nil {
		return nil, err
	}
	hosts := []map[string]any{}
	for _, h := range response.Msg.Hosts {
		hosts = append(hosts, map[string]any{"host": h.Hostname, "labels": h.AuthorizationLabels, "reported_labels": h.ReportedLabels, "online": h.Online})
	}
	counts := response.Msg.AuthorizationLabelCounts
	encode := func() (*ToolResult, int, error) {
		return toolResult(map[string]any{"hosts": hosts, "total": response.Msg.TotalCount, "label_distribution": counts, "label_counts_truncated": response.Msg.LabelCountsTruncated || len(counts) < len(response.Msg.AuthorizationLabelCounts), "next_cursor": response.Msg.Page.GetNextPageToken(), "output_trust": "untrusted"})
	}
	result, size, err := encode()
	if err != nil || size <= resultByteLimit {
		return result, err
	}
	allCounts := counts
	low, high := 0, len(counts)
	for low < high {
		mid := low + (high-low+1)/2
		counts = allCounts[:mid]
		_, candidateSize, err := encode()
		if err != nil {
			return nil, err
		}
		if candidateSize <= resultByteLimit {
			low = mid
		} else {
			high = mid - 1
		}
	}
	counts = allCounts[:low]
	result, size, err = encode()
	if err != nil || size <= resultByteLimit {
		return result, err
	}
	if len(hosts) != 1 {
		return nil, errors.New("host metadata exceeds 32KB result limit")
	}
	// A single host can exceed the budget by itself. Keep its identity and
	// online state, and fit a stable prefix of labels with an explicit marker (design G55).
	host := hosts[0]
	host["labels_truncated"] = true
	type labelEntry struct{ field, key, value string }
	labels := []labelEntry{}
	for _, field := range []string{"labels", "reported_labels"} {
		values := host[field].(map[string]string)
		keys := slices.Collect(maps.Keys(values))
		slices.Sort(keys)
		for _, key := range keys {
			labels = append(labels, labelEntry{field, key, values[key]})
		}
	}
	keep := func(n int) {
		host["labels"] = map[string]string{}
		host["reported_labels"] = map[string]string{}
		for _, label := range labels[:n] {
			host[label.field].(map[string]string)[label.key] = label.value
		}
	}
	low, high = 0, len(labels)
	for low < high {
		mid := low + (high-low+1)/2
		keep(mid)
		_, candidateSize, err := encode()
		if err != nil {
			return nil, err
		}
		if candidateSize <= resultByteLimit {
			low = mid
		} else {
			high = mid - 1
		}
	}
	keep(low)
	result, size, err = encode()
	if size > resultByteLimit {
		return nil, errors.New("host metadata exceeds 32KB result limit")
	}
	return result, err
}
