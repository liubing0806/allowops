package job

import (
	"context"
	"encoding/hex"
	"errors"
	"google.golang.org/protobuf/encoding/protojson"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
	"github.com/liubing0806/allowops/internal/executor"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/params"
)

func failure(code connect.Code, reason string) error {
	e := connect.NewError(code, errors.New(reason))
	d, err := connect.NewErrorDetail(&v1.ErrorDetail{Reason: reason})
	if err == nil {
		e.AddDetail(d)
	}
	return e
}

func detailError(code connect.Code, d *v1.ErrorDetail) error {
	for {
		raw, err := protojson.Marshal(d)
		if err != nil || len(raw) <= ResponseBytes-1024 {
			break
		}
		d.DetailsTruncated = true
		if len(d.DeniedHosts) > 0 {
			d.DeniedHosts = d.DeniedHosts[:len(d.DeniedHosts)-1]
		} else if len(d.Violations) > 0 {
			d.Violations = d.Violations[:len(d.Violations)-1]
		} else {
			break
		}
	}
	e := connect.NewError(code, errors.New(d.Reason))
	x, err := connect.NewErrorDetail(d)
	if err == nil {
		e.AddDetail(x)
	}
	return e
}

func format(value string) (string, error) {
	if value == "" {
		return "concise", nil
	}
	if value != "concise" && value != "detailed" {
		return "", failure(connect.CodeInvalidArgument, "INVALID_RESPONSE_FORMAT")
	}
	return value, nil
}

func (s *Service) waitValue(value *uint32, defaultValue uint32) (uint32, error) {
	if value == nil {
		return defaultValue, nil
	}
	if *value > s.Config.MaxWaitSeconds {
		return 0, failure(connect.CodeInvalidArgument, "WAIT_SECONDS_EXCEEDED")
	}
	return *value, nil
}

func prepare(action catalog.Action, r *v1.RunJobRequest, c Config) (uint32, uint32, error) {
	if strings.TrimSpace(r.Reason) == "" || len(r.Reason) > 4096 {
		return 0, 0, failure(connect.CodeInvalidArgument, "REASON_REQUIRED_OR_TOO_LONG")
	}
	data := r.GetParams().GetJson()
	if len(data) == 0 {
		data = []byte("{}")
	}
	input, err := execd.DecodeParameters(data)
	if err != nil {
		return 0, 0, failure(connect.CodeInvalidArgument, "INVALID_PARAMETERS")
	}
	defs, err := catalog.ParameterDefinitions(action)
	if err != nil {
		return 0, 0, failure(connect.CodeFailedPrecondition, "ACTION_UNSUPPORTED")
	}
	if _, err := params.ParseGateway(defs, input); err != nil {
		// Values never enter error text. Constraints come from the signed schema.
		violations := []*v1.FieldViolation{}
		for name, def := range defs {
			violations = append(violations, &v1.FieldViolation{Field: name, Description: string(def.Type), AllowedValues: def.Values})
		}
		slices.SortFunc(violations, func(a, b *v1.FieldViolation) int { return strings.Compare(a.Field, b.Field) })
		return 0, 0, detailError(connect.CodeInvalidArgument, &v1.ErrorDetail{Reason: "INVALID_PARAMETERS", Violations: violations})
	}
	filters := map[string]any{}
	selected := 0
	if f := r.Filters; f != nil {
		if f.Match != nil {
			filters["match"] = *f.Match
		}
		if f.Exclude != nil {
			filters["exclude"] = *f.Exclude
		}
		if f.Head != nil {
			filters["head"] = int64(*f.Head)
			selected++
		}
		if f.Tail != nil {
			filters["tail"] = int64(*f.Tail)
			selected++
		}
		if f.Count != nil {
			filters["count"] = *f.Count
			selected++
		}
	}
	if selected > 1 {
		return 0, 0, failure(connect.CodeInvalidArgument, "INVALID_FILTERS")
	}
	if _, err := executor.ParseFilters(action.Filters, filters); err != nil {
		return 0, 0, failure(connect.CodeInvalidArgument, "INVALID_FILTERS")
	}
	batch, failures := c.BatchSize, c.MaxFailures
	if action.BatchSize > 0 {
		batch = uint32(min(int64(batch), int64(action.BatchSize)))
	}
	if action.MaxFailures != nil {
		failures = uint32(min(int64(failures), int64(*action.MaxFailures)))
	}
	if r.BatchSize != nil {
		if *r.BatchSize == 0 || *r.BatchSize > batch {
			return 0, 0, failure(connect.CodeInvalidArgument, "BATCH_SIZE_MUST_TIGHTEN")
		}
		batch = *r.BatchSize
	}
	if r.MaxFailures != nil {
		if *r.MaxFailures > failures {
			return 0, 0, failure(connect.CodeInvalidArgument, "MAX_FAILURES_MUST_TIGHTEN")
		}
		failures = *r.MaxFailures
	}
	return batch, failures, nil
}

func (s *Service) action(ctx context.Context, name string) (*catalog.Package, catalog.Action, []byte, error) {
	refs, err := s.Store.Queries.CurrentCatalogs(ctx)
	if err != nil {
		return nil, catalog.Action{}, nil, failure(connect.CodeUnavailable, "CATALOG_UNAVAILABLE")
	}
	for _, ref := range refs {
		if !slices.Contains(ref.ActionNames, name) {
			continue
		}
		row, err := s.Store.Queries.GetCatalog(ctx, structCatalogRef(ref.CatalogID, ref.Version))
		if err != nil {
			return nil, catalog.Action{}, nil, failure(connect.CodeUnavailable, "CATALOG_UNAVAILABLE")
		}
		env, err := catalog.ParseEnvelope(row.Dsse)
		if err != nil {
			return nil, catalog.Action{}, nil, failure(connect.CodeUnavailable, "CATALOG_INVALID")
		}
		p, err := catalog.Verify(env, s.Trusted, catalog.VerifyOptions{})
		if err != nil {
			return nil, catalog.Action{}, nil, failure(connect.CodeFailedPrecondition, "CATALOG_INVALID_OR_EXPIRED")
		}
		a, ok := p.Actions[name]
		if !ok {
			continue
		}
		digest, err := hex.DecodeString(p.Digests[name])
		if err != nil {
			return nil, a, nil, err
		}
		return p, a, digest, nil
	}
	return nil, catalog.Action{}, nil, failure(connect.CodeNotFound, "ACTION_UNKNOWN")
}

type host struct {
	ID, Name, Connection string
	Labels, Reported     map[string]string
}

func (h host) attributes() authz.Host { return authz.Host{ID: h.ID, Labels: h.Labels} }

func selectTargets(all []host, targets *v1.HostTargets) ([]host, error) {
	if targets == nil {
		return nil, failure(connect.CodeInvalidArgument, "TARGETS_REQUIRED")
	}
	result := []host{}
	switch sel := targets.Selection.(type) {
	case *v1.HostTargets_Hosts:
		if sel.Hosts == nil || len(sel.Hosts.Names) == 0 {
			return nil, failure(connect.CodeInvalidArgument, "HOSTS_REQUIRED")
		}
		names := slices.Clone(sel.Hosts.Names)
		slices.Sort(names)
		names = slices.Compact(names)
		for _, name := range names {
			found := false
			for _, h := range all {
				if h.Name == name {
					result = append(result, h)
					found = true
					break
				}
			}
			if !found {
				return nil, failure(connect.CodeNotFound, "HOST_UNKNOWN")
			}
		}
	case *v1.HostTargets_Selector:
		labels := map[string]string{}
		for _, term := range strings.Split(sel.Selector, ",") {
			p := strings.Split(term, "=")
			if len(p) != 2 || strings.TrimSpace(p[0]) == "" || strings.TrimSpace(p[1]) == "" {
				return nil, failure(connect.CodeInvalidArgument, "INVALID_SELECTOR")
			}
			k, v := strings.TrimSpace(p[0]), strings.TrimSpace(p[1])
			if old, ok := labels[k]; ok && old != v {
				return nil, failure(connect.CodeInvalidArgument, "CONFLICTING_SELECTOR")
			}
			labels[k] = v
		}
		for _, h := range all {
			match := true
			for k, v := range labels {
				actual := h.Labels[k]
				if strings.HasPrefix(k, "reported.") {
					actual = h.Reported[strings.TrimPrefix(k, "reported.")]
				}
				if actual != v {
					match = false
					break
				}
			}
			if match {
				result = append(result, h)
			}
		}
	default:
		return nil, failure(connect.CodeInvalidArgument, "TARGETS_REQUIRED")
	}
	return result, nil
}

func timeout(a catalog.Action) time.Duration { v, _ := time.ParseDuration(a.Timeout); return v }
