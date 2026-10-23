package api

import (
	"context"
	"time"

	"github.com/Masterminds/semver/v3"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/updatecheck"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func optionalStamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return stamp(t)
}

// gatewayUpdate returns the stored check result and, when the check is enabled
// and the build is a strict SemVer release older than the stored latest
// version, the update to announce. A missing row is "not checked yet".
func (s *Service) gatewayUpdate(ctx context.Context) (*v1.GatewayUpdate, updatecheck.State, error) {
	if !s.Config.UpdateCheckEnabled {
		return nil, updatecheck.State{}, nil
	}
	st, err := updatecheck.Load(ctx, s.Store.Pool)
	if err != nil {
		return nil, st, dbError(err)
	}
	build, err := semver.StrictNewVersion(s.buildVersion())
	if err != nil {
		return nil, st, nil
	}
	latest, err := semver.StrictNewVersion(st.LatestVersion)
	if err != nil || !latest.GreaterThan(build) {
		return nil, st, nil
	}
	return &v1.GatewayUpdate{LatestVersion: st.LatestVersion, PublishedAt: optionalStamp(st.PublishedAt), CheckedAt: optionalStamp(st.CheckedAt)}, st, nil
}

// hostsBelowGatewayVersion counts hosts whose agent version is a strict SemVer
// lower than the gateway's SemVer version.
func hostsBelowGatewayVersion(gateway string, hosts []*v1.Host) uint64 {
	g, err := semver.StrictNewVersion(gateway)
	if err != nil {
		return 0
	}
	var n uint64
	for _, h := range hosts {
		if a, err := semver.StrictNewVersion(h.AgentVersion); err == nil && a.LessThan(g) {
			n++
		}
	}
	return n
}
