package api

import (
	"context"
	"slices"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
)

func (s *Service) systemHosts(ctx context.Context) ([]*v1.Host, error) {
	all, err := s.hosts(ctx, s.Store.Pool, false)
	if err != nil {
		return nil, err
	}
	out := []*v1.Host{}
	for _, h := range all {
		ok, err := s.can(ctx, authz.ViewHosts, authz.Action{}, hostAttributes(h))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, h)
		}
	}
	return out, nil
}
func (s *Service) dependencyHealth(ctx context.Context) []*v1.DependencyHealth {
	postgres := &v1.DependencyHealth{Name: "postgresql", Status: v1.HealthStatus_HEALTH_STATUS_HEALTHY}
	if s.Store.Pool.Ping(ctx) != nil {
		postgres.Status = v1.HealthStatus_HEALTH_STATUS_UNAVAILABLE
		postgres.Reason = "dependency unavailable"
	}
	jobs := &v1.DependencyHealth{Name: "job_statistics", Status: v1.HealthStatus_HEALTH_STATUS_HEALTHY}
	if s.jobStatistics == nil {
		jobs.Status = v1.HealthStatus_HEALTH_STATUS_UNAVAILABLE
		jobs.Reason = "job counts unavailable"
	}
	objects := &v1.DependencyHealth{Name: "object_storage", Status: v1.HealthStatus_HEALTH_STATUS_UNAVAILABLE, Reason: "dependency unavailable"}
	if s.objectStorage != nil {
		check, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := s.objectStorage.Check(check)
		cancel()
		if err == nil {
			objects.Status = v1.HealthStatus_HEALTH_STATUS_HEALTHY
			objects.Reason = ""
		}
	}
	return []*v1.DependencyHealth{postgres, jobs, objects}
}
func (s *Service) GetSystemStatus(ctx context.Context, _ *connect.Request[v1.GetSystemStatusRequest]) (*connect.Response[v1.GetSystemStatusResponse], error) {
	out := &v1.GetSystemStatusResponse{ObservedAt: stamp(time.Now()), Status: v1.HealthStatus_HEALTH_STATUS_DEGRADED, Dependencies: s.dependencyHealth(ctx)}
	g := s.gatewayConfig()
	out.UpdateCheckEnabled, out.GatewayVersion = s.Config.UpdateCheckEnabled, s.buildVersion()
	out.Limits = &v1.ApiLimits{MaxMessageBytes: uint32(s.Config.MessageBytes), MaxChunkBytes: uint32(g.ChunkBytes), DefaultPageSize: uint32(s.Config.PageSize), MaxPageSize: uint32(s.Config.MaxPageSize), DefaultOutputPageBytes: 16 << 10, MaxOutputPageBytes: 24 << 10, MaxCatalogBytes: uint64(g.EnvelopeBytes), MaxCsvBytes: uint32(s.management.config.MaxCSVBytes)}
	if out.Dependencies[0].Status == v1.HealthStatus_HEALTH_STATUS_UNAVAILABLE {
		out.Status = v1.HealthStatus_HEALTH_STATUS_UNAVAILABLE
		return connect.NewResponse(out), nil
	}
	update, checked, err := s.gatewayUpdate(ctx)
	if err != nil {
		return nil, err
	}
	out.GatewayUpdate, out.UpdateCheckedAt, out.UpdateCheckError = update, optionalStamp(checked.CheckedAt), checked.LastError
	if s.jobStatistics != nil {
		out.RunningJobs, out.FailedJobsLast_24Hours, err = s.jobStatistics.Statistics(ctx)
		if err != nil {
			out.RunningJobs, out.FailedJobsLast_24Hours = 0, 0
			out.Dependencies[1].Status = v1.HealthStatus_HEALTH_STATUS_UNAVAILABLE
			out.Dependencies[1].Reason = "job counts unavailable"
		}
		out.Limits.DefaultOutputPageBytes = 16 << 10
		out.Limits.MaxOutputPageBytes = 24 << 10
	}
	out.Status = v1.HealthStatus_HEALTH_STATUS_HEALTHY
	for _, d := range out.Dependencies {
		if d.Status != v1.HealthStatus_HEALTH_STATUS_HEALTHY {
			out.Status = v1.HealthStatus_HEALTH_STATUS_DEGRADED
		}
	}
	hosts, err := s.systemHosts(ctx)
	if err != nil {
		return nil, err
	}
	out.HostsBelowGatewayVersion = hostsBelowGatewayVersion(g.Version, hosts)
	for _, h := range hosts {
		if h.Online {
			out.OnlineHosts++
		} else {
			out.OfflineHosts++
		}
	}
	ok, err := s.can(ctx, authz.ViewCatalog, authz.Action{}, authz.Host{})
	if err != nil {
		return nil, err
	}
	if ok {
		if err = s.Store.Pool.QueryRow(ctx, `SELECT count(*) FROM catalog_versions c WHERE c.version=(SELECT max(version) FROM catalog_versions WHERE catalog_id=c.catalog_id) AND expires_at>now() AND expires_at<=now()+interval '14 days'`).Scan(&out.ExpiringCatalogs); err != nil {
			return nil, dbError(err)
		}
	}
	ok, err = s.can(ctx, authz.ManageServiceAccounts, authz.Action{}, authz.Host{})
	if err != nil {
		return nil, err
	}
	if ok {
		if err = s.Store.Pool.QueryRow(ctx, "SELECT count(*) FROM service_account_tokens WHERE revoked_at IS NULL AND expires_at>now() AND expires_at<=now()+interval '7 days'").Scan(&out.ExpiringServiceAccountTokens); err != nil {
			return nil, dbError(err)
		}
	}
	return connect.NewResponse(out), nil
}
func (s *Service) ListGatewayInstances(ctx context.Context, req *connect.Request[v1.ListGatewayInstancesRequest]) (*connect.Response[v1.ListGatewayInstancesResponse], error) {
	hosts, err := s.systemHosts(ctx)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, h := range hosts {
		if h.Online {
			ids = append(ids, h.HostId)
		}
	}
	rows, err := s.Store.Pool.Query(ctx, `SELECT i.instance_id,i.version,i.draining,i.started_at,i.last_seen,(SELECT count(*) FROM hosts h WHERE h.instance_id=i.instance_id AND host_id=ANY($1::text[]) AND certificate_status='active') FROM gateway_instances i ORDER BY instance_id`, ids)
	if err != nil {
		return nil, dbError(err)
	}
	defer rows.Close()
	items := []*v1.GatewayInstance{}
	for rows.Next() {
		item := &v1.GatewayInstance{}
		var started, last time.Time
		if err = rows.Scan(&item.InstanceId, &item.Version, &item.Draining, &started, &last, &item.ConnectedHosts); err != nil {
			return nil, dbError(err)
		}
		item.StartedAt = stamp(started)
		item.LastSeen = stamp(last)
		status := v1.HealthStatus_HEALTH_STATUS_HEALTHY
		reason := ""
		if time.Since(last) > InstanceLostAfter(s.gatewayConfig()) {
			status = v1.HealthStatus_HEALTH_STATUS_UNAVAILABLE
			reason = "instance heartbeat stale"
		}
		item.Dependencies = []*v1.DependencyHealth{{Name: "instance_heartbeat", Status: status, Reason: reason}}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, dbError(err)
	}
	items, cursor, err := page(ctx, s.Config, "gateway_instances", req.Msg.Page, items)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.ListGatewayInstancesResponse{Instances: items, Page: cursor}), nil
}
func (s *Service) GetAgentVersionDistribution(ctx context.Context, req *connect.Request[v1.GetAgentVersionDistributionRequest]) (*connect.Response[v1.GetAgentVersionDistributionResponse], error) {
	hosts, err := s.systemHosts(ctx)
	if err != nil {
		return nil, err
	}
	counts := map[string]*v1.AgentVersionCount{}
	for _, h := range hosts {
		c := counts[h.AgentVersion]
		if c == nil {
			c = &v1.AgentVersionCount{AgentVersion: h.AgentVersion}
			counts[h.AgentVersion] = c
		}
		c.HostCount++
		if h.Online {
			c.OnlineCount++
		}
	}
	versions := []string{}
	for version := range counts {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	items := []*v1.AgentVersionCount{}
	for _, v := range versions {
		items = append(items, counts[v])
	}
	items, cursor, err := page(ctx, s.Config, "agent_versions", req.Msg.Page, items)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.GetAgentVersionDistributionResponse{Versions: items, Page: cursor}), nil
}
