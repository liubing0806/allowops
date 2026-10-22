package api

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
)

type statisticsFixture struct{}

func (statisticsFixture) Statistics(context.Context) (uint64, uint64, error) { return 2, 3, nil }

type storageHealthFixture struct{ err error }

func (s storageHealthFixture) Check(context.Context) error { return s.err }

func TestP6SystemDependencyIntegration(t *testing.T) {
	f := newFixture(t)
	client := rpc.NewSystemServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(f.adminToken)))
	r, err := client.GetSystemStatus(context.Background(), connect.NewRequest(&v1.GetSystemStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if r.Msg.Limits.DefaultOutputPageBytes != 16<<10 || r.Msg.Limits.MaxOutputPageBytes != 24<<10 {
		t.Fatalf("output limits without job service=%v", r.Msg.Limits)
	}
	f.service.ConfigureJobDependencies(statisticsFixture{}, storageHealthFixture{})
	r, err = client.GetSystemStatus(context.Background(), connect.NewRequest(&v1.GetSystemStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if r.Msg.Limits.DefaultOutputPageBytes != 16<<10 || r.Msg.Limits.MaxOutputPageBytes != 24<<10 {
		t.Fatalf("output limits with job service=%v", r.Msg.Limits)
	}
	if r.Msg.RunningJobs != 2 || r.Msg.FailedJobsLast_24Hours != 3 || r.Msg.Status != v1.HealthStatus_HEALTH_STATUS_HEALTHY {
		t.Fatalf("system=%v", r.Msg)
	}
	for _, d := range r.Msg.Dependencies {
		if d.Status != v1.HealthStatus_HEALTH_STATUS_HEALTHY {
			t.Fatalf("dependency=%v", d)
		}
	}
	f.service.ConfigureJobDependencies(statisticsFixture{}, storageHealthFixture{err: errors.New("fixture credential must not appear")})
	r, err = client.GetSystemStatus(context.Background(), connect.NewRequest(&v1.GetSystemStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if r.Msg.Status != v1.HealthStatus_HEALTH_STATUS_DEGRADED || r.Msg.Dependencies[2].Reason != "dependency unavailable" {
		t.Fatalf("dependency response=%v", r.Msg)
	}
}
