package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
)

func TestP4BSystemVisibilityAndUnavailableStatistics(t *testing.T) {
	f := newFixture(t)
	addHost(t, f, "private")
	ctx := context.Background()
	client := rpc.NewSystemServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(f.adminToken)))
	r, err := client.GetSystemStatus(ctx, connect.NewRequest(&v1.GetSystemStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if r.Msg.OfflineHosts != 1 || r.Msg.Status != v1.HealthStatus_HEALTH_STATUS_DEGRADED || r.Msg.Limits.MaxCsvBytes != 512<<10 {
		t.Fatal("system status counts, health or limits invalid")
	}
	found := false
	for _, d := range r.Msg.Dependencies {
		if d.Name == "job_statistics" && d.Status == v1.HealthStatus_HEALTH_STATUS_UNAVAILABLE && strings.Contains(d.Reason, "unavailable") {
			found = true
		}
	}
	if !found {
		t.Fatal("unknown job counts not marked unavailable")
	}
	dist, err := client.GetAgentVersionDistribution(ctx, connect.NewRequest(&v1.GetAgentVersionDistributionRequest{}))
	if err != nil || len(dist.Msg.Versions) != 1 || dist.Msg.Versions[0].HostCount != 1 {
		t.Fatal("agent version distribution invalid", err)
	}
	viewer := rpc.NewSystemServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(f.viewerToken)))
	_, err = viewer.GetSystemStatus(ctx, connect.NewRequest(&v1.GetSystemStatusRequest{}))
	code(t, err, connect.CodePermissionDenied)
	// A view_system-only subject must not learn host counts through overview.
	rules := defaultRules()
	rules.Rules = append(rules.Rules, &v1.PolicyRule{Name: "system-only", Roles: []string{"system-only"}, Operations: []string{"view_system"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW})
	b, err := encode(rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Pool.Exec(ctx, "INSERT INTO policy_versions(version,rules,created_by,reason) VALUES (2,$1,'fixture','fixture')", b); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Pool.Exec(ctx, "DELETE FROM role_mappings WHERE group_name='readers'"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Pool.Exec(ctx, "UPDATE console_users SET manual_roles=ARRAY['system-only'] WHERE user_id=$1", f.viewer.UserId); err != nil {
		t.Fatal(err)
	}
	r, err = viewer.GetSystemStatus(ctx, connect.NewRequest(&v1.GetSystemStatusRequest{}))
	if err != nil || r.Msg.OfflineHosts+r.Msg.OnlineHosts != 0 {
		t.Fatal("overview exposed unauthorized hosts", err)
	}
	dist, err = viewer.GetAgentVersionDistribution(ctx, connect.NewRequest(&v1.GetAgentVersionDistributionRequest{}))
	if err != nil || len(dist.Msg.Versions) != 0 {
		t.Fatal("version distribution exposed unauthorized hosts", err)
	}
}
func TestP4BTLSCAPinAndMissingPin(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TLS root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now, NotAfter: now.Add(time.Hour)}
	raw, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	if pin := TLSCAPin([][]byte{raw}); !strings.HasPrefix(pin, "sha256:") || len(pin) != 71 {
		t.Fatalf("invalid derived TLS CA pin %q", pin)
	}
	ca.IsCA = false
	raw, err = x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	if TLSCAPin([][]byte{raw}) != "" {
		t.Fatal("derived CA pin from leaf certificate")
	}
	f := newFixture(t)
	_, err = joinClient(f, f.adminToken).CreateJoinToken(context.Background(), connect.NewRequest(&v1.CreateJoinTokenRequest{MaxUses: 1}))
	code(t, err, connect.CodeFailedPrecondition)
	var count int
	if err = f.db.Pool.QueryRow(context.Background(), "SELECT count(*) FROM join_tokens").Scan(&count); err != nil || count != 0 {
		t.Fatal("created token without TLS CA pin", err)
	}
	if err = f.service.ConfigureManagement(ManagementConfig{CAPin: "sha256:bad"}, nil, nil); err == nil {
		t.Fatal("accepted invalid configured TLS CA pin")
	}
}
