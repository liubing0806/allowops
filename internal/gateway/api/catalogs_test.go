package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"google.golang.org/protobuf/proto"
)

func catalogFixture(t *testing.T) (*fixture, ed25519.PrivateKey) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	f := newFixture(t)
	s := &catalogsvc.Service{Store: f.db, Trusted: map[string]ed25519.PublicKey{catalog.KeyID(pub): pub}, MaxEnvelopeBytes: 64 << 20, MaxActionBytes: 256 << 10}
	if err := f.service.ConfigureManagement(ManagementConfig{}, nil, s); err != nil {
		t.Fatal(err)
	}
	return f, key
}

func catalogClient(f *fixture, token string) rpc.CatalogServiceClient {
	return rpc.NewCatalogServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(token)))
}

func signedTestCatalog(t *testing.T, key ed25519.PrivateKey, id, name string, now time.Time) []byte {
	t.Helper()
	p, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: id}, Actions: map[string]catalog.Action{name: {Name: name, Description: "fixture", Risk: "read", Exec: []any{"/usr/bin/true"}, Timeout: "1s", MaxOutput: 1024}}}, catalog.BuildOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	b, err := catalog.CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	e, err := catalog.Sign(b, catalog.SigningKey{PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	b, err = json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func uploadTestCatalog(t *testing.T, client rpc.CatalogServiceClient, raw []byte) string {
	t.Helper()
	ctx := context.Background()
	r, err := client.BeginCatalogUpload(ctx, connect.NewRequest(&v1.BeginCatalogUploadRequest{EnvelopeSizeBytes: uint64(len(raw)), EnvelopeSha256: hash(string(raw))}))
	if err != nil {
		t.Fatal(err)
	}
	for offset := 0; offset < len(raw); {
		end := min(offset+int(r.Msg.MaxChunkBytes), len(raw))
		if _, err = client.UploadCatalogChunk(ctx, connect.NewRequest(&v1.UploadCatalogChunkRequest{UploadId: r.Msg.UploadId, Offset: uint64(offset), Data: raw[offset:end]})); err != nil {
			t.Fatal(err)
		}
		offset = end
	}
	return r.Msg.UploadId
}

func TestP4BCatalogAtomicPublishAndUpload(t *testing.T) {
	f, key := catalogFixture(t)
	client := catalogClient(f, f.adminToken)
	ctx := context.Background()
	raw := signedTestCatalog(t, key, "one", "status", time.Now())
	id := uploadTestCatalog(t, client, raw)
	retry, err := client.UploadCatalogChunk(ctx, connect.NewRequest(&v1.UploadCatalogChunkRequest{UploadId: id, Data: raw}))
	if err != nil || retry.Msg.NextOffset != uint64(len(raw)) {
		t.Fatal("identical chunk retry failed", err)
	}
	different := bytes.Clone(raw)
	different[0] ^= 1
	_, err = client.UploadCatalogChunk(ctx, connect.NewRequest(&v1.UploadCatalogChunkRequest{UploadId: id, Data: different}))
	code(t, err, connect.CodeAborted)
	first, err := client.PublishCatalog(ctx, connect.NewRequest(&v1.PublishCatalogRequest{UploadId: id}))
	if err != nil {
		t.Fatal(err)
	}
	again, err := client.PublishCatalog(ctx, connect.NewRequest(&v1.PublishCatalogRequest{UploadId: id}))
	if err != nil || !proto.Equal(first.Msg, again.Msg) {
		t.Fatal("publish retry changed result", err)
	}
	for _, r := range [][]byte{raw, signedTestCatalog(t, key, "two", "status", time.Now())} {
		id = uploadTestCatalog(t, client, r)
		_, err = client.PublishCatalog(ctx, connect.NewRequest(&v1.PublishCatalogRequest{UploadId: id}))
		code(t, err, connect.CodeAborted)
	}
	versions, err := client.ListCatalogs(ctx, connect.NewRequest(&v1.ListCatalogsRequest{}))
	if err != nil || len(versions.Msg.Catalogs) != 1 {
		t.Fatal("failed publish changed visible versions", err)
	}
	action, err := catalogClient(f, f.viewerToken).GetAction(ctx, connect.NewRequest(&v1.GetActionRequest{Action: "status"}))
	if err != nil || len(action.Msg.DefinitionJson) == 0 {
		t.Fatal("action definition unavailable", err)
	}
	id = uploadTestCatalog(t, client, signedTestCatalog(t, key, "one", "status", time.Now().Add(time.Second)))
	if _, err = f.db.Pool.Exec(ctx, "UPDATE catalog_uploads SET expires_at=now()-interval '1 second' WHERE upload_id=$1", id); err != nil {
		t.Fatal(err)
	}
	_, err = client.PublishCatalog(ctx, connect.NewRequest(&v1.PublishCatalogRequest{UploadId: id}))
	code(t, err, connect.CodeFailedPrecondition)
	_, err = catalogClient(f, f.viewerToken).BeginCatalogUpload(ctx, connect.NewRequest(&v1.BeginCatalogUploadRequest{EnvelopeSizeBytes: 1, EnvelopeSha256: make([]byte, 32)}))
	code(t, err, connect.CodePermissionDenied)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	id = uploadTestCatalog(t, client, signedTestCatalog(t, other, "three", "different", time.Now()))
	_, err = client.PublishCatalog(ctx, connect.NewRequest(&v1.PublishCatalogRequest{UploadId: id}))
	code(t, err, connect.CodeInvalidArgument)
}

func TestP4BResourcePermissionAndRealAudit(t *testing.T) {
	f := newFixture(t)
	addHost(t, f, "test")
	addHost(t, f, "prod")
	ctx := context.Background()
	if _, err := f.db.Pool.Exec(ctx, `UPDATE hosts SET authorization_labels=jsonb_build_object('env',hostname)`); err != nil {
		t.Fatal(err)
	}
	rules := defaultRules()
	rules.Rules = append(rules.Rules, &v1.PolicyRule{Name: "scoped-view", Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW, Roles: []string{"restricted"}, Operations: []string{"view_hosts", "manage_hosts"}, HostLabels: map[string]string{"env": "test"}})
	b, err := encode(rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Pool.Exec(ctx, "INSERT INTO policy_versions(version,rules,created_by,reason) VALUES (2,$1,'fixture','fixture')", b); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Pool.Exec(ctx, "UPDATE console_users SET manual_roles=ARRAY['restricted'] WHERE user_id=$1", f.viewer.UserId); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Pool.Exec(ctx, "DELETE FROM role_mappings WHERE group_name='readers'"); err != nil {
		t.Fatal(err)
	}
	f.service.Audit = NewAuditor(audit.New(f.db.Pool, audit.Config{}))
	client := hostClient(f, f.viewerToken)
	visible, err := client.ListHosts(ctx, connect.NewRequest(&v1.ListHostsRequest{}))
	if err != nil || visible.Msg.TotalCount != 1 || visible.Msg.Hosts[0].Hostname != "test" {
		t.Fatal("resource-scoped list rejected or exposed prod", err)
	}
	h := visible.Msg.Hosts[0]
	_, err = client.SetHostLabels(ctx, connect.NewRequest(&v1.SetHostLabelsRequest{Targets: namedTargets("test"), ExpectedCount: 1, ExpectedRevisions: []*v1.HostRevision{{HostId: h.HostId, Revision: h.Revision}}, Changes: &v1.LabelChanges{Set: map[string]string{"owner": "ops"}}}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DeleteHost(ctx, connect.NewRequest(&v1.DeleteHostRequest{HostId: h.HostId, ExpectedRevision: h.Revision}))
	code(t, err, connect.CodeAborted)
	var authorized, result int
	if err = f.db.Pool.QueryRow(ctx, "SELECT count(*) FILTER(WHERE reason='authorized'),count(*) FILTER(WHERE reason='result') FROM audit_events WHERE operation=$1", rpc.HostServiceSetHostLabelsProcedure).Scan(&authorized, &result); err != nil {
		t.Fatal(err)
	}
	if authorized != 1 || result != 1 {
		t.Fatalf("authorized=%d result=%d want 1 each", authorized, result)
	}
	var denied int
	if err = f.db.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE operation=$1 AND decision='deny'", rpc.HostServiceDeleteHostProcedure).Scan(&denied); err != nil || denied != 1 {
		t.Fatal("missing denial audit", err)
	}
}

func TestP4BHostWriteAuthorizationAuditFailure(t *testing.T) {
	f := newFixture(t)
	addHost(t, f, "a")
	client := hostClient(f, f.adminToken)
	ctx := context.Background()
	h, err := client.GetHost(ctx, connect.NewRequest(&v1.GetHostRequest{Hostname: "a"}))
	if err != nil {
		t.Fatal(err)
	}
	f.audit.mu.Lock()
	f.audit.fail = true
	f.audit.mu.Unlock()
	_, err = client.SetHostLabels(ctx, connect.NewRequest(&v1.SetHostLabelsRequest{Targets: namedTargets("a"), ExpectedCount: 1, ExpectedRevisions: []*v1.HostRevision{{HostId: h.Msg.Host.HostId, Revision: h.Msg.Host.Revision}}, Changes: &v1.LabelChanges{Set: map[string]string{"env": "prod"}}}))
	code(t, err, connect.CodeUnavailable)
	var unchanged bool
	if err = f.db.Pool.QueryRow(ctx, "SELECT authorization_labels='{}'::jsonb FROM hosts WHERE hostname='a'").Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("mutation before authorization audit", err)
	}
}

type resultFailureAudit struct{}

func (resultFailureAudit) Append(_ context.Context, e AuditEvent) error {
	if e.Phase == "result" {
		return errors.New("fixture result failure")
	}
	return nil
}

func TestP4BHostResultAuditFailureReportsCommittedState(t *testing.T) {
	f := newFixture(t)
	addHost(t, f, "a")
	client := hostClient(f, f.adminToken)
	ctx := context.Background()
	h, err := client.GetHost(ctx, connect.NewRequest(&v1.GetHostRequest{Hostname: "a"}))
	if err != nil {
		t.Fatal(err)
	}
	f.service.Audit = resultFailureAudit{}
	_, err = client.SetHostLabels(ctx, connect.NewRequest(&v1.SetHostLabelsRequest{Targets: namedTargets("a"), ExpectedCount: 1, ExpectedRevisions: []*v1.HostRevision{{HostId: h.Msg.Host.HostId, Revision: h.Msg.Host.Revision}}, Changes: &v1.LabelChanges{Set: map[string]string{"env": "test"}}}))
	code(t, err, connect.CodeUnavailable)
	ce := err.(*connect.Error)
	found := false
	for _, d := range ce.Details() {
		value, e := d.Value()
		if detail, ok := value.(*v1.ErrorDetail); e == nil && ok && detail.Reason == "AUDIT_RESULT_UNAVAILABLE" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing committed-state audit error detail")
	}
	var labels string
	if err = f.db.Pool.QueryRow(ctx, "SELECT authorization_labels->>'env' FROM hosts WHERE hostname='a'").Scan(&labels); err != nil || labels != "test" {
		t.Fatal("expected committed change despite result audit failure", err)
	}
}

func TestP4BUploadRetriesRequireOriginalChunkBoundaries(t *testing.T) {
	f, key := catalogFixture(t)
	client := catalogClient(f, f.adminToken)
	raw := signedTestCatalog(t, key, "one", "status", time.Now())
	id := uploadTestCatalog(t, client, raw)
	for _, r := range []*v1.UploadCatalogChunkRequest{{UploadId: id, Data: raw[:len(raw)-1]}, {UploadId: id, Offset: 1, Data: raw[1:]}} {
		_, err := client.UploadCatalogChunk(context.Background(), connect.NewRequest(r))
		code(t, err, connect.CodeAborted)
	}
}
