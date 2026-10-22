package api

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/store"
	"google.golang.org/protobuf/types/known/durationpb"
)

func hostClient(f *fixture, token string) rpc.HostServiceClient {
	return rpc.NewHostServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(token)))
}
func joinClient(f *fixture, token string) rpc.JoinTokenServiceClient {
	return rpc.NewJoinTokenServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(token)))
}
func addHost(t *testing.T, f *fixture, name string) string {
	t.Helper()
	token, err := f.db.CreateJoinToken(context.Background(), 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.db.Register(context.Background(), token, name, func(string) (string, time.Time, error) { return "serial-" + name, time.Now().Add(time.Hour), nil })
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func namedTargets(names ...string) *v1.HostTargets {
	return &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: names}}}
}
func TestP4BHostsAtomicLabelsAndSelectors(t *testing.T) {
	f := newFixture(t)
	addHost(t, f, "a")
	addHost(t, f, "b")
	ctx := context.Background()
	client := hostClient(f, f.adminToken)
	listed, err := client.ListHosts(ctx, connect.NewRequest(&v1.ListHostsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if listed.Msg.TotalCount != 2 {
		t.Fatalf("count=%d want 2", listed.Msg.TotalCount)
	}
	revisions := []*v1.HostRevision{}
	for _, h := range listed.Msg.Hosts {
		revisions = append(revisions, &v1.HostRevision{HostId: h.HostId, Revision: h.Revision})
	}
	request := &v1.SetHostLabelsRequest{Targets: namedTargets("a", "b"), ExpectedCount: 2, ExpectedRevisions: revisions, Changes: &v1.LabelChanges{Set: map[string]string{"env": "test"}}}
	if _, err = client.SetHostLabels(ctx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	_, err = client.SetHostLabels(ctx, connect.NewRequest(request))
	code(t, err, connect.CodeAborted)
	for _, sel := range []string{"env", ",env=test", "env=test,", "env=test OR os=linux", "env=test,env=prod"} {
		_, err = client.ListHosts(ctx, connect.NewRequest(&v1.ListHostsRequest{Query: &v1.HostQuery{Selector: sel}}))
		code(t, err, connect.CodeInvalidArgument)
	}
	if _, err = f.db.Pool.Exec(ctx, `UPDATE hosts SET reported_labels='{"os":"linux","env":"prod"}'`); err != nil {
		t.Fatal(err)
	}
	for sel, want := range map[string]uint64{"env=test,reported.os=linux": 2, "env=prod": 0, "reported.env=prod": 2} {
		r, e := client.ListHosts(ctx, connect.NewRequest(&v1.ListHostsRequest{Query: &v1.HostQuery{Selector: sel}}))
		if e != nil || r.Msg.TotalCount != want {
			t.Fatalf("selector=%s count=%d error=%v want=%d", sel, r.Msg.GetTotalCount(), e, want)
		}
	}
	_, err = hostClient(f, f.viewerToken).SetHostLabels(ctx, connect.NewRequest(request))
	code(t, err, connect.CodePermissionDenied)
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	found := false
	for _, e := range f.audit.events {
		if e.Operation == rpc.HostServiceSetHostLabelsProcedure && e.Outcome == "deny" && e.ActorID == f.viewer.UserId {
			found = true
		}
	}
	if !found {
		t.Fatal("missing denial audit")
	}
}
func TestP4BConcurrentLabels(t *testing.T) {
	f := newFixture(t)
	addHost(t, f, "a")
	ctx := context.Background()
	client := hostClient(f, f.adminToken)
	r, err := client.GetHost(ctx, connect.NewRequest(&v1.GetHostRequest{Hostname: "a"}))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	codes := make(chan connect.Code, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.SetHostLabels(ctx, connect.NewRequest(&v1.SetHostLabelsRequest{Targets: namedTargets("a"), ExpectedCount: 1, ExpectedRevisions: []*v1.HostRevision{{HostId: r.Msg.Host.HostId, Revision: r.Msg.Host.Revision}}, Changes: &v1.LabelChanges{Set: map[string]string{"value": fmt.Sprint(i)}}}))
			if err == nil {
				codes <- 0
			} else {
				codes <- connect.CodeOf(err)
			}
		}()
	}
	wg.Wait()
	close(codes)
	success, conflict := 0, 0
	for c := range codes {
		if c == 0 {
			success++
		}
		if c == connect.CodeAborted {
			conflict++
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d want 1 each", success, conflict)
	}
}
func TestP4BCSVAtomicPreviewAndChangedTarget(t *testing.T) {
	f := newFixture(t)
	addHost(t, f, "a")
	addHost(t, f, "b")
	ctx := context.Background()
	client := hostClient(f, f.adminToken)
	preview := func(csv string) string {
		t.Helper()
		p, err := client.PreviewHostImport(ctx, connect.NewRequest(&v1.PreviewHostImportRequest{Csv: []byte(csv)}))
		if err != nil {
			t.Fatal(err)
		}
		return p.Msg.Preview.PreviewId
	}
	invalid := preview("hostname,set:env\na,test\nmissing,test\n")
	_, err := client.ExecuteHostImport(ctx, connect.NewRequest(&v1.ExecuteHostImportRequest{PreviewId: invalid}))
	code(t, err, connect.CodeInvalidArgument)
	a, err := client.GetHost(ctx, connect.NewRequest(&v1.GetHostRequest{Hostname: "a"}))
	if err != nil || len(a.Msg.Host.AuthorizationLabels) != 0 {
		t.Fatal("invalid CSV partially committed")
	}
	id := preview("hostname,set:env,set:empty\na,test,\nb,test,\n")
	if _, err = f.db.Pool.Exec(ctx, `UPDATE hosts SET authorization_labels='{"edited":"yes"}' WHERE hostname='b'`); err != nil {
		t.Fatal(err)
	}
	_, err = client.ExecuteHostImport(ctx, connect.NewRequest(&v1.ExecuteHostImportRequest{PreviewId: id}))
	code(t, err, connect.CodeAborted)
	id = preview("hostname,set:env,remove:edited\na,test,\nb,test,true\n")
	r, err := client.ExecuteHostImport(ctx, connect.NewRequest(&v1.ExecuteHostImportRequest{PreviewId: id}))
	if err != nil || r.Msg.UpdatedCount != 2 {
		t.Fatalf("CSV execute=%v error=%v", r, err)
	}
	if _, err = f.db.Pool.Exec(ctx, `UPDATE hosts SET authorization_labels='{"later":"yes"}' WHERE hostname='a'`); err != nil {
		t.Fatal(err)
	}
	r, err = client.ExecuteHostImport(ctx, connect.NewRequest(&v1.ExecuteHostImportRequest{PreviewId: id}))
	if err != nil || r.Msg.UpdatedCount != 2 {
		t.Fatal("preview retry is not idempotent")
	}
	a, err = client.GetHost(ctx, connect.NewRequest(&v1.GetHostRequest{Hostname: "a"}))
	if err != nil || a.Msg.Host.AuthorizationLabels["later"] != "yes" {
		t.Fatal("retry overwrote later changes")
	}
	id = preview("hostname,set:env\na,test\n")
	if _, err = f.db.Pool.Exec(ctx, "UPDATE host_import_previews SET expires_at=now()-interval '1 second' WHERE preview_id=$1", id); err != nil {
		t.Fatal(err)
	}
	_, err = client.ExecuteHostImport(ctx, connect.NewRequest(&v1.ExecuteHostImportRequest{PreviewId: id}))
	code(t, err, connect.CodeFailedPrecondition)
}
func TestP4BJoinTokenLifecycle(t *testing.T) {
	f := newFixture(t)
	f.service.management.config.CAPin = "sha256:" + strings.Repeat("0", 64)
	ctx := context.Background()
	client := joinClient(f, f.adminToken)
	for _, r := range []*v1.CreateJoinTokenRequest{{}, {MaxUses: 1, Ttl: durationpb.New(0)}, {MaxUses: 2, Ttl: durationpb.New(-time.Second)}} {
		_, err := client.CreateJoinToken(ctx, connect.NewRequest(r))
		code(t, err, connect.CodeInvalidArgument)
	}
	created, err := client.CreateJoinToken(ctx, connect.NewRequest(&v1.CreateJoinTokenRequest{MaxUses: 2}))
	if err != nil {
		t.Fatal(err)
	}
	if created.Msg.Secret == "" || created.Msg.Token.ExpiresAt.AsTime().Sub(created.Msg.Token.CreatedAt.AsTime()) < 24*time.Hour-time.Second {
		t.Fatal("missing secret or incorrect default TTL")
	}
	sign := func(string) (string, time.Time, error) { return "serial", time.Now().Add(time.Hour), nil }
	for _, name := range []string{"a", "b"} {
		if _, err = f.db.Register(ctx, created.Msg.Secret, name, sign); err != nil {
			t.Fatal(err)
		}
	}
	_, err = f.db.Register(ctx, created.Msg.Secret, "c", sign)
	if err != store.ErrCredential {
		t.Fatalf("exhausted token=%v", err)
	}
	listed, err := client.ListJoinTokens(ctx, connect.NewRequest(&v1.ListJoinTokensRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Msg.Tokens) != 1 || listed.Msg.Tokens[0].UsedCount != 2 || strings.Contains(fmt.Sprint(listed.Msg), created.Msg.Secret) {
		t.Fatal("invalid token list or secret exposed")
	}
	exp, err := client.CreateJoinToken(ctx, connect.NewRequest(&v1.CreateJoinTokenRequest{MaxUses: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Pool.Exec(ctx, "UPDATE join_tokens SET expires_at=now()-interval '1 second' WHERE token_id=$1", exp.Msg.Token.TokenId); err != nil {
		t.Fatal(err)
	}
	_, err = f.db.Register(ctx, exp.Msg.Secret, "c", sign)
	if err != store.ErrCredential {
		t.Fatalf("expired token=%v", err)
	}
	rev, err := client.CreateJoinToken(ctx, connect.NewRequest(&v1.CreateJoinTokenRequest{MaxUses: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.RevokeJoinToken(ctx, connect.NewRequest(&v1.RevokeJoinTokenRequest{TokenId: rev.Msg.Token.TokenId})); err != nil {
		t.Fatal(err)
	}
	_, err = f.db.Register(ctx, rev.Msg.Secret, "c", sign)
	if err != store.ErrCredential {
		t.Fatalf("revoked token=%v", err)
	}
}
