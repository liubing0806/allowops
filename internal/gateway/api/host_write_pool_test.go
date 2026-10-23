package api

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

func writeContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func labelRequest(t *testing.T, f *fixture, name string) *v1.SetHostLabelsRequest {
	t.Helper()
	r, err := hostClient(f, f.adminToken).GetHost(context.Background(), connect.NewRequest(&v1.GetHostRequest{Hostname: name}))
	if err != nil {
		t.Fatal(err)
	}
	return &v1.SetHostLabelsRequest{Targets: namedTargets(name), ExpectedCount: 1, ExpectedRevisions: []*v1.HostRevision{{HostId: r.Msg.Host.HostId, Revision: r.Msg.Host.Revision}}, Changes: &v1.LabelChanges{Set: map[string]string{"env": "x"}}}
}

// A write holds one pooled connection for its transaction. Authorization and
// audit inside it must not need a second connection from the same pool, so a
// pool of one connection still serves every host write.
func TestHostWritesNeedOnlyOnePoolConnection(t *testing.T) {
	f := poolFixture(t, poolOptions{maxConns: 1, realAudit: true})
	client := hostClient(f, f.adminToken)
	for _, name := range []string{"a", "b", "c"} {
		addHost(t, f, name)
	}
	t.Run("SetHostLabels", func(t *testing.T) {
		req := labelRequest(t, f, "a")
		ctx, cancel := writeContext()
		defer cancel()
		if _, err := client.SetHostLabels(ctx, connect.NewRequest(req)); err != nil {
			t.Fatalf("SetHostLabels with pool_max_conns=1: %v", err)
		}
	})
	t.Run("DeleteHost", func(t *testing.T) {
		h, err := client.GetHost(context.Background(), connect.NewRequest(&v1.GetHostRequest{Hostname: "b"}))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := writeContext()
		defer cancel()
		if _, err := client.DeleteHost(ctx, connect.NewRequest(&v1.DeleteHostRequest{HostId: h.Msg.Host.HostId, ExpectedRevision: h.Msg.Host.Revision})); err != nil {
			t.Fatalf("DeleteHost with pool_max_conns=1: %v", err)
		}
	})
	t.Run("PreviewHostImport", func(t *testing.T) {
		ctx, cancel := writeContext()
		defer cancel()
		if _, err := client.PreviewHostImport(ctx, connect.NewRequest(&v1.PreviewHostImportRequest{Csv: []byte("hostname,set:env\nc,test\n")})); err != nil {
			t.Fatalf("PreviewHostImport with pool_max_conns=1: %v", err)
		}
	})
	t.Run("ExecuteHostImport", func(t *testing.T) {
		// Stored directly so this case does not depend on PreviewHostImport.
		h, err := client.GetHost(context.Background(), connect.NewRequest(&v1.GetHostRequest{Hostname: "c"}))
		if err != nil {
			t.Fatal(err)
		}
		targets := fmt.Sprintf(`[{"HostID":%q,"Revision":%q,"Hostname":"c","After":{"env":"test"}}]`, h.Msg.Host.HostId, h.Msg.Host.Revision)
		if _, err = f.db.Pool.Exec(context.Background(), "INSERT INTO host_import_previews(preview_id,actor_id,csv_sha256,rows,targets,invalid_count,expires_at) VALUES ('hip_pool',$1,decode(repeat('00',32),'hex'),'[]',$2,0,now()+interval '1 hour')", f.admin.UserId, targets); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := writeContext()
		defer cancel()
		if _, err = client.ExecuteHostImport(ctx, connect.NewRequest(&v1.ExecuteHostImportRequest{PreviewId: "hip_pool"})); err != nil {
			t.Fatalf("ExecuteHostImport with pool_max_conns=1: %v", err)
		}
	})
}

// Writers that each hold a pooled connection while they wait for a row lock
// must still finish: nothing they need after the lock may come from the pool.
func TestHostWritersWaitingOnRowLocksDoNotExhaustPool(t *testing.T) {
	f := poolFixture(t, poolOptions{maxConns: 2, realAudit: true})
	ctx := context.Background()
	names := []string{"a", "b"}
	reqs := []*v1.SetHostLabelsRequest{}
	for _, name := range names {
		addHost(t, f, name)
	}
	for _, name := range names {
		reqs = append(reqs, labelRequest(t, f, name))
	}
	// A connection outside the pool holds the host rows until every pool
	// connection is checked out by a writer.
	blocker, err := pgx.ConnectConfig(ctx, f.db.Pool.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(ctx)
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "SELECT 1 FROM hosts FOR UPDATE"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, len(reqs))
	for i, req := range reqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := writeContext()
			defer cancel()
			_, errs[i] = hostClient(f, f.adminToken).SetHostLabels(ctx, connect.NewRequest(req))
		}()
	}
	for until := time.Now().Add(3 * time.Second); f.db.Pool.Stat().AcquiredConns() < f.db.Pool.Config().MaxConns && time.Now().Before(until); {
		time.Sleep(10 * time.Millisecond)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	for i, err := range errs {
		// Serializable writers may be told to retry; what must not happen is a
		// hang until the deadline or an unavailable pool.
		if err != nil && connect.CodeOf(err) != connect.CodeAborted {
			t.Errorf("writer %s: %v", names[i], err)
		}
	}
}
