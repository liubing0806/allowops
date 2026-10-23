package api

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgconn"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
)

// pausingAudit holds one operation inside its authorization audit, which runs
// with the target row locks held and before the first mutation.
type pausingAudit struct {
	operation       string
	reached, resume chan struct{}
	once            sync.Once
}

func (p *pausingAudit) Append(ctx context.Context, e AuditEvent) error {
	if e.Phase == "authorized" && e.Operation == p.operation {
		p.once.Do(func() { close(p.reached) })
		select {
		case <-p.resume:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// hostLockedBy reports whether a routing-style FOR SHARE read of the active
// host would have to wait.
func hostLockedBy(t *testing.T, f *fixture, hostname string) bool {
	t.Helper()
	ctx := context.Background()
	tx, err := f.db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, "SELECT 1 FROM hosts WHERE hostname=$1 AND certificate_status='active' FOR SHARE NOWAIT", hostname)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "55P03" {
		return true
	}
	if err != nil {
		t.Fatal(err)
	}
	return false
}

// A write locks the rows of the hosts it changes, not every host: routing reads
// of other hosts must not wait for it.
func TestHostWritesLockOnlyTargetRows(t *testing.T) {
	cases := []struct {
		name      string
		operation string
		prepare   func(t *testing.T, f *fixture) func() error
	}{
		{"SetHostLabels by name", rpc.HostServiceSetHostLabelsProcedure, func(t *testing.T, f *fixture) func() error {
			req := labelRequest(t, f, "a")
			return func() error {
				_, err := hostClient(f, f.adminToken).SetHostLabels(context.Background(), connect.NewRequest(req))
				return err
			}
		}},
		{"SetHostLabels by selector", rpc.HostServiceSetHostLabelsProcedure, func(t *testing.T, f *fixture) func() error {
			req := labelRequest(t, f, "a")
			req.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "tier=front"}}
			return func() error {
				_, err := hostClient(f, f.adminToken).SetHostLabels(context.Background(), connect.NewRequest(req))
				return err
			}
		}},
		{"ExecuteHostImport", rpc.HostServiceExecuteHostImportProcedure, func(t *testing.T, f *fixture) func() error {
			ctx := context.Background()
			preview, err := hostClient(f, f.adminToken).PreviewHostImport(ctx, connect.NewRequest(&v1.PreviewHostImportRequest{Csv: []byte("hostname,set:env\na,test\n")}))
			if err != nil {
				t.Fatal(err)
			}
			return func() error {
				_, err := hostClient(f, f.adminToken).ExecuteHostImport(ctx, connect.NewRequest(&v1.ExecuteHostImportRequest{PreviewId: preview.Msg.Preview.PreviewId}))
				return err
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			addHost(t, f, "a")
			addHost(t, f, "b")
			if _, err := f.db.Pool.Exec(context.Background(), `UPDATE hosts SET authorization_labels=jsonb_build_object('tier',CASE hostname WHEN 'a' THEN 'front' ELSE 'back' END)`); err != nil {
				t.Fatal(err)
			}
			pause := &pausingAudit{operation: c.operation, reached: make(chan struct{}), resume: make(chan struct{})}
			f.service.Audit = pause
			run := c.prepare(t, f)
			done := make(chan error, 1)
			go func() { done <- run() }()
			select {
			case <-pause.reached:
			case err := <-done:
				t.Fatalf("write finished before the authorization audit: %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("write did not reach its authorization audit")
			}
			if !hostLockedBy(t, f, "a") {
				t.Error("target host a is not locked while the write is in progress")
			}
			if hostLockedBy(t, f, "b") {
				t.Error("host b, which the write does not change, is locked: FOR SHARE NOWAIT failed with 55P03")
			}
			close(pause.resume)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
