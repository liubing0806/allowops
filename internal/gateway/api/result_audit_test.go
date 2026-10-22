package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/audit"
)

type cancelAuditKey struct{}
type cancelAuditRequest struct {
	ctx    context.Context
	cancel context.CancelFunc
}
type cancelledResultAudit struct {
	delegate Auditor
	t        *testing.T
}

func (a cancelledResultAudit) Append(ctx context.Context, e AuditEvent) error {
	if e.Phase == "result" {
		request := ctx.Value(cancelAuditKey{}).(cancelAuditRequest)
		request.cancel()
		if request.ctx.Err() != context.Canceled {
			a.t.Error("originating request was not cancelled")
		}
	}
	return a.delegate.Append(ctx, e)
}

func TestResultAuditSurvivesCancelledRequest(t *testing.T) {
	f := newFixture(t, func(_ *Service, handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			ctx = context.WithValue(ctx, cancelAuditKey{}, cancelAuditRequest{ctx, cancel})
			handler.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	f.service.Audit = cancelledResultAudit{NewAuditor(audit.New(f.db.Pool, audit.Config{})), t}
	ctx := context.Background()
	client := rpc.NewServiceAccountServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(f.adminToken)))
	_, writeErr := client.CreateServiceAccount(ctx, connect.NewRequest(&v1.CreateServiceAccountRequest{Name: "safe-name", OwnerUserId: f.admin.UserId}))
	_, readErr := f.auth(f.adminToken).GetCurrentSession(ctx, connect.NewRequest(&v1.GetCurrentSessionRequest{}))
	_, denyErr := f.users().SetUserRoles(ctx, connect.NewRequest(&v1.SetUserRolesRequest{}))
	// Verify committed state independently of the cancelled response and real P7 rows.
	var accounts, results int
	if err := f.db.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM service_accounts),(SELECT count(*) FROM audit_events WHERE reason='result')`).Scan(&accounts, &results); err != nil {
		t.Fatal(err)
	}
	if accounts != 1 || results != 3 {
		t.Errorf("committed accounts=%d persisted result audits=%d; want 1 and 3 (write=%v read=%v denial=%v)", accounts, results, writeErr, readErr, denyErr)
	}
	if writeErr != nil || readErr != nil || connect.CodeOf(denyErr) != connect.CodeInvalidArgument {
		t.Errorf("RPC semantics changed: write=%v read=%v denial=%v", writeErr, readErr, denyErr)
	}
	var actors int
	if err := f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE reason='result' AND subject_id=$1`, f.admin.UserId).Scan(&actors); err != nil {
		t.Fatal(err)
	}
	if actors != 3 {
		t.Errorf("result actors=%d; want 3", actors)
	}
	var tail uint64
	if err := f.db.Pool.QueryRow(ctx, `SELECT max(seq) FROM audit_events`).Scan(&tail); err != nil {
		t.Fatal(err)
	}
	verified, err := audit.New(f.db.Pool, audit.Config{}).Verify(ctx, audit.VerifyOptions{From: 1, To: tail})
	if err != nil || !verified.Valid {
		t.Fatalf("audit chain=%+v error=%v", verified, err)
	}
}

func TestResultAuditContextPreservesValuesAndIsBounded(t *testing.T) {
	f := newFixture(t)
	// Exercise the public result boundary through an authenticated production RPC.
	f.service.Audit = boundedResultAudit{t: t, delegate: NewAuditor(audit.New(f.db.Pool, audit.Config{}))}
	if _, err := f.auth(f.adminToken).GetCurrentSession(context.Background(), connect.NewRequest(&v1.GetCurrentSessionRequest{})); err != nil {
		t.Fatal(err)
	}
}

type boundedResultAudit struct {
	t        *testing.T
	delegate Auditor
}

func (a boundedResultAudit) Append(ctx context.Context, e AuditEvent) error {
	if e.Phase == "result" {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second {
			a.t.Errorf("result context deadline=%v present=%t; want independent timeout <=5s", deadline, ok)
		}
		if info := RequestAuditInfo(ctx); info.ActorID != e.ActorID || info.ActorID == "" {
			a.t.Errorf("identity lost: info=%+v event=%+v", info, e)
		}
	}
	return a.delegate.Append(ctx, e)
}
