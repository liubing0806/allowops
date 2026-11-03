package mcp

import (
	"context"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"net/http"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/gateway/api"
)

type cancelResultKey struct{}

type cancelResultRequest struct {
	ctx    context.Context
	cancel context.CancelFunc
}

type cancelledToolAudit struct {
	delegate api.Auditor
	t        *testing.T
	done     chan error
}

func (a cancelledToolAudit) Append(ctx context.Context, e api.AuditEvent) error {
	if e.Phase == "result" {
		request := ctx.Value(cancelResultKey{}).(cancelResultRequest)
		request.cancel()
		if request.ctx.Err() != context.Canceled {
			a.t.Error("MCP request not cancelled")
		}
	}
	err := a.delegate.Append(ctx, e)
	if e.Phase == "result" {
		a.done <- err
	}
	return err
}

func TestSDKResultAuditSurvivesCancelledRequest(t *testing.T) {
	f := newTransportFixture(t)
	done := make(chan error, 1)
	f.identity.Audit = cancelledToolAudit{f.audit, t, done}
	handler := f.gateway.Config.Handler
	f.gateway.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		ctx = context.WithValue(ctx, cancelResultKey{}, cancelResultRequest{ctx, cancel})
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
	c, _ := f.client(t, f.admin, nil)
	_, callErr := c.CallTool(context.Background(), &sdk.CallToolParams{Name: "hosts_search", Arguments: map[string]any{"hostname": "web-01"}})
	select {
	case appendErr := <-done:
		t.Logf("cancelled transport error=%v result Append error=%v", callErr, appendErr)
	case <-time.After(10 * time.Second):
		t.Fatal("result Append did not finish")
	}
	var count int
	if err := f.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE operation='mcp/hosts_search' AND reason='result' AND decision='allow' AND subject_id='admin'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("persisted MCP result audits=%d; want 1 (result=%v)", count, callErr)
	}
}
