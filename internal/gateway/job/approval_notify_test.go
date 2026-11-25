package job_test

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/liubing0806/allowops/extensions/notifier/webhook"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
	"github.com/liubing0806/allowops/plugin/notifier"
	"gopkg.in/yaml.v3"
)

func withApprovalNotifier(sender job.ApprovalNotifier) func(*fixture) {
	return func(f *fixture) {
		before := f.BeforeStart
		f.BeforeStart = func(hosts *hostconn.Service, jobs *job.Service) {
			before(hosts, jobs)
			jobs.ApprovalNotifier = sender
		}
	}
}

func waitNotifyStatus(t *testing.T, f *approvalFixture, approvalID string, wantSeq int64, wantStatus, wantError string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		var seq int64
		var status, code string
		if err := f.DB.Pool.QueryRow(ctx, `SELECT notify_seq,notify_status,notify_error FROM approval_requests WHERE approval_id=$1`, approvalID).Scan(&seq, &status, &code); err != nil {
			t.Fatal(err)
		}
		if seq == wantSeq && status == wantStatus && code == wantError {
			return
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatalf("notification sequence/status/error = %d/%s/%s, want %d/%s/%s", seq, status, code, wantSeq, wantStatus, wantError)
		}
	}
}

func testWebhookNotifier(t *testing.T, endpoint *httptest.Server, timeout time.Duration) (*pluginhost.Host, job.ApprovalNotifierFunc) {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: endpoint.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	var configs pluginhost.ConfigList
	if err := yaml.Unmarshal(fmt.Appendf(nil, "- id: webhook\n  module: notifier.webhook\n  config: {url: %q}\n", endpoint.URL), &configs); err != nil {
		t.Fatal(err)
	}
	configs[0].Egress, configs[0].CAFile, configs[0].AllowPrivateEgress, configs[0].Timeout = []string{endpoint.URL}, caFile, true, timeout
	host, err := pluginhost.New(t.Context(), configs, pluginhost.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		host.Close(ctx)
	})
	return host, func(ctx context.Context, event job.ApprovalNotification) (string, string) {
		if failures := host.Notify(ctx, notifier.Event{Type: notifier.EventType(event.Type), EventID: event.EventID, ApprovalID: event.ApprovalID}); len(failures) != 0 {
			return "failed", "NOTIFY_DELIVERY_FAILED"
		}
		return "sent", ""
	}
}

func TestApprovalNotificationWebhook500AndTimeout(t *testing.T) {
	var requests atomic.Int32
	timedOut := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		switch requests.Add(1) {
		case 1:
			http.Error(w, "private upstream failure", http.StatusInternalServerError)
		case 2:
			<-r.Context().Done()
			close(timedOut)
		}
	}))
	t.Cleanup(upstream.Close)
	_, sender := testWebhookNotifier(t, upstream, 500*time.Millisecond)
	f := setupApprovals(t, 1, job.DefaultApprovalConfig(), withApprovalNotifier(sender))
	f.labelTargets(t)
	f.policy(t, approvalRule(1, false, "reviewer"))
	for range 2 {
		pending := f.submit(t, "sa", gatedRequest())
		waitNotifyStatus(t, f, pending.Approval.ApprovalId, 1, "failed", "NOTIFY_DELIVERY_FAILED")
		if got := f.metadata(t, "viewer", pending.Approval.ApprovalId); got.Status != v1.ApprovalStatus_APPROVAL_STATUS_PENDING {
			t.Fatalf("delivery failure changed the approval to %s", got.Status)
		}
	}
	select {
	case <-timedOut:
	case <-time.After(time.Second):
		t.Fatal("webhook timeout did not cancel the request")
	}
}

func TestApprovalNotificationMonotonicSequence(t *testing.T) {
	requested, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	sender := job.ApprovalNotifierFunc(func(ctx context.Context, event job.ApprovalNotification) (string, string) {
		if event.Type == string(notifier.EventApprovalRequested) {
			close(requested)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return "failed", "NOTIFY_DELIVERY_FAILED"
		}
		return "sent", ""
	})
	f := setupApprovals(t, 1, job.DefaultApprovalConfig(), withApprovalNotifier(sender))
	defer unblock()
	f.labelTargets(t)
	f.policy(t, approvalRule(1, false, "reviewer"))
	pending := f.submit(t, "sa", gatedRequest())
	select {
	case <-requested:
	case <-time.After(time.Second):
		t.Fatal("requested event did not start delivery")
	}
	approval := f.metadata(t, "alice", pending.Approval.ApprovalId)
	if result, err := f.vote(t, "alice", approval); err != nil || result.Msg.Approval.Status != v1.ApprovalStatus_APPROVAL_STATUS_APPROVED {
		t.Fatalf("approving while requested event is in flight: %v, %v", result, err)
	}
	waitNotifyStatus(t, f, approval.ApprovalId, 2, "sent", "")
	unblock()
	f.A.Job.DrainNotifications(t.Context())
	f.B.Job.DrainNotifications(t.Context())
	waitNotifyStatus(t, f, approval.ApprovalId, 2, "sent", "")
}

func TestNotifyQueueFullKeepsApprovalAndRecordsFailure(t *testing.T) {
	var deliveries atomic.Int32
	started, release := make(chan struct{}, 2), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	sender := job.ApprovalNotifierFunc(func(_ context.Context, _ job.ApprovalNotification) (string, string) {
		if deliveries.Add(1) <= 2 {
			started <- struct{}{}
			<-release
		}
		return "sent", ""
	})
	cfg := job.DefaultApprovalConfig()
	cfg.MaxPendingPerSubject = 100
	f := setupApprovals(t, 0, cfg, withApprovalNotifier(sender))
	defer unblock()
	f.labelTargets(t)
	f.policy(t, approvalRule(1, false, "reviewer"))
	r := gatedRequest()
	r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host"}}}}
	r.ExpectedCount = nil
	for range 2 {
		f.submit(t, "sa", r)
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("notification worker did not start")
		}
	}
	for index := range 256 {
		user := []string{"sa", "human", "foreign"}[(index+2)/100]
		f.submit(t, user, r)
	}
	pending := f.submit(t, "foreign", r)
	waitNotifyStatus(t, f, pending.Approval.ApprovalId, 1, "failed", "NOTIFY_QUEUE_FULL")
	if got := f.metadata(t, "viewer", pending.Approval.ApprovalId); got.Status != v1.ApprovalStatus_APPROVAL_STATUS_PENDING {
		t.Fatalf("queue saturation changed the approval to %s", got.Status)
	}
	unblock()
	f.A.Job.DrainNotifications(t.Context())
	if count := deliveries.Load(); count != 258 {
		t.Fatalf("deliveries = %d, want two active and 256 queued", count)
	}
}

func TestNotifyDrainKeepsPluginHostActiveAndStopsAdmission(t *testing.T) {
	var deliveries atomic.Int32
	started, release := make(chan struct{}, 2), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if deliveries.Add(1) <= 2 {
			started <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	host, sender := testWebhookNotifier(t, upstream, 5*time.Second)
	f := setupApprovals(t, 1, job.DefaultApprovalConfig(), withApprovalNotifier(sender))
	defer unblock()
	f.labelTargets(t)
	f.policy(t, approvalRule(1, false, "reviewer"))
	var accepted []string
	for range 2 {
		pending := f.submit(t, "sa", gatedRequest())
		accepted = append(accepted, pending.Approval.ApprovalId)
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("webhook delivery did not start")
		}
	}
	queued := f.submit(t, "sa", gatedRequest())
	accepted = append(accepted, queued.Approval.ApprovalId)
	drainCtx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	f.A.Job.DrainNotifications(drainCtx)
	if drainCtx.Err() != context.DeadlineExceeded {
		t.Fatal("drain returned before the pending delivery or deadline")
	}
	cancel()
	afterDrain := f.submit(t, "sa", gatedRequest())
	unblock()
	drainCtx, cancel = context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	f.A.Job.DrainNotifications(drainCtx)
	f.A.Job.Close()
	host.Close(drainCtx)
	if err := drainCtx.Err(); err != nil {
		t.Fatal(err)
	}
	for _, id := range accepted {
		waitNotifyStatus(t, f, id, 1, "sent", "")
	}
	waitNotifyStatus(t, f, afterDrain.Approval.ApprovalId, 1, "skipped", "")
	if got := deliveries.Load(); got != 3 {
		t.Fatalf("deliveries = %d, want three accepted notifications", got)
	}
}
