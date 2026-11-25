package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
	"github.com/liubing0806/allowops/plugin/notifier"
)

func TestApprovalNotifierGatewayAdapter(t *testing.T) {
	var phase atomic.Int32
	received := make(chan notifier.Event, 6)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event notifier.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Error("webhook received an invalid approval event")
		}
		received <- event
		if stage := phase.Load(); stage == 2 || stage == 1 && r.URL.Path == "/second" {
			http.Error(w, "private response text", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	var configText strings.Builder
	configText.WriteString("plugins:\n")
	for _, name := range []string{"first", "second"} {
		fmt.Fprintf(&configText, `  - id: %s
    module: notifier.webhook
    egress: [%q]
    allow_private_egress: true
    ca_file: %q
    config: {url: %q, events: [approval.approved]}
`, name, upstream.URL, caFile, upstream.URL+"/"+name)
	}
	cfg, err := decodeConfig(strings.NewReader(configText.String()))
	if err != nil {
		t.Fatal(err)
	}
	host, err := pluginhost.New(t.Context(), cfg.Plugins, pluginhost.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(t.Context())
	now := time.Date(2026, time.November, 24, 10, 11, 12, 0, time.UTC)
	submitted := job.ApprovalNotification{
		Type: "approval.approved", EventID: "ap-1:2", Sequence: 2, At: now, ApprovalID: "ap-1", JobID: "job-1",
		Action: "restart", Risk: "write", Requester: "operator", TargetCount: 2, SampleHosts: []string{"node-1"},
		RequiredApproverRoleSets: [][]string{{"reviewer"}, {"security"}}, MinApprovals: 2, ApprovedCount: 2,
		ExpiresAt: now.Add(time.Hour), ConsoleURL: "https://console.example/approvals/ap-1", Actor: "reviewer",
		Status: v1.ApprovalStatus_APPROVAL_STATUS_APPROVED,
	}
	want := notifier.Event{
		Type: notifier.EventApprovalApproved, EventID: "ap-1:2", At: now, ApprovalID: "ap-1", JobID: "job-1",
		Action: "restart", Risk: "write", Requester: "operator", TargetCount: 2, SampleHosts: []string{"node-1"},
		RequiredApproverRoleSets: [][]string{{"reviewer"}, {"security"}}, MinApprovals: 2, ApprovedCount: 2,
		ExpiresAt: now.Add(time.Hour), ConsoleURL: "https://console.example/approvals/ap-1", Actor: "reviewer", Status: "approved",
	}
	adapter := approvalNotifier(host)
	for i, result := range []struct{ status, errCode string }{{"sent", ""}, {"partial_failed", "NOTIFY_DELIVERY_FAILED"}, {"failed", "NOTIFY_DELIVERY_FAILED"}} {
		phase.Store(int32(i))
		status, errCode := adapter(t.Context(), submitted)
		if status != result.status || errCode != result.errCode {
			t.Errorf("phase %d: outcome = %s/%s, want %s/%s", i, status, errCode, result.status, result.errCode)
		}
		for range 2 {
			select {
			case got := <-received:
				if !reflect.DeepEqual(got, want) {
					t.Errorf("event = %+v, want %+v", got, want)
				}
			default:
				t.Fatal("webhook did not receive the approval event")
			}
		}
	}
}
