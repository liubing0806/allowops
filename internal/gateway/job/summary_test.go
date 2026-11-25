package job

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/cluster"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func makeSampleJob(totalTasks uint64) *v1.Job {
	return &v1.Job{
		JobId:         "job-20261124-0001",
		Action:        "fleet_health",
		Catalog:       &v1.CatalogRef{CatalogId: "ops", Version: 1},
		ActionSha256:  bytes.Repeat([]byte{0xab}, 32),
		SubjectId:     "sa-ops",
		Reason:        "fleet health check",
		Status:        v1.JobStatus_JOB_STATUS_PARTIALLY_FAILED,
		CreatedAt:     timestamppb.New(time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)),
		FinishedAt:    timestamppb.New(time.Date(2026, 11, 24, 12, 1, 0, 0, time.UTC)),
		TotalTasks:    totalTasks,
		PolicyVersion: 3,
	}
}

func makeHashedPreview(hostID, hostname string, status v1.TaskStatus, exitCode *int32, reason, stdout, stderr string) Preview {
	outSum := sha256.Sum256([]byte(stdout))
	errSum := sha256.Sum256([]byte(stderr))
	return Preview{
		Task: &v1.Task{
			HostId:   hostID,
			Hostname: hostname,
			Result: &v1.ExecutionResult{
				Status:   status,
				ExitCode: exitCode,
				Reason:   reason,
			},
		},
		Stdout:     []byte(stdout),
		Stderr:     []byte(stderr),
		StdoutHash: outSum[:],
		StderrHash: errSum[:],
		StdoutSize: uint64(len(stdout)),
		StderrSize: uint64(len(stderr)),
	}
}

func assertHostConservation(t *testing.T, summary *v1.JobSummary, expectedTotal uint64) {
	t.Helper()
	var grouped uint64
	for _, g := range summary.Groups {
		grouped += g.HostCount
	}
	got := grouped + uint64(len(summary.OfflineHosts)) + summary.UnfinishedHostsCount + summary.OmittedHosts
	if got != expectedTotal {
		t.Fatalf("host conservation violated: grouped(%d) + offline(%d) + unfinished(%d) + omitted(%d) = %d != %d",
			grouped, len(summary.OfflineHosts), summary.UnfinishedHostsCount, summary.OmittedHosts, got, expectedTotal)
	}
}

func TestGroupingModeValidation(t *testing.T) {
	if got, err := groupingMode("", cluster.GroupingExact); err != nil || got != cluster.GroupingExact {
		t.Fatalf("default exact: got=%q err=%v", got, err)
	}
	if got, err := groupingMode("", cluster.GroupingNormalized); err != nil || got != cluster.GroupingNormalized {
		t.Fatalf("default normalized: got=%q err=%v", got, err)
	}
	if got, err := groupingMode("exact", cluster.GroupingNormalized); err != nil || got != cluster.GroupingExact {
		t.Fatalf("explicit exact: got=%q err=%v", got, err)
	}
	if got, err := groupingMode("normalized", cluster.GroupingExact); err != nil || got != cluster.GroupingNormalized {
		t.Fatalf("explicit normalized: got=%q err=%v", got, err)
	}
	_, err := groupingMode("semantic", cluster.GroupingExact)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid grouping err=%v, want InvalidArgument", err)
	}
	var reason string
	if ce, ok := err.(*connect.Error); ok {
		for _, d := range ce.Details() {
			if v, err := d.Value(); err == nil {
				if ed, ok := v.(*v1.ErrorDetail); ok {
					reason = ed.Reason
				}
			}
		}
	}
	if reason != "INVALID_GROUPING" {
		t.Fatalf("reason=%q want INVALID_GROUPING", reason)
	}
}

func TestSummary120NoisyHostsNormalizedFits32KiBAnomalyFirst(t *testing.T) {
	items := make([]Preview, 0, 120)
	// 117 healthy noisy hosts with distinct timestamps, PIDs, hostnames, and metrics.
	for i := 0; i < 117; i++ {
		host := fmt.Sprintf("web-%03d.prod.internal", i)
		out := fmt.Sprintf("2026-11-24T12:00:%02dZ host=%s pid=%d load=1.%02d mem=%dMiB disk=%d%% status=ok\n",
			i%60, host, 1000+i, i%50, 2048+i*4, 40+(i%15))
		items = append(items, makeHashedPreview(fmt.Sprintf("hid-%03d", i), host, v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", out, ""))
	}
	// 1 minority structure succeeded host (different format/version).
	items = append(items, makeHashedPreview("hid-min", "web-117.prod.internal", v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "",
		"2026-11-24T12:00:05Z host=web-117.prod.internal nginx/1.25.3 DEGRADED upstream=stale\n", ""))
	// 1 nonzero exit host.
	items = append(items, makeHashedPreview("hid-fail", "web-118.prod.internal", v1.TaskStatus_TASK_STATUS_FAILED, proto.Int32(2), "EXECUTION_FAILED",
		"", "fatal: connection refused to db:5432\n"))
	// 1 timeout host.
	items = append(items, makeHashedPreview("hid-to", "web-119.prod.internal", v1.TaskStatus_TASK_STATUS_TIMEOUT, nil, "TIMEOUT",
		"partial output before timeout\n", ""))

	j := makeSampleJob(120)
	summary := &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED}
	groupPreviewsWithMode(summary, items, "concise", cluster.GroupingNormalized)
	if err := trimSummaryResponse(j, summary, ResponseBytes); err != nil {
		t.Fatalf("trimSummaryResponse: %v", err)
	}

	resp := &v1.GetJobResponse{Job: j, Summary: summary}
	raw, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatalf("protojson.Marshal: %v", err)
	}
	if len(raw) > ResponseBytes || proto.Size(resp) > ResponseBytes {
		t.Fatalf("exceeded 32 KiB: json=%d proto=%d", len(raw), proto.Size(resp))
	}
	if summary.Truncated {
		t.Fatalf("expected 120 noisy hosts in normalized mode to fit without truncation, got truncated=true (groups=%d omitted=%d)", len(summary.Groups), summary.OmittedGroups)
	}
	if summary.Grouping != string(cluster.GroupingNormalized) || summary.Ranking != cluster.RankingAnomalyFirst {
		t.Fatalf("metadata grouping=%q ranking=%q", summary.Grouping, summary.Ranking)
	}
	if len(summary.Groups) != 4 {
		t.Fatalf("expected 4 groups (timeout, nonzero, minority, majority), got %d", len(summary.Groups))
	}
	// Verify Anomaly-First order: timeout -> nonzero_exit -> minority_cluster -> majority_normal.
	wantSev := []v1.GroupSeverity{
		v1.GroupSeverity_GROUP_SEVERITY_FAILURE,
		v1.GroupSeverity_GROUP_SEVERITY_FAILURE,
		v1.GroupSeverity_GROUP_SEVERITY_ANOMALY,
		v1.GroupSeverity_GROUP_SEVERITY_NORMAL,
	}
	wantReasons := []string{
		cluster.ReasonTimeout,
		cluster.ReasonNonZeroExit,
		cluster.ReasonMinorityCluster,
		cluster.ReasonMajorityNormal,
	}
	for i := range wantSev {
		g := summary.Groups[i]
		if g.Severity != wantSev[i] || g.AnomalyReason != wantReasons[i] {
			t.Fatalf("group[%d] severity=%v reason=%q, want severity=%v reason=%q", i, g.Severity, g.AnomalyReason, wantSev[i], wantReasons[i])
		}
	}
	normal := summary.Groups[3]
	if normal.HostCount != 117 || len(normal.Hosts) != 2 || summary.FoldedNormalHosts != 115 {
		t.Fatalf("normal group host_count=%d len(hosts)=%d folded=%d", normal.HostCount, len(normal.Hosts), summary.FoldedNormalHosts)
	}
	if len(normal.Variances) == 0 {
		t.Fatalf("expected numeric variances on noisy 117-host cluster")
	}
	assertHostConservation(t, summary, 120)
}

func TestSummaryHostConservationUnhashedTerminalUnfinishedAndTruncated(t *testing.T) {
	items := []Preview{
		// Unhashed terminal tasks (SKIPPED/MAX_FAILURES, FAILED/DISPATCH_CAPACITY, CANCELLED).
		{Task: &v1.Task{HostId: "h-skip-1", Hostname: "skip-1", Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_SKIPPED, Reason: "MAX_FAILURES"}}},
		{Task: &v1.Task{HostId: "h-skip-2", Hostname: "skip-2", Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_SKIPPED, Reason: "MAX_FAILURES"}}},
		{Task: &v1.Task{HostId: "h-cap-1", Hostname: "cap-1", Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_FAILED, Reason: "DISPATCH_CAPACITY"}}},
		{Task: &v1.Task{HostId: "h-can-1", Hostname: "can-1", Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_CANCELLED, Reason: "CANCELLED"}}},
		// Unfinished tasks (PENDING, RUNNING).
		{Task: &v1.Task{HostId: "h-pend-1", Hostname: "pend-1", Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_PENDING}}},
		{Task: &v1.Task{HostId: "h-run-1", Hostname: "run-1", Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_RUNNING}}},
		// Offline tasks.
		{Task: &v1.Task{HostId: "h-off-1", Hostname: "off-1", Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_OFFLINE, Reason: "OFFLINE"}}},
		{Task: &v1.Task{HostId: "h-off-2", Hostname: "off-2", Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_OFFLINE, Reason: "OFFLINE"}}},
		// Succeeded normal tasks.
		makeHashedPreview("h-ok-1", "ok-1", v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", "healthy\n", ""),
		makeHashedPreview("h-ok-2", "ok-2", v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", "healthy\n", ""),
		makeHashedPreview("h-ok-3", "ok-3", v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", "healthy\n", ""),
	}

	j := makeSampleJob(uint64(len(items)))
	summary := &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED}
	groupPreviewsWithMode(summary, items, "concise", cluster.GroupingExact)
	if err := trimSummaryResponse(j, summary, ResponseBytes); err != nil {
		t.Fatalf("trimSummaryResponse: %v", err)
	}
	if summary.UnfinishedHostsCount != 2 {
		t.Fatalf("unfinished=%d want 2", summary.UnfinishedHostsCount)
	}
	if len(summary.OfflineHosts) != 2 {
		t.Fatalf("offline=%v want 2", summary.OfflineHosts)
	}
	if summary.TotalGroups != 4 {
		t.Fatalf("total_groups=%d want 4 (failed, cancelled, skipped, succeeded)", summary.TotalGroups)
	}
	if summary.FoldedNormalHosts != 1 {
		t.Fatalf("folded_normal_hosts=%d want 1", summary.FoldedNormalHosts)
	}
	assertHostConservation(t, summary, uint64(len(items)))

	// Now test strict host conservation under heavy 32 KiB truncation (both groups and offline hosts omitted).
	heavy := make([]Preview, 0, 120)
	heavy = append(heavy, items...)
	// Add 50 distinct 3 KiB succeeded groups + 40 offline hosts + 10 unfinished tasks.
	for i := 0; i < 50; i++ {
		payload := fmt.Sprintf("unique-group-%03d-%s", i, bytes.Repeat([]byte("x"), 3000))
		heavy = append(heavy, makeHashedPreview(fmt.Sprintf("hid-u-%03d", i), fmt.Sprintf("uniq-%03d", i),
			v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", payload, ""))
	}
	for i := 0; i < 40; i++ {
		heavy = append(heavy, Preview{Task: &v1.Task{
			HostId:   fmt.Sprintf("hid-off-%03d", i),
			Hostname: fmt.Sprintf("offline-node-%03d.prod.example.com", i),
			Result:   &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_OFFLINE, Reason: "OFFLINE"},
		}})
	}
	for i := 0; i < 10; i++ {
		heavy = append(heavy, Preview{Task: &v1.Task{
			HostId:   fmt.Sprintf("hid-run-%03d", i),
			Hostname: fmt.Sprintf("running-node-%03d", i),
			Result:   &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_RUNNING},
		}})
	}

	jHeavy := makeSampleJob(uint64(len(heavy)))
	sHeavy := &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED}
	groupPreviewsWithMode(sHeavy, heavy, "detailed", cluster.GroupingExact)
	if err := trimSummaryResponse(jHeavy, sHeavy, ResponseBytes); err != nil {
		t.Fatalf("trimSummaryResponse heavy: %v", err)
	}
	resp := &v1.GetJobResponse{Job: jHeavy, Summary: sHeavy}
	raw, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatalf("protojson.Marshal heavy: %v", err)
	}
	if len(raw) > ResponseBytes || proto.Size(resp) > ResponseBytes {
		t.Fatalf("heavy response exceeded 32 KiB: json=%d proto=%d", len(raw), proto.Size(resp))
	}
	if !sHeavy.Truncated || sHeavy.OmittedGroups == 0 || sHeavy.OmittedHosts == 0 {
		t.Fatalf("expected truncation and omissions, got truncated=%t omitted_groups=%d omitted_hosts=%d",
			sHeavy.Truncated, sHeavy.OmittedGroups, sHeavy.OmittedHosts)
	}
	if sHeavy.UnfinishedHostsCount != 12 {
		t.Fatalf("unfinished=%d want 12", sHeavy.UnfinishedHostsCount)
	}
	// Failure groups must appear first despite truncation.
	if len(sHeavy.Groups) == 0 || sHeavy.Groups[0].Severity != v1.GroupSeverity_GROUP_SEVERITY_FAILURE {
		t.Fatalf("expected failure group first, got %v", sHeavy.Groups)
	}
	assertHostConservation(t, sHeavy, uint64(len(heavy)))
}

func TestAcquireAnalysisSemaphoreAndNilFallback(t *testing.T) {
	// Zero-value Service (nil analysisSem) must not panic and must succeed.
	var zero Service
	release, err := zero.acquireAnalysis(context.Background())
	if err != nil {
		t.Fatalf("zero service acquireAnalysis: %v", err)
	}
	release()

	// Saturated semaphore must respect context cancellation.
	s := &Service{analysisSem: make(chan struct{}, 1)}
	r1, err := s.acquireAnalysis(context.Background())
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.acquireAnalysis(ctx); err != context.Canceled {
		t.Fatalf("cancelled acquire err=%v want context.Canceled", err)
	}
	r1()
	r2, err := s.acquireAnalysis(context.Background())
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	r2()
}

func TestTrimSummaryDropsOversizedApprovalRoleSets(t *testing.T) {
	j := makeSampleJob(1)
	j.Status = v1.JobStatus_JOB_STATUS_PENDING_APPROVAL
	j.Approval = &v1.JobApprovalSummary{
		ApprovalId:    "apr-20261124-0001",
		Status:        v1.ApprovalStatus_APPROVAL_STATUS_PENDING,
		ExpiresAt:     timestamppb.New(time.Date(2026, 11, 24, 13, 0, 0, 0, time.UTC)),
		MinApprovals:  2,
		ApprovedCount: 0,
		ConsoleUrl:    "https://approvals.test/approvals/apr-20261124-0001",
	}
	for i := 0; i < 48; i++ {
		roles := make([]string, 0, 16)
		for k := 0; k < 16; k++ {
			roles = append(roles, fmt.Sprintf("approval-role-group-%02d-member-%02d-with-long-name-padding", i, k))
		}
		j.Approval.RequiredApproverRoleSets = append(j.Approval.RequiredApproverRoleSets, &v1.PolicyApprovalRoleSet{Roles: roles})
	}
	summary := &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED}
	if sz, err := encodedMessageSize(&v1.GetJobResponse{Job: j, Summary: summary}); err != nil || sz <= ResponseBytes {
		t.Fatalf("test fixture not oversized: size=%d err=%v", sz, err)
	}
	if err := trimSummaryResponse(j, summary, ResponseBytes); err != nil {
		t.Fatalf("trimSummaryResponse oversized approval role sets: %v", err)
	}
	if !summary.Truncated {
		t.Fatalf("expected summary.Truncated=true")
	}
	if len(j.Approval.RequiredApproverRoleSets) != 0 {
		t.Fatalf("expected RequiredApproverRoleSets to be omitted as a whole, got %d", len(j.Approval.RequiredApproverRoleSets))
	}
	if sz, err := encodedMessageSize(&v1.GetJobResponse{Job: j, Summary: summary}); err != nil || sz > ResponseBytes {
		t.Fatalf("encoded GetJobResponse size=%d err=%v, want <= %d", sz, err, ResponseBytes)
	}
}

func BenchmarkTrimSummary1000Groups(b *testing.B) {
	j := makeSampleJob(1000)
	templateGroups := make([]*v1.OutputGroup, 1000)
	payload := string(bytes.Repeat([]byte("a"), 3900))
	for i := 0; i < 1000; i++ {
		out := fmt.Sprintf("grp-%04d:%s", i, payload)
		sum := sha256.Sum256([]byte(out))
		empty := sha256.Sum256(nil)
		sev := v1.GroupSeverity_GROUP_SEVERITY_NORMAL
		reason := cluster.ReasonMajorityNormal
		if i < 5 {
			sev = v1.GroupSeverity_GROUP_SEVERITY_FAILURE
			reason = cluster.ReasonNonZeroExit
		}
		templateGroups[i] = &v1.OutputGroup{
			ExitCode:      proto.Int32(0),
			StdoutSha256:  sum[:],
			StderrSha256:  empty[:],
			HostCount:     1,
			Hosts:         []string{fmt.Sprintf("host-%04d", i)},
			Stdout:        out,
			Severity:      sev,
			AnomalyReason: reason,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		groups := make([]*v1.OutputGroup, len(templateGroups))
		for k, g := range templateGroups {
			groups[k] = proto.Clone(g).(*v1.OutputGroup)
		}
		summary := &v1.JobSummary{
			Groups:      groups,
			OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED,
			Grouping:    string(cluster.GroupingExact),
			Ranking:     cluster.RankingAnomalyFirst,
			TotalGroups: uint64(len(groups)),
		}
		b.StartTimer()
		if err := trimSummaryResponse(j, summary, ResponseBytes); err != nil {
			b.Fatal(err)
		}
	}
}
