package job_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/cluster"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func errorReason(err error) string {
	ce, ok := err.(*connect.Error)
	if !ok {
		return ""
	}
	for _, d := range ce.Details() {
		if v, derr := d.Value(); derr == nil {
			if ed, ok := v.(*v1.ErrorDetail); ok {
				return ed.Reason
			}
		}
	}
	return ""
}

type mappedPreviews map[string][]job.Preview

func (m mappedPreviews) Load(_ context.Context, id string) ([]job.Preview, error) {
	return m[id], nil
}

func hashedPreview(hostID, hostname string, status v1.TaskStatus, exitCode *int32, reason, stdout, stderr string) job.Preview {
	outSum := sha256.Sum256([]byte(stdout))
	errSum := sha256.Sum256([]byte(stderr))
	return job.Preview{
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

func TestDiffJobsAuthorizationPreconditionsSemanticsBudgetAndAudit(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	spy := &auditSpy{Appender: f.A.Job.Audit}
	f.A.Job.Audit = spy

	// Run two completed "stable" jobs and one completed "fail" job as owner service account "sa".
	baseResp := run(t, f.A, request("stable"))
	targetResp := run(t, f.A, request("stable"))
	failResp := run(t, f.A, request("fail"))

	baseID := baseResp.Job.JobId
	targetID := targetResp.Job.JobId
	failID := failResp.Job.JobId

	// Also create a running/unfinished job ("slow") and a denied job.
	slowReq := request("slow")
	slowReq.BatchSize = proto.Uint32(1)
	slowReq.WaitSeconds = proto.Uint32(0)
	slowResp := run(t, f.A, slowReq)
	slowID := slowResp.Job.JobId

	// Create a denied job by temporarily removing labels on c-host.
	if _, err := f.DB.Pool.Exec(ctx, "UPDATE hosts SET authorization_labels='{}' WHERE host_id=$1", f.Hosts[2]); err != nil {
		t.Fatal(err)
	}
	denyReq := request("stable")
	denyReq.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host", "b-host", "c-host"}}}}
	denyReq.ExpectedCount = nil
	_, denyErr := f.A.Client.RunJob(ctx, connect.NewRequest(denyReq))
	if connect.CodeOf(denyErr) != connect.CodePermissionDenied {
		t.Fatalf("expected denied job, got %v", denyErr)
	}
	var deniedID string
	for _, d := range denyErr.(*connect.Error).Details() {
		if v, err := d.Value(); err == nil {
			if ed, ok := v.(*v1.ErrorDetail); ok {
				deniedID = ed.RequestId
			}
		}
	}
	if deniedID == "" {
		t.Fatal("missing denied job id")
	}
	if _, err := f.DB.Pool.Exec(ctx, "UPDATE hosts SET authorization_labels='{\"env\":\"test\"}' WHERE host_id=$1", f.Hosts[2]); err != nil {
		t.Fatal(err)
	}

	// Verify GetJob with grouping=normalized and invalid grouping over Connect RPC.
	t.Run("get_job_grouping_rpc", func(t *testing.T) {
		got, err := f.A.Client.GetJob(ctx, connect.NewRequest(&v1.GetJobRequest{
			JobId:       baseID,
			WaitSeconds: proto.Uint32(0),
			Grouping:    "normalized",
		}))
		if err != nil {
			t.Fatalf("GetJob normalized: %v", err)
		}
		if got.Msg.Summary.Grouping != string(cluster.GroupingNormalized) || got.Msg.Summary.Ranking != cluster.RankingAnomalyFirst {
			t.Fatalf("grouping=%q ranking=%q", got.Msg.Summary.Grouping, got.Msg.Summary.Ranking)
		}
		if _, err := f.A.Client.GetJob(ctx, connect.NewRequest(&v1.GetJobRequest{
			JobId:       baseID,
			WaitSeconds: proto.Uint32(0),
			Grouping:    "bogus",
		})); connect.CodeOf(err) != connect.CodeInvalidArgument || errorReason(err) != "INVALID_GROUPING" {
			t.Fatalf("invalid grouping err=%v reason=%q", err, errorReason(err))
		}
	})

	// 1. Parameter & unknown job checks.
	t.Run("validation_and_not_found", func(t *testing.T) {
		if _, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: "", TargetJobId: targetID})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("missing base_job_id=%v", err)
		}
		if _, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: baseID, TargetJobId: ""})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("missing target_job_id=%v", err)
		}
		if _, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: baseID, TargetJobId: targetID, Grouping: "bad"})); connect.CodeOf(err) != connect.CodeInvalidArgument || errorReason(err) != "INVALID_GROUPING" {
			t.Fatalf("invalid grouping=%v reason=%q", err, errorReason(err))
		}
		if _, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: "job-missing", TargetJobId: targetID})); connect.CodeOf(err) != connect.CodeNotFound || errorReason(err) != "JOB_UNKNOWN" {
			t.Fatalf("unknown base=%v reason=%q", err, errorReason(err))
		}
		if _, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: baseID, TargetJobId: "job-missing"})); connect.CodeOf(err) != connect.CodeNotFound || errorReason(err) != "JOB_UNKNOWN" {
			t.Fatalf("unknown target=%v reason=%q", err, errorReason(err))
		}
	})

	// 2. Preconditions: unfinished, denied, action mismatch.
	t.Run("preconditions", func(t *testing.T) {
		// Unfinished target (slow job with different action would hit action mismatch first, so diff slow vs slow).
		if _, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: slowID, TargetJobId: slowID})); connect.CodeOf(err) != connect.CodeFailedPrecondition || errorReason(err) != "DIFF_JOB_NOT_FINISHED" {
			t.Fatalf("unfinished job=%v reason=%q", err, errorReason(err))
		}
		// Denied job.
		if _, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: baseID, TargetJobId: deniedID})); connect.CodeOf(err) != connect.CodeFailedPrecondition || errorReason(err) != "DIFF_JOB_DENIED" {
			t.Fatalf("denied target=%v reason=%q", err, errorReason(err))
		}
		if _, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: deniedID, TargetJobId: targetID})); connect.CodeOf(err) != connect.CodeFailedPrecondition || errorReason(err) != "DIFF_JOB_DENIED" {
			t.Fatalf("denied base=%v reason=%q", err, errorReason(err))
		}
		// Action mismatch.
		if _, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: baseID, TargetJobId: failID})); connect.CodeOf(err) != connect.CodeInvalidArgument || errorReason(err) != "DIFF_ACTION_MISMATCH" {
			t.Fatalf("action mismatch=%v reason=%q", err, errorReason(err))
		}
	})

	// 3. Cross-service-account denial, missing view_output denial, and partial host unauthorized denial.
	t.Run("authorization", func(t *testing.T) {
		// Foreign service account (admin role, different subject_id).
		foreignTok, record, err := authn.GenerateServiceToken(time.Now(), 1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.DB.Pool.Exec(ctx, "INSERT INTO service_accounts(account_id,name,owner_user_id,roles) VALUES ('foreign-diff','foreign-diff','owner','{admin}')"); err != nil {
			t.Fatal(err)
		}
		if _, err = f.DB.Pool.Exec(ctx, "INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES ('foreign-diff','foreign-diff',$1,$2)", record.Hash[:], record.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		foreignClient := rpc.NewJobServiceClient(f.A.HTTP, "https://"+f.A.Address, connect.WithInterceptors(bearer(foreignTok)))
		// Must reject with JOB_OWNER_REQUIRED even when actions differ (authz before action mismatch).
		if _, err = foreignClient.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: baseID, TargetJobId: failID})); connect.CodeOf(err) != connect.CodePermissionDenied || errorReason(err) != "JOB_OWNER_REQUIRED" {
			t.Fatalf("foreign service account=%v reason=%q", err, errorReason(err))
		}

		// Owner service account downgraded to publisher (lacks view_output).
		if _, err = f.DB.Pool.Exec(ctx, "UPDATE service_accounts SET roles='{publisher}' WHERE account_id='sa'"); err != nil {
			t.Fatal(err)
		}
		if _, err = f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: baseID, TargetJobId: targetID})); connect.CodeOf(err) != connect.CodePermissionDenied || errorReason(err) != "JOB_OPERATION_DENIED" {
			t.Fatalf("sa without view_output=%v reason=%q", err, errorReason(err))
		}
		if _, err = f.DB.Pool.Exec(ctx, "UPDATE service_accounts SET roles='{admin}' WHERE account_id='sa'"); err != nil {
			t.Fatal(err)
		}

		// Console CLI user: viewer (has view_jobs, lacks view_output) -> denied.
		random := make([]byte, 32)
		if _, err = rand.Read(random); err != nil {
			t.Fatal(err)
		}
		cliTok := "aops_cli_" + base64.RawURLEncoding.EncodeToString(random)
		cliHash := sha256.Sum256([]byte(cliTok))
		if _, err = f.DB.Pool.Exec(ctx, "INSERT INTO identity_sessions(session_id,user_id,token_hash,client,expires_at) VALUES ('console-diff','owner',$1,'cli',now()+interval '1 hour')", cliHash[:]); err != nil {
			t.Fatal(err)
		}
		consoleClient := rpc.NewJobServiceClient(f.A.HTTP, "https://"+f.A.Address, connect.WithInterceptors(bearer(cliTok)))
		if _, err = f.DB.Pool.Exec(ctx, "UPDATE console_users SET manual_roles='{viewer}' WHERE user_id='owner'"); err != nil {
			t.Fatal(err)
		}
		if _, err = consoleClient.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: baseID, TargetJobId: targetID})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("viewer without view_output=%v", err)
		}

		// Partial host unauthorized: add a policy rule denying auditor view_output on tier=restricted,
		// tag only c-host with tier=restricted, and verify DiffJobs rejects the whole diff.
		var rawPolicy []byte
		if err = f.DB.Pool.QueryRow(ctx, "SELECT rules FROM policy_versions WHERE version=1").Scan(&rawPolicy); err != nil {
			t.Fatal(err)
		}
		var pr v1.PolicyRules
		if err = protojson.Unmarshal(rawPolicy, &pr); err != nil {
			t.Fatal(err)
		}
		pr.Rules = append(pr.Rules, &v1.PolicyRule{
			Name:       "deny-restricted-output",
			Effect:     v1.PolicyEffect_POLICY_EFFECT_DENY,
			Roles:      []string{"auditor"},
			Operations: []string{"view_output"},
			HostLabels: map[string]string{"tier": "restricted"},
		})
		updatedPolicy, err := protojson.Marshal(&pr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.DB.Pool.Exec(ctx, "INSERT INTO policy_versions(version,rules,created_by,reason) VALUES (2,$1,'fixture','deny restricted output')", updatedPolicy); err != nil {
			t.Fatal(err)
		}
		if _, err = f.DB.Pool.Exec(ctx, "UPDATE console_users SET manual_roles='{auditor}' WHERE user_id='owner'; UPDATE hosts SET authorization_labels='{\"env\":\"test\",\"tier\":\"restricted\"}' WHERE hostname='c-host'"); err != nil {
			t.Fatal(err)
		}
		if _, err = consoleClient.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: baseID, TargetJobId: targetID})); connect.CodeOf(err) != connect.CodePermissionDenied || errorReason(err) != "JOB_OPERATION_DENIED" {
			t.Fatalf("partial host unauthorized=%v reason=%q", err, errorReason(err))
		}
		if _, err = f.DB.Pool.Exec(ctx, "UPDATE hosts SET authorization_labels='{\"env\":\"test\"}' WHERE hostname='c-host'"); err != nil {
			t.Fatal(err)
		}
		if _, err = consoleClient.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: baseID, TargetJobId: targetID})); err != nil {
			t.Fatalf("console auditor all hosts allowed=%v", err)
		}
		if _, err = f.DB.Pool.Exec(ctx, "UPDATE console_users SET manual_roles='{admin}' WHERE user_id='owner'"); err != nil {
			t.Fatal(err)
		}
	})

	// 4. base == target zero-change, only_changed=false, and audit check.
	t.Run("same_job_only_changed_and_audit", func(t *testing.T) {
		spy.mu.Lock()
		beforeLen := len(spy.events)
		spy.mu.Unlock()

		same, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{
			BaseJobId:   baseID,
			TargetJobId: baseID,
		}))
		if err != nil {
			t.Fatalf("same job diff: %v", err)
		}
		d := same.Msg.Diff
		if d.OutputTrust != v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED {
			t.Fatalf("output_trust=%v", d.OutputTrust)
		}
		if d.Grouping != string(cluster.GroupingNormalized) {
			t.Fatalf("default grouping=%q want normalized", d.Grouping)
		}
		if d.UnchangedHostsCount != 3 || d.AddedHostsCount != 0 || d.RemovedHostsCount != 0 || d.ReplacedHostsCount != 0 {
			t.Fatalf("counts=%+v", d)
		}
		if len(d.StatusTransitions) != 0 || len(d.PatternChanges) != 0 || len(d.MetricDrifts) != 0 {
			t.Fatalf("expected zero changes, got %+v", d)
		}

		// only_changed = false returns unchanged pattern entry.
		withUnchanged, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{
			BaseJobId:   baseID,
			TargetJobId: targetID,
			OnlyChanged: proto.Bool(false),
		}))
		if err != nil {
			t.Fatalf("only_changed=false diff: %v", err)
		}
		if len(withUnchanged.Msg.Diff.PatternChanges) != 1 || !withUnchanged.Msg.Diff.PatternChanges[0].Unchanged || withUnchanged.Msg.Diff.PatternChanges[0].HostCount != 3 {
			t.Fatalf("unchanged patterns=%+v", withUnchanged.Msg.Diff.PatternChanges)
		}

		// Verify audit record for diff_jobs(baseID, targetID).
		spy.mu.Lock()
		newEvents := append([]audit.Payload(nil), spy.events[beforeLen:]...)
		spy.mu.Unlock()
		found := false
		for _, ev := range newEvents {
			raw, _ := json.Marshal(ev)
			if strings.Contains(string(raw), "same output") {
				t.Fatalf("audit payload leaked execution output: %s", string(raw))
			}
			if ev.Operation == "diff_jobs" && ev.Reason == "result" && ev.JobID == targetID && ev.Resource == "job:"+baseID {
				found = true
				if ev.Decision != "allow" || ev.PolicyVersion == 0 || len(ev.MatchedRules) == 0 {
					t.Fatalf("incomplete audit payload: %+v", ev)
				}
				// MatchedRules must be deduplicated.
				sorted := slices.Clone(ev.MatchedRules)
				slices.Sort(sorted)
				if len(slices.Compact(sorted)) != len(ev.MatchedRules) {
					t.Fatalf("duplicate matched_rules in audit: %v", ev.MatchedRules)
				}
			}
		}
		if !found {
			t.Fatalf("missing diff_jobs audit event with job_id=%s resource=job:%s in %+v", targetID, baseID, newEvents)
		}
	})

	// 5. action_definition_changed=true when action_sha256 differs between base and target.
	t.Run("action_definition_changed", func(t *testing.T) {
		altHash := bytes.Repeat([]byte{0x42}, 32)
		if _, err := f.DB.Pool.Exec(ctx, "UPDATE jobs SET action_sha256=$2 WHERE job_id=$1", targetID, altHash); err != nil {
			t.Fatal(err)
		}
		resp, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{
			BaseJobId:   baseID,
			TargetJobId: targetID,
		}))
		if err != nil {
			t.Fatalf("diff after action hash change: %v", err)
		}
		if !resp.Msg.Diff.ActionDefinitionChanged {
			t.Fatal("expected action_definition_changed=true")
		}
	})

	// 6. Replaced host (same hostname, different host_id) + metric drift + status transition.
	t.Run("replaced_hosts_and_semantic_diff", func(t *testing.T) {
		origPreviews := f.A.Job.Previews
		defer func() { f.A.Job.Previews = origPreviews }()

		f.A.Job.Previews = mappedPreviews{
			baseID: {
				hashedPreview("host-id-a", "a-host", v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", "disk=30% load=1.10 status=ok\n", ""),
				hashedPreview("host-id-b-old", "b-host", v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", "disk=35% load=1.20 status=ok\n", ""),
				hashedPreview("host-id-c", "c-host", v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", "disk=40% load=1.05 status=ok\n", ""),
			},
			targetID: {
				hashedPreview("host-id-a", "a-host", v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", "disk=85% load=4.50 status=ok\n", ""),
				// b-host re-registered with a brand new host_id -> must be reported in replaced_hosts!
				hashedPreview("host-id-b-new", "b-host", v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", "disk=10% load=0.50 status=ok\n", ""),
				hashedPreview("host-id-c", "c-host", v1.TaskStatus_TASK_STATUS_TIMEOUT, nil, "TIMEOUT", "hung\n", ""),
			},
		}

		resp, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{
			BaseJobId:   baseID,
			TargetJobId: targetID,
		}))
		if err != nil {
			t.Fatalf("replaced host diff: %v", err)
		}
		d := resp.Msg.Diff
		if d.ReplacedHostsCount != 1 || !slices.Equal(d.ReplacedHosts, []string{"b-host"}) {
			t.Fatalf("replaced_hosts=%v count=%d want [b-host]", d.ReplacedHosts, d.ReplacedHostsCount)
		}
		if d.AddedHostsCount != 1 || d.RemovedHostsCount != 1 {
			t.Fatalf("added=%d removed=%d want 1/1", d.AddedHostsCount, d.RemovedHostsCount)
		}
		if len(d.StatusTransitions) != 1 || !d.StatusTransitions[0].Degradation || d.StatusTransitions[0].ToStatus != v1.TaskStatus_TASK_STATUS_TIMEOUT {
			t.Fatalf("status_transitions=%+v", d.StatusTransitions)
		}
		if len(d.MetricDrifts) == 0 {
			t.Fatalf("expected significant metric drifts for a-host disk 30%% -> 85%%")
		}
	})

	// 7. Large-scale diff strictly <= 32 KiB with priority trimming.
	t.Run("large_scale_diff_32kib_budget", func(t *testing.T) {
		origPreviews := f.A.Job.Previews
		defer func() { f.A.Job.Previews = origPreviews }()

		baseItems := make([]job.Preview, 0, 260)
		targetItems := make([]job.Preview, 0, 320)
		// 2 status degradations (highest priority).
		for i := 0; i < 2; i++ {
			id := fmt.Sprintf("hid-deg-%d", i)
			name := fmt.Sprintf("deg-%d.prod", i)
			baseItems = append(baseItems, hashedPreview(id, name, v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", "ok\n", ""))
			targetItems = append(targetItems, hashedPreview(id, name, v1.TaskStatus_TASK_STATUS_FAILED, proto.Int32(1), "EXECUTION_FAILED", "", "boom\n"))
		}
		// 120 distinct large pattern changes (each ~2 KiB output -> way over 32 KiB).
		for i := 0; i < 120; i++ {
			id := fmt.Sprintf("hid-pat-%03d", i)
			name := fmt.Sprintf("pat-%03d.prod", i)
			bOut := fmt.Sprintf("base-pattern-%03d-%s\n", i, strings.Repeat("B", 1500))
			tOut := fmt.Sprintf("target-pattern-%03d-%s\n", i, strings.Repeat("T", 1500))
			baseItems = append(baseItems, hashedPreview(id, name, v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", bOut, ""))
			targetItems = append(targetItems, hashedPreview(id, name, v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", tOut, ""))
		}
		// 150 added hosts and 100 removed hosts.
		for i := 0; i < 100; i++ {
			baseItems = append(baseItems, hashedPreview(fmt.Sprintf("hid-rem-%03d", i), fmt.Sprintf("removed-host-%03d.prod.example.com", i),
				v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", "ok\n", ""))
		}
		for i := 0; i < 150; i++ {
			targetItems = append(targetItems, hashedPreview(fmt.Sprintf("hid-add-%03d", i), fmt.Sprintf("added-host-%03d.prod.example.com", i),
				v1.TaskStatus_TASK_STATUS_SUCCEEDED, proto.Int32(0), "", "ok\n", ""))
		}

		f.A.Job.Previews = mappedPreviews{
			baseID:   baseItems,
			targetID: targetItems,
		}

		resp, err := f.A.Client.DiffJobs(ctx, connect.NewRequest(&v1.DiffJobsRequest{
			BaseJobId:   baseID,
			TargetJobId: targetID,
			Grouping:    "exact",
		}))
		if err != nil {
			t.Fatalf("large diff: %v", err)
		}
		raw, err := protojson.Marshal(resp.Msg)
		if err != nil {
			t.Fatalf("protojson.Marshal: %v", err)
		}
		if len(raw) > job.ResponseBytes || proto.Size(resp.Msg) > job.ResponseBytes {
			t.Fatalf("diff exceeded 32 KiB: json=%d proto=%d", len(raw), proto.Size(resp.Msg))
		}
		d := resp.Msg.Diff
		if !d.Truncated {
			t.Fatal("expected diff.Truncated=true")
		}
		if d.AddedHostsCount != 150 || d.RemovedHostsCount != 100 {
			t.Fatalf("counts lost during trimming: added=%d removed=%d", d.AddedHostsCount, d.RemovedHostsCount)
		}
		if len(d.StatusTransitions) != 1 || !d.StatusTransitions[0].Degradation {
			t.Fatalf("highest-priority status transition lost: %+v", d.StatusTransitions)
		}
		if d.OmittedPatternChanges == 0 || uint64(len(d.PatternChanges))+d.OmittedPatternChanges != d.TotalPatternChanges {
			t.Fatalf("pattern change accounting mismatch: kept=%d omitted=%d total=%d",
				len(d.PatternChanges), d.OmittedPatternChanges, d.TotalPatternChanges)
		}
	})

	// Cleanly cancel the lingering slow job so fixture shutdown is fast.
	_, _ = f.A.Client.CancelJob(ctx, connect.NewRequest(&v1.CancelJobRequest{JobId: slowID}))
}
