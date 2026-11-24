package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"google.golang.org/protobuf/proto"
)

type stubDiffJobs struct {
	JobService
	lastReq *v1.DiffJobsRequest
	resp    *v1.DiffJobsResponse
	err     error
}

func (s *stubDiffJobs) DiffJobs(_ context.Context, r *v1.DiffJobsRequest) (*v1.DiffJobsResponse, error) {
	s.lastReq = r
	return s.resp, s.err
}

func TestDiffJobsArgumentValidation(t *testing.T) {
	validBase := "job-20261124-0001"
	validTarget := "job-20261124-0002"
	cases := []struct {
		name string
		raw  string
	}{
		{"empty object", `{}`},
		{"missing target", `{"base_job_id":"` + validBase + `"}`},
		{"missing base", `{"target_job_id":"` + validTarget + `"}`},
		{"bad base id", `{"base_job_id":"not-a-job","target_job_id":"` + validTarget + `"}`},
		{"bad target id", `{"base_job_id":"` + validBase + `","target_job_id":"job-123"}`},
		{"null base id", `{"base_job_id":null,"target_job_id":"` + validTarget + `"}`},
		{"unknown arg", `{"base_job_id":"` + validBase + `","target_job_id":"` + validTarget + `","next_cursor":"abc"}`},
		{"bad grouping", `{"base_job_id":"` + validBase + `","target_job_id":"` + validTarget + `","grouping":"fuzzy"}`},
		{"null grouping", `{"base_job_id":"` + validBase + `","target_job_id":"` + validTarget + `","grouping":null}`},
		{"bad only_changed", `{"base_job_id":"` + validBase + `","target_job_id":"` + validTarget + `","only_changed":"true"}`},
		{"null only_changed", `{"base_job_id":"` + validBase + `","target_job_id":"` + validTarget + `","only_changed":null}`},
		{"duplicate key", `{"base_job_id":"` + validBase + `","base_job_id":"` + validBase + `","target_job_id":"` + validTarget + `"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jobs := &stubDiffJobs{}
			svc := &Service{jobs: jobs, config: Config{Jobs: job.DefaultConfig()}}
			state := &callState{}
			_, err := svc.diffJobs(context.Background(), json.RawMessage(tc.raw), state)
			if connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("case=%s err=%v want InvalidArgument", tc.name, err)
			}
			if jobs.lastReq != nil {
				t.Fatalf("case=%s invalid args reached backend", tc.name)
			}
		})
	}
}

func TestDiffJobsMappingDefaultsAndTrustValidation(t *testing.T) {
	pct := 25.5
	nan := math.NaN()
	jobs := &stubDiffJobs{
		resp: &v1.DiffJobsResponse{
			BaseJob:   &v1.Job{JobId: "job-20261124-0001", Action: "disk_usage", Status: v1.JobStatus_JOB_STATUS_SUCCEEDED, TotalTasks: 4},
			TargetJob: &v1.Job{JobId: "job-20261124-0002", Action: "disk_usage", Status: v1.JobStatus_JOB_STATUS_PARTIALLY_FAILED, TotalTasks: 5},
			Diff: &v1.JobDiff{
				OutputTrust:             v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED,
				PreviewTruncated:        true,
				ActionDefinitionChanged: true,
				Grouping:                "normalized",
				UnchangedHostsCount:     2,
				AddedHostsCount:         1,
				AddedHosts:              []string{"web-05"},
				RemovedHostsCount:       1,
				RemovedHosts:            []string{"web-00"},
				ReplacedHostsCount:      1,
				ReplacedHosts:           []string{"web-03"},
				StatusTransitions: []*v1.StatusTransition{{
					FromStatus:   v1.TaskStatus_TASK_STATUS_SUCCEEDED,
					ToStatus:     v1.TaskStatus_TASK_STATUS_FAILED,
					FromExitCode: proto.Int32(0),
					ToExitCode:   proto.Int32(1),
					Reason:       "EXECUTION_FAILED",
					HostCount:    1,
					Hosts:        []string{"web-02"},
					Degradation:  true,
				}},
				TotalPatternChanges: 1,
				PatternChanges: []*v1.PatternChange{{
					BaseSeverity:    v1.GroupSeverity_GROUP_SEVERITY_NORMAL,
					TargetSeverity:  v1.GroupSeverity_GROUP_SEVERITY_FAILURE,
					HostCount:       1,
					Hosts:           []string{"web-02"},
					BasePreview:     "ok",
					TargetPreview:   "fail",
					RemovedLines:    []string{"status=ok"},
					AddedLines:      []string{"status=err"},
					DiffComputed:    true,
					TargetTruncated: true,
				}},
				MetricDrifts: []*v1.MetricDrift{
					{
						Label:          "disk.used",
						Unit:           "%",
						BaseP50:        40,
						TargetP50:      50,
						BaseMax:        45,
						TargetMax:      60,
						MaxDelta:       15,
						MaxDeltaBase:   45,
						MaxDeltaTarget: 60,
						MaxDeltaPct:    &pct,
						MaxHost:        "web-01",
						AffectedHosts:  2,
						HostCount:      3,
					},
					{
						// Base==0 => max_delta_pct omitted (nil or non-finite filtered).
						Label:          "errors",
						BaseP50:        0,
						TargetP50:      2,
						BaseMax:        0,
						TargetMax:      5,
						MaxDelta:       5,
						MaxDeltaBase:   0,
						MaxDeltaTarget: 5,
						MaxDeltaPct:    &nan,
						MaxHost:        "web-02",
						AffectedHosts:  1,
						HostCount:      3,
					},
					{
						// Non-finite required float is skipped.
						Label:   "bad",
						BaseP50: math.Inf(1),
					},
				},
			},
		},
	}

	svc := &Service{jobs: jobs, config: Config{Jobs: job.DefaultConfig()}}
	state := &callState{}
	res, err := svc.diffJobs(context.Background(), json.RawMessage(`{"base_job_id":"job-20261124-0001","target_job_id":"job-20261124-0002"}`), state)
	if err != nil {
		t.Fatal(err)
	}
	if state.jobID != "job-20261124-0002" {
		t.Fatalf("audit jobID=%q want target", state.jobID)
	}
	if jobs.lastReq.Grouping != "normalized" || jobs.lastReq.OnlyChanged == nil || !*jobs.lastReq.OnlyChanged {
		t.Fatalf("defaults forwarded=%+v", jobs.lastReq)
	}

	m := nativeContent(t, res)
	if m["output_trust"] != "untrusted" || m["grouping"] != "normalized" || m["action_definition_changed"] != true || m["preview_truncated"] != true || m["truncated"] != false {
		t.Fatalf("top-level diff=%v", m)
	}
	if m["unchanged_hosts_count"] != float64(2) || m["added_hosts_count"] != float64(1) || m["removed_hosts_count"] != float64(1) || m["replaced_hosts_count"] != float64(1) {
		t.Fatalf("host counts=%v", m)
	}
	if m["hint"] == "" {
		t.Fatalf("missing hint: %v", m)
	}
	drifts := m["metric_drifts"].([]any)
	if len(drifts) != 2 {
		t.Fatalf("drifts=%v", drifts)
	}
	d0 := drifts[0].(map[string]any)
	if d0["max_delta_pct"] != float64(25.5) || d0["unit"] != "%" {
		t.Fatalf("d0=%v", d0)
	}
	d1 := drifts[1].(map[string]any)
	if _, hasPct := d1["max_delta_pct"]; hasPct {
		t.Fatalf("expected nil/NaN max_delta_pct to be omitted: %v", d1)
	}

	// Reject response with missing OutputTrust.
	badResp := proto.Clone(jobs.resp).(*v1.DiffJobsResponse)
	badResp.Diff.OutputTrust = v1.OutputTrust_OUTPUT_TRUST_UNSPECIFIED
	if _, err := diffJobsResult(badResp); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("unspecified output_trust err=%v", err)
	}
}

func TestDiffJobsEnforces32KiBBudgetInPriorityOrder(t *testing.T) {
	added := make([]string, 300)
	removed := make([]string, 300)
	replaced := make([]string, 100)
	for i := range added {
		added[i] = fmt.Sprintf("added-host-%04d.example.org", i)
	}
	for i := range removed {
		removed[i] = fmt.Sprintf("removed-host-%04d.example.org", i)
	}
	for i := range replaced {
		replaced[i] = fmt.Sprintf("replaced-host-%04d.example.org", i)
	}
	drifts := make([]*v1.MetricDrift, 12)
	for i := range drifts {
		drifts[i] = &v1.MetricDrift{
			Label:          fmt.Sprintf("metric_%02d", i),
			Unit:           "ms",
			BaseP50:        10,
			TargetP50:      50,
			BaseMax:        20,
			TargetMax:      100,
			MaxDelta:       80,
			MaxDeltaBase:   20,
			MaxDeltaTarget: 100,
			MaxHost:        fmt.Sprintf("drift-host-%02d", i),
			AffectedHosts:  5,
			HostCount:      10,
		}
	}
	patterns := make([]*v1.PatternChange, 25)
	for i := range patterns {
		patterns[i] = &v1.PatternChange{
			BaseSeverity:   v1.GroupSeverity_GROUP_SEVERITY_NORMAL,
			TargetSeverity: v1.GroupSeverity_GROUP_SEVERITY_ANOMALY,
			HostCount:      3,
			Hosts:          []string{fmt.Sprintf("p%02d-a", i), fmt.Sprintf("p%02d-b", i), fmt.Sprintf("p%02d-c", i)},
			BasePreview:    strings.Repeat("b", 400),
			TargetPreview:  strings.Repeat("t", 400),
			RemovedLines:   []string{strings.Repeat("-x", 100), strings.Repeat("-y", 100)},
			AddedLines:     []string{strings.Repeat("+x", 100), strings.Repeat("+y", 100)},
			DiffComputed:   true,
		}
	}
	transitions := []*v1.StatusTransition{{
		FromStatus:   v1.TaskStatus_TASK_STATUS_SUCCEEDED,
		ToStatus:     v1.TaskStatus_TASK_STATUS_TIMEOUT,
		FromExitCode: proto.Int32(0),
		HostCount:    5,
		Hosts:        []string{"crit-01", "crit-02"},
		Degradation:  true,
	}}

	resp := &v1.DiffJobsResponse{
		BaseJob:   &v1.Job{JobId: "job-20261124-0010", Action: "noisy_cmd", Status: v1.JobStatus_JOB_STATUS_SUCCEEDED, TotalTasks: 500},
		TargetJob: &v1.Job{JobId: "job-20261124-0011", Action: "noisy_cmd", Status: v1.JobStatus_JOB_STATUS_PARTIALLY_FAILED, TotalTasks: 500},
		Diff: &v1.JobDiff{
			OutputTrust:         v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED,
			Grouping:            "normalized",
			UnchangedHostsCount: 100,
			AddedHostsCount:     uint64(len(added)),
			AddedHosts:          added,
			RemovedHostsCount:   uint64(len(removed)),
			RemovedHosts:        removed,
			ReplacedHostsCount:  uint64(len(replaced)),
			ReplacedHosts:       replaced,
			StatusTransitions:   transitions,
			TotalPatternChanges: uint64(len(patterns)),
			PatternChanges:      patterns,
			MetricDrifts:        drifts,
		},
	}

	result, err := diffJobsResult(resp)
	if err != nil {
		t.Fatal(err)
	}
	raw := mustJSON(t, result)
	if len(raw) > resultByteLimit {
		t.Fatalf("MCP diff JSON %d exceeds 32 KiB", len(raw))
	}
	m := nativeContent(t, result)
	if m["truncated"] != true || m["output_trust"] != "untrusted" {
		t.Fatalf("expected truncated=true and untrusted: %v", m)
	}
	// Exact counts must be preserved even after trimming.
	if m["added_hosts_count"] != float64(300) || m["removed_hosts_count"] != float64(300) || m["replaced_hosts_count"] != float64(100) || m["total_pattern_changes"] != float64(25) {
		t.Fatalf("counts altered: added=%v removed=%v replaced=%v total_pat=%v", m["added_hosts_count"], m["removed_hosts_count"], m["replaced_hosts_count"], m["total_pattern_changes"])
	}
	// Highest-priority status transition must survive while lower-priority lists were trimmed.
	if len(m["status_transitions"].([]any)) != 1 {
		t.Fatalf("highest priority status transition lost: %v", m["status_transitions"])
	}
	if len(m["added_hosts"].([]any)) != 0 || len(m["removed_hosts"].([]any)) != 0 || len(m["replaced_hosts"].([]any)) != 0 || len(m["metric_drifts"].([]any)) != 0 {
		t.Fatalf("expected lower priority lists trimmed before pattern_changes")
	}
	keptPatterns := len(m["pattern_changes"].([]any))
	omittedPatterns := int(m["omitted_pattern_changes"].(float64))
	if keptPatterns+omittedPatterns != 25 || omittedPatterns == 0 {
		t.Fatalf("kept=%d omitted=%d want sum=25 with omitted>0", keptPatterns, omittedPatterns)
	}
}

func TestSDKJobsDiffTransportAndAudit(t *testing.T) {
	f := newTransportFixture(t)
	c, _ := f.client(t, f.admin, nil)
	r1 := call(t, c, "logs_read", actionArgs())
	r2 := call(t, c, "logs_read", actionArgs())
	if r1.IsError || r2.IsError {
		t.Fatalf("setup runs failed: r1=%+v r2=%+v", r1, r2)
	}
	id1 := content(t, r1)["job_id"].(string)
	id2 := content(t, r2)["job_id"].(string)

	diffRes := call(t, c, "jobs_diff", map[string]any{"base_job_id": id1, "target_job_id": id2, "only_changed": false})
	if diffRes.IsError {
		t.Fatalf("jobs_diff error=%+v", content(t, diffRes))
	}
	m := content(t, diffRes)
	if m["base_job_id"] != id1 || m["target_job_id"] != id2 || m["grouping"] != "normalized" || m["output_trust"] != "untrusted" {
		t.Fatalf("jobs_diff result=%v", m)
	}

	foundAudit := false
	for _, e := range f.audit.snapshot() {
		if e.Operation == "mcp/jobs_diff" && e.Phase == "result" && e.Outcome == "allow" && e.JobID == id2 {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Fatalf("missing mcp/jobs_diff allow audit with target job_id=%s", id2)
	}
}
