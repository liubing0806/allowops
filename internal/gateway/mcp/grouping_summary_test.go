package mcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
)

func TestNativeSummaryMapsClusteringMetadataAndVariances(t *testing.T) {
	tmplHash := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	j := &v1.Job{
		JobId:      "job-20261124-0001",
		Action:     "disk_usage",
		Status:     v1.JobStatus_JOB_STATUS_PARTIALLY_FAILED,
		TotalTasks: 12,
		Counts: []*v1.TaskCount{
			{Status: v1.TaskStatus_TASK_STATUS_FAILED, Count: 1},
			{Status: v1.TaskStatus_TASK_STATUS_SUCCEEDED, Count: 9},
			{Status: v1.TaskStatus_TASK_STATUS_OFFLINE, Count: 1},
			{Status: v1.TaskStatus_TASK_STATUS_RUNNING, Count: 1},
		},
	}
	summary := &v1.JobSummary{
		OutputTrust:          v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED,
		Grouping:             "normalized",
		Ranking:              "anomaly_first",
		TotalGroups:          4,
		OmittedGroups:        1,
		OmittedHosts:         2,
		FoldedNormalHosts:    6,
		UnfinishedHostsCount: 1,
		OfflineHosts:         []string{"off-1"},
		Groups: []*v1.OutputGroup{
			{
				Severity:      v1.GroupSeverity_GROUP_SEVERITY_FAILURE,
				AnomalyReason: "nonzero_exit",
				ExitCode:      proto.Int32(1),
				HostCount:     1,
				Hosts:         []string{"web-fail"},
				Stderr:        "disk error",
			},
			{
				Severity:       v1.GroupSeverity_GROUP_SEVERITY_ANOMALY,
				AnomalyReason:  "metric_outlier",
				ExitCode:       proto.Int32(0),
				HostCount:      8,
				Hosts:          []string{"web-01", "web-09"},
				Stdout:         "used=92% free=10GB",
				TemplateSha256: tmplHash,
				TemplateStdout: "used=<PCT> free=<SIZE>",
				TemplateStderr: "warn=<NUM>",
				Variances: []*v1.MetricVariance{
					{
						Label:        "used",
						Unit:         "%",
						Min:          20,
						P50:          25,
						P95:          88,
						Max:          92,
						MinHost:      "web-01",
						MaxHost:      "web-09",
						OutlierHosts: []string{"web-09"},
					},
					{
						Label:   "count",
						Min:     0,
						P50:     0,
						P95:     1,
						Max:     1,
						MinHost: "web-01",
						MaxHost: "web-02",
					},
					{
						// Non-finite variance must be skipped so JSON marshaling never fails.
						Label: "bad",
						Min:   math.NaN(),
						P50:   1,
						P95:   1,
						Max:   math.Inf(1),
					},
				},
			},
		},
	}

	result, err := nativeSummaryResult("owner", j, summary, "concise", "")
	if err != nil {
		t.Fatal(err)
	}
	m := nativeContent(t, result)
	if m["grouping"] != "normalized" || m["ranking"] != "anomaly_first" {
		t.Fatalf("grouping/ranking=%v", m)
	}
	if m["total_groups"] != float64(4) || m["omitted_groups"] != float64(1) || m["omitted_hosts"] != float64(2) || m["folded_normal_hosts"] != float64(6) || m["unfinished_hosts_count"] != float64(1) {
		t.Fatalf("conservation metadata=%v", m)
	}
	groups := m["groups"].([]any)
	if len(groups) != 2 {
		t.Fatalf("groups=%v", groups)
	}
	g0 := groups[0].(map[string]any)
	if g0["severity"] != "failure" || g0["anomaly_reason"] != "nonzero_exit" {
		t.Fatalf("g0=%v", g0)
	}
	if _, ok := g0["template_sha256"]; ok {
		t.Fatalf("unexpected template_sha256 in g0=%v", g0)
	}
	g1 := groups[1].(map[string]any)
	if g1["severity"] != "anomaly" || g1["anomaly_reason"] != "metric_outlier" {
		t.Fatalf("g1=%v", g1)
	}
	if g1["template_sha256"] != hex.EncodeToString(tmplHash) {
		t.Fatalf("template_sha256=%v", g1["template_sha256"])
	}
	if g1["template_stdout"] != "used=<PCT> free=<SIZE>" || g1["template_stderr"] != "warn=<NUM>" {
		t.Fatalf("templates=%v", g1)
	}
	variances := g1["variances"].([]any)
	if len(variances) != 2 {
		t.Fatalf("variances=%v", variances)
	}
	v0 := variances[0].(map[string]any)
	if v0["label"] != "used" || v0["unit"] != "%" || v0["min"] != float64(20) || v0["p50"] != float64(25) || v0["p95"] != float64(88) || v0["max"] != float64(92) || v0["min_host"] != "web-01" || v0["max_host"] != "web-09" {
		t.Fatalf("v0=%v", v0)
	}
	if len(v0["outlier_hosts"].([]any)) != 1 || v0["outlier_hosts"].([]any)[0] != "web-09" {
		t.Fatalf("v0 outliers=%v", v0)
	}
	v1Map := variances[1].(map[string]any)
	if _, hasUnit := v1Map["unit"]; hasUnit {
		t.Fatalf("empty unit should be omitted: %v", v1Map)
	}
	if _, hasOutliers := v1Map["outlier_hosts"]; hasOutliers {
		t.Fatalf("empty outlier_hosts should be omitted: %v", v1Map)
	}
}

func TestNativeSummaryCompressesLargeTemplatesAndVariancesWithin32KiB(t *testing.T) {
	j := &v1.Job{JobId: "job-20261124-0002", Status: v1.JobStatus_JOB_STATUS_SUCCEEDED, TotalTasks: 5}

	t.Run("halves shared preview and template budget", func(t *testing.T) {
		// Control characters expand 6x in JSON (\u0000), forcing halving across stdout+template.
		summary := &v1.JobSummary{
			OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED,
			Grouping:    "normalized",
			Groups: []*v1.OutputGroup{{
				Severity:       v1.GroupSeverity_GROUP_SEVERITY_NORMAL,
				AnomalyReason:  "majority_normal",
				HostCount:      5,
				Hosts:          []string{"h1", "h2"},
				Stdout:         strings.Repeat("\x00a", 1500),
				Stderr:         strings.Repeat("\x00b", 1500),
				TemplateStdout: strings.Repeat("\x00t", 1500),
				TemplateStderr: strings.Repeat("\x00e", 1500),
			}},
		}
		result, err := nativeSummaryResult("owner", j, summary, "concise", "")
		if err != nil {
			t.Fatal(err)
		}
		raw := mustJSON(t, result)
		if len(raw) > resultByteLimit {
			t.Fatalf("result size %d exceeds 32 KiB", len(raw))
		}
		m := nativeContent(t, result)
		if m["truncated"] != true {
			t.Fatalf("expected truncated=true, got %v", m)
		}
		g := m["groups"].([]any)[0].(map[string]any)
		if g["truncated"] != true {
			t.Fatalf("expected group truncated=true, got %v", g)
		}
	})

	t.Run("drops variances on final fallback when previewLimit zero still exceeds 32KiB", func(t *testing.T) {
		var hugeVariances []*v1.MetricVariance
		for i := range 200 {
			hugeVariances = append(hugeVariances, &v1.MetricVariance{
				Label:        fmt.Sprintf("metric_%03d_%s", i, strings.Repeat("x", 40)),
				Unit:         "bytes",
				Min:          1,
				P50:          2,
				P95:          3,
				Max:          4,
				MinHost:      "host-min",
				MaxHost:      "host-max",
				OutlierHosts: []string{"outlier-a", "outlier-b", "outlier-c"},
			})
		}
		summary := &v1.JobSummary{
			OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED,
			Grouping:    "normalized",
			Groups: []*v1.OutputGroup{{
				Severity:       v1.GroupSeverity_GROUP_SEVERITY_ANOMALY,
				AnomalyReason:  "metric_outlier",
				HostCount:      5,
				Hosts:          []string{"h1", "h2"},
				Stdout:         "ok",
				TemplateStdout: "ok <NUM>",
				Variances:      hugeVariances,
			}},
		}
		result, err := nativeSummaryResult("owner", j, summary, "concise", "")
		if err != nil {
			t.Fatal(err)
		}
		raw := mustJSON(t, result)
		if len(raw) > resultByteLimit {
			t.Fatalf("result size %d exceeds 32 KiB", len(raw))
		}
		m := nativeContent(t, result)
		if m["truncated"] != true {
			t.Fatalf("expected truncated=true, got %v", m)
		}
		g := m["groups"].([]any)[0].(map[string]any)
		if g["truncated"] != true {
			t.Fatalf("expected group truncated=true, got %v", g)
		}
		if _, hasVar := g["variances"]; hasVar {
			t.Fatalf("expected variances to be dropped on fallback, got %v", g)
		}
	})
}

func TestNativeSummaryCursorRejectsCrossGrouping(t *testing.T) {
	j := &v1.Job{JobId: "job-20261124-0003", Status: v1.JobStatus_JOB_STATUS_SUCCEEDED, TotalTasks: 20}
	makeSummary := func(grouping string) *v1.JobSummary {
		s := &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED, Grouping: grouping}
		for i := range 20 {
			s.Groups = append(s.Groups, &v1.OutputGroup{
				ExitCode:  proto.Int32(0),
				HostCount: 1,
				Hosts:     []string{fmt.Sprintf("host-%02d", i)},
				Stdout:    strings.Repeat("x", 3000),
			})
		}
		return s
	}
	exactFirst, err := nativeSummaryResult("owner", j, makeSummary("exact"), "concise", "")
	if err != nil {
		t.Fatal(err)
	}
	cursor, _ := nativeContent(t, exactFirst)["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("expected paginated summary")
	}
	if _, err := nativeSummaryResult("owner", j, makeSummary("normalized"), "concise", cursor); err == nil {
		t.Fatal("accepted cursor across grouping modes")
	}
}

type groupingCaptureJobs struct {
	JobService
	lastGet *v1.GetJobRequest
}

func (j *groupingCaptureJobs) GetJob(_ context.Context, r *v1.GetJobRequest) (*v1.GetJobResponse, error) {
	j.lastGet = r
	return &v1.GetJobResponse{
		Job: &v1.Job{JobId: r.JobId, Status: v1.JobStatus_JOB_STATUS_SUCCEEDED, TotalTasks: 1},
		Summary: &v1.JobSummary{
			OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED,
			Grouping:    r.Grouping,
			Groups:      []*v1.OutputGroup{{ExitCode: proto.Int32(0), HostCount: 1, Hosts: []string{"web-01"}, Stdout: "ok"}},
		},
	}, nil
}

type stubRequest struct {
	actor string
}

func (r stubRequest) Identity() *reqctx.Identity {
	return &reqctx.Identity{Subject: authz.Subject{ID: r.actor, Kind: "service_account"}}
}
func (r stubRequest) SourceIP() string       { return "127.0.0.1" }
func (r stubRequest) PolicyVersion() uint64  { return 1 }
func (r stubRequest) MatchedRules() []string { return nil }
func (r stubRequest) Fork() reqctx.Request   { return r }

func TestGroupingArgumentsForActionAndJobsGet(t *testing.T) {
	// Action tool accepts exact and normalized, rejects invalid/null, defaults to "".
	base := `{"targets":{"hosts":["web-01"]},"params":{"mode":"recent"},"reason":"check"}`
	req, _, err := actionRequest(testAction(), json.RawMessage(base), job.DefaultConfig())
	if err != nil || req.Grouping != "" {
		t.Fatalf("default grouping=%q err=%v", req.Grouping, err)
	}
	for _, mode := range []string{"exact", "normalized"} {
		raw := strings.Replace(base, `"reason":"check"`, `"reason":"check","grouping":"`+mode+`"`, 1)
		req, _, err := actionRequest(testAction(), json.RawMessage(raw), job.DefaultConfig())
		if err != nil || req.Grouping != mode {
			t.Fatalf("mode=%s grouping=%q err=%v", mode, req.Grouping, err)
		}
	}
	for _, bad := range []string{`""`, `"fuzzy"`, `null`, `123`} {
		raw := strings.Replace(base, `"reason":"check"`, `"reason":"check","grouping":`+bad, 1)
		if _, _, err := actionRequest(testAction(), json.RawMessage(raw), job.DefaultConfig()); err == nil {
			t.Fatalf("accepted invalid action grouping %s", bad)
		}
	}

	// jobs_get rejects host + grouping, rejects invalid grouping, forwards valid grouping.
	ctx := reqctx.With(context.Background(), stubRequest{actor: "owner"})
	jobs := &groupingCaptureJobs{}
	svc := &Service{jobs: jobs, config: Config{Jobs: job.DefaultConfig()}}

	_, err = svc.getJob(ctx, &sdk.CallToolRequest{Params: &sdk.CallToolParamsRaw{
		Name:      "jobs_get",
		Arguments: json.RawMessage(`{"job_id":"job-20261124-0001","host":"web-01","grouping":"normalized"}`),
	}}, &callState{})
	if connect.CodeOf(err) != connect.CodeInvalidArgument || err.Error() != "invalid_argument: grouping applies to job summaries, not host output" {
		t.Fatalf("host+grouping err=%v", err)
	}
	if jobs.lastGet != nil {
		t.Fatal("host+grouping reached backend")
	}

	for _, bad := range []string{`""`, `"other"`, `null`, `1`} {
		_, err = svc.getJob(ctx, &sdk.CallToolRequest{Params: &sdk.CallToolParamsRaw{
			Name:      "jobs_get",
			Arguments: json.RawMessage(`{"job_id":"job-20261124-0001","grouping":` + bad + `}`),
		}}, &callState{})
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("bad grouping %s err=%v", bad, err)
		}
	}

	res, err := svc.getJob(ctx, &sdk.CallToolRequest{Params: &sdk.CallToolParamsRaw{
		Name:      "jobs_get",
		Arguments: json.RawMessage(`{"job_id":"job-20261124-0001","grouping":"normalized"}`),
	}}, &callState{})
	if err != nil || res == nil || jobs.lastGet == nil || jobs.lastGet.Grouping != "normalized" {
		t.Fatalf("valid grouping res=%v err=%v lastGet=%+v", res, err, jobs.lastGet)
	}
}
