package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type diffCaptureGateway struct {
	rpc.UnimplementedJobServiceHandler
	mu       sync.Mutex
	lastRun  *v1.RunJobRequest
	lastGet  *v1.GetJobRequest
	lastDiff *v1.DiffJobsRequest
}

func (g *diffCaptureGateway) RunJob(_ context.Context, r *connect.Request[v1.RunJobRequest]) (*connect.Response[v1.RunJobResponse], error) {
	g.mu.Lock()
	g.lastRun = proto.Clone(r.Msg).(*v1.RunJobRequest)
	g.mu.Unlock()
	return connect.NewResponse(&v1.RunJobResponse{
		Job: &v1.Job{JobId: "job-20261124-0001", Action: r.Msg.Action, Status: v1.JobStatus_JOB_STATUS_SUCCEEDED, TotalTasks: 2},
		Summary: &v1.JobSummary{
			OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED,
			Grouping:    r.Msg.Grouping,
			Ranking:     "anomaly_first",
			TotalGroups: 1,
			Groups: []*v1.OutputGroup{{
				Severity:      v1.GroupSeverity_GROUP_SEVERITY_NORMAL,
				AnomalyReason: "majority_normal",
				ExitCode:      proto.Int32(0),
				HostCount:     2,
				Hosts:         []string{"web-01", "web-02"},
				Stdout:        "ok",
			}},
		},
	}), nil
}

func (g *diffCaptureGateway) GetJob(_ context.Context, r *connect.Request[v1.GetJobRequest]) (*connect.Response[v1.GetJobResponse], error) {
	g.mu.Lock()
	g.lastGet = proto.Clone(r.Msg).(*v1.GetJobRequest)
	g.mu.Unlock()
	return connect.NewResponse(&v1.GetJobResponse{
		Job: &v1.Job{JobId: r.Msg.JobId, Action: "disk_usage", Status: v1.JobStatus_JOB_STATUS_PARTIALLY_FAILED, TotalTasks: 3},
		Summary: &v1.JobSummary{
			OutputTrust:       v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED,
			Grouping:          r.Msg.Grouping,
			Ranking:           "anomaly_first",
			TotalGroups:       2,
			FoldedNormalHosts: 1,
			Groups: []*v1.OutputGroup{
				{
					Severity:      v1.GroupSeverity_GROUP_SEVERITY_FAILURE,
					AnomalyReason: "nonzero_exit",
					ExitCode:      proto.Int32(1),
					HostCount:     1,
					Hosts:         []string{"web-03"},
					Stderr:        "disk full",
				},
				{
					Severity:      v1.GroupSeverity_GROUP_SEVERITY_NORMAL,
					AnomalyReason: "majority_normal",
					ExitCode:      proto.Int32(0),
					HostCount:     2,
					Hosts:         []string{"web-01"},
					Stdout:        "ok",
				},
			},
		},
	}), nil
}

func (g *diffCaptureGateway) DiffJobs(_ context.Context, r *connect.Request[v1.DiffJobsRequest]) (*connect.Response[v1.DiffJobsResponse], error) {
	g.mu.Lock()
	g.lastDiff = proto.Clone(r.Msg).(*v1.DiffJobsRequest)
	g.mu.Unlock()
	pct := 400.0
	return connect.NewResponse(&v1.DiffJobsResponse{
		BaseJob:   &v1.Job{JobId: r.Msg.BaseJobId, Action: "disk_usage", Status: v1.JobStatus_JOB_STATUS_SUCCEEDED, TotalTasks: 3},
		TargetJob: &v1.Job{JobId: r.Msg.TargetJobId, Action: "disk_usage", Status: v1.JobStatus_JOB_STATUS_PARTIALLY_FAILED, TotalTasks: 4},
		Diff: &v1.JobDiff{
			OutputTrust:             v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED,
			Grouping:                r.Msg.Grouping,
			ActionDefinitionChanged: true,
			PreviewTruncated:        true,
			UnchangedHostsCount:     1,
			AddedHostsCount:         1,
			AddedHosts:              []string{"web-04"},
			RemovedHostsCount:       1,
			RemovedHosts:            []string{"web-00"},
			ReplacedHostsCount:      1,
			ReplacedHosts:           []string{"web-02"},
			StatusTransitions: []*v1.StatusTransition{{
				FromStatus:   v1.TaskStatus_TASK_STATUS_SUCCEEDED,
				ToStatus:     v1.TaskStatus_TASK_STATUS_FAILED,
				FromExitCode: proto.Int32(0),
				ToExitCode:   proto.Int32(1),
				Reason:       "EXECUTION_FAILED",
				HostCount:    1,
				Hosts:        []string{"web-03"},
				Degradation:  true,
			}},
			TotalPatternChanges:   2,
			OmittedPatternChanges: 1,
			PatternChanges: []*v1.PatternChange{{
				BaseSeverity:   v1.GroupSeverity_GROUP_SEVERITY_NORMAL,
				TargetSeverity: v1.GroupSeverity_GROUP_SEVERITY_FAILURE,
				HostCount:      1,
				Hosts:          []string{"web-03"},
				RemovedLines:   []string{"status=ok", "\x1b[31mold\x00"},
				AddedLines:     []string{"status=error", "\x1b[2Jbad\u009b2J"},
				DiffComputed:   true,
			}},
			MetricDrifts: []*v1.MetricDrift{
				{
					Label:          "latency",
					Unit:           "ms",
					BaseP50:        10,
					TargetP50:      50,
					BaseMax:        10,
					TargetMax:      50,
					MaxDelta:       40,
					MaxDeltaBase:   10,
					MaxDeltaTarget: 50,
					MaxDeltaPct:    &pct,
					MaxHost:        "web-01",
					AffectedHosts:  1,
					HostCount:      1,
				},
				{
					Label:          "errors",
					BaseP50:        0,
					TargetP50:      3,
					BaseMax:        0,
					TargetMax:      3,
					MaxDelta:       3,
					MaxDeltaBase:   0,
					MaxDeltaTarget: 3,
					MaxHost:        "web-03",
					AffectedHosts:  1,
					HostCount:      1,
				},
			},
		},
	}), nil
}

func prepareDiffCaptureGateway(t *testing.T) *diffCaptureGateway {
	t.Helper()
	gw := &diffCaptureGateway{}
	_, handler := rpc.NewJobServiceHandler(gw)
	s := httptest.NewTLSServer(handler)
	t.Cleanup(s.Close)
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveCredentials(credentials{Gateway: s.URL, CAFile: ca, Token: "synthetic-token", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return gw
}

func TestRunAndJobsGetGroupingFlag(t *testing.T) {
	gw := prepareDiffCaptureGateway(t)

	// Invalid --grouping fails before calling gateway.
	for _, fn := range []func() error{
		func() error {
			cmd := NewRunCmd()
			cmd.SetArgs([]string{"disk_usage", "--hosts", "web-01", "--reason", "check", "--grouping", "bad"})
			return cmd.Execute()
		},
		func() error {
			cmd := NewJobsCmd()
			cmd.SetArgs([]string{"get", "job-20261124-0001", "--grouping", "bad"})
			return cmd.Execute()
		},
	} {
		if err := fn(); err == nil || !strings.Contains(err.Error(), "--grouping") {
			t.Fatalf("expected --grouping validation error, got %v", err)
		}
	}
	if gw.lastRun != nil || gw.lastGet != nil {
		t.Fatal("invalid --grouping reached gateway")
	}

	// Valid run --grouping normalized.
	runCmd := NewRunCmd()
	var runOut bytes.Buffer
	runCmd.SetOut(&runOut)
	runCmd.SetArgs([]string{"disk_usage", "--hosts", "web-01", "--reason", "check", "--grouping", "normalized"})
	if err := runCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if gw.lastRun == nil || gw.lastRun.Grouping != "normalized" {
		t.Fatalf("run grouping=%+v", gw.lastRun)
	}
	if !strings.Contains(runOut.String(), "SEVERITY") || !strings.Contains(runOut.String(), "grouping=normalized") {
		t.Fatalf("run table=%q", runOut.String())
	}

	// Valid jobs get --grouping normalized.
	getCmd := NewJobsCmd()
	var getOut bytes.Buffer
	getCmd.SetOut(&getOut)
	getCmd.SetArgs([]string{"get", "job-20261124-0001", "--grouping", "normalized"})
	if err := getCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if gw.lastGet == nil || gw.lastGet.Grouping != "normalized" {
		t.Fatalf("get grouping=%+v", gw.lastGet)
	}
	if !strings.Contains(getOut.String(), "failure") || !strings.Contains(getOut.String(), "nonzero_exit") {
		t.Fatalf("get table missing severity/anomaly=%q", getOut.String())
	}
}

func TestJobsDiffCommandValidationTableAndJSON(t *testing.T) {
	gw := prepareDiffCaptureGateway(t)

	// Wrong arg count and invalid grouping rejected locally.
	for _, args := range [][]string{
		{"diff"},
		{"diff", "job-20261124-0001"},
		{"diff", "job-20261124-0001", "job-20261124-0002", "extra"},
		{"diff", "job-20261124-0001", "job-20261124-0002", "--grouping", "invalid"},
	} {
		cmd := NewJobsCmd()
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("args=%v unexpectedly succeeded", args)
		}
	}
	if gw.lastDiff != nil {
		t.Fatal("invalid diff args reached gateway")
	}

	// Default flags (--grouping=normalized, --only-changed=true) + table output.
	tableCmd := NewJobsCmd()
	var tableOut bytes.Buffer
	tableCmd.SetOut(&tableOut)
	tableCmd.SetArgs([]string{"diff", "job-20261124-0001", "job-20261124-0002"})
	if err := tableCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if gw.lastDiff == nil || gw.lastDiff.BaseJobId != "job-20261124-0001" || gw.lastDiff.TargetJobId != "job-20261124-0002" || gw.lastDiff.Grouping != "normalized" || gw.lastDiff.OnlyChanged == nil || !*gw.lastDiff.OnlyChanged {
		t.Fatalf("default diff request=%+v", gw.lastDiff)
	}
	text := tableOut.String()
	for _, want := range []string{
		"job-20261124-0001", "job-20261124-0002", "disk_usage", "normalized",
		"action definition digest changed",
		"HOST SET CHANGES", "web-04", "web-00", "web-02",
		"STATUS TRANSITIONS", "succeeded(exit=0)", "failed(exit=1)", "EXECUTION_FAILED",
		"PATTERN CHANGES", `- "status=ok"`, `+ "status=error"`, `- "\x1b[31mold\x00"`, `+ "\x1b[2Jbad\u009b2J"`, "1 additional pattern changes omitted",
		"METRIC DRIFTS", "latency", "10ms", "50ms", "+40ms (+400.0%)", "errors",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("table output missing %q:\n%s", want, text)
		}
	}
	if strings.ContainsAny(text, "\x1b\x00") || strings.Contains(text, "\u009b") {
		t.Fatalf("table output leaked raw terminal control sequences:\n%q", text)
	}

	// Explicit --grouping=exact --only-changed=false --json (protojson UseProtoNames).
	jsonCmd := NewJobsCmd()
	var jsonOut bytes.Buffer
	jsonCmd.SetOut(&jsonOut)
	jsonCmd.SetArgs([]string{"diff", "job-20261124-0001", "job-20261124-0002", "--grouping", "exact", "--only-changed=false", "--json"})
	if err := jsonCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if gw.lastDiff.Grouping != "exact" || gw.lastDiff.OnlyChanged == nil || *gw.lastDiff.OnlyChanged {
		t.Fatalf("explicit diff request=%+v", gw.lastDiff)
	}
	var rawMap map[string]any
	if err := json.Unmarshal(jsonOut.Bytes(), &rawMap); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, jsonOut.String())
	}
	if _, ok := rawMap["base_job"]; !ok {
		t.Fatalf("expected snake_case protojson key base_job: %s", jsonOut.String())
	}
	var decoded v1.DiffJobsResponse
	if err := protojson.Unmarshal(jsonOut.Bytes(), &decoded); err != nil {
		t.Fatalf("protojson unmarshal: %v", err)
	}
	if decoded.GetDiff().GetGrouping() != "exact" || len(decoded.GetDiff().GetMetricDrifts()) != 2 {
		t.Fatalf("decoded diff=%+v", decoded.GetDiff())
	}
}
