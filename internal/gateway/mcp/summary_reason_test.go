package mcp

import (
	"testing"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"google.golang.org/protobuf/proto"
)

func TestNativeSummaryReasonAndHint(t *testing.T) {
	j := &v1.Job{JobId: "job-20261023-0001", Status: v1.JobStatus_JOB_STATUS_FAILED, TotalTasks: 4}
	summary := &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED, Groups: []*v1.OutputGroup{
		{ExitCode: proto.Int32(1), HostCount: 1, Hosts: []string{"a"}, Reason: "SOURCE_NO_FILES"},
		{ExitCode: proto.Int32(1), HostCount: 1, Hosts: []string{"b"}, Reason: "PATH_OUTSIDE_ROOTS"},
		{ExitCode: proto.Int32(1), HostCount: 1, Hosts: []string{"c"}, Reason: "EXECUTION_FAILED"},
		{ExitCode: proto.Int32(0), HostCount: 1, Hosts: []string{"d"}},
	}}
	result, err := nativeSummaryResult("owner", j, summary, "concise", "")
	if err != nil {
		t.Fatal(err)
	}
	groups := nativeContent(t, result)["groups"].([]any)
	if len(groups) != 4 {
		t.Fatalf("groups=%v", groups)
	}
	for i, want := range []struct {
		reason string
		hint   bool
	}{{"SOURCE_NO_FILES", true}, {"PATH_OUTSIDE_ROOTS", false}, {"EXECUTION_FAILED", false}, {"", false}} {
		g := groups[i].(map[string]any)
		reason, hasReason := g["reason"]
		hint, hasHint := g["hint"]
		if (want.reason == "") == hasReason || (hasReason && reason != want.reason) || hasHint != want.hint || (hasHint && hint == "") {
			t.Errorf("group %d=%v; want reason %q hint %v", i, g, want.reason, want.hint)
		}
	}
}

func TestReasonHintsCoverDesignTable(t *testing.T) {
	j := &v1.Job{JobId: "job-20261023-0001", Status: v1.JobStatus_JOB_STATUS_FAILED, TotalTasks: 1}
	for _, code := range []string{"SOURCE_UNKNOWN", "SOURCE_NO_FILES", "SOURCE_UNSUPPORTED", "SOURCE_UNAVAILABLE", "WINDOW_TOO_LARGE", "TIME_INVALID", "TIMESTAMP_UNPARSED", "PATTERN_INVALID", "CURSOR_INVALID", "CURSOR_EXPIRED"} {
		summary := &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED, Groups: []*v1.OutputGroup{{ExitCode: proto.Int32(1), HostCount: 1, Hosts: []string{"a"}, Reason: code}}}
		result, err := nativeSummaryResult("owner", j, summary, "concise", "")
		if err != nil {
			t.Fatal(err)
		}
		g := nativeContent(t, result)["groups"].([]any)[0].(map[string]any)
		if hint, _ := g["hint"].(string); g["reason"] != code || hint == "" {
			t.Errorf("%s: group=%v", code, g)
		}
	}
}
