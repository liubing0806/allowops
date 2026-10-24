package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"google.golang.org/protobuf/proto"
)

func nativeContent(t *testing.T, r *ToolResult) map[string]any {
	t.Helper()
	var result map[string]any
	data, err := json.Marshal(r.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNativeSummaryMappingPaginationAndBinding(t *testing.T) {
	j := &v1.Job{JobId: "job-20261014-0001", Status: v1.JobStatus_JOB_STATUS_SUCCEEDED, TotalTasks: 60, Counts: []*v1.TaskCount{{Status: v1.TaskStatus_TASK_STATUS_SUCCEEDED, Count: 60}}}
	summary := &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED, Truncated: true, OfflineHosts: []string{"offline-host"}}
	for i := range 60 {
		summary.Groups = append(summary.Groups, &v1.OutputGroup{ExitCode: proto.Int32(int32(i)), HostCount: 1, Hosts: []string{fmt.Sprintf("host-%02d", i)}, Stdout: strings.Repeat("a", 3500)})
	}
	cursor := ""
	seen := map[string]bool{}
	offline := 0
	for {
		result, err := nativeSummaryResult("owner", j, summary, "detailed", cursor)
		if err != nil {
			t.Fatal(err)
		}
		if len(mustJSON(t, result)) > resultByteLimit {
			t.Fatal("MCP JSON exceeds 32KB")
		}
		m := nativeContent(t, result)
		if m["truncated"] != true || m["counts"].(map[string]any)["succeeded"] != float64(60) || m["output_trust"] != "untrusted" {
			t.Fatalf("metadata=%v", m)
		}
		for _, g := range m["groups"].([]any) {
			for _, name := range g.(map[string]any)["hosts"].([]any) {
				host := name.(string)
				if seen[host] {
					t.Fatal("duplicate host")
				}
				seen[host] = true
			}
		}
		offline += len(m["offline_hosts"].([]any))
		next, _ := m["next_cursor"].(string)
		if next == "" {
			break
		}
		if next == cursor {
			t.Fatal("cursor stalled")
		}
		cursor = next
		if _, err := nativeSummaryResult("other", j, summary, "detailed", cursor); err == nil {
			t.Fatal("cursor crossed identity")
		}
		if _, err := nativeSummaryResult("owner", j, summary, "concise", cursor); err == nil {
			t.Fatal("cursor crossed format")
		}
		changed := proto.Clone(summary).(*v1.JobSummary)
		changed.Groups[0].Stdout = "changed"
		if _, err := nativeSummaryResult("owner", j, changed, "detailed", cursor); err == nil {
			t.Fatal("cursor crossed snapshot")
		}
	}
	if len(seen) != 60 || offline != 1 {
		t.Fatalf("hosts=%d offline=%d", len(seen), offline)
	}
}

func TestNativeSummaryKeepsBackendGroupingAndFitsEscapedPreview(t *testing.T) {
	j := &v1.Job{JobId: "job-20261014-0002", TotalTasks: 3}
	summary := &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED, Groups: []*v1.OutputGroup{{HostCount: 3, Hosts: []string{"a", "b", "c"}, Stdout: strings.Repeat("\x00", 4096)}}}
	result, err := nativeSummaryResult("owner", j, summary, "concise", "")
	if err != nil {
		t.Fatal(err)
	}
	m := nativeContent(t, result)
	groups := m["groups"].([]any)
	g := groups[0].(map[string]any)
	if len(groups) != 1 || g["host_count"] != float64(3) || len(g["sample_hosts"].([]any)) != 2 || g["truncated"] != true || len(mustJSON(t, result)) > resultByteLimit {
		t.Fatalf("mapped group=%v", g)
	}
	if len(summary.Groups[0].Stdout) != 4096 || summary.Groups[0].Truncated {
		t.Fatal("modified backend summary")
	}
}

func TestNativeSummaryDetailedLargeGroupHostsContinue(t *testing.T) {
	j := &v1.Job{JobId: "job-20261014-0003", TotalTasks: 260}
	g := &v1.OutputGroup{HostCount: 260}
	for i := range 260 {
		g.Hosts = append(g.Hosts, strings.Repeat("h", 246)+fmt.Sprintf("-%04d", i))
	}
	summary := &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED, Groups: []*v1.OutputGroup{g}}
	cursor := ""
	seen := map[string]bool{}
	for {
		result, err := nativeSummaryResult("owner", j, summary, "detailed", cursor)
		if err != nil {
			t.Fatal(err)
		}
		if len(mustJSON(t, result)) > resultByteLimit {
			t.Fatal("large group exceeded budget")
		}
		m := nativeContent(t, result)
		group := m["groups"].([]any)[0].(map[string]any)
		if group["host_count"] != float64(260) {
			t.Fatal("changed native group count")
		}
		for _, host := range group["hosts"].([]any) {
			name := host.(string)
			if seen[name] {
				t.Fatal("duplicate group host")
			}
			seen[name] = true
		}
		cursor, _ = m["next_cursor"].(string)
		if cursor == "" {
			break
		}
	}
	if len(seen) != 260 {
		t.Fatalf("hosts=%d", len(seen))
	}
}
