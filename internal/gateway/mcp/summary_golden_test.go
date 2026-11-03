package mcp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"google.golang.org/protobuf/proto"
)

type nativeSummaryGoldenCase struct {
	name    string
	scope   string
	job     *v1.Job
	summary *v1.JobSummary
	format  string
}

func nativeSummaryGoldenCases() []nativeSummaryGoldenCase {
	untrusted := v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED
	job := func() *v1.Job {
		return &v1.Job{JobId: "job-20261014-0001", Action: "logs_read", Status: v1.JobStatus_JOB_STATUS_SUCCEEDED, TotalTasks: 7, Counts: []*v1.TaskCount{{Status: v1.TaskStatus_TASK_STATUS_SUCCEEDED, Count: 5}, {Status: v1.TaskStatus_TASK_STATUS_FAILED, Count: 2}}}
	}
	mixed := func() *v1.JobSummary {
		return &v1.JobSummary{OutputTrust: untrusted, Truncated: true, OfflineHosts: []string{"off-1", "off-2"}, Groups: []*v1.OutputGroup{
			{ExitCode: proto.Int32(0), HostCount: 3, Hosts: []string{"a", "b", "c"}, Stdout: "ok\n"},
			{ExitCode: proto.Int32(2), HostCount: 2, Hosts: []string{"d", "e"}, Stdout: "partial", Stderr: "boom \x00 \"quoted\" <tag>\n", Truncated: true},
			{HostCount: 1, Hosts: []string{"f"}, Stderr: "no exit code\xff"},
			{HostCount: 1},
		}}
	}
	many := func(n, size int) *v1.JobSummary {
		s := &v1.JobSummary{OutputTrust: untrusted, OfflineHosts: []string{"offline-host"}}
		for i := range n {
			s.Groups = append(s.Groups, &v1.OutputGroup{ExitCode: proto.Int32(int32(i)), HostCount: 2, Hosts: []string{fmt.Sprintf("host-%02d", i), fmt.Sprintf("peer-%02d", i)}, Stdout: strings.Repeat("a\"", size), Stderr: strings.Repeat("\x01e", size)})
		}
		return s
	}
	return []nativeSummaryGoldenCase{
		{"empty scope", "", job(), mixed(), "concise"},
		{"nil job", "s", nil, mixed(), "concise"},
		{"nil summary", "s", job(), nil, "concise"},
		{"trust unspecified", "s", job(), &v1.JobSummary{}, "concise"},
		{"bad format", "s", job(), mixed(), "verbose"},
		{"empty format", "s", job(), mixed(), ""},
		{"nil group", "s", job(), &v1.JobSummary{OutputTrust: untrusted, Groups: []*v1.OutputGroup{{HostCount: 1}, nil}}, "concise"},
		{"no groups concise", "s", job(), &v1.JobSummary{OutputTrust: untrusted}, "concise"},
		{"no groups detailed offline", "s", job(), &v1.JobSummary{OutputTrust: untrusted, OfflineHosts: []string{"x", "y"}, Truncated: true}, "detailed"},
		{"mixed concise", "s", job(), mixed(), "concise"},
		{"mixed detailed", "s", job(), mixed(), "detailed"},
		{"many concise", "s", job(), many(40, 1500), "concise"},
		{"many detailed", "s", job(), many(40, 1500), "detailed"},
		{"many small concise", "s", job(), many(30, 20), "concise"},
		{"huge previews", "s", job(), many(6, 20000), "concise"},
		{"huge hostnames", "s", job(), &v1.JobSummary{OutputTrust: untrusted, Groups: []*v1.OutputGroup{{HostCount: 2, Hosts: []string{strings.Repeat("h", 20000), strings.Repeat("i", 20000)}}}}, "concise"},
		{"huge metadata", "s", &v1.Job{JobId: strings.Repeat("j", 40000)}, &v1.JobSummary{OutputTrust: untrusted}, "concise"},
		{"huge metadata with groups", "s", &v1.Job{JobId: strings.Repeat("j", 40000)}, mixed(), "concise"},
	}
}

func nativeSummaryGoldenPage(result *ToolResult, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	data, merr := json.Marshal(result)
	if merr != nil {
		return "marshal error: " + merr.Error()
	}
	if len(data) > 2000 {
		return fmt.Sprintf("len=%d sha256=%x", len(data), sha256.Sum256(data))
	}
	return string(data)
}

func nativeSummaryGoldenRun(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, tc := range nativeSummaryGoldenCases() {
		cursor := ""
		for page := 0; page < 200; page++ {
			result, err := nativeSummaryResult(tc.scope, tc.job, tc.summary, tc.format, cursor)
			out[tc.name] = append(out[tc.name], nativeSummaryGoldenPage(result, err))
			if err != nil {
				break
			}
			cursor, _ = nativeContent(t, result)["next_cursor"].(string)
			if cursor == "" {
				break
			}
		}
	}
	// Cursor validation: take a valid cursor and alter it.
	tc := nativeSummaryGoldenCases()[12]
	first, err := nativeSummaryResult(tc.scope, tc.job, tc.summary, "detailed", "")
	if err != nil {
		t.Fatal(err)
	}
	valid, _ := nativeContent(t, first)["next_cursor"].(string)
	if valid == "" {
		t.Fatal("fixture has a single page")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(valid)
	if err != nil {
		t.Fatal(err)
	}
	var c summaryCursor
	if err := json.Unmarshal(decoded, &c); err != nil {
		t.Fatal(err)
	}
	enc := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	for name, cursor := range map[string]string{
		"not base64":        "!!!",
		"padded":            valid + "=",
		"too long":          strings.Repeat("A", 257),
		"not json":          base64.RawURLEncoding.EncodeToString([]byte("nope")),
		"offset zero":       enc(summaryCursor{Snapshot: c.Snapshot, Offset: 0}),
		"offset negative":   enc(summaryCursor{Snapshot: c.Snapshot, Offset: -1}),
		"offset at end":     enc(summaryCursor{Snapshot: c.Snapshot, Offset: 100}),
		"wrong snapshot":    enc(summaryCursor{Snapshot: "x", Offset: c.Offset}),
		"extra member":      enc(map[string]any{"snapshot": c.Snapshot, "offset": c.Offset, "x": 1}),
		"duplicate member":  base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"snapshot":%q,"offset":%d,"offset":%d}`, c.Snapshot, c.Offset, c.Offset))),
		"offset wrong type": base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"snapshot":%q,"offset":"1"}`, c.Snapshot))),
		"valid":             valid,
	} {
		result, err := nativeSummaryResult(tc.scope, tc.job, tc.summary, "detailed", cursor)
		out["cursor "+name] = []string{nativeSummaryGoldenPage(result, err)}
	}
	return out
}

func TestNativeSummaryGolden(t *testing.T) {
	got, err := json.MarshalIndent(nativeSummaryGoldenRun(t), "", " ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := "testdata/native_summary_golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("nativeSummaryResult output differs from %s; set UPDATE_GOLDEN=1 only for an intended behavior change", path)
	}
}
