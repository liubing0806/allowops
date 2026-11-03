package job

import (
	"bytes"
	"testing"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"google.golang.org/protobuf/proto"
)

func TestGroupPreviewsSplitsByReason(t *testing.T) {
	hash := bytes.Repeat([]byte{1}, 32)
	task := func(host, reason string) Preview {
		return Preview{Task: &v1.Task{Hostname: host, Result: &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_FAILED, ExitCode: proto.Int32(1), Reason: reason}}, StdoutHash: hash, StderrHash: hash}
	}
	result := &v1.JobSummary{}
	groupPreviews(result, []Preview{task("a", "PATH_OUTSIDE_ROOTS"), task("b", "EXECUTION_FAILED"), task("c", "PATH_OUTSIDE_ROOTS"), task("d", "")}, "detailed")
	got := map[string]uint64{}
	for _, g := range result.Groups {
		got[g.Reason] = g.HostCount
	}
	if len(result.Groups) != 3 || got["PATH_OUTSIDE_ROOTS"] != 2 || got["EXECUTION_FAILED"] != 1 || got[""] != 1 {
		t.Fatalf("groups=%v", result.Groups)
	}
}
