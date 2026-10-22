package job

import (
	"crypto/sha256"
	"testing"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestGatewayValidationUsesSignedLimitsAndRemotePaths(t *testing.T) {
	a := catalog.Action{Name: "read", BatchSize: 3, MaxFailures: new(1), Filters: []string{"tail", "count"}, Params: map[string]params.Definition{"path": {Type: params.Path, Description: "remote path", AllowedRoots: []string{"/remote"}}}}
	r := &v1.RunJobRequest{Reason: "test", Params: &v1.Parameters{Json: []byte(`{"path":"/remote/exists-only-on-agent"}`)}}
	batch, failures, err := prepare(a, r, DefaultConfig())
	if err != nil || batch != 3 || failures != 1 {
		t.Fatalf("prepare=%d %d %v", batch, failures, err)
	}
	r.BatchSize = proto.Uint32(4)
	if _, _, err := prepare(a, r, DefaultConfig()); err == nil {
		t.Fatal("expanded signed batch size")
	}
	r.BatchSize = nil
	r.MaxFailures = proto.Uint32(2)
	if _, _, err := prepare(a, r, DefaultConfig()); err == nil {
		t.Fatal("expanded signed max failures")
	}
	r.MaxFailures = nil
	r.Filters = &v1.OutputFilters{Tail: proto.Uint32(1), Count: proto.Bool(false)}
	if _, _, err := prepare(a, r, DefaultConfig()); err == nil {
		t.Fatal("accepted conflicting filter presence")
	}
	r.Filters = nil
	r.Params.Json = []byte(`{"path":"a","path":"b"}`)
	if _, _, err := prepare(a, r, DefaultConfig()); err == nil {
		t.Fatal("accepted duplicate parameter")
	}
}

func TestOutputResultRequiresEOFAndCorrectHash(t *testing.T) {
	sum := sha256.Sum256([]byte("safe"))
	empty := sha256.Sum256(nil)
	out := &taskOutput{Streams: map[streamKey]*streamOutput{{-1, v1.OutputStream_OUTPUT_STREAM_STDOUT}: {Data: []byte("safe"), EOF: true}, {-1, v1.OutputStream_OUTPUT_STREAM_STDERR}: {EOF: true}}}
	r := &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_SUCCEEDED, ExitCode: proto.Int32(0), Duration: durationpb.New(0), Stdout: &v1.OutputMetadata{SizeBytes: 4, Sha256: sum[:]}, Stderr: &v1.OutputMetadata{Sha256: empty[:]}}
	if err := validateResult(r, out, -1, false); err != nil {
		t.Fatal(err)
	}
	r.Stdout.Sha256 = empty[:]
	if err := validateResult(r, out, -1, false); err == nil {
		t.Fatal("accepted incorrect output hash")
	}
	r.Stdout.Sha256 = sum[:]
	out.Streams[streamKey{-1, v1.OutputStream_OUTPUT_STREAM_STDERR}].EOF = false
	if err := validateResult(r, out, -1, false); err == nil {
		t.Fatal("accepted result before stderr EOF")
	}
}

func TestSelectorKeepsConflictingConditions(t *testing.T) {
	hosts := []host{{Name: "prod", Labels: map[string]string{"env": "prod"}, Reported: map[string]string{"os": "linux"}}}
	_, err := selectTargets(hosts, &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "env=test,env=prod"}})
	if err == nil {
		t.Fatal("discarded conflicting condition")
	}
	selected, err := selectTargets(hosts, &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "reported.os=linux"}})
	if err != nil || len(selected) != 1 {
		t.Fatalf("reported label selection=%v %v", selected, err)
	}
}

func TestUnsupportedWithoutProcessMetadata(t *testing.T) {
	r := &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_UNSUPPORTED, Reason: "ACTION_UNSUPPORTED"}
	if err := validateResult(r, &taskOutput{Streams: map[streamKey]*streamOutput{}}, -1, false); err != nil {
		t.Fatalf("P3 pre-start unsupported result rejected: %v", err)
	}
	r.Reason = "host output password=secret"
	if err := validateResult(r, &taskOutput{Streams: map[streamKey]*streamOutput{}}, -1, false); err == nil {
		t.Fatal("accepted raw host text in metadata reason")
	}
}
