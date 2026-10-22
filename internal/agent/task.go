package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
	"github.com/liubing0806/allowops/internal/executor"
	"github.com/liubing0806/allowops/internal/params"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (a *Agent) execute(ctx context.Context, task *v1.TaskAssignment, chunkSize int, send func(*v1.ConnectRequest, bool) error) {
	fail := func(status v1.TaskStatus, reason string) {
		_ = send(completed(task, &v1.ExecutionResult{Status: status, Reason: reason}), false)
	}
	for _, message := range []proto.Message{task, task.GetCatalog(), task.GetParams(), task.GetFilters()} {
		if message.ProtoReflect().IsValid() && len(message.ProtoReflect().GetUnknown()) > 0 {
			fail(v1.TaskStatus_TASK_STATUS_UNSUPPORTED, "UNSUPPORTED_TASK_FEATURE")
			return
		}
	}
	ref := task.Catalog
	if ref == nil || ref.CatalogId == "" || ref.Version == 0 || ref.Version > 1<<63-1 {
		fail(v1.TaskStatus_TASK_STATUS_UNSUPPORTED, "CATALOG_UNAVAILABLE")
		return
	}
	p, err := a.catalogs.cache.Load(ref.CatalogId, int64(ref.Version))
	if err != nil {
		fail(v1.TaskStatus_TASK_STATUS_UNSUPPORTED, "CATALOG_UNAVAILABLE")
		return
	}
	action, ok := p.Actions[task.Action]
	if !ok {
		fail(v1.TaskStatus_TASK_STATUS_UNSUPPORTED, "ACTION_UNKNOWN")
		return
	}
	digest, err := hex.DecodeString(p.Digests[task.Action])
	if err != nil || len(task.ActionSha256) != sha256.Size || !bytes.Equal(digest, task.ActionSha256) {
		fail(v1.TaskStatus_TASK_STATUS_UNSUPPORTED, "ACTION_DIGEST_MISMATCH")
		return
	}
	if support := catalog.CheckHost(action); !support.Supported {
		fail(v1.TaskStatus_TASK_STATUS_UNSUPPORTED, "ACTION_UNSUPPORTED")
		return
	}
	var input map[string]any
	parameterData := task.GetParams().GetJson()
	if len(parameterData) > a.config.Limits.ParameterBytes {
		fail(v1.TaskStatus_TASK_STATUS_FAILED, "INVALID_PARAMETERS")
		return
	}
	err = execd.DecodeJSONDepth(parameterData, &input, a.config.Limits.ParameterDepth)
	if err != nil || input == nil {
		fail(v1.TaskStatus_TASK_STATUS_FAILED, "INVALID_PARAMETERS")
		return
	}
	defs, err := catalog.ParameterDefinitions(action)
	if err != nil {
		fail(v1.TaskStatus_TASK_STATUS_UNSUPPORTED, "ACTION_UNSUPPORTED")
		return
	}
	if _, err := params.Parse(defs, input); err != nil {
		fail(v1.TaskStatus_TASK_STATUS_FAILED, "INVALID_PARAMETERS")
		return
	}
	filters, err := taskFilters(task.Filters)
	if err != nil {
		fail(v1.TaskStatus_TASK_STATUS_FAILED, "INVALID_FILTERS")
		return
	}
	if _, err := executor.ParseFilters(action.Filters, filters); err != nil {
		fail(v1.TaskStatus_TASK_STATUS_FAILED, "INVALID_FILTERS")
		return
	}
	if task.Timeout == nil || task.Timeout.CheckValid() != nil {
		fail(v1.TaskStatus_TASK_STATUS_FAILED, "INVALID_TIMEOUT")
		return
	}
	timeout, err := boundedTimeout(action, task.Timeout.AsDuration())
	if err != nil {
		fail(v1.TaskStatus_TASK_STATUS_FAILED, "INVALID_TIMEOUT")
		return
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	callbacks := executor.Callbacks{
		Started: func() error {
			return send(&v1.ConnectRequest{Message: &v1.ConnectRequest_TaskStarted{TaskStarted: &v1.TaskStarted{JobId: task.JobId, TaskId: task.TaskId, StartedAt: timestamppb.Now()}}}, false)
		},
		StepCompleted: func(step executor.StepResult, err error) error {
			code := -1
			if step.ExitCode != nil {
				code = *step.ExitCode
			}
			stepResult := executionResult(code, step.DurationMS, step.Truncated, step.ScanLimitReached, err)
			if step.Skipped {
				stepResult.Status = v1.TaskStatus_TASK_STATUS_SKIPPED
			} else {
				stepResult.Status, stepResult.Reason = taskStatus(code, err)
				if err := sendOutput(task, proto.Uint32(uint32(step.Index)), step.Stdout, step.Stderr, stepResult, chunkSize, send); err != nil {
					return err
				}
			}
			return send(&v1.ConnectRequest{Message: &v1.ConnectRequest_StepCompleted{StepCompleted: &v1.StepCompleted{JobId: task.JobId, TaskId: task.TaskId, StepIndex: uint32(step.Index), StepName: step.Name, Result: stepResult}}}, true)
		},
	}
	result, runErr := a.options.Runner.Run(runCtx, action, input, filters, ref.CatalogId, int64(ref.Version), callbacks)
	if ctx.Err() != nil && !errors.Is(ctx.Err(), context.Canceled) {
		return
	}
	status, reason := taskStatus(result.ExitCode, runErr)
	output := executionResult(result.ExitCode, result.DurationMS, result.Truncated, result.ScanLimitReached, runErr)
	output.Status, output.Reason = status, reason
	output.Duration = durationpb.New(time.Since(started))
	if action.Steps == nil {
		if err := sendOutput(task, nil, result.Stdout, result.Stderr, output, chunkSize, send); err != nil {
			return
		}
	}
	message := completed(task, output)
	message.GetTaskCompleted().CompletedSteps = uint32(len(result.Steps))
	_ = send(message, true)
}

func taskStatus(code int, err error) (v1.TaskStatus, string) {
	switch {
	case errors.Is(err, context.Canceled):
		return v1.TaskStatus_TASK_STATUS_CANCELLED, "CANCELLED"
	case errors.Is(err, context.DeadlineExceeded):
		return v1.TaskStatus_TASK_STATUS_TIMEOUT, "TIMEOUT"
	case err != nil:
		return v1.TaskStatus_TASK_STATUS_FAILED, "EXECUTION_FAILED"
	case code != 0:
		return v1.TaskStatus_TASK_STATUS_FAILED, ""
	default:
		return v1.TaskStatus_TASK_STATUS_SUCCEEDED, ""
	}
}

func executionResult(code int, duration int64, truncated, scan bool, err error) *v1.ExecutionResult {
	result := &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_SUCCEEDED, Duration: durationpb.New(time.Duration(duration) * time.Millisecond), Truncated: truncated, ScanLimitReached: scan}
	if code >= 0 {
		result.ExitCode = proto.Int32(int32(code))
	}
	if code != 0 || err != nil {
		result.Status = v1.TaskStatus_TASK_STATUS_FAILED
	}
	return result
}

func taskFilters(f *v1.OutputFilters) (map[string]any, error) {
	result := map[string]any{}
	if f == nil {
		return result, nil
	}
	selected := 0
	if f.Match != nil {
		result["match"] = *f.Match
	}
	if f.Exclude != nil {
		result["exclude"] = *f.Exclude
	}
	if f.Tail != nil {
		result["tail"] = int64(*f.Tail)
		selected++
	}
	if f.Head != nil {
		result["head"] = int64(*f.Head)
		selected++
	}
	if f.Count != nil {
		result["count"] = *f.Count
		selected++
	}
	if selected > 1 {
		return nil, errors.New("INVALID_FILTERS")
	}
	return result, nil
}

func sendOutput(task *v1.TaskAssignment, stepIndex *uint32, stdout, stderr string, output *v1.ExecutionResult, chunkSize int, send func(*v1.ConnectRequest, bool) error) error {
	for _, stream := range []struct {
		kind     v1.OutputStream
		text     string
		metadata **v1.OutputMetadata
	}{{v1.OutputStream_OUTPUT_STREAM_STDOUT, stdout, &output.Stdout}, {v1.OutputStream_OUTPUT_STREAM_STDERR, stderr, &output.Stderr}} {
		data := []byte(stream.text)
		sum := sha256.Sum256(data)
		*stream.metadata = &v1.OutputMetadata{SizeBytes: uint64(len(data)), Sha256: sum[:], Truncated: output.Truncated}
		for offset := 0; offset < max(1, len(data)); offset += chunkSize {
			end := min(offset+chunkSize, len(data))
			chunk := &v1.TaskOutputChunk{JobId: task.JobId, TaskId: task.TaskId, StepIndex: stepIndex, Stream: stream.kind, Offset: uint64(offset), Data: data[offset:end], Eof: end == len(data)}
			if err := send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Output{Output: chunk}}, true); err != nil {
				return err
			}
		}
	}
	return nil
}
