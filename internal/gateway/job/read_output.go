package job

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func (s *Service) GetJobOutput(ctx context.Context, r *v1.GetJobOutputRequest) (*v1.GetJobOutputResponse, error) {
	m, err := s.operation(ctx, "get_job_output", false, func(ctx context.Context) (proto.Message, error) {
		if r == nil || r.Hostname == "" || (r.Stream != v1.OutputStream_OUTPUT_STREAM_STDOUT && r.Stream != v1.OutputStream_OUTPUT_STREAM_STDERR) {
			return nil, failure(connect.CodeInvalidArgument, "OUTPUT_TARGET_REQUIRED")
		}
		if r.LimitBytes > 24<<10 {
			return nil, failure(connect.CodeInvalidArgument, "OUTPUT_PAGE_LIMIT")
		}
		limit := r.LimitBytes
		if limit == 0 {
			limit = 16 << 10
		}
		j, err := s.get(ctx, r.JobId)
		if err != nil {
			return nil, err
		}
		if _, _, err := s.authorize(ctx, j, authz.ViewOutput, false, r.Hostname); err != nil {
			return nil, err
		}
		row, err := getTaskOutput(ctx, s.Store.Pool, r.JobId, r.Hostname)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, failure(connect.CodeNotFound, "TASK_UNKNOWN")
		}
		if err != nil {
			return nil, err
		}
		taskID, hostID, state, raw, definition, at, stored := row.taskID, row.hostID, row.state, row.result, row.definition, row.created, row.stored
		var a catalog.Action
		if err := json.Unmarshal(definition, &a); err != nil {
			return nil, err
		}
		if (a.Steps != nil && (r.StepIndex == nil || int(*r.StepIndex) >= len(a.Steps))) || (a.Steps == nil && r.StepIndex != nil) {
			return nil, failure(connect.CodeInvalidArgument, "INVALID_OUTPUT_STEP")
		}
		result := &v1.ExecutionResult{}
		if err := proto.Unmarshal(raw, result); err != nil {
			return nil, err
		}
		if r.StepIndex != nil {
			stepRaw, err := getTaskStepResult(ctx, s.Store.Pool, r.JobId, taskID, *r.StepIndex)
			if err == nil {
				if err := proto.Unmarshal(stepRaw, result); err != nil {
					return nil, err
				}
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
		}
		meta := result.Stdout
		name := "stdout"
		if r.Stream == v1.OutputStream_OUTPUT_STREAM_STDERR {
			meta = result.Stderr
			name = "stderr"
		}
		var data []byte
		eof := false
		available := false
		// Complete output is served only through object storage (design A23).
		if stored && meta != nil {
			data, err = s.Storage.Get(ctx, output.Key(at, r.JobId, hostID, r.StepIndex, name), int64(meta.SizeBytes))
			if err != nil {
				return nil, failure(connect.CodeNotFound, "OUTPUT_UNAVAILABLE")
			}
			sum := sha256.Sum256(data)
			if !bytes.Equal(sum[:], meta.Sha256) {
				return nil, failure(connect.CodeDataLoss, "OUTPUT_HASH_MISMATCH")
			}
			eof, available = true, true
		}
		if !available {
			if result.Status == v1.TaskStatus_TASK_STATUS_PENDING || result.Status == v1.TaskStatus_TASK_STATUS_RUNNING {
				if r.Offset > 0 {
					return nil, failure(connect.CodeOutOfRange, "OUTPUT_OFFSET")
				}
				return &v1.GetJobOutputResponse{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED}, nil
			}
			if state == "pending" {
				return nil, detailError(connect.CodeUnavailable, &v1.ErrorDetail{Reason: "OUTPUT_PENDING", RetryAfter: durationpb.New(time.Second)})
			}
			return nil, failure(connect.CodeNotFound, "OUTPUT_UNAVAILABLE")
		}
		if r.Offset > uint64(len(data)) {
			return nil, failure(connect.CodeOutOfRange, "OUTPUT_OFFSET")
		}
		end := min(r.Offset+uint64(limit), uint64(len(data)))
		response := &v1.GetJobOutputResponse{Data: data[r.Offset:end], NextOffset: end, Eof: eof && end == uint64(len(data)), Truncated: result.Truncated, ScanLimitReached: result.ScanLimitReached, OutputStored: stored, OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED, Output: meta}
		for {
			raw, err := protojson.Marshal(response)
			if err != nil {
				return nil, err
			}
			if len(raw) <= ResponseBytes {
				break
			}
			if len(response.Data) == 0 {
				return nil, failure(connect.CodeResourceExhausted, "JOB_RESPONSE_LIMIT")
			}
			response.Data = response.Data[:len(response.Data)-min(512, len(response.Data))]
			response.NextOffset = r.Offset + uint64(len(response.Data))
			response.Eof = false
		}
		return response, nil
	})
	if err != nil {
		return nil, err
	}
	return m.(*v1.GetJobOutputResponse), nil
}
