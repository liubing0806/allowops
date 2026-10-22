package mcp

import (
	"encoding/json"
	"errors"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

// A33: omitted step stays nil so P6 decides whether the action requires it.
// MCP adds reading guidance to that parameter error and never joins outputs.
func outputStepSchema() map[string]any {
	return map[string]any{"type": "integer", "description": "Required zero-based step for composite action output; read one step at a time. Only with host. P6 validates the step. Omit for a single-step action.", "minimum": 0, "maximum": uint64(^uint32(0))}
}
func outputStepArgument(args map[string]json.RawMessage, host string) (*uint32, error) {
	if args["step_index"] == nil {
		return nil, nil
	}
	if host == "" {
		return nil, accessError(connect.CodeInvalidArgument, "step_index requires host")
	}
	var step uint32
	if decodeField(args, "step_index", &step, false) != nil {
		return nil, accessError(connect.CodeInvalidArgument, "step_index allowed: integer in [0,4294967295], with host")
	}
	return &step, nil
}

func outputStepError(step *uint32, err error) error {
	var backend *connect.Error
	if step != nil || !errors.As(err, &backend) || backend.Code() != connect.CodeInvalidArgument {
		return err
	}
	for _, detail := range backend.Details() {
		value, decodeErr := detail.Value()
		if d, ok := value.(*v1.ErrorDetail); decodeErr == nil && ok && d.Reason == "INVALID_OUTPUT_STEP" {
			guided := connect.NewError(connect.CodeInvalidArgument, errors.New("step_index is required for composite action output; read output one step at a time using step_index=0, then step_index=1"))
			for _, detail := range backend.Details() {
				guided.AddDetail(detail)
			}
			return guided
		}
	}
	return err
}
