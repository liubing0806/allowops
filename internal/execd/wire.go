package execd

import (
	"encoding/json"

	"github.com/liubing0806/allowops/internal/executor"
)

// JSON's string encoding replaces invalid UTF-8. The local helper wire uses
// base64 byte fields, preserving exactly the bytes hashed by the task protocol.
type wireResult struct {
	ExitCode             int        `json:"exit_code"`
	DurationMS           int64      `json:"duration_ms"`
	Stdout               []byte     `json:"stdout"`
	Stderr               []byte     `json:"stderr"`
	Truncated            bool       `json:"truncated"`
	ScanLimitReached     bool       `json:"scan_limit_reached"`
	ResourceLimitReached bool       `json:"resource_limit_reached,omitempty"`
	StatusCode           int        `json:"status_code,omitempty"`
	Steps                []wireStep `json:"steps,omitempty"`
}

type wireStep struct {
	Index            int    `json:"index"`
	Name             string `json:"name"`
	Skipped          bool   `json:"skipped,omitempty"`
	ExitCode         *int   `json:"exit_code,omitempty"`
	DurationMS       int64  `json:"duration_ms"`
	Stdout           []byte `json:"stdout"`
	Stderr           []byte `json:"stderr"`
	Truncated        bool   `json:"truncated"`
	ScanLimitReached bool   `json:"scan_limit_reached"`
}

type wireResponse struct {
	Result wireResult `json:"result"`
	Reason string     `json:"reason,omitempty"`
}

func (r Response) MarshalJSON() ([]byte, error) {
	result := r.Result
	w := wireResult{ExitCode: result.ExitCode, DurationMS: result.DurationMS, Stdout: []byte(result.Stdout), Stderr: []byte(result.Stderr), Truncated: result.Truncated, ScanLimitReached: result.ScanLimitReached, ResourceLimitReached: result.ResourceLimitReached}
	w.StatusCode = result.StatusCode
	for _, step := range result.Steps {
		w.Steps = append(w.Steps, wireStep{Index: step.Index, Name: step.Name, Skipped: step.Skipped, ExitCode: step.ExitCode, DurationMS: step.DurationMS, Stdout: []byte(step.Stdout), Stderr: []byte(step.Stderr), Truncated: step.Truncated, ScanLimitReached: step.ScanLimitReached})
	}
	return json.Marshal(wireResponse{Result: w, Reason: r.Reason})
}

func (r *Response) UnmarshalJSON(data []byte) error {
	var w wireResponse
	if err := DecodeJSON(data, &w); err != nil {
		return err
	}
	r.Reason = w.Reason
	r.Result = executor.Result{ExitCode: w.Result.ExitCode, DurationMS: w.Result.DurationMS, Stdout: string(w.Result.Stdout), Stderr: string(w.Result.Stderr), Truncated: w.Result.Truncated, ScanLimitReached: w.Result.ScanLimitReached, ResourceLimitReached: w.Result.ResourceLimitReached}
	r.Result.StatusCode = w.Result.StatusCode
	for _, step := range w.Result.Steps {
		r.Result.Steps = append(r.Result.Steps, executor.StepResult{Index: step.Index, Name: step.Name, Skipped: step.Skipped, ExitCode: step.ExitCode, DurationMS: step.DurationMS, Stdout: string(step.Stdout), Stderr: string(step.Stderr), Truncated: step.Truncated, ScanLimitReached: step.ScanLimitReached})
	}
	return nil
}
