package mcp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

const resultByteLimit = 32 << 10
const groupByteLimit = 4 << 10

// ToolResult has the MCP wire fields needed to measure the complete result,
// including the JSON text copy, before adapting to the official SDK.
type ToolResult struct {
	// Account for the SDK metadata added to current-protocol responses.
	Meta              map[string]any `json:"_meta,omitempty"`
	ResultType        string         `json:"resultType,omitempty"`
	Content           []TextContent  `json:"content"`
	StructuredContent any            `json:"structuredContent"`
	IsError           bool           `json:"isError,omitempty"`
}
type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func toolResult(value any) (*ToolResult, int, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, 0, err
	}
	result := &ToolResult{Meta: map[string]any{"io.modelcontextprotocol/serverInfo": map[string]string{"name": "allowops", "version": "1"}}, ResultType: "complete", StructuredContent: value, Content: []TextContent{{Type: "text", Text: string(data)}}}
	encoded, err := json.Marshal(result)
	return result, len(encoded), err
}
func taskStatus(status v1.TaskStatus) string {
	return strings.ToLower(strings.TrimPrefix(status.String(), "TASK_STATUS_"))
}
func textPrefix(text string, limit int) string {
	text = strings.ToValidUTF8(text, "\ufffd")
	if len(text) <= limit {
		return text
	}
	for limit > 0 && !utf8.RuneStart(text[limit]) {
		limit--
	}
	return text[:limit]
}

// HostOutputPage uses base64 so byte offsets remain lossless even when the
// backend page boundary divides a multi-byte UTF-8 character (G43).
type HostOutputPage struct {
	JobID            string  `json:"job_id"`
	StepIndex        *uint32 `json:"step_index,omitempty"`
	Host             string  `json:"host"`
	Stream           string  `json:"stream"`
	DataBase64       string  `json:"data_base64"`
	Encoding         string  `json:"encoding"`
	NextOffset       uint64  `json:"next_offset"`
	EOF              bool    `json:"eof"`
	Truncated        bool    `json:"truncated"`
	ScanLimitReached bool    `json:"scan_limit_reached"`
	OutputStored     bool    `json:"output_stored"`
	OutputTrust      string  `json:"output_trust"`
}

// Call only after P6 has authorized view_output for this job and hostname.
// A result-budget cut is a page boundary, not permanent output truncation.
func outputPageResult(jobID, host string, stream v1.OutputStream, offset uint64, response *v1.GetJobOutputResponse, index *uint32) (*ToolResult, error) {
	if jobID == "" || host == "" || response == nil {
		return nil, errors.New("job, hostname and output response required")
	}
	if stream != v1.OutputStream_OUTPUT_STREAM_STDOUT && stream != v1.OutputStream_OUTPUT_STREAM_STDERR {
		return nil, errors.New("stream allowed: stdout, stderr")
	}
	if uint64(len(response.Data)) > ^uint64(0)-offset {
		return nil, errors.New("output offset overflow")
	}
	candidate := func(n int) (*ToolResult, int, error) {
		return toolResult(&HostOutputPage{JobID: jobID, StepIndex: index, Host: host, Stream: strings.ToLower(strings.TrimPrefix(stream.String(), "OUTPUT_STREAM_")), DataBase64: base64.StdEncoding.EncodeToString(response.Data[:n]), Encoding: "base64", NextOffset: offset + uint64(n), EOF: response.Eof && n == len(response.Data), Truncated: response.Truncated, ScanLimitReached: response.ScanLimitReached, OutputStored: response.OutputStored, OutputTrust: "untrusted"})
	}
	// Binary search counts the whole JSON result, including its text copy.
	low, high := 0, len(response.Data)
	var best *ToolResult
	for low <= high {
		middle := low + (high-low)/2
		result, size, err := candidate(middle)
		if err != nil {
			return nil, err
		}
		if size <= resultByteLimit {
			best = result
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	if best == nil || (len(response.Data) > 0 && best.StructuredContent.(*HostOutputPage).NextOffset == offset) {
		return nil, errors.New("output metadata exceeds 32KB result limit")
	}
	return best, nil
}
