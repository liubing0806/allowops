package mcp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"connectrpc.com/connect"
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

// HostOutputPage uses base64 by default so byte offsets remain lossless even
// when the backend page boundary divides a multi-byte UTF-8 character (G43).
// With encoding=text, Data carries the page and NextOffset stops at the last
// complete character, so concatenated pages equal the base64 bytes.
type HostOutputPage struct {
	JobID            string  `json:"job_id"`
	StepIndex        *uint32 `json:"step_index,omitempty"`
	Host             string  `json:"host"`
	Stream           string  `json:"stream"`
	DataBase64       *string `json:"data_base64,omitempty"`
	Data             *string `json:"data,omitempty"`
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
func outputPageResult(jobID, host string, stream v1.OutputStream, offset uint64, response *v1.GetJobOutputResponse, index *uint32, text bool) (*ToolResult, error) {
	if jobID == "" || host == "" || response == nil {
		return nil, errors.New("job, hostname and output response required")
	}
	if stream != v1.OutputStream_OUTPUT_STREAM_STDOUT && stream != v1.OutputStream_OUTPUT_STREAM_STDERR {
		return nil, errors.New("stream allowed: stdout, stderr")
	}
	if uint64(len(response.Data)) > ^uint64(0)-offset {
		return nil, errors.New("output offset overflow")
	}
	limit := len(response.Data)
	if text {
		var err error
		if limit, err = textLimit(response.Data, response.Eof); err != nil {
			return nil, err
		}
	}
	candidate := func(n int) (*ToolResult, int, error) {
		page := &HostOutputPage{JobID: jobID, StepIndex: index, Host: host, Stream: strings.ToLower(strings.TrimPrefix(stream.String(), "OUTPUT_STREAM_")), Encoding: "base64", Truncated: response.Truncated, ScanLimitReached: response.ScanLimitReached, OutputStored: response.OutputStored, OutputTrust: "untrusted"}
		if text {
			for n > 0 && n < limit && !utf8.RuneStart(response.Data[n]) {
				n--
			}
			data := string(response.Data[:n])
			page.Data, page.Encoding = &data, "text"
		} else {
			data := base64.StdEncoding.EncodeToString(response.Data[:n])
			page.DataBase64 = &data
		}
		page.NextOffset, page.EOF = offset+uint64(n), response.Eof && n == len(response.Data)
		return toolResult(page)
	}
	// Binary search counts the whole JSON result, including its text copy.
	low, high := 0, limit
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
	if best == nil || (limit > 0 && best.StructuredContent.(*HostOutputPage).NextOffset == offset) {
		return nil, errors.New("output metadata exceeds 32KB result limit")
	}
	return best, nil
}

// textLimit returns the length of the valid UTF-8 prefix of a page. Before EOF
// a trailing incomplete character is a page boundary cut and is left for the
// next page; any other invalid byte makes the page non-text.
func textLimit(data []byte, eof bool) (int, error) {
	limit := len(data)
	if !eof {
		for i := len(data) - 1; i >= 0 && i >= len(data)-utf8.UTFMax+1; i-- {
			if utf8.RuneStart(data[i]) {
				if !utf8.FullRune(data[i:]) {
					limit = i
				}
				break
			}
		}
	}
	if !utf8.Valid(data[:limit]) {
		err := connect.NewError(connect.CodeFailedPrecondition, errors.New("output page is not valid UTF-8 text; use encoding=base64"))
		if detail, detailErr := connect.NewErrorDetail(&v1.ErrorDetail{Reason: "ENCODING_NOT_TEXT"}); detailErr == nil {
			err.AddDetail(detail)
		}
		return 0, err
	}
	return limit, nil
}
