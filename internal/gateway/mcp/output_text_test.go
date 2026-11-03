package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// pagedOutputJobs serves payload in fixed-size backend pages so tests control
// where page boundaries fall inside multi-byte UTF-8 characters.
type pagedOutputJobs struct {
	JobService
	payload   []byte
	pageBytes uint64
	calls     int
}

func (j *pagedOutputJobs) GetJob(_ context.Context, r *v1.GetJobRequest) (*v1.GetJobResponse, error) {
	return &v1.GetJobResponse{Job: &v1.Job{JobId: r.JobId}}, nil
}
func (j *pagedOutputJobs) GetJobOutput(_ context.Context, r *v1.GetJobOutputRequest) (*v1.GetJobOutputResponse, error) {
	j.calls++
	start := min(r.Offset, uint64(len(j.payload)))
	end := min(start+j.pageBytes, uint64(len(j.payload)))
	return &v1.GetJobOutputResponse{Data: j.payload[start:end], NextOffset: end, Eof: end == uint64(len(j.payload)), OutputStored: true}, nil
}

func getJobOutput(t *testing.T, jobs JobService, args map[string]any) (map[string]any, error) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{jobs: jobs}
	state := &callState{}
	result, err := service.getJob(context.Background(), &sdk.CallToolRequest{Params: &sdk.CallToolParamsRaw{Name: "jobs_get", Arguments: raw}}, state)
	if err != nil {
		return toolError(err, state).StructuredContent.(map[string]any), err
	}
	var page map[string]any
	if err = json.Unmarshal(mustJSON(t, result.StructuredContent), &page); err != nil {
		t.Fatal(err)
	}
	return page, nil
}

// readAllOutput follows next_offset until eof and returns the concatenated bytes.
func readAllOutput(t *testing.T, jobs JobService, encoding string) []byte {
	t.Helper()
	var combined []byte
	offset := uint64(0)
	for range 1000 {
		args := map[string]any{"job_id": "job-20261014-0001", "host": "web-01", "wait_seconds": 0, "offset": offset}
		if encoding != "" {
			args["encoding"] = encoding
		}
		page, err := getJobOutput(t, jobs, args)
		if err != nil {
			t.Fatalf("offset=%d error=%v data=%v", offset, err, page)
		}
		want := encoding
		if want == "" {
			want = "base64"
		}
		if page["encoding"] != want || page["output_trust"] != "untrusted" {
			t.Fatalf("page=%v", page)
		}
		var data []byte
		if want == "text" {
			if _, ok := page["data_base64"]; ok {
				t.Fatalf("text page carries data_base64: %v", page)
			}
			data = []byte(page["data"].(string))
		} else {
			if _, ok := page["data"]; ok {
				t.Fatalf("base64 page carries data: %v", page)
			}
			data, err = base64.StdEncoding.DecodeString(page["data_base64"].(string))
			if err != nil {
				t.Fatal(err)
			}
		}
		combined = append(combined, data...)
		next := uint64(page["next_offset"].(float64))
		if next != offset+uint64(len(data)) {
			t.Fatalf("offset=%d bytes=%d next_offset=%d", offset, len(data), next)
		}
		offset = next
		if page["eof"] == true {
			return combined
		}
	}
	t.Fatal("output pagination did not reach eof")
	return nil
}

func TestJobsGetTextEncodingASCII(t *testing.T) {
	payload := []byte("line 1\nline 2 <ok> & done\n")
	jobs := &pagedOutputJobs{payload: payload, pageBytes: 16 << 10}
	page, err := getJobOutput(t, jobs, map[string]any{"job_id": "job-20261014-0001", "host": "web-01", "wait_seconds": 0, "encoding": "text"})
	if err != nil {
		t.Fatal(err)
	}
	if page["data"] != string(payload) || page["encoding"] != "text" || page["eof"] != true || page["next_offset"] != float64(len(payload)) {
		t.Fatalf("page=%v", page)
	}
}

func TestJobsGetTextEncodingSplitMultiByteMatchesBase64(t *testing.T) {
	payload := []byte(strings.Repeat("中文日志 line\n", 3))
	// 4-byte backend pages cut every three-byte character at some boundary.
	for _, size := range []uint64{4, 5, 7} {
		text := readAllOutput(t, &pagedOutputJobs{payload: payload, pageBytes: size}, "text")
		raw := readAllOutput(t, &pagedOutputJobs{payload: payload, pageBytes: size}, "base64")
		if !bytes.Equal(text, payload) || !bytes.Equal(raw, payload) {
			t.Fatalf("page=%d text=%q base64=%q want=%q", size, text, raw, payload)
		}
	}
}

func TestJobsGetTextEncodingResultBudgetKeepsCharacters(t *testing.T) {
	// Large output forces the 32KB result budget to cut inside the backend page.
	payload := []byte(strings.Repeat("中<", 20000))
	text := readAllOutput(t, &pagedOutputJobs{payload: payload, pageBytes: uint64(len(payload))}, "text")
	if !bytes.Equal(text, payload) {
		t.Fatal("text pagination changed output bytes")
	}
}

func TestJobsGetTextEncodingRejectsBinary(t *testing.T) {
	for _, payload := range [][]byte{{'o', 'k', 0xff, 'x'}, {'o', 'k', 0xe4, 0xb8}} {
		jobs := &pagedOutputJobs{payload: payload, pageBytes: 16 << 10}
		data, err := getJobOutput(t, jobs, map[string]any{"job_id": "job-20261014-0001", "host": "web-01", "wait_seconds": 0, "encoding": "text"})
		if err == nil || connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("payload=%x error=%v data=%v", payload, err, data)
		}
		if data["reason"] != "ENCODING_NOT_TEXT" || !strings.Contains(data["error"].(string), "base64") {
			t.Fatalf("payload=%x data=%v", payload, data)
		}
	}
}

func TestJobsGetDefaultEncodingIsBase64(t *testing.T) {
	payload := append([]byte("中文"), 0, 0xff)
	jobs := &pagedOutputJobs{payload: payload, pageBytes: 16 << 10}
	page, err := getJobOutput(t, jobs, map[string]any{"job_id": "job-20261014-0001", "host": "web-01", "wait_seconds": 0})
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := getJobOutput(t, jobs, map[string]any{"job_id": "job-20261014-0001", "host": "web-01", "wait_seconds": 0, "encoding": "base64"})
	if err != nil {
		t.Fatal(err)
	}
	if page["encoding"] != "base64" || page["data_base64"] != base64.StdEncoding.EncodeToString(payload) || page["next_offset"] != float64(len(payload)) {
		t.Fatalf("page=%v", page)
	}
	if string(mustJSON(t, page)) != string(mustJSON(t, explicit)) {
		t.Fatalf("explicit base64=%v default=%v", explicit, page)
	}
}

func TestJobsGetEncodingArgumentErrors(t *testing.T) {
	for _, args := range []map[string]any{
		{"job_id": "job-20261014-0001", "wait_seconds": 0, "encoding": "text"},
		{"job_id": "job-20261014-0001", "wait_seconds": 0, "encoding": "base64"},
		{"job_id": "job-20261014-0001", "host": "web-01", "wait_seconds": 0, "encoding": "utf8"},
		{"job_id": "job-20261014-0001", "host": "web-01", "wait_seconds": 0, "encoding": 1},
	} {
		jobs := &pagedOutputJobs{payload: []byte("ok"), pageBytes: 16 << 10}
		data, err := getJobOutput(t, jobs, args)
		if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(data["error"].(string), "encoding") || jobs.calls != 0 {
			t.Fatalf("args=%v error=%v data=%v calls=%d", args, err, data, jobs.calls)
		}
	}
}
