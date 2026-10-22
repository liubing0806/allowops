package mcp

import (
	"bytes"
	"encoding/base64"
	"testing"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

func TestHostOutputPagesPreserveSplitUTF8Bytes(t *testing.T) {
	payload := append([]byte("中文日志"), 0, 255)
	var combined []byte
	for offset := uint64(0); offset < uint64(len(payload)); {
		end := min(offset+2, uint64(len(payload))) // Split every three-byte UTF-8 rune.
		result, err := outputPageResult("job-20261014-0001", "web-01", v1.OutputStream_OUTPUT_STREAM_STDOUT, offset, &v1.GetJobOutputResponse{Data: payload[offset:end], NextOffset: end, Eof: end == uint64(len(payload)), OutputStored: true}, nil)
		if err != nil {
			t.Fatal(err)
		}
		page := result.StructuredContent.(*HostOutputPage)
		raw, err := base64.StdEncoding.DecodeString(page.DataBase64)
		if err != nil {
			t.Fatal(err)
		}
		combined = append(combined, raw...)
		if page.Encoding != "base64" || page.OutputTrust != "untrusted" || page.NextOffset != end || page.EOF != (end == uint64(len(payload))) {
			t.Fatalf("page=%+v", page)
		}
		offset = page.NextOffset
	}
	if !bytes.Equal(payload, combined) {
		t.Fatalf("output=%x want=%x", combined, payload)
	}
}

func TestHostOutputByteBudgetPreservesContinuation(t *testing.T) {
	payload := bytes.Repeat([]byte{0, 255, '<', 0xe7}, 30000)
	var combined []byte
	for offset := uint64(0); offset < uint64(len(payload)); {
		result, err := outputPageResult("job-20261014-0002", "web-01", v1.OutputStream_OUTPUT_STREAM_STDERR, offset, &v1.GetJobOutputResponse{Data: payload[offset:], NextOffset: uint64(len(payload)), Eof: true, Truncated: true, OutputStored: true}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(mustJSON(t, result)) > 32<<10 {
			t.Fatal("host output result exceeded 32KB")
		}
		page := result.StructuredContent.(*HostOutputPage)
		data, err := base64.StdEncoding.DecodeString(page.DataBase64)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 || page.NextOffset != offset+uint64(len(data)) || !page.Truncated {
			t.Fatalf("invalid continuation %+v", page)
		}
		if page.EOF != (page.NextOffset == uint64(len(payload))) {
			t.Fatal("early EOF")
		}
		combined = append(combined, data...)
		offset = page.NextOffset
	}
	if !bytes.Equal(payload, combined) {
		t.Fatal("pagination lost output bytes")
	}
}
