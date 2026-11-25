package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/gateway/job"
)

func TestActionApprovalArguments(t *testing.T) {
	action := progressiveActions()["data_purge"]
	cfg := job.DefaultConfig()
	const base = `"targets":{"hosts":["web-01"]},"reason":"inspect"`
	request, _, err := actionRequest(action, json.RawMessage(`{`+base+`,"evidence":{"job_ids":["job-20261124-0001"],"summary":"Checked the host"},"client_request_id":"agent.1_retry-2"}`), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if request.GetClientRequestId() != "agent.1_retry-2" || request.GetEvidence().GetSummary() != "Checked the host" ||
		len(request.GetEvidence().GetJobIds()) != 1 || request.GetEvidence().GetJobIds()[0] != "job-20261124-0001" {
		t.Fatalf("unexpected request: %v", request)
	}
	request, _, err = actionRequest(action, json.RawMessage(`{`+base+`,"evidence":{"summary":"Context only"}}`), cfg)
	if err != nil || request.GetEvidence().GetSummary() != "Context only" || len(request.GetEvidence().GetJobIds()) != 0 {
		t.Fatalf("summary-only evidence was not forwarded: request=%v err=%v", request, err)
	}
	for _, input := range []string{
		`"evidence":null`, `"evidence":[]`, `"evidence":{"other":true}`,
		`"evidence":{"summary":"a","summary":"b"}`,
		`"evidence":{"summary":null}`, `"evidence":{"summary":""}`, `"evidence":{"summary":"\u0000"}`,
		`"evidence":{"summary":"` + strings.Repeat("证", 1025) + `"}`,
		`"evidence":{"job_ids":null}`, `"evidence":{"job_ids":[]}`, `"evidence":{"job_ids":[null]}`,
		`"evidence":{"job_ids":["unknown"]}`,
		`"evidence":{"job_ids":["job-20261124-0001","job-20261124-0001"]}`,
		`"evidence":{"job_ids":["job-20261124-0001","job-20261124-0002","job-20261124-0003","job-20261124-0004","job-20261124-0005","job-20261124-0006"]}`,
		`"client_request_id":null`, `"client_request_id":1`, `"client_request_id":""`,
		`"client_request_id":"contains a space"`, `"client_request_id":"` + strings.Repeat("a", 65) + `"`,
	} {
		if _, _, err := actionRequest(action, json.RawMessage(`{`+base+","+input+`}`), cfg); err == nil {
			t.Errorf("accepted invalid input %s", input)
		}
	}
}
