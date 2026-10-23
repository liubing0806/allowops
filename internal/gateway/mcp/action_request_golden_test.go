package mcp

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
)

// Inputs cover each validation step of actionRequest, including combinations
// that fail several steps at once, so the order of error reporting is fixed.
var actionRequestGoldenInputs = []string{
	`null`,
	`[]`,
	`{"reason":"x","targets":{"hosts":["a"]},"zzz":1}`,
	`{"zzz":1}`,
	`{"targets":{"hosts":["a"]}}`,
	`{"reason":null,"targets":{"hosts":["a"]}}`,
	`{"reason":5,"targets":{"hosts":["a"]}}`,
	`{"reason":"  ","targets":{"hosts":["a"]}}`,
	`{"reason":"x"}`,
	`{"reason":"x","targets":[]}`,
	`{"reason":"x","targets":{}}`,
	`{"reason":"x","targets":{"hosts":["a"],"selector":"a=b"}}`,
	`{"reason":"x","targets":{"other":1}}`,
	`{"reason":"x","targets":{"hosts":[]}}`,
	`{"reason":"x","targets":{"hosts":"a"}}`,
	`{"reason":"x","targets":{"hosts":["a"," "]}}`,
	`{"reason":"x","targets":{"hosts":["a\nb"]}}`,
	`{"reason":"x","targets":{"hosts":["a","a"]}}`,
	`{"reason":"x","targets":{"selector":5}}`,
	`{"reason":"x","targets":{"selector":"a"}}`,
	`{"reason":"x","targets":{"selector":"a=b,a=c"},"expected_count":1}`,
	`{"reason":"x","targets":{"selector":"a=b,a=b"},"expected_count":1,"params":{"mode":"all"}}`,
	`{"reason":"x","targets":{"selector":"a=b"}}`,
	`{"reason":"x","targets":{"selector":"a=b"},"expected_count":"1"}`,
	`{"reason":"x","targets":{"selector":"a=b"},"expected_count":-1}`,
	`{"reason":"x","targets":{"selector":"a=b"},"expected_count":3,"params":{"mode":"all"}}`,
	`{"reason":"x","targets":{"hosts":["a"]},"expected_count":"1"}`,
	`{"reason":"x","targets":{"hosts":["a"]},"expected_count":2,"params":{"mode":"all"}}`,
	`{"reason":"x","targets":{"hosts":["a"]},"wait_seconds":121}`,
	`{"reason":"x","targets":{"hosts":["a"]},"wait_seconds":"1"}`,
	`{"reason":"x","targets":{"hosts":["a"]},"wait_seconds":null,"batch_size":0}`,
	`{"reason":"x","targets":{"hosts":["a"]},"batch_size":0}`,
	`{"reason":"x","targets":{"hosts":["a"]},"batch_size":21,"max_failures":6}`,
	`{"reason":"x","targets":{"hosts":["a"]},"max_failures":6,"response_format":"bad"}`,
	`{"reason":"x","targets":{"hosts":["a"]},"max_failures":-1}`,
	`{"reason":"x","targets":{"hosts":["a"]},"wait_seconds":0,"batch_size":1,"max_failures":0,"params":{"mode":"all"}}`,
	`{"reason":"x","targets":{"hosts":["a"]},"response_format":5}`,
	`{"reason":"x","targets":{"hosts":["a"]},"response_format":"bad","params":[]}`,
	`{"reason":"x","targets":{"hosts":["a"]},"response_format":"detailed","params":{"mode":"all"}}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":[]}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":5}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"nope"},"tail":0}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"nope":1}}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all","lines":1000}}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all","lines":5,"reason":"abc"}}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all","reason":"ABC"}}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all"},"tail":null}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all"},"tail":"x"}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all"},"tail":0,"head":null}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all"},"head":-1}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all"},"tail":1,"head":1,"match":5}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all"},"match":5}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all"},"exclude":false}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all"},"count":"yes"}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all"},"tail":1,"count":false}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all"},"tail":1,"head":2,"count":true}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all"},"match":"["}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all"},"match":"a","exclude":"b","tail":4294967295}`,
	`{"reason":"x","targets":{"hosts":["a"]},"params":{"mode":"all"},"head":4294967296}`,
	`{"reason":"x","targets":{"hosts":["b","a"]},"params":{"mode":"recent"},"count":true}`,
	`{"reason":"x","targets":{"selector":" a = b "},"expected_count":0,"params":{"mode":"recent"},"wait_seconds":120,"response_format":"detailed"}`,
}

func actionRequestGoldenActions() map[string]catalog.Action {
	a := testAction()
	noFilters := testAction()
	noFilters.Filters = nil
	limited := testAction()
	failures := 0
	limited.BatchSize, limited.MaxFailures = 3, &failures
	badBatch := testAction()
	badBatch.BatchSize = -1
	return map[string]catalog.Action{"default": a, "no_filters": noFilters, "limited": limited, "bad_batch": badBatch}
}

type actionRequestGoldenResult struct {
	Request json.RawMessage `json:",omitempty"`
	Format  string          `json:",omitempty"`
	Error   string          `json:",omitempty"`
}

func actionRequestGoldenRun() map[string][]actionRequestGoldenResult {
	out := map[string][]actionRequestGoldenResult{}
	for name, a := range actionRequestGoldenActions() {
		for _, input := range actionRequestGoldenInputs {
			var result actionRequestGoldenResult
			req, format, err := actionRequest(a, json.RawMessage(input))
			if err != nil {
				result.Error = err.Error()
			} else {
				result.Request, _ = json.Marshal(req)
				result.Format = format
			}
			out[name] = append(out[name], result)
		}
	}
	return out
}

func TestActionRequestGolden(t *testing.T) {
	got, err := json.MarshalIndent(actionRequestGoldenRun(), "", " ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := "testdata/action_request_golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("actionRequest results differ from %s; set UPDATE_GOLDEN=1 only for an intended behavior change", path)
	}
}
