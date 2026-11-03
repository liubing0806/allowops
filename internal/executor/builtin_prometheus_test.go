package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuiltinPrometheusQueryE2E(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"success","warnings":["slow storage"],"data":{"resultType":"vector","result":[`+
			`{"metric":{"__name__":"up","job":"a","password":"hunter2"},"value":[1792725120,"1"]},`+
			`{"metric":{"__name__":"up","job":"b"},"value":[1792725120,"0"]}]}}`)
	}))
	defer s.Close()
	a := localBuiltinAction("prometheus_query", map[string]any{"api": "query", "address": s.URL})
	r, err := RunWithFilters(context.Background(), a, map[string]any{"query": "up"}, map[string]any{"match": `job="b"`}, nil)
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("result %+v err=%v", r, err)
	}
	if r.Stdout != "up{job=\"b\"}\t2026-10-23T03:12:00Z\t0\n" || !strings.Contains(r.Stderr, "warning: slow storage") {
		t.Errorf("stdout %q stderr %q", r.Stdout, r.Stderr)
	}
	r, err = RunWithFilters(context.Background(), a, map[string]any{"query": "up"}, nil, nil)
	if err != nil || strings.Contains(r.Stdout, "hunter2") || !strings.Contains(r.Stdout, "[REDACTED") {
		t.Errorf("secret label not masked: %q err=%v", r.Stdout, err)
	}
	if _, err := RunWithFilters(context.Background(), a, map[string]any{"query": "up", "start": "now"}, nil, nil); err == nil {
		t.Error("parameter of another api accepted")
	}
}
