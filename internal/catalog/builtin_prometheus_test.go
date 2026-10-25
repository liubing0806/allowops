package catalog

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/params"
)

func prometheusAction(api string, config map[string]any) Action {
	c := map[string]any{"api": api, "address": "http://127.0.0.1:9090"}
	maps.Copy(c, config)
	return Action{Name: "prometheus_" + api, Description: "Prometheus " + api, Risk: "read", Builtin: "prometheus_query", BuiltinConfig: c, Timeout: "15s", MaxOutput: 64 << 10, Filters: []string{"match", "exclude", "tail", "head", "count"}}
}

func TestPrometheusRegisteredWithPerAPIParameters(t *testing.T) {
	if _, ok := Builtins["prometheus_query"]; !ok {
		t.Fatal("prometheus_query is not registered")
	}
	want := map[string][]string{
		"query":        {"query", "time"},
		"query_range":  {"end", "query", "start", "step", "summary"},
		"series":       {"end", "match", "start"},
		"labels":       {"end", "match", "start"},
		"label_values": {"end", "label", "match", "start"},
		"alerts":       {},
		"rules":        {"rule_type"},
		"targets":      {},
	}
	for api, names := range want {
		a := prometheusAction(api, nil)
		if _, err := ValidateAction(a); err != nil {
			t.Errorf("%s: %v", api, err)
			continue
		}
		defs, err := ParameterDefinitions(a)
		if err != nil {
			t.Errorf("%s definitions: %v", api, err)
			continue
		}
		got := slices.Sorted(maps.Keys(defs))
		if !slices.Equal(got, names) && len(got)+len(names) != 0 {
			t.Errorf("%s parameters = %v; want %v", api, got, names)
		}
		if _, err := params.JSONSchema(defs); err != nil {
			t.Errorf("%s schema: %v", api, err)
		}
	}
}

func TestPrometheusParameterOverridesOnlyTighten(t *testing.T) {
	a := prometheusAction("query", nil)
	a.Params = map[string]params.Definition{"query": {Type: params.String, Description: "metric", MaxLen: 100}}
	if _, err := ValidateAction(a); err != nil {
		t.Errorf("tighter max_len: %v", err)
	}
	a.Params = map[string]params.Definition{"query": {Type: params.String, Description: "metric", MaxLen: 5000}}
	if _, err := ValidateAction(a); err == nil {
		t.Error("widened max_len accepted")
	}
	a.Params = map[string]params.Definition{"start": {Type: params.String, Description: "not offered by query"}}
	if _, err := ValidateAction(a); err == nil {
		t.Error("parameter of another api accepted")
	}
}

func TestPrometheusConfigValidation(t *testing.T) {
	valid := map[string]any{"timeout": "30s", "max_range": "168h", "min_step": "1m", "max_points": 11000, "max_series": 1000, "max_response_bytes": "16MB"}
	if _, err := ValidateAction(prometheusAction("query_range", valid)); err != nil {
		t.Errorf("limits at the maximum: %v", err)
	}
	narrow := map[string]any{"timeout": "2s", "max_range": "1h", "min_step": "30s", "max_points": 100, "max_series": 10, "max_response_bytes": "64KB"}
	if _, err := ValidateAction(prometheusAction("query_range", narrow)); err != nil {
		t.Errorf("narrow limits: %v", err)
	}
	bad := map[string]any{
		"timeout":            "31s",
		"max_range":          "169h",
		"min_step":           "14s",
		"max_points":         11001,
		"max_series":         1001,
		"max_response_bytes": "17MB",
		"unknown_field":      true,
		"address":            "ftp://127.0.0.1",
		"credential":         "relative.json",
		"ca_file":            "/etc/ca.pem", // address is http
		"api":                "status_config",
	}
	for key, value := range bad {
		a := prometheusAction("query", map[string]any{key: value})
		if _, err := ValidateAction(a); err == nil {
			t.Errorf("%s=%v accepted", key, value)
		}
	}
	for _, drop := range []string{"api", "address"} {
		a := prometheusAction("query", nil)
		delete(a.BuiltinConfig, drop)
		if _, err := ValidateAction(a); err == nil {
			t.Errorf("config without %s accepted", drop)
		}
	}
	a := prometheusAction("query", map[string]any{"timeout": 10})
	if _, err := ValidateAction(a); err == nil {
		t.Error("numeric timeout accepted")
	}
}

func TestPrometheusCredentialRequiresRunAsRoot(t *testing.T) {
	withCredential := map[string]any{"credential": "/etc/allowops/credentials/prometheus-main.json"}
	for _, tc := range []struct {
		name, runAs string
		config      map[string]any
		valid       bool
	}{
		{"no credential, no run_as", "", nil, true},
		{"no credential, run_as root", "root", nil, true},
		{"credential, run_as root", "root", withCredential, true},
		{"credential, no run_as", "", withCredential, false},
		{"credential, other run_as", "allowops", withCredential, false},
	} {
		a := prometheusAction("query", tc.config)
		a.RunAs = tc.runAs
		_, err := ValidateAction(a)
		if (err == nil) != tc.valid {
			t.Errorf("%s: err=%v; want valid=%v", tc.name, err, tc.valid)
		}
		if err != nil && !strings.Contains(err.Error(), "run_as") {
			t.Errorf("%s: error %q does not mention run_as", tc.name, err)
		}
	}
	// Executing through allowops-exec follows from the declared run_as.
	a := prometheusAction("query", withCredential)
	a.RunAs = "root"
	if !a.RequiresExec() {
		t.Error("credential action does not require allowops-exec")
	}
}

func TestPrometheusHandlerRun(t *testing.T) {
	var gotPath, gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		fmt.Fprintf(w, `{"status":"success","warnings":["w1"],"data":{"resultType":"vector","result":[{"metric":{"__name__":"up","job":"a"},"value":[1792725120,"1"]},{"metric":{"__name__":"up","job":"b"},"value":[1792725120,"1"]}]}}`)
	}))
	defer server.Close()
	a := prometheusAction("query", map[string]any{"address": server.URL, "max_series": 1})
	handler := Builtins["prometheus_query"]
	r, err := handler.Run(context.Background(), a.BuiltinConfig, map[string]any{"query": "up", "time": "2026-10-23T03:12:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/query" || !strings.Contains(gotQuery, "query=up") {
		t.Errorf("request %s?%s", gotPath, gotQuery)
	}
	wantOut := "# api=query time=2026-10-23T03:12:00Z\nup{job=\"a\"}\t2026-10-23T03:12:00Z\t1\n"
	if r.Stdout != wantOut || r.Stderr != "warning: w1\ntruncated: returned 1 of 2 results (max_series)\n" || r.ExitCode != 0 || !r.ResourceLimited || r.StatusCode != 200 {
		t.Errorf("result = %+v", r)
	}
	redacting, ok := handler.(RedactingBuiltinHandler)
	if !ok {
		t.Fatal("prometheus_query must mask before TSV encoding")
	}
	r, err = redacting.RunRedacted(context.Background(), a.BuiltinConfig, map[string]any{"query": "up"}, func(s string) string { return strings.ReplaceAll(s, `job="a"`, "job=***") })
	if err != nil || !strings.Contains(r.Stdout, "up{job=***}") {
		t.Errorf("redacted = %+v, %v", r, err)
	}
}

func TestPrometheusHandlerRunConvertsParameterTypes(t *testing.T) {
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"cpu"},"values":[[1792725060,"1"],[1792725120,"3"]]}]}}`)
	}))
	defer server.Close()
	a := prometheusAction("query_range", map[string]any{"address": server.URL})
	defs, err := ParameterDefinitions(a)
	if err != nil {
		t.Fatal(err)
	}
	values, err := params.Parse(defs, map[string]any{"query": "cpu", "start": "2026-10-23T02:12:00Z", "end": "2026-10-23T03:12:00Z", "step": "1m", "summary": true})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Builtins["prometheus_query"].Run(context.Background(), a.BuiltinConfig, values)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(r.Stdout, "cpu\t1\t2\t3\t3\n") || !strings.Contains(query, "step=60") {
		t.Errorf("stdout %q query %q", r.Stdout, query)
	}

	series := prometheusAction("series", map[string]any{"address": server.URL})
	defs, _ = ParameterDefinitions(series)
	values, err = params.Parse(defs, map[string]any{"match": []any{"up", `node_load1{job="a"}`}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Builtins["prometheus_query"].Run(context.Background(), series.BuiltinConfig, values); err == nil {
		// The fake answers with a matrix, which a series request must reject.
		t.Error("series accepted a query response")
	}
	if !strings.Contains(query, "match%5B%5D=up") || !strings.Contains(query, "match%5B%5D=node_load1") {
		t.Errorf("series query = %q", query)
	}
}

func TestPrometheusHandlerReportsPrometheusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"status":"error","errorType":"bad_data","error":"parse error"}`)
	}))
	defer server.Close()
	a := prometheusAction("query", map[string]any{"address": server.URL, "timeout": "1s"})
	r, err := Builtins["prometheus_query"].Run(context.Background(), a.BuiltinConfig, map[string]any{"query": "up"})
	if err != nil || r.ExitCode != 1 || r.StatusCode != 400 || !strings.Contains(r.Stderr, "bad_data") {
		t.Errorf("result = %+v, %v", r, err)
	}
	// An invalid configuration fails the run with exit code 1 as well.
	bad := prometheusAction("query", map[string]any{"timeout": (31 * time.Second).String()})
	if r, err := Builtins["prometheus_query"].Run(context.Background(), bad.BuiltinConfig, map[string]any{"query": "up"}); err == nil || r.ExitCode != 1 {
		t.Errorf("invalid config run = %+v, %v", r, err)
	}
}

func TestPrometheusExplicitZeroStepIsRejected(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[]}}`)
	}))
	defer server.Close()
	a := prometheusAction("query_range", map[string]any{"address": server.URL})
	defs, err := ParameterDefinitions(a)
	if err != nil {
		t.Fatal(err)
	}
	values, err := params.Parse(defs, map[string]any{"query": "up", "start": "now-1h", "step": "0s"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Builtins["prometheus_query"].Run(context.Background(), a.BuiltinConfig, values)
	if err == nil || r.ExitCode != 1 || requests != 0 {
		t.Errorf("step=0s accepted: %+v err=%v requests=%d", r, err, requests)
	}
	// Omitting step still selects the derived step.
	values, _ = params.Parse(defs, map[string]any{"query": "up", "start": "now-1h"})
	if _, err := Builtins["prometheus_query"].Run(context.Background(), a.BuiltinConfig, values); err != nil || requests != 1 {
		t.Errorf("omitted step: err=%v requests=%d", err, requests)
	}
}
