package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
)

const builtinSecret = "AKIAABCDEFGHIJKLMNOP"
const builtinSecretMask = "[REDACTED:aws_access_key]"

func localBuiltinAction(name string, config map[string]any) catalog.Action {
	return catalog.Action{Name: name, Description: name, Risk: "read", Builtin: name, BuiltinConfig: config, Timeout: "2s", MaxOutput: 1024, Filters: []string{"match", "exclude", "head", "tail", "count"}}
}

func TestBuiltinLogSearchE2E(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	text := builtinSecret + "\nkeep first\nkeep skip\nkeep final\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	a := localBuiltinAction("log_search", map[string]any{"allowed_roots": []string{dir}})
	input := map[string]any{"path_glob": path, "pattern": ".", "fixed": false}
	a.MaxOutput = catalog.Size(len(path+":1:") + 8)
	r, err := RunWithFilters(context.Background(), a, input, nil, nil)
	want := path + ":1:" + builtinSecretMask[:8]
	if err != nil || r.ExitCode != 0 || r.Stdout != want || !r.Truncated || strings.Contains(r.Stdout, "AKIA") {
		t.Fatalf("redact before cap: %+v %v; want %q", r, err, want)
	}
	a.MaxOutput = 2
	r, err = RunWithFilters(context.Background(), a, input, map[string]any{"match": "AKIA", "count": true}, nil)
	if err != nil || r.Stdout != "0\n" {
		t.Fatalf("raw-secret filter: %+v %v", r, err)
	}
	input["pattern"] = "keep"
	input["exclude"] = "skip"
	input["fixed"] = true
	r, err = RunWithFilters(context.Background(), a, input, map[string]any{"exclude": "first", "count": true}, nil)
	if err != nil || r.Stdout != "1\n" {
		t.Fatalf("independent excludes: %+v %v", r, err)
	}
	r, err = Run(context.Background(), a, maps.Clone(input), nil)
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("compatibility handler exclude: %+v %v", r, err)
	}
	a.MaxOutput = 1024
	a.BuiltinConfig["max_matches"] = 1
	delete(input, "exclude")
	r, err = RunWithFilters(context.Background(), a, input, nil, nil)
	if err != nil || !r.Truncated || !r.ResourceLimitReached || strings.Count(r.Stdout, "\n") != 1 {
		t.Fatalf("match resource cap: %+v %v", r, err)
	}
	input["max_matches"] = 2
	if _, err := RunWithFilters(context.Background(), a, input, nil, nil); err == nil {
		t.Fatal("widened parameter accepted")
	}
	delete(input, "max_matches")
	input["pattern"] = "absent"
	r, err = RunWithFilters(context.Background(), a, input, nil, nil)
	if err != nil || r.ExitCode != 0 || r.Stdout != "" {
		t.Fatalf("no matches: %+v %v", r, err)
	}
}

func TestBuiltinHTTPGetE2E(t *testing.T) {
	var requests atomic.Int32
	body := builtinSecret + "\nvisible\n"
	prefix := fmt.Sprintf("HTTP 200\nContent-Type: text/plain\nContent-Length: %d\n\n", len(body))
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		if r.URL.Path == "/status" {
			w.WriteHeader(503)
		}
		fmt.Fprint(w, body)
	}))
	defer s.Close()
	a := localBuiltinAction("http_get", map[string]any{"allowed_prefixes": []string{s.URL}})
	input := map[string]any{"url": s.URL}
	a.MaxOutput = catalog.Size(len(prefix) + 8)
	r, err := RunWithFilters(context.Background(), a, input, nil, nil)
	want := prefix + builtinSecretMask[:8]
	if err != nil || r.Stdout != want || !r.Truncated || strings.Contains(r.Stdout, "AKIA") {
		t.Fatalf("redact before cap: %+v %v; want %q", r, err, want)
	}
	a.MaxOutput = 8
	r, err = RunWithFilters(context.Background(), a, input, map[string]any{"match": "visible"}, nil)
	if err != nil || r.Stdout != "visible\n" || r.Truncated {
		t.Fatalf("handler must not cap at max_output: %+v %v", r, err)
	}
	r, err = RunWithFilters(context.Background(), a, input, map[string]any{"match": "AKIA", "count": true}, nil)
	if err != nil || r.Stdout != "0\n" {
		t.Fatalf("filter after redaction: %+v %v", r, err)
	}
	a.MaxOutput = 1024
	a.BuiltinConfig["max_response_bytes"] = catalog.Size(20)
	r, err = RunWithFilters(context.Background(), a, input, nil, nil)
	if err != nil || r.ExitCode != 0 || !r.Truncated || !r.ResourceLimitReached {
		t.Fatalf("response cap: %+v %v", r, err)
	}
	delete(a.BuiltinConfig, "max_response_bytes")
	input["url"] = s.URL + "/status"
	r, err = RunWithFilters(context.Background(), a, input, nil, nil)
	data, _ := json.Marshal(r)
	var metadata map[string]any
	_ = json.Unmarshal(data, &metadata)
	if err != nil || r.ExitCode != 0 || metadata["status_code"] != float64(503) {
		t.Fatalf("non-2xx status: %+v %v, metadata=%s", r, err, data)
	}
	before := requests.Load()
	a.BuiltinConfig["max_response_bytes"] = "65KB"
	if _, err := RunWithFilters(context.Background(), a, input, nil, nil); err == nil || requests.Load() != before {
		t.Fatal("widened response config reached server")
	}
}

func TestBuiltinHTTPErrorOutputUsesPipeline(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Header().Set("Location", "http://demo:synthetic-password@example.invalid/private")
		w.WriteHeader(200)
	}))
	defer s.Close()
	a := localBuiltinAction("http_get", map[string]any{"allowed_prefixes": []string{s.URL}})
	a.MaxOutput = 2
	r, err := RunWithFilters(context.Background(), a, map[string]any{"url": s.URL}, map[string]any{"match": "REDACTED", "count": true}, nil)
	if err == nil || r.ExitCode != 1 || r.StatusCode != 200 || r.Stdout != "1\n" {
		t.Fatalf("partial error output pipeline: %+v %v", r, err)
	}
}
