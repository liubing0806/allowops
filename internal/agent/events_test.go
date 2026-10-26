package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
)

func TestAgentReportsEventsBeforeActionFinishes(t *testing.T) {
	g, _, config := startGateway(t, false)
	a, _ := startAgent(t, config)
	c := connection(t, g)
	action := catalog.Action{Name: "live_steps", Description: "live steps", Risk: "read", Steps: []catalog.Step{{Name: "first", Exec: []any{"/usr/bin/printf", "first"}}, {Name: "waiting", Exec: []any{"/usr/bin/sleep", "3"}}}, Timeout: "5s", MaxOutput: 1024}
	p, notice := publish(t, g, a, []catalog.Action{action}, time.Now(), time.Hour)
	c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}})
	c.next(t, func(m *v1.ConnectRequest) bool { return m.GetCatalogLoad() != nil })
	sendTask(t, c, task(p, action.Name, "live"))
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	started := false
	for {
		select {
		case message := <-c.messages:
			if message.GetTaskStarted().GetTaskId() == "live" {
				started = true
			}
			if step := message.GetStepCompleted(); step != nil && step.TaskId == "live" {
				if !started || step.StepIndex != 0 {
					t.Fatalf("event order: started=%v step=%v", started, step)
				}
				c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{JobId: "job-test", TaskId: "live"}}})
				collectTask(t, c, "live")
				return
			}
		case <-timer.C:
			t.Fatalf("events withheld until action finishes: TaskStarted=%v, StepCompleted=false", started)
		}
	}
}

func TestAgentBuiltinCapabilitiesAndCatalogUnsupported(t *testing.T) {
	g, _, config := startGateway(t, false)
	a, _ := startAgent(t, config)
	c := connection(t, g)
	for _, name := range []string{"log_search", "log_query", "http_get", "redis_command", "mysql_query", "prometheus_query", "alertmanager_alerts", "starrocks_query", "dremio_query", "starrocks_diag"} {
		if !slices.Contains(c.hello.Capabilities.Builtins, name) {
			t.Fatalf("missing builtin %s: %v", name, c.hello)
		}
	}
	if !slices.Contains(c.hello.Capabilities.ParameterTypes, "bool") || !slices.Contains(c.hello.Capabilities.ParameterTypes, "string_array") || len(c.hello.Capabilities.OutputFilters) != 5 {
		t.Fatalf("capabilities=%v", c.hello.Capabilities)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("password=secret\nbody\n"))
	}))
	defer server.Close()
	logs := t.TempDir()
	path := filepath.Join(logs, "host.log")
	if err := os.WriteFile(path, []byte("match password=secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	actions := []catalog.Action{
		{Name: "logs", Description: "logs", Risk: "read", Builtin: "log_search", BuiltinConfig: map[string]any{"allowed_roots": []string{logs}}, Timeout: "5s", MaxOutput: 4096},
		{Name: "http", Description: "http", Risk: "read", Builtin: "http_get", BuiltinConfig: map[string]any{"allowed_prefixes": []string{server.URL + "/"}}, Timeout: "5s", MaxOutput: 4096},
		{Name: "future", Description: "future", Risk: "read", Builtin: "future_builtin", Timeout: "5s", MaxOutput: 1024},
	}
	p, notice := publish(t, g, a, actions, time.Now(), time.Hour)
	c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}})
	report := c.next(t, func(m *v1.ConnectRequest) bool { return m.GetCatalogLoad() != nil }).GetCatalogLoad()
	if !report.Loaded || len(report.UnsupportedActions) != 1 || report.UnsupportedActions[0].Action != "future" {
		t.Fatalf("load=%v", report)
	}
	for _, scenario := range []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"logs", map[string]any{"path_glob": path, "pattern": "match", "fixed": true}, "match [REDACTED:credential]"},
		{"http", map[string]any{"url": server.URL + "/"}, "HTTP 404"},
		{"future", map[string]any{}, ""},
	} {
		assignment := task(p, scenario.name, scenario.name)
		var err error
		assignment.Params.Json, err = json.Marshal(scenario.params)
		if err != nil {
			t.Fatal(err)
		}
		sendTask(t, c, assignment)
		messages := collectTask(t, c, scenario.name)
		var output strings.Builder
		started := false
		for _, m := range messages {
			if m.GetTaskStarted() != nil {
				started = true
			}
			if chunk := m.GetOutput(); chunk != nil && chunk.Stream == v1.OutputStream_OUTPUT_STREAM_STDOUT {
				output.Write(chunk.Data)
			}
		}
		result := messages[len(messages)-1].GetTaskCompleted().Result
		if scenario.name == "future" {
			if started || result.Status != v1.TaskStatus_TASK_STATUS_UNSUPPORTED {
				t.Fatalf("unknown action: started=%v result=%v", started, result)
			}
		} else if !started || result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED || !strings.Contains(output.String(), scenario.want) || strings.Contains(output.String(), "secret") {
			t.Fatalf("started=%v result=%v output=%q", started, result, output.String())
		}
	}
}
