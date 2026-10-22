package agent

import (
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
)

func TestAgentMixedFutureParameterCatalog(t *testing.T) {
	g, _, cfg := startGateway(t, false)
	a, _ := startAgent(t, cfg)
	c := connection(t, g)
	known := catalog.Action{Name: "known", Description: "known", Risk: "read", Exec: []any{"/usr/bin/printf", "ok"}, Timeout: "5s", MaxOutput: 1024}
	future := known
	future.Name = "future"
	future.Params = map[string]params.Definition{"value": {Type: "future_type", Description: "future", Default: "future-default", MaxLen: 10, Regex: `^[a-z]+$`}}
	p, notice := publish(t, g, a, []catalog.Action{known, future}, time.Now(), time.Hour)
	c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}})
	report := c.next(t, func(m *v1.ConnectRequest) bool { return m.GetCatalogLoad() != nil }).GetCatalogLoad()
	if !report.Loaded || len(report.UnsupportedActions) != 1 || report.UnsupportedActions[0].Action != "future" {
		t.Fatalf("mixed catalog report=%v; want loaded and only future unsupported", report)
	}
	for _, name := range []string{"known", "future"} {
		sendTask(t, c, task(p, name, name))
		messages := collectTask(t, c, name)
		result := messages[len(messages)-1].GetTaskCompleted().Result
		want := v1.TaskStatus_TASK_STATUS_SUCCEEDED
		if name == "future" {
			want = v1.TaskStatus_TASK_STATUS_UNSUPPORTED
		}
		if result.Status != want {
			t.Errorf("%s: status=%v want=%v", name, result.Status, want)
		}
		if name == "future" {
			for _, m := range messages {
				if m.GetTaskStarted() != nil {
					t.Error("unsupported future action executed")
				}
			}
		}
	}
}
