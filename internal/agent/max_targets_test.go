package agent

import (
	"slices"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
)

// max_targets is enforced by the gateway, but it is part of the signed action.
// An agent that does not know the field rejects the whole package, so the agent
// reports the feature and must load and run an action that carries it.
func TestAgentReportsAndLoadsMaxTargets(t *testing.T) {
	g, _, cfg := startGateway(t, false)
	a, _ := startAgent(t, cfg)
	c := connection(t, g)
	if features := c.hello.GetCapabilities().GetFeatures(); !slices.Contains(features, "max_targets") {
		t.Fatalf("features=%v; want max_targets", features)
	}
	action, err := catalog.ParseAction([]byte("name: limited\ndescription: limited\nrisk: read\nexec: [/usr/bin/printf, ok]\ntimeout: 5s\nmax_output: 1KB\nmax_targets: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	p, notice := publish(t, g, a, []catalog.Action{action}, time.Now(), time.Hour)
	c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}})
	report := c.next(t, func(m *v1.ConnectRequest) bool { return m.GetCatalogLoad() != nil }).GetCatalogLoad()
	if !report.Loaded || len(report.UnsupportedActions) != 0 {
		t.Fatalf("report=%v; want loaded without unsupported actions", report)
	}
	sendTask(t, c, task(p, "limited", "limited-task"))
	messages := collectTask(t, c, "limited-task")
	if result := messages[len(messages)-1].GetTaskCompleted().Result; result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED {
		t.Fatalf("result=%v", result)
	}
}
