package agent

import (
	"slices"
	"strings"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
)

// toolset, tags and entity_kinds only guide the gateway, but they are part of
// the signed action. An agent that does not know them rejects the whole
// package, so the agent reports the feature and must load and run an action
// that carries them.
func TestAgentReportsAndLoadsActionMetadata(t *testing.T) {
	g, _, cfg := startGateway(t, false)
	a, _ := startAgent(t, cfg)
	c := connection(t, g)
	if features := c.hello.GetCapabilities().GetFeatures(); !slices.Contains(features, "action_metadata") {
		t.Fatalf("features=%v; want action_metadata", features)
	}
	action, err := catalog.ParseAction([]byte("name: tagged\ndescription: tagged\nrisk: read\nexec: [/usr/bin/printf, ok]\ntimeout: 5s\nmax_output: 1KB\ntoolset: jvm\ntags: [gc, heap]\nentity_kinds: [jvm]\n"))
	if err != nil {
		t.Fatal(err)
	}
	p, notice := publish(t, g, a, []catalog.Action{action}, time.Now(), time.Hour)
	if signed := p.Actions["tagged"]; signed.Toolset != "jvm" || !slices.Equal(signed.Tags, []string{"gc", "heap"}) || !slices.Equal(signed.EntityKinds, []string{"jvm"}) {
		t.Fatalf("signed action lacks metadata: %+v", signed)
	}
	c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}})
	report := c.next(t, func(m *v1.ConnectRequest) bool { return m.GetCatalogLoad() != nil }).GetCatalogLoad()
	if !report.Loaded || len(report.UnsupportedActions) != 0 {
		t.Fatalf("report=%v; want loaded without unsupported actions", report)
	}
	sendTask(t, c, task(p, "tagged", "tagged-task"))
	messages := collectTask(t, c, "tagged-task")
	if result := messages[len(messages)-1].GetTaskCompleted().Result; result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED {
		t.Fatalf("result=%v", result)
	}
	var output strings.Builder
	for _, m := range messages {
		output.Write(m.GetOutput().GetData())
	}
	if output.String() != "ok" {
		t.Fatalf("output=%q; want ok", output.String())
	}
}
