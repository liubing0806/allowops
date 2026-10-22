package agent

import (
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
)

func TestAgentScanContractSuccess(t *testing.T) {
	for _, mode := range []string{"exec", "steps"} {
		t.Run(mode, func(t *testing.T) {
			g, _, config := startGateway(t, false)
			a, _ := startAgent(t, config)
			c := connection(t, g)
			action := catalog.Action{Name: "scan", Description: "scan", Risk: "read", Exec: []any{"/usr/bin/printf", `one\ntwo\nthree\n`}, Timeout: "5s", MaxOutput: 1024, MaxScan: 8}
			if mode == "steps" {
				action.Steps = []catalog.Step{{Name: "capped", Exec: action.Exec}, {Name: "next", Exec: []any{"/usr/bin/printf", `next\n`}}}
				action.Exec = nil
				action.OnError = "stop"
			}
			p, notice := publish(t, g, a, []catalog.Action{action}, time.Now(), time.Hour)
			c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}})
			if !c.next(t, func(m *v1.ConnectRequest) bool { return m.GetCatalogLoad() != nil }).GetCatalogLoad().Loaded {
				t.Fatal("load failed")
			}
			sendTask(t, c, task(p, "scan", "scan"))
			messages := collectTask(t, c, "scan")
			result := messages[len(messages)-1].GetTaskCompleted().Result
			if result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED || result.ExitCode == nil || *result.ExitCode != 0 || !result.ScanLimitReached {
				t.Errorf("scan task=%v; want succeeded/exit0/scan_limit", result)
			}
			if mode == "steps" {
				steps := 0
				for _, m := range messages {
					if s := m.GetStepCompleted(); s != nil {
						steps++
						if s.Result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED {
							t.Errorf("step=%v; want succeeded", s)
						}
					}
				}
				if steps != 2 {
					t.Errorf("steps=%d want2", steps)
				}
			}
		})
	}
}
