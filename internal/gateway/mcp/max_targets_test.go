package mcp

import (
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/job"
)

func maxTargetsTool(t *testing.T, field string) *ToolDefinition {
	t.Helper()
	a, err := catalog.ParseAction([]byte("name: limited_read\ndescription: Read something\nrisk: read\nexec: [/usr/bin/true]\ntimeout: 1s\nmax_output: 1KB\n" + field))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.ValidateAction(a); err != nil {
		t.Fatal(err)
	}
	tool, err := actionTool(a, job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return tool
}

func targetsDescription(t *testing.T, tool *ToolDefinition) string {
	t.Helper()
	properties, _ := tool.InputSchema["properties"].(map[string]any)
	targets, _ := properties["targets"].(map[string]any)
	description, _ := targets["description"].(string)
	if description == "" {
		t.Fatalf("targets description missing: %v", properties["targets"])
	}
	return description
}

func TestActionToolStatesMaxTargetsOnlyWhenSet(t *testing.T) {
	for field, want := range map[string]string{"max_targets: 1\n": "at most 1 target host", "max_targets: 3\n": "at most 3 target hosts"} {
		tool := maxTargetsTool(t, field)
		if !strings.Contains(tool.Description, want) || !strings.Contains(targetsDescription(t, tool), want) {
			t.Errorf("%q: description=%q targets=%q; want both to contain %q", field, tool.Description, targetsDescription(t, tool), want)
		}
	}
	tool := maxTargetsTool(t, "")
	for _, text := range []string{tool.Description, targetsDescription(t, tool)} {
		if strings.Contains(text, "at most") || strings.Contains(text, "max_targets") {
			t.Errorf("limit stated without max_targets: %q", text)
		}
	}
}
