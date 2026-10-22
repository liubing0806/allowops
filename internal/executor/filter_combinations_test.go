package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
)

func TestMutuallyExclusiveFilters(t *testing.T) {
	a := catalog.Action{Name: "filters", Description: "filters", Risk: "read", Exec: []any{"/bin/echo", "must-not-run"}, Timeout: "1s", MaxOutput: 1024, Filters: []string{"match", "exclude", "tail", "head", "count"}}
	for _, input := range []map[string]any{
		{"tail": 1, "head": 1}, {"tail": 1, "count": true}, {"head": 1, "count": true},
		{"tail": 1, "head": 1, "count": true}, {"head": 1, "count": false},
	} {
		options, err := ParseFilters(a.Filters, input)
		if err == nil || !strings.Contains(err.Error(), "allowed:") {
			t.Errorf("%v => options=%+v err=%v; want error listing allowed combinations", input, options, err)
		}
		result, err := Run(context.Background(), a, input, nil)
		if err == nil || result.Stdout != "" {
			t.Errorf("%v => result=%+v err=%v; want rejection before execution", input, result, err)
		}
	}
}
