//go:build guardrails

package guardrails

import "testing"

func TestRepoGuardrails(t *testing.T) {
	violations, err := Analyze("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range violations {
		t.Errorf("%s:%d:%d [%s] %s", v.File, v.Line, v.Column, v.Rule, v.Message)
	}
}
