package executor

import (
	"context"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
)

func TestStepBudgetIncludesBothStreams(t *testing.T) {
	a := helperAction("output")
	argv := a.Exec
	a.Exec = nil
	a.MaxOutput = 128
	a.Steps = []catalog.Step{{Name: "first", Exec: argv}, {Name: "second", Exec: argv}}
	r, err := Run(context.Background(), a, nil, nil)
	if err != nil || r.ExitCode != 0 || !r.Truncated {
		t.Fatalf("got %+v err=%v", r, err)
	}
	bytes := 0
	for _, step := range r.Steps {
		bytes += len(step.Stdout) + len(step.Stderr)
	}
	if bytes != 128 {
		t.Fatalf("all step stdout+stderr bytes=%d; want shared budget 128", bytes)
	}
}

func TestStepsKeepFirstDistinctFailureCode(t *testing.T) {
	a := helperAction("exit")
	second := a.Exec
	a.Exec = nil
	a.Steps = []catalog.Step{{Name: "first", Exec: []any{"/usr/bin/false"}}, {Name: "second", Exec: second}}
	r, err := Run(context.Background(), a, nil, nil)
	if err != nil || r.ExitCode != 1 || len(r.Steps) != 2 || r.Steps[0].ExitCode == nil || r.Steps[1].ExitCode == nil || *r.Steps[0].ExitCode != 1 || *r.Steps[1].ExitCode != 7 {
		t.Fatalf("got %+v err=%v; want first failure 1 followed by 7", r, err)
	}
}
