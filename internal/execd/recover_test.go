package execd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/builtin/jvmarthas"
	"github.com/liubing0806/allowops/internal/executor"
)

func TestReadRequestAcceptsTheRecoveryOperation(t *testing.T) {
	r, err := ReadRequest(strings.NewReader(`{"operation":"arthas_recover"}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Operation != OperationArthasRecover {
		t.Errorf("operation = %q", r.Operation)
	}
}

func TestReadRequestRefusesTheRecoveryOperationWithOtherFields(t *testing.T) {
	for name, input := range map[string]string{
		"unknown operation": `{"operation":"shell"}`,
		"catalog id":        `{"operation":"arthas_recover","catalog_id":"test"}`,
		"version":           `{"operation":"arthas_recover","catalog_version":1}`,
		"action":            `{"operation":"arthas_recover","action":"identity"}`,
		"params":            `{"operation":"arthas_recover","params":{}}`,
		"filters":           `{"operation":"arthas_recover","filters":{}}`,
		"an action request": `{"operation":"arthas_recover","catalog_id":"test","catalog_version":1,"action":"a","params":{}}`,
		"empty operation":   `{"operation":""}`,
		"duplicate":         `{"operation":"arthas_recover","operation":"arthas_recover"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if r, err := ReadRequest(strings.NewReader(input)); err == nil {
				t.Errorf("accepted: %+v", r)
			}
		})
	}
}

func TestAnActionRequestHasNoOperation(t *testing.T) {
	r, err := ReadRequest(strings.NewReader(`{"catalog_id":"test","catalog_version":1,"action":"a","params":{}}`))
	if err != nil || r.Operation != "" {
		t.Errorf("request = %+v, err = %v", r, err)
	}
}

func TestRecoveryNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	called := stubRecovery(t, jvmarthas.Recovery{}, nil)
	response := ExecuteWithCallbacks(context.Background(), strings.NewReader(`{"operation":"arthas_recover"}`), executor.Callbacks{})
	if response.Reason != "ROOT_REQUIRED" {
		t.Errorf("reason = %q, want ROOT_REQUIRED", response.Reason)
	}
	if *called != 0 {
		t.Error("the recovery ran without root")
	}
}

// stubRecovery replaces the recovery and returns how often it ran.
func stubRecovery(t *testing.T, rec jvmarthas.Recovery, err error) *int {
	t.Helper()
	old := recoverArthas
	t.Cleanup(func() { recoverArthas = old })
	calls := 0
	recoverArthas = func(context.Context) (jvmarthas.Recovery, error) {
		calls++
		return rec, err
	}
	return &calls
}

func TestRunArthasRecoverReportsWhatItDid(t *testing.T) {
	calls := stubRecovery(t, jvmarthas.Recovery{Cleaned: 2, Stale: 1}, nil)
	started := 0
	response := runArthasRecover(context.Background(), executor.Callbacks{Started: func() error { started++; return nil }})
	if response.Reason != "" || response.Result.ExitCode != 0 {
		t.Fatalf("response = %+v", response)
	}
	if *calls != 1 || started != 1 {
		t.Errorf("recovery ran %d times, started %d times", *calls, started)
	}
	if !strings.Contains(response.Result.Stdout, "cleaned 2, stale 1") {
		t.Errorf("stdout = %q", response.Result.Stdout)
	}
}

func TestRunArthasRecoverWithNothingToDo(t *testing.T) {
	stubRecovery(t, jvmarthas.Recovery{}, nil)
	response := runArthasRecover(context.Background(), executor.Callbacks{})
	if response.Reason != "" || response.Result.ExitCode != 0 || response.Result.Stdout != "" {
		t.Errorf("response = %+v", response)
	}
}

func TestRunArthasRecoverFailsWhenARecordCannotBeCleared(t *testing.T) {
	stubRecovery(t, jvmarthas.Recovery{Cleaned: 1, Failed: []string{"the Arthas server on port 18570 of process 7 is still running"}}, nil)
	response := runArthasRecover(context.Background(), executor.Callbacks{})
	if response.Reason != "EXECUTION_FAILED" || response.Result.ExitCode != 1 {
		t.Fatalf("response = %+v", response)
	}
	if !strings.Contains(response.Result.Stderr, "port 18570") || !strings.Contains(response.Result.Stdout, "cleaned 1, failed 1") {
		t.Errorf("stdout = %q, stderr = %q", response.Result.Stdout, response.Result.Stderr)
	}
}

func TestRunArthasRecoverFailsWhenTheStateIsUnusable(t *testing.T) {
	stubRecovery(t, jvmarthas.Recovery{}, errors.New("state directory /var/lib/allowops-exec/arthas must belong to uid 0"))
	response := runArthasRecover(context.Background(), executor.Callbacks{})
	if response.Reason != "EXECUTION_FAILED" || response.Result.ExitCode != 1 || !strings.Contains(response.Result.Stderr, "state directory") {
		t.Errorf("response = %+v", response)
	}
}

func TestRunArthasRecoverReportsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	old := recoverArthas
	t.Cleanup(func() { recoverArthas = old })
	recoverArthas = func(ctx context.Context) (jvmarthas.Recovery, error) {
		cancel()
		return jvmarthas.Recovery{Cleaned: 1}, ctx.Err()
	}
	response := runArthasRecover(ctx, executor.Callbacks{})
	if response.Reason != "CANCELLED" {
		t.Errorf("reason = %q, want CANCELLED", response.Reason)
	}
}

func TestRunArthasRecoverStopsWhenStartedCannotBeReported(t *testing.T) {
	calls := stubRecovery(t, jvmarthas.Recovery{}, nil)
	response := runArthasRecover(context.Background(), executor.Callbacks{Started: func() error { return errors.New("pipe closed") }})
	if response.Reason == "" || *calls != 0 {
		t.Errorf("reason = %q, recovery ran %d times", response.Reason, *calls)
	}
}
