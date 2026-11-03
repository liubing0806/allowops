package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
	"github.com/liubing0806/allowops/internal/executor"
)

func TestHelloOffersJvmArthasOnlyWhereThePackageIsInstalled(t *testing.T) {
	_, _, config := startGateway(t, false)
	for _, installed := range []bool{true, false} {
		a := newAgentWith(t, config, func(o *Options) { o.ArthasInstalled = func() bool { return installed } })
		got := slices.Contains(a.hello().Capabilities.Builtins, "jvm_arthas")
		if got != installed {
			t.Errorf("installed = %v, but hello lists jvm_arthas = %v", installed, got)
		}
		if !slices.Contains(a.hello().Capabilities.Builtins, "jvm_perfdata") {
			t.Error("the other builtins disappeared from hello")
		}
	}
}

func TestAgentRecoversArthasSessionsInTheBackgroundAtStart(t *testing.T) {
	g, _, config := startGateway(t, false)
	release := make(chan struct{})
	called := make(chan struct{}, 4)
	startAgentWith(t, config, func(o *Options) {
		o.ArthasInstalled = func() bool { return true }
		o.Logf = func(string, ...any) {}
		o.RecoverArthas = func(ctx context.Context) (string, error) {
			called <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return "arthas recovery: cleaned 1", nil
		}
	})
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("the recovery did not run")
	}
	// The agent connects while the recovery is still running.
	connection(t, g)
	close(release)
	select {
	case <-called:
		t.Error("the recovery ran twice")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestAgentLogsWhatTheRecoveryDid(t *testing.T) {
	_, _, config := startGateway(t, false)
	logged := make(chan string, 4)
	startAgentWith(t, config, func(o *Options) {
		o.ArthasInstalled = func() bool { return true }
		o.Logf = func(format string, args ...any) { logged <- fmt.Sprintf(format, args...) }
		o.RecoverArthas = func(context.Context) (string, error) { return "arthas recovery: cleaned 2", nil }
	})
	select {
	case line := <-logged:
		if !strings.Contains(line, "cleaned 2") {
			t.Errorf("log line = %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was logged")
	}
}

func TestAgentStaysQuietWhenThereWasNothingToRecover(t *testing.T) {
	g, _, config := startGateway(t, false)
	var calls atomic.Int32
	var logged atomic.Int32
	startAgentWith(t, config, func(o *Options) {
		o.ArthasInstalled = func() bool { return true }
		o.Logf = func(string, ...any) { logged.Add(1) }
		o.RecoverArthas = func(context.Context) (string, error) { calls.Add(1); return "", nil }
	})
	connection(t, g)
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != 1 || logged.Load() != 0 {
		t.Errorf("recovery ran %d times and logged %d lines", calls.Load(), logged.Load())
	}
}

func TestAgentDoesNotRecoverWithoutThePackage(t *testing.T) {
	g, _, config := startGateway(t, false)
	var calls atomic.Int32
	startAgentWith(t, config, func(o *Options) {
		o.ArthasInstalled = func() bool { return false }
		o.RecoverArthas = func(context.Context) (string, error) { calls.Add(1); return "", nil }
	})
	connection(t, g)
	time.Sleep(200 * time.Millisecond)
	if calls.Load() != 0 {
		t.Errorf("the recovery ran %d times on a host without the Arthas package", calls.Load())
	}
}

func TestAgentConnectsAndLogsWhenTheRecoveryFails(t *testing.T) {
	g, _, config := startGateway(t, false)
	logged := make(chan string, 4)
	startAgentWith(t, config, func(o *Options) {
		o.ArthasInstalled = func() bool { return true }
		o.Logf = func(format string, args ...any) { logged <- fmt.Sprintf(format, args...) }
		o.RecoverArthas = func(context.Context) (string, error) { return "", errors.New("HELPER_FAILED") }
	})
	connection(t, g)
	select {
	case line := <-logged:
		if !strings.Contains(line, "failed") {
			t.Errorf("log line = %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the failure was not logged")
	}
}

func TestAgentStopWaitsForTheRecoveryToEnd(t *testing.T) {
	_, _, config := startGateway(t, false)
	var finished atomic.Bool
	entered := make(chan struct{})
	a := newAgentWith(t, config, func(o *Options) {
		o.ArthasInstalled = func() bool { return true }
		o.RecoverArthas = func(ctx context.Context) (string, error) {
			close(entered)
			<-ctx.Done()
			time.Sleep(300 * time.Millisecond) // the helper finishes its clean-up after the signal
			finished.Store(true)
			return "", ctx.Err()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the recovery did not run")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the agent did not stop")
	}
	if !finished.Load() {
		t.Error("Run returned while the recovery was still ending")
	}
}

func TestRecoveryRequestIsAcceptedByTheHelper(t *testing.T) {
	data := arthasRecoverRequest()
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil || len(fields) != 1 {
		t.Fatalf("request %q: %v", data, err)
	}
	request, err := execd.ReadRequest(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if request.Operation != execd.OperationArthasRecover {
		t.Errorf("operation = %q", request.Operation)
	}
}

func TestHelperEventsOfTheRecovery(t *testing.T) {
	encode := func(events ...execd.Event) string {
		var out strings.Builder
		for _, e := range events {
			if err := json.NewEncoder(&out).Encode(e); err != nil {
				t.Fatal(err)
			}
		}
		return out.String()
	}
	done := execd.Response{Result: executor.Result{ExitCode: 0, Stdout: "arthas recovery: cleaned 1\n"}}
	response, err := readHelperEvents(strings.NewReader(encode(execd.Event{Type: "started"}, execd.Event{Type: "completed", Response: &done})), catalog.Action{}, executor.Callbacks{})
	if err != nil || response.Result.Stdout != done.Result.Stdout {
		t.Errorf("response = %+v, err = %v", response, err)
	}
	if _, err := readHelperEvents(strings.NewReader(encode(execd.Event{Type: "completed", Response: &done})), catalog.Action{}, executor.Callbacks{}); err == nil {
		t.Error("a result without the started event was accepted")
	}
	failed := execd.Response{Result: executor.Result{ExitCode: 1, Stderr: "port 18570 is still open\n"}, Reason: "EXECUTION_FAILED"}
	result, err := recoveryOutcome(failed.Result, errors.New(failed.Reason))
	if err == nil || !strings.Contains(err.Error(), "port 18570") {
		t.Errorf("a failed recovery gave err = %v (result %q)", err, result)
	}
	summary, err := recoveryOutcome(done.Result, nil)
	if err != nil || summary != "arthas recovery: cleaned 1" {
		t.Errorf("summary = %q, err = %v", summary, err)
	}
}
