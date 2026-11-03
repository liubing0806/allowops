package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// sessionHarness calls (*Agent).session directly so that every return value is
// observable; Agent.Run discards them.
type sessionHarness struct {
	g      *testGateway
	a      *Agent
	client allowopsv1connect.AgentServiceClient
	cancel context.CancelFunc
	ctx    context.Context
}

type sessionOutcome struct {
	delay time.Duration
	err   error
}

func newSessionHarness(t *testing.T, limits Limits) *sessionHarness {
	t.Helper()
	g, _, config := startGateway(t, false)
	config.Limits = limits
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Join(context.Background(), config, "test-token", "test-host", dataDir); err != nil {
		t.Fatal(err)
	}
	a, err := New(config, Options{DataDir: dataDir, KeysDir: t.TempDir(), KeyOwner: os.Getuid(), Version: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	client, transport, err := newClient(a.config, a.identity)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(func() { cancel(); transport.CloseIdleConnections() })
	return &sessionHarness{g: g, a: a, client: client, cancel: cancel, ctx: ctx}
}

func (h *sessionHarness) start() <-chan sessionOutcome {
	done := make(chan sessionOutcome, 1)
	go func() {
		delay, err := h.a.session(h.ctx, h.client)
		done <- sessionOutcome{delay, err}
	}()
	return done
}

func waitOutcome(t *testing.T, done <-chan sessionOutcome) sessionOutcome {
	t.Helper()
	select {
	case outcome := <-done:
		return outcome
	case <-time.After(20 * time.Second):
		t.Fatal("session did not return")
		return sessionOutcome{}
	}
}

func hello(mutate func(*v1.GatewayHello)) *v1.ConnectResponse {
	value := &v1.GatewayHello{GatewayVersion: "0.1.0", ConnectionId: "test-connection", Limits: &v1.ConnectionLimits{HeartbeatInterval: durationpb.New(50 * time.Millisecond), HeartbeatTimeout: durationpb.New(time.Second), MaxMessageBytes: MaxMessageBytes, MaxChunkBytes: 7, MaxInflightTasks: MaxConcurrentTasks}}
	if mutate != nil {
		mutate(value)
	}
	return &v1.ConnectResponse{Message: &v1.ConnectResponse_Hello{Hello: value}}
}

func cancelMessage(job, task string) *v1.ConnectResponse {
	return &v1.ConnectResponse{Message: &v1.ConnectResponse_Cancel{Cancel: &v1.CancelTask{JobId: job, TaskId: task}}}
}

func reconnectMessage(closeAt time.Time, min, max time.Duration) *v1.ConnectResponse {
	return &v1.ConnectResponse{Message: &v1.ConnectResponse_Reconnect{Reconnect: &v1.Reconnect{CloseAt: timestamppb.New(closeAt), RetryAfterMin: durationpb.New(min), RetryAfterMax: durationpb.New(max)}}}
}

func TestSessionHandshakeFailures(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		hello   func() (*v1.ConnectResponse, error)
		silent  bool
		want    string
		timeout bool
	}{
		{name: "stream ends before hello", hello: func() (*v1.ConnectResponse, error) {
			return nil, connect.NewError(connect.CodeAborted, errors.New("closed"))
		}},
		{name: "heartbeat instead of hello", hello: func() (*v1.ConnectResponse, error) {
			return &v1.ConnectResponse{Message: &v1.ConnectResponse_Heartbeat{Heartbeat: &v1.GatewayHeartbeat{Sequence: 1}}}, nil
		}, want: "INVALID_GATEWAY_HELLO"},
		{name: "empty connection id", hello: func() (*v1.ConnectResponse, error) {
			return hello(func(h *v1.GatewayHello) { h.ConnectionId = "" }), nil
		}, want: "INVALID_GATEWAY_HELLO"},
		{name: "missing limits", hello: func() (*v1.ConnectResponse, error) {
			return hello(func(h *v1.GatewayHello) { h.Limits = nil }), nil
		}, want: "INVALID_GATEWAY_HELLO"},
		{name: "missing heartbeat interval", hello: func() (*v1.ConnectResponse, error) {
			return hello(func(h *v1.GatewayHello) { h.Limits.HeartbeatInterval = nil }), nil
		}, want: "INVALID_CONNECTION_LIMITS"},
		{name: "invalid heartbeat timeout", hello: func() (*v1.ConnectResponse, error) {
			return hello(func(h *v1.GatewayHello) { h.Limits.HeartbeatTimeout = &durationpb.Duration{Seconds: 1, Nanos: -1} }), nil
		}, want: "INVALID_CONNECTION_LIMITS"},
		{name: "timeout not above interval", hello: func() (*v1.ConnectResponse, error) {
			return hello(func(h *v1.GatewayHello) { h.Limits.HeartbeatTimeout = h.Limits.HeartbeatInterval }), nil
		}, want: "INVALID_CONNECTION_LIMITS"},
		{name: "zero message size", hello: func() (*v1.ConnectResponse, error) {
			return hello(func(h *v1.GatewayHello) { h.Limits.MaxMessageBytes = 0 }), nil
		}, want: "INVALID_CONNECTION_LIMITS"},
		{name: "zero inflight tasks", hello: func() (*v1.ConnectResponse, error) {
			return hello(func(h *v1.GatewayHello) { h.Limits.MaxInflightTasks = 0 }), nil
		}, want: "INVALID_CONNECTION_LIMITS"},
		{name: "hello timeout", hello: func() (*v1.ConnectResponse, error) { return nil, nil }, want: "HELLO_TIMEOUT", timeout: true},
		{name: "heartbeat timeout", silent: true, hello: func() (*v1.ConnectResponse, error) {
			return hello(func(h *v1.GatewayHello) {
				h.Limits.HeartbeatInterval = durationpb.New(10 * time.Millisecond)
				h.Limits.HeartbeatTimeout = durationpb.New(150 * time.Millisecond)
			}), nil
		}, want: "HEARTBEAT_TIMEOUT"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			h := newSessionHarness(t, Limits{})
			h.g.mu.Lock()
			h.g.hello, h.g.silent = scenario.hello, scenario.silent
			h.g.mu.Unlock()
			started := time.Now()
			outcome := waitOutcome(t, h.start())
			if outcome.err == nil || !strings.Contains(outcome.err.Error(), scenario.want) || outcome.delay != 0 {
				t.Fatalf("outcome=%+v want error containing %q", outcome, scenario.want)
			}
			if scenario.timeout && time.Since(started) < 9*time.Second {
				t.Fatalf("hello timeout after %s", time.Since(started))
			}
		})
	}
}

func TestSessionRejectsInvalidGatewayMessages(t *testing.T) {
	small := Limits{MessageBytes: 2048, ChunkBytes: 512, ControlMessages: 2}
	longID := strings.Repeat("t", 1000)
	taskMessage := func(id string) *v1.ConnectResponse {
		return &v1.ConnectResponse{Message: &v1.ConnectResponse_Task{Task: &v1.TaskAssignment{JobId: "job", TaskId: id}}}
	}
	for _, scenario := range []struct {
		name   string
		limits Limits
		// gatewayMaxMessage lowers the message size announced in the gateway hello.
		gatewayMaxMessage uint32
		messages          []*v1.ConnectResponse
		want              string
	}{
		{name: "unexpected sequence", messages: []*v1.ConnectResponse{{Message: &v1.ConnectResponse_Heartbeat{Heartbeat: &v1.GatewayHeartbeat{Sequence: 99}}}}, want: "INVALID_HEARTBEAT"},
		{name: "zero sequence", messages: []*v1.ConnectResponse{{Message: &v1.ConnectResponse_Heartbeat{Heartbeat: &v1.GatewayHeartbeat{}}}}, want: "INVALID_HEARTBEAT"},
		{name: "empty message", messages: []*v1.ConnectResponse{{}}, want: "UNKNOWN_MESSAGE"},
		{name: "task without id", messages: []*v1.ConnectResponse{taskMessage("")}, want: "INVALID_TASK"},
		{name: "task without job", messages: []*v1.ConnectResponse{{Message: &v1.ConnectResponse_Task{Task: &v1.TaskAssignment{TaskId: "x"}}}}, want: "INVALID_TASK"},
		{name: "reconnect without close time", messages: []*v1.ConnectResponse{{Message: &v1.ConnectResponse_Reconnect{Reconnect: &v1.Reconnect{RetryAfterMin: durationpb.New(time.Second), RetryAfterMax: durationpb.New(time.Second)}}}}, want: "INVALID_RECONNECT"},
		{name: "reconnect without retry bounds", messages: []*v1.ConnectResponse{{Message: &v1.ConnectResponse_Reconnect{Reconnect: &v1.Reconnect{CloseAt: timestamppb.Now()}}}}, want: "INVALID_RECONNECT"},
		{name: "reconnect with negative retry", messages: []*v1.ConnectResponse{reconnectMessage(time.Now(), -time.Second, time.Second)}, want: "INVALID_RECONNECT"},
		{name: "reconnect with inverted retry bounds", messages: []*v1.ConnectResponse{reconnectMessage(time.Now(), 10*time.Second, 2*time.Second)}, want: "INVALID_RECONNECT"},
		{name: "receive rate", limits: Limits{ReceiveBurst: 1, ReceiveRate: 1}, messages: []*v1.ConnectResponse{cancelMessage("job", "a"), cancelMessage("job", "b")}, want: "RECEIVE_LIMIT_EXCEEDED"},
		{name: "message above the gateway limit", gatewayMaxMessage: 1024, messages: []*v1.ConnectResponse{cancelMessage(strings.Repeat("j", 3000), "a")}, want: "RECEIVE_LIMIT_EXCEEDED"},
		{name: "task history", limits: small, messages: []*v1.ConnectResponse{taskMessage("a" + longID), taskMessage("b" + longID), taskMessage("c" + longID), taskMessage("d" + longID), taskMessage("e" + longID)}, want: "TASK_HISTORY_LIMIT_EXCEEDED"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			h := newSessionHarness(t, scenario.limits)
			if scenario.gatewayMaxMessage != 0 {
				h.g.mu.Lock()
				h.g.hello = func() (*v1.ConnectResponse, error) {
					return hello(func(g *v1.GatewayHello) { g.Limits.MaxMessageBytes = scenario.gatewayMaxMessage }), nil
				}
				h.g.mu.Unlock()
			}
			done := h.start()
			c := connection(t, h.g)
			for _, message := range scenario.messages {
				c.send(t, message)
			}
			outcome := waitOutcome(t, done)
			if outcome.err == nil || outcome.err.Error() != scenario.want || outcome.delay != 0 {
				t.Fatalf("outcome=%+v err=%v want %q", outcome, outcome.err, scenario.want)
			}
		})
	}
}

func TestSessionCatalogWorkerFailures(t *testing.T) {
	t.Run("invalid notice cancels the session", func(t *testing.T) {
		t.Parallel()
		h := newSessionHarness(t, Limits{})
		done := h.start()
		c := connection(t, h.g)
		c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: &v1.CatalogAvailable{}}})
		outcome := waitOutcome(t, done)
		if !errors.Is(outcome.err, context.Canceled) || outcome.delay != 0 {
			t.Fatalf("outcome=%+v", outcome)
		}
	})
	t.Run("full notice queue", func(t *testing.T) {
		t.Parallel()
		h := newSessionHarness(t, Limits{ControlMessages: 2})
		action := catalog.Action{Name: "noop", Description: "noop", Risk: "read", Exec: []any{"/usr/bin/true"}, Timeout: "5s", MaxOutput: 1024}
		_, notice := publish(t, h.g, h.a, []catalog.Action{action}, time.Now(), time.Hour)
		pulling := make(chan struct{}, 1)
		h.g.mu.Lock()
		h.g.blockPull = true
		h.g.pulling = pulling
		h.g.mu.Unlock()
		done := h.start()
		c := connection(t, h.g)
		available := &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}}
		// The single catalog worker holds the first notice in a blocked pull.
		c.send(t, available)
		select {
		case <-pulling:
		case <-time.After(5 * time.Second):
			t.Fatal("catalog pull did not start")
		}
		// Two notices fill the queue and the third overflows it. Nothing is sent
		// after that: the session ends and closes the stream.
		for range 3 {
			c.send(t, available)
		}
		outcome := waitOutcome(t, done)
		if outcome.err == nil || outcome.err.Error() != "CATALOG_QUEUE_FULL" || outcome.delay != 0 {
			t.Fatalf("outcome=%+v", outcome)
		}
	})
}

func TestSessionCapacityAndDrain(t *testing.T) {
	h := newSessionHarness(t, Limits{ConcurrentTasks: 2})
	sleeper := catalog.Action{Name: "sleeper", Description: "sleeper", Risk: "read", Exec: []any{"/usr/bin/sleep", "30"}, Timeout: "40s", MaxOutput: 1024}
	p, notice := publish(t, h.g, h.a, []catalog.Action{sleeper}, time.Now(), time.Hour)
	done := h.start()
	c := connection(t, h.g)
	c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}})
	c.next(t, func(m *v1.ConnectRequest) bool { return m.GetCatalogLoad() != nil })
	rejected := func(id string) {
		t.Helper()
		sendTask(t, c, task(p, "sleeper", id))
		result := collectTask(t, c, id)[0].GetTaskCompleted().GetResult()
		if result.GetStatus() != v1.TaskStatus_TASK_STATUS_FAILED || result.GetReason() != "AGENT_CAPACITY_EXCEEDED" {
			t.Fatalf("task %s result=%v", id, result)
		}
	}
	for _, id := range []string{"run-1", "run-2"} {
		sendTask(t, c, task(p, "sleeper", id))
		c.next(t, func(m *v1.ConnectRequest) bool { return m.GetTaskStarted().GetTaskId() == id })
	}
	rejected("over-capacity")
	// The agent stops accepting tasks after a reconnect notice, and a second notice
	// replaces the first close timer.
	closeAt := time.Now().Add(400 * time.Millisecond)
	c.send(t, reconnectMessage(time.Now().Add(time.Hour), time.Second, time.Second))
	c.send(t, reconnectMessage(closeAt, time.Second, time.Second))
	select {
	case outcome := <-done:
		t.Fatalf("session ended before the close time: %+v", outcome)
	case <-time.After(100 * time.Millisecond):
	}
	outcome := waitOutcome(t, done)
	if outcome.err != nil || outcome.delay != time.Second || time.Now().Before(closeAt.Add(-50*time.Millisecond)) {
		t.Fatalf("outcome=%+v at %s (close at %s)", outcome, time.Now(), closeAt)
	}
}

func TestSessionDrainRejectsNewTasks(t *testing.T) {
	h := newSessionHarness(t, Limits{ConcurrentTasks: 2})
	sleeper := catalog.Action{Name: "sleeper", Description: "sleeper", Risk: "read", Exec: []any{"/usr/bin/sleep", "30"}, Timeout: "40s", MaxOutput: 1024}
	p, notice := publish(t, h.g, h.a, []catalog.Action{sleeper}, time.Now(), time.Hour)
	done := h.start()
	c := connection(t, h.g)
	c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}})
	c.next(t, func(m *v1.ConnectRequest) bool { return m.GetCatalogLoad() != nil })
	sendTask(t, c, task(p, "sleeper", "running"))
	c.next(t, func(m *v1.ConnectRequest) bool { return m.GetTaskStarted().GetTaskId() == "running" })
	c.send(t, reconnectMessage(time.Now().Add(time.Hour), time.Second, time.Second))
	sendTask(t, c, task(p, "sleeper", "late"))
	result := collectTask(t, c, "late")[0].GetTaskCompleted().GetResult()
	if result.GetStatus() != v1.TaskStatus_TASK_STATUS_FAILED || result.GetReason() != "AGENT_CAPACITY_EXCEEDED" {
		t.Fatalf("draining result=%v", result)
	}
	// A cancellation for the running task lets the draining session end.
	c.send(t, cancelMessage("job-test", "running"))
	completed := collectTask(t, c, "running")
	if status := completed[len(completed)-1].GetTaskCompleted().GetResult().GetStatus(); status == v1.TaskStatus_TASK_STATUS_SUCCEEDED {
		t.Fatalf("cancelled task status=%v", status)
	}
	outcome := waitOutcome(t, done)
	if outcome.err != nil || outcome.delay != time.Second {
		t.Fatalf("outcome=%+v", outcome)
	}
}
