package agent

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

type retryLogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *retryLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *retryLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func captureRetryLogs(t *testing.T) *retryLogBuffer {
	t.Helper()
	previous := slog.Default()
	var logs retryLogBuffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func TestAgentConnectionRetryLogs(t *testing.T) {
	h := newSessionHarness(t, Limits{ReconnectMin: time.Millisecond, ReconnectMax: time.Millisecond})
	logs := captureRetryLogs(t)
	var attempts atomic.Int32
	h.g.mu.Lock()
	h.g.hello = func() (*v1.ConnectResponse, error) {
		if attempts.Add(1) <= 3 {
			return nil, connect.NewError(connect.CodeUnimplemented, errors.New("agent version unsupported"))
		}
		return hello(nil), nil
	}
	h.g.mu.Unlock()
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.a.Run(ctx) }()
	c := connection(t, h.g)
	c.next(t, func(m *v1.ConnectRequest) bool { return m.GetHeartbeat() != nil })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	output := logs.String()
	if strings.Count(output, "agent connection ended") != 1 || !strings.Contains(output, "reason=VERSION_UNSUPPORTED retry_delay=1ms consecutive_failures=1") {
		t.Fatalf("expected one classified connection warning, got %q", output)
	}
	if strings.Count(output, "agent reconnected") != 1 || !strings.Contains(output, "consecutive_failures=3") {
		t.Fatalf("expected one recovery log after three failures, got %q", output)
	}
}

func TestAgentRenewalRetryLogs(t *testing.T) {
	h := newSessionHarness(t, Limits{ReconnectMin: time.Millisecond, ReconnectMax: time.Millisecond})
	logs := captureRetryLogs(t)
	h.g.mu.Lock()
	h.g.renewError = func(attempt int32) error {
		if attempt <= 3 {
			return connect.NewError(connect.CodeUnavailable, errors.New("sensitive-renewal-detail"))
		}
		return nil
	}
	h.g.mu.Unlock()
	value := h.a.identity.get()
	value.RenewAfter = time.Now()
	h.a.identity.set(value)
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	h.a.options.Sleep = func(ctx context.Context, delay time.Duration) error {
		if delay > time.Hour {
			cancel()
			return ctx.Err()
		}
		return sleep(ctx, delay)
	}
	if err := h.a.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if h.g.renewals.Load() != 4 {
		t.Fatalf("renewal attempts=%d, want 4", h.g.renewals.Load())
	}
	output := logs.String()
	if strings.Count(output, "agent certificate renewal failed") != 1 || !strings.Contains(output, "reason=RPC_UNAVAILABLE retry_delay=1ms consecutive_failures=1") {
		t.Fatalf("expected one classified renewal warning, got %q", output)
	}
	if strings.Contains(output, "sensitive-renewal-detail") {
		t.Fatalf("renewal log contains remote error text: %q", output)
	}
	if strings.Count(output, "agent certificate renewal recovered") != 1 || !strings.Contains(output, "consecutive_failures=3") {
		t.Fatalf("expected one recovery log after three failures, got %q", output)
	}
}

func TestAgentLogsCAPinMismatch(t *testing.T) {
	h := newSessionHarness(t, Limits{ReconnectMin: time.Millisecond, ReconnectMax: time.Millisecond})
	logs := captureRetryLogs(t)
	h.a.config.CAPin = "sha256:" + strings.Repeat("0", 64)
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	h.a.options.Sleep = func(ctx context.Context, delay time.Duration) error {
		if delay == time.Millisecond {
			cancel()
		}
		return sleep(ctx, delay)
	}
	if err := h.a.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if output := logs.String(); !strings.Contains(output, "reason=CA_PIN_MISMATCH retry_delay=1ms consecutive_failures=1") || strings.Contains(output, h.a.config.CAPin) {
		t.Fatalf("expected a CA pin mismatch warning without the pin, got %q", output)
	}
}
