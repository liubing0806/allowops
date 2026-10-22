package authn

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func limiterForTest(t *testing.T, failures, keys int) *loginLimiter {
	t.Helper()
	config := ldapConfig()
	config.RateLimit = RateLimit{Attempts: failures, Window: 5 * time.Minute}
	client, err := NewLDAP(config)
	if err != nil {
		t.Fatal(err)
	}
	client.limiter.maxKeys = keys
	return &client.limiter
}

func TestLoginLimiterCountsOnlyFailuresAndResetsOnSuccess(t *testing.T) {
	l := limiterForTest(t, 2, 2)
	now := func() time.Time { return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) }
	for range 6 {
		finish, err := l.begin(context.Background(), "alice", "192.0.2.1", now)
		if err != nil {
			t.Fatal(err)
		}
		finish(true, false)
	}
	for range 2 {
		finish, err := l.begin(context.Background(), "alice", "192.0.2.1", now)
		if err != nil {
			t.Fatal(err)
		}
		finish(false, true)
		finish, err = l.begin(context.Background(), "alice", "192.0.2.1", now)
		if err != nil {
			t.Fatal(err)
		}
		finish(true, false)
	}
	for range 2 {
		finish, err := l.begin(context.Background(), "alice", "192.0.2.1", now)
		if err != nil {
			t.Fatal(err)
		}
		finish(false, true)
	}
	if _, err := l.begin(context.Background(), "alice", "192.0.2.1", now); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("failure threshold: %v", err)
	}
}

func TestLoginLimiterRollingWindow(t *testing.T) {
	l := limiterForTest(t, 3, 2)
	start := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	clock := start
	now := func() time.Time { return clock }
	for _, offset := range []time.Duration{0, 4 * time.Minute, 4*time.Minute + 30*time.Second} {
		clock = start.Add(offset)
		finish, err := l.begin(context.Background(), "alice", "192.0.2.1", now)
		if err != nil {
			t.Fatal(err)
		}
		finish(false, true)
	}
	clock = start.Add(5*time.Minute - time.Nanosecond)
	if _, err := l.begin(context.Background(), "alice", "192.0.2.1", now); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("failure expired early: %v", err)
	}
	clock = start.Add(5 * time.Minute)
	finish, err := l.begin(context.Background(), "alice", "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	finish(false, true)
	clock = clock.Add(time.Nanosecond)
	if _, err := l.begin(context.Background(), "alice", "192.0.2.1", now); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("remaining failures were reset at fixed boundary: %v", err)
	}
	clock = start.Add(9 * time.Minute)
	finish, err = l.begin(context.Background(), "alice", "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	finish(true, false)
}

func TestLoginLimiterConcurrency(t *testing.T) {
	for _, outcome := range []struct {
		success, credentialRejected bool
		want                        int32
	}{
		{false, true, 5},
		{true, false, 30},
		{false, false, 30},
	} {
		l := limiterForTest(t, 5, 2)
		now := func() time.Time { return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) }
		var admitted atomic.Int32
		var wg sync.WaitGroup
		for range 30 {
			wg.Go(func() {
				finish, err := l.begin(context.Background(), "alice", "192.0.2.1", now)
				if err == nil {
					admitted.Add(1)
					finish(outcome.success, outcome.credentialRejected)
				} else if !errors.Is(err, ErrRateLimited) {
					t.Errorf("begin: %v", err)
				}
			})
		}
		wg.Wait()
		if admitted.Load() != outcome.want {
			t.Fatalf("outcome=%+v: admitted=%d, want %d", outcome, admitted.Load(), outcome.want)
		}
	}
}

func TestLoginLimiterCapacityAndExpiredCleanup(t *testing.T) {
	l := limiterForTest(t, 2, 2)
	start := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	clock := start
	now := func() time.Time { return clock }
	for _, user := range []string{"alice", "bob"} {
		finish, err := l.begin(context.Background(), user, "192.0.2.1", now)
		if err != nil {
			t.Fatal(err)
		}
		finish(false, true)
	}
	if _, err := l.begin(context.Background(), "charlie", "192.0.2.1", now); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("key capacity exceeded: %v", err)
	}
	if len(l.entries) != 2 {
		t.Fatalf("retained keys=%d, want 2", len(l.entries))
	}
	finish, err := l.begin(context.Background(), "alice", "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	finish(true, false)
	finish, err = l.begin(context.Background(), "charlie", "192.0.2.1", now)
	if err != nil {
		t.Fatalf("success did not release key: %v", err)
	}
	finish(false, true)
	clock = start.Add(5 * time.Minute)
	finish, err = l.begin(context.Background(), "dave", "192.0.2.1", now)
	if err != nil {
		t.Fatalf("expired keys were not cleared: %v", err)
	}
	finish(true, false)
	if len(l.entries) != 0 {
		t.Fatalf("expired/successful keys retained: %d", len(l.entries))
	}
}

func TestLoginLimiterSerializesKeyAndHonorsWaitingDeadline(t *testing.T) {
	l := limiterForTest(t, 5, 2)
	now := time.Now
	finish, err := l.begin(context.Background(), "alice", "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	defer finish(true, false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := l.begin(ctx, "alice", "192.0.2.1", now); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("same key did not wait for its deadline: %v", err)
	}
	other, err := l.begin(context.Background(), "alice", "192.0.2.2", now)
	if err != nil {
		t.Fatalf("different IP serialized: %v", err)
	}
	other(true, false)
}

func TestLoginLimiterQueueIsBounded(t *testing.T) {
	l := limiterForTest(t, 5, 2)
	l.maxPending = 1
	now := time.Now
	finish, err := l.begin(context.Background(), "alice", "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.begin(context.Background(), "alice", "192.0.2.1", now); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("pending limit exceeded: %v", err)
	}
	finish(true, false)
	finish, err = l.begin(context.Background(), "alice", "192.0.2.1", now)
	if err != nil {
		t.Fatalf("queue slot not released: %v", err)
	}
	finish(true, false)
}

func TestLoginLimiterCancellationBeforeAuthentication(t *testing.T) {
	l := limiterForTest(t, 5, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := func() time.Time { cancel(); return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) }
	finish, err := l.begin(ctx, "alice", "192.0.2.1", now)
	if finish != nil {
		finish(true, false)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request admitted: %v", err)
	}
	if len(l.entries) != 0 {
		t.Fatalf("canceled request retained keys: %d", len(l.entries))
	}
}
