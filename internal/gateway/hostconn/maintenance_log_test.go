package hostconn

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
)

type recordSink struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordSink) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordSink) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}
func (h *recordSink) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordSink) WithGroup(string) slog.Handler      { return h }
func (h *recordSink) snapshot() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]slog.Record(nil), h.records...)
}

func recordAttrs(r slog.Record) map[string]any {
	out := map[string]any{}
	r.Attrs(func(a slog.Attr) bool {
		out[a.Key] = a.Value.Any()
		return true
	})
	return out
}

// unreachableStore returns a store whose every write fails immediately. The
// pool connects lazily, so no database is needed.
func unreachableStore(t *testing.T) *store.Store {
	t.Helper()
	p, err := pgxpool.New(context.Background(), "postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return &store.Store{Pool: p, Queries: db.New(p)}
}

func captureLogs(t *testing.T) *recordSink {
	t.Helper()
	sink := &recordSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return sink
}

func TestMaintenanceLogsFailedWritesOncePerTick(t *testing.T) {
	sink := captureLogs(t)
	ctx, cancel := context.WithCancel(context.Background())
	cfg := DefaultConfig()
	cfg.FlushInterval = 20 * time.Millisecond
	cfg.CleanupInterval = 20 * time.Millisecond
	s := &Service{Store: unreachableStore(t), Config: cfg, InstanceID: "gw", connections: map[string]*connection{}, ctx: ctx}
	now := time.Now()
	for _, id := range []string{"a", "b", "c"} {
		c := &connection{identity: Identity{HostID: "host-" + id}, id: "conn-" + id}
		c.lastSeen.Store(&now)
		s.connections[id] = c
	}
	done := make(chan struct{})
	go func() { s.maintenance(); close(done) }()
	counts := func() map[string]int {
		out := map[string]int{}
		for _, r := range sink.snapshot() {
			out[r.Message]++
		}
		return out
	}
	deadline := time.After(10 * time.Second)
	for len(counts()) < 3 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("expected warnings for touch, last_seen and cleanup failures, got %v", counts())
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
	for _, r := range sink.snapshot() {
		if r.Level != slog.LevelWarn {
			t.Errorf("%q logged at %v, want warn", r.Message, r.Level)
		}
		a := recordAttrs(r)
		if _, ok := a["failed"]; ok && (a["failed"] != int64(3) || a["total"] != int64(3)) {
			t.Errorf("%q is not aggregated across connections: %v", r.Message, a)
		}
	}
	// One warning per failing write per tick, never one per host.
	c := counts()
	if touch, instance := c["host connection last_seen flush failed"], c["gateway instance last_seen update failed"]; touch == 0 || touch > instance+1 {
		t.Errorf("%d touch warnings for %d instance updates", touch, instance)
	}
}

func TestDrainLogsFailedInstanceUpdate(t *testing.T) {
	sink := captureLogs(t)
	s := &Service{Store: unreachableStore(t), Config: DefaultConfig(), InstanceID: "gw", connections: map[string]*connection{}}
	if err := s.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	records := sink.snapshot()
	if len(records) != 1 || records[0].Level != slog.LevelWarn || records[0].Message != "gateway instance draining update failed" {
		t.Fatalf("records = %v", records)
	}
}
