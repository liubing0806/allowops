package agent

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
)

func TestAgentCancelledFIFOTaskJoins(t *testing.T) {
	g, _, config := startGateway(t, false)
	a, _ := startAgent(t, config)
	path := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(path, []byte("ELF fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	action := catalog.Action{Name: "fifo", Description: "fifo", Risk: "read", Exec: []any{path}, Timeout: "5s", MaxOutput: 1024}
	p, notice := publish(t, g, a, []catalog.Action{action}, time.Now(), time.Hour)
	c := connection(t, g)
	c.send(t, &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: notice}})
	if !c.next(t, func(m *v1.ConnectRequest) bool { return m.GetCatalogLoad() != nil }).GetCatalogLoad().Loaded {
		t.Fatal("catalog not loaded")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.execute(ctx, task(p, "fifo", "fifo"), 1024, func(*v1.ConnectRequest, bool) error { return nil })
	}()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("task cleanup failed")
		}
		t.Error("cancelled FIFO task did not join; want bounded unsupported completion")
	}
}
