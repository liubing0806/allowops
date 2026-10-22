package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
	"github.com/liubing0806/allowops/internal/executor"
)

// The P3 root container supplies a genuinely signed helper request over stdin,
// then runs this test as allowops. No host sudo/helper files are replaced.
func TestRealHelperFinalReason(t *testing.T) {
	if os.Getenv("ALLOWOPS_REASON_CONTAINER_CHILD") != "1" {
		t.Skip("runs via dedicated P3 container")
	}
	if os.Geteuid() == 0 {
		t.Fatal("runner must run as allowops")
	}
	var fixture struct {
		Action        catalog.Action
		Request       execd.Request
		Envelope, Key []byte
		Expect        string
	}
	if err := json.NewDecoder(os.Stdin).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cache := execd.Cache{CatalogDir: filepath.Join(dir, "catalogs"), KeysDir: filepath.Join(dir, "keys"), StateDir: filepath.Join(dir, "versions"), StateOwner: os.Getuid(), KeyOwner: os.Getuid()}
	path := execd.CatalogPath(cache.CatalogDir, fixture.Request.CatalogID, fixture.Request.CatalogVersion)
	for _, d := range []string{filepath.Dir(path), cache.KeysDir, cache.StateDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, fixture.Envelope, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache.KeysDir, "signer.pem"), fixture.Key, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := cache.Load(fixture.Request.CatalogID, fixture.Request.CatalogVersion)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if fixture.Expect == "CANCELLED" {
		cancel()
	}
	r, err := (LocalRunner{}).Run(ctx, fixture.Action, fixture.Request.Params, nil, fixture.Request.CatalogID, fixture.Request.CatalogVersion, executor.Callbacks{})
	want := v1.TaskStatus_TASK_STATUS_FAILED
	reason := ""
	switch fixture.Expect {
	case "TIMEOUT":
		want = v1.TaskStatus_TASK_STATUS_TIMEOUT
		reason = "TIMEOUT"
		if ctx.Err() != nil {
			t.Fatalf("parent context expired before inner timeout: %v", ctx.Err())
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("LocalRunner final error=%v; errors.Is(DeadlineExceeded)=false, want true with live parent", err)
		}
	case "CANCELLED":
		want = v1.TaskStatus_TASK_STATUS_CANCELLED
		reason = "CANCELLED"
		if !errors.Is(err, context.Canceled) {
			t.Errorf("cancel error=%v", err)
		}
	case "FAILED":
		if err != nil || r.ExitCode != 1 {
			t.Errorf("ordinary failure: result=%+v err=%v", r, err)
		}
	}
	if status, gotReason := taskStatus(r.ExitCode, err); status != want || gotReason != reason {
		t.Errorf("final classification=%v/%s want=%v/%s", status, gotReason, want, reason)
	}
	a := &Agent{config: Config{Limits: Limits{}.defaults()}, options: Options{Runner: LocalRunner{}}, catalogs: &catalogs{cache: cache}}
	assignment := task(p, fixture.Action.Name, "helper-reason")
	assignment.Params.Json, _ = json.Marshal(fixture.Request.Params)
	var completed *v1.TaskCompleted
	a.execute(ctx, assignment, 1024, func(m *v1.ConnectRequest, _ bool) error {
		if m.GetTaskCompleted() != nil {
			completed = m.GetTaskCompleted()
		}
		return nil
	})
	if completed == nil || completed.Result.Status != want || completed.Result.Reason != reason {
		t.Errorf("TaskCompleted=%v; want %v/%s", completed, want, reason)
	}
}
