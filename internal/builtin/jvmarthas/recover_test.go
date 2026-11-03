package jvmarthas

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRecoverWithoutRecords(t *testing.T) {
	r := newRig(t)
	got, err := Recover(context.Background(), r.env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cleaned != 0 || got.Stale != 0 || got.Busy != 0 || len(got.Failed) != 0 {
		t.Errorf("recovery = %+v", got)
	}
}

func TestRecoverShutsDownARunningServer(t *testing.T) {
	r := newRig(t)
	r.leaveRecord(18570, true)
	got, err := Recover(context.Background(), r.env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cleaned != 1 || len(got.Failed) != 0 {
		t.Errorf("recovery = %+v", got)
	}
	if seen := r.server.seen(); !slices.Equal(seen, cleanupActions) {
		t.Errorf("Arthas requests = %v, want %v", seen, cleanupActions)
	}
	r.wantEnded()
}

func TestRecoverDeletesTheRecordOfAServerThatNeverStarted(t *testing.T) {
	r := newRig(t)
	r.leaveRecord(18570, false)
	got, err := Recover(context.Background(), r.env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stale != 1 || got.Cleaned != 0 {
		t.Errorf("recovery = %+v", got)
	}
	if seen := r.server.seen(); len(seen) != 0 {
		t.Errorf("Arthas received %v", seen)
	}
	r.wantEnded()
}

func TestRecoverDeletesTheRecordOfAnExitedProcess(t *testing.T) {
	r := newRig(t)
	rec := r.leaveRecord(18570, true)
	delete(r.resolver.known, rec.PID)
	got, err := Recover(context.Background(), r.env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stale != 1 {
		t.Errorf("recovery = %+v", got)
	}
	if seen := r.server.seen(); len(seen) != 0 {
		t.Errorf("Arthas received %v although the process is gone", seen)
	}
	if _, err := r.state().ReadRecord(rec.Key()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("record still there: %v", err)
	}
}

func TestRecoverDeletesTheRecordOfAnotherBoot(t *testing.T) {
	r := newRig(t)
	rec := r.leaveRecord(18570, true)
	r.host.boot = "ffffffff-0000-4000-8000-000000000000"
	got, err := Recover(context.Background(), r.env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stale != 1 {
		t.Errorf("recovery = %+v", got)
	}
	if _, err := r.state().ReadRecord(rec.Key()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("record still there: %v", err)
	}
	if seen := r.server.seen(); len(seen) != 0 {
		t.Errorf("Arthas received %v although the record belongs to another boot", seen)
	}
}

func TestRecoverSkipsAJVMWhoseLockIsHeld(t *testing.T) {
	r := newRig(t)
	rec := r.leaveRecord(18570, true)
	lock, err := r.state().TryLock(rec.Key())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Unlock()
	got, err := Recover(context.Background(), r.env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Busy != 1 || got.Cleaned != 0 {
		t.Errorf("recovery = %+v", got)
	}
	if seen := r.server.seen(); len(seen) != 0 {
		t.Errorf("Arthas received %v although a call is using the JVM", seen)
	}
	if _, err := r.state().ReadRecord(rec.Key()); err != nil {
		t.Errorf("the record of a running call was removed: %v", err)
	}
}

func TestRecoverKeepsTheRecordWhenTheServerStays(t *testing.T) {
	r := newRig(t)
	r.server.ignoreStop = true
	rec := r.leaveRecord(18570, true)
	got, err := Recover(context.Background(), r.env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Failed) != 1 || got.Cleaned != 0 {
		t.Fatalf("recovery = %+v", got)
	}
	if strings.Contains(got.Failed[0], rigPassword) {
		t.Errorf("failure text holds the password: %q", got.Failed[0])
	}
	if _, err := r.state().ReadRecord(rec.Key()); err != nil {
		t.Errorf("record was removed although the server runs: %v", err)
	}
	// The lock is free again for the next attempt.
	lock, err := r.state().TryLock(rec.Key())
	if err != nil {
		t.Fatalf("lock held after the recovery: %v", err)
	}
	lock.Unlock()
}

func TestRecoverReportsAnUnreadableRecord(t *testing.T) {
	r := newRig(t)
	rec := r.leaveRecord(18570, false)
	path := filepath.Join(r.stateDir, rec.Key().String()+".session")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Recover(context.Background(), r.env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Failed) != 1 {
		t.Errorf("recovery = %+v", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("an unreadable record was deleted: %v", err)
	}
}

func TestRecoverPrunesTheFilesOfEndedProcesses(t *testing.T) {
	r := newRig(t)
	ended := Key{BootID: r.key.BootID, PID: 31337, StartTime: 1}
	if _, err := r.state().AddAttach(ended, time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.state().AddAttach(r.key, time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(context.Background(), r.env); err != nil {
		t.Fatal(err)
	}
	if c, _ := r.state().Counter(ended); c.Attaches != 0 {
		t.Error("the counter of an ended process was kept")
	}
	if c, _ := r.state().Counter(r.key); c.Attaches != 1 {
		t.Error("the counter of a running process was removed")
	}
}

func TestRecoverNeedsAUsableStateDirectory(t *testing.T) {
	r := newRig(t)
	r.env.StateDir = "relative"
	if _, err := Recover(context.Background(), r.env); err == nil {
		t.Error("a relative state directory was accepted")
	}
}

func TestRecoverWithoutAStateDirectoryYet(t *testing.T) {
	// Before the first call there is no directory; the agent calls Recover at startup anyway.
	r := newRig(t)
	got, err := Recover(context.Background(), r.env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cleaned+got.Stale+got.Busy != 0 {
		t.Errorf("recovery = %+v", got)
	}
	if _, err := os.Stat(r.stateDir); err != nil {
		t.Errorf("the state directory was not created: %v", err)
	}
}
