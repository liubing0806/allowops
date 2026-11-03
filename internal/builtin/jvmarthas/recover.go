package jvmarthas

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/liubing0806/allowops/internal/jvmtarget"
)

// Recovery is what Recover did.
type Recovery struct {
	// Cleaned counts the Arthas servers that were shut down.
	Cleaned int
	// Stale counts the records of processes that are gone, or of servers that were not running.
	Stale int
	// Busy counts the records skipped because a call holds the lock of the JVM.
	Busy int
	// Failed describes the records that could not be cleared; they are kept.
	Failed []string
}

func (r *Recovery) add(o Recovery) {
	r.Cleaned += o.Cleaned
	r.Stale += o.Stale
	r.Busy += o.Busy
	r.Failed = append(r.Failed, o.Failed...)
}

// String lists the counts that are not zero; it is empty when there was nothing to do.
func (r Recovery) String() string {
	var parts []string
	for _, p := range []struct {
		name string
		n    int
	}{{"cleaned", r.Cleaned}, {"stale", r.Stale}, {"busy", r.Busy}, {"failed", len(r.Failed)}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", p.name, p.n))
		}
	}
	return strings.Join(parts, ", ")
}

// Recover ends the Arthas servers that earlier calls left behind and deletes their records.
// A record whose JVM is locked belongs to a call that is running and is left alone. Files of
// processes that ended are removed as well. The error is that of the state directory.
func Recover(ctx context.Context, env Env) (Recovery, error) {
	env = env.withDefaults()
	state, err := OpenState(env.StateDir, env.StateOwner)
	if err != nil {
		return Recovery{}, err
	}
	defer state.Close()
	boot, err := env.Host.BootID()
	if err != nil {
		return Recovery{}, err
	}
	return recoverAll(ctx, env, state, boot, nil), nil
}

type recovery int

const (
	// nothing: there was no record.
	nothing recovery = iota
	// recovered: the server was shut down.
	recovered
	// stale: the process is gone, or the server was not running.
	stale
)

// recoverAll handles the records of every JVM but skip, then removes the files of ended processes.
func recoverAll(ctx context.Context, env Env, state *State, boot string, skip *Key) Recovery {
	var rec Recovery
	keys, err := state.Records()
	if err != nil {
		rec.Failed = append(rec.Failed, fmt.Sprintf("list of session records: %v", err))
		return rec
	}
	for _, key := range keys {
		if skip != nil && key == *skip {
			continue
		}
		lock, err := state.TryLock(key)
		if errors.Is(err, ErrBusy) {
			rec.Busy++
			continue
		}
		if err != nil {
			rec.Failed = append(rec.Failed, err.Error())
			continue
		}
		out, err := recoverKey(ctx, env, state, boot, key)
		lock.Unlock()
		switch {
		case err != nil:
			rec.Failed = append(rec.Failed, err.Error())
		case out == recovered:
			rec.Cleaned++
		case out == stale:
			rec.Stale++
		}
	}
	state.Prune(func(k Key) bool {
		if k.BootID != boot {
			return false
		}
		start, err := env.Host.StartTime(k.PID)
		return err == nil && start == k.StartTime
	})
	return rec
}

// recoverKey ends the server a record describes. The caller holds the lock of the key, so the
// call that wrote the record is not running: either it ended, or its process died.
func recoverKey(ctx context.Context, env Env, state *State, boot string, key Key) (recovery, error) {
	rec, err := state.ReadRecord(key)
	if errors.Is(err, fs.ErrNotExist) {
		return nothing, nil
	}
	if err != nil {
		return nothing, fmt.Errorf("session record of process %d: %w", key.PID, err)
	}
	if key.BootID != boot {
		return stale, state.RemoveRecord(key)
	}
	proc, err := env.Resolver.Identify(rec.PID, rec.StartTime)
	if errors.Is(err, jvmtarget.ErrProcessChanged) {
		return stale, state.RemoveRecord(key)
	}
	if err != nil {
		return nothing, fmt.Errorf("process %d: %w", rec.PID, err)
	}
	if !serverPresent(env, proc, rec.Port) {
		return stale, state.RemoveRecord(key)
	}
	res := shutdown(ctx, env, proc, rec.Port, newClient(proc, rec.Port, rec.Password), rec.SessionID)
	if !res.stopped {
		return nothing, fmt.Errorf("the Arthas server on port %d of process %d is still running: %s", rec.Port, rec.PID, res.problem())
	}
	return recovered, state.RemoveRecord(key)
}
