package job

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// retrySQL retains the current state-machine position. Callers may pass only
// reads or idempotent SQL writes, never a dispatch or an external side effect.
func retrySQL(ctx context.Context, jobID string, fn func(context.Context) error) error {
	backoff := 20 * time.Millisecond
	logged := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := fn(attempt)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !retryableSQL(err) {
			return err
		}
		if !logged {
			logSQLFailure(ctx, slog.LevelWarn, "job SQL retrying", jobID, err)
			logged = true
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff = min(2*backoff, time.Second)
	}
}
func retryableSQL(err error) bool {
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) {
		return len(pgerr.Code) >= 2 && (pgerr.Code[:2] == "08" || pgerr.Code[:2] == "40" || pgerr.Code[:2] == "53" || pgerr.Code == "55P03" || pgerr.Code == "57P01" || pgerr.Code == "57P02" || pgerr.Code == "57P03")
	}
	var network net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &network) || pgconn.SafeToRetry(err)
}

// A required final write stays owned while the service is alive. Cancellation
// starts one independent five-second cleanup budget, shared by all its retries.
func terminalSQL(ctx context.Context, jobID string, fn func(context.Context) error) error {
	err := retrySQL(ctx, jobID, fn)
	if ctx.Err() == nil {
		return err
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return retrySQL(cleanup, jobID, fn)
}

// Provider errors can contain SQL, connection details and parameters. Emit only
// their Go type and SQLSTATE, once per affected operation/state transition.
func logSQLFailure(ctx context.Context, level slog.Level, message, jobID string, err error, attrs ...any) {
	state := ""
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) {
		state = pgerr.Code
	}
	slog.Log(ctx, level, message, append([]any{"job_id", jobID, "sqlstate", state, "error_type", fmt.Sprintf("%T", err)}, attrs...)...)
}
