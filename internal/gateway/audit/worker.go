package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// LogWorkerError reports the error category without logging provider messages.
func LogWorkerError(ctx context.Context, message string, err error) {
	var state string
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		state = pgErr.Code
	}
	slog.ErrorContext(ctx, message, "sqlstate", state, "error_type", fmt.Sprintf("%T", err))
}

type workerBackoff time.Duration

func (b *workerBackoff) wait(ctx context.Context, message string, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	LogWorkerError(ctx, message, err)
	delay := max(time.Second, time.Duration(*b))
	*b = workerBackoff(min(2*delay, 30*time.Second))
	return waitForWorker(ctx, delay)
}

func waitForWorker(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
