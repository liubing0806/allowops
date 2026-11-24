package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const expiryCleanupInterval = 10 * time.Minute
const expiryCleanupBatchSize = 1000

func (s *Service) maintainExpiry(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(expiryCleanupInterval)
	defer ticker.Stop()
	q := s.Store.Queries
	targets := []struct {
		table  string
		remove func(context.Context, int32) error
	}{
		{"policy_tests", q.DeleteExpiredPolicyTestBatch},
		{"cli_login_codes", q.DeleteExpiredCliLoginCodeBatch},
		{"oidc_transactions", q.DeleteExpiredOidcTransactionBatch},
		{"identity_sessions", q.DeleteOldIdentitySessionBatch},
	}
	for {
		for _, target := range targets {
			if ctx.Err() != nil {
				return
			}
			if err := target.remove(ctx, expiryCleanupBatchSize); err != nil && ctx.Err() == nil {
				var sqlstate string
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) {
					sqlstate = pgErr.Code
				}
				slog.WarnContext(ctx, "expired record cleanup failed", "table", target.table, "sqlstate", sqlstate, "error_type", fmt.Sprintf("%T", err))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
