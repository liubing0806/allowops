package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/store"
)

func startMetrics(listener net.Listener, db *store.Store, agent *hostconn.Service) func() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		expiry := math.NaN()
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		// Select the current version first so a superseded version cannot reappear after expiry.
		err := db.Pool.QueryRow(ctx, `
			SELECT COALESCE(EXTRACT(EPOCH FROM min(expires_at) - now())::double precision, 'NaN'::double precision)
			FROM (SELECT DISTINCT ON (catalog_id) expires_at FROM catalog_versions ORDER BY catalog_id, version DESC) current
			WHERE expires_at > now()`).Scan(&expiry)
		if err != nil {
			expiry = math.NaN()
		}
		pool := db.Pool.Stat()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		for _, metric := range []struct {
			name, help string
			value      float64
		}{
			{"allowops_gateway_up", "Whether the gateway metrics listener is serving.", 1},
			{"allowops_db_pool_total_conns", "Total PostgreSQL pool connections.", float64(pool.TotalConns())},
			{"allowops_db_pool_acquired_conns", "Acquired PostgreSQL pool connections.", float64(pool.AcquiredConns())},
			{"allowops_db_pool_idle_conns", "Idle PostgreSQL pool connections.", float64(pool.IdleConns())},
			{"allowops_db_pool_max_conns", "Maximum PostgreSQL pool connections.", float64(pool.MaxConns())},
			{"allowops_connected_hosts", "Agent sessions owned by this gateway instance.", float64(agent.ConnectedHosts())},
			{"allowops_catalog_min_expiry_seconds", "Minimum seconds until expiry among unexpired current catalog versions. NaN if none or unavailable.", expiry},
			{"go_goroutines", "Number of goroutines that currently exist.", float64(runtime.NumGoroutine())},
		} {
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", metric.name, metric.help, metric.name, metric.name, metric.value)
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: time.Minute}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("gateway metrics listener stopped", "error", err)
		}
	}()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			//allowops:ignore-error best-effort force close after graceful metrics shutdown timeout
			_ = srv.Close()
		}
		<-done
	}
}
