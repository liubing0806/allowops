package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/store"
)

func TestHealthUnavailableDatabase(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://localhost/unused")
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	s := &Server{Agent: &hostconn.Service{Store: &store.Store{Pool: pool}}}
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/health/ready", http.StatusServiceUnavailable},
		{http.MethodGet, "/health/live", http.StatusOK},
		{http.MethodPost, "/health/live", http.StatusMethodNotAllowed},
	} {
		response := httptest.NewRecorder()
		s.health(response, httptest.NewRequest(tc.method, tc.path, nil))
		if response.Code != tc.status {
			t.Fatalf("%s %s status=%d want %d", tc.method, tc.path, response.Code, tc.status)
		}
	}
}
