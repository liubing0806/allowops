package store

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/testpg"
)

func TestOpenPoolConfig(t *testing.T) {
	dsn := testpg.Start(t)
	serviceFile := filepath.Join(t.TempDir(), "pg_service.conf")
	if err := os.WriteFile(serviceFile, []byte("[allowops]\npool_max_conns=31\npool_max_conn_idle_time=4m\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name        string
		configure   func(*url.URL) string
		maxConns    int32
		lifetime    time.Duration
		maxIdleTime time.Duration
	}{
		{"default", func(u *url.URL) string { return u.String() }, 20, 30 * time.Minute, 5 * time.Minute},
		{"URL overrides", func(u *url.URL) string {
			u.RawQuery += "&pool_max_conns=35&pool_max_conn_lifetime=9m&pool_max_conn_idle_time=2m"
			return u.String()
		}, 35, 9 * time.Minute, 2 * time.Minute},
		{"keyword overrides", func(u *url.URL) string {
			password, _ := u.User.Password()
			return "host=" + u.Hostname() + " port=" + u.Port() + " dbname=fixture user=fixture password=" + password +
				" sslmode=disable pool_max_conns=32 pool_max_conn_lifetime=11m"
		}, 32, 11 * time.Minute, 5 * time.Minute},
		{"service overrides", func(u *url.URL) string {
			query := u.Query()
			query.Set("service", "allowops")
			query.Set("servicefile", serviceFile)
			u.RawQuery = query.Encode()
			return u.String()
		}, 31, 30 * time.Minute, 4 * time.Minute},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatal("invalid test database URL")
			}
			s, err := Open(context.Background(), tt.configure(u))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			cfg := s.Pool.Config()
			if cfg.MaxConns != tt.maxConns || cfg.MaxConnLifetime != tt.lifetime || cfg.MaxConnIdleTime != tt.maxIdleTime {
				t.Errorf("pool max connections=%d lifetime=%s idle time=%s, want %d, %s, %s",
					cfg.MaxConns, cfg.MaxConnLifetime, cfg.MaxConnIdleTime, tt.maxConns, tt.lifetime, tt.maxIdleTime)
			}
		})
	}
}
