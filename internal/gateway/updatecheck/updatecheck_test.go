package updatecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func newChecker(db *store.Store, srv *httptest.Server) *Checker {
	c := New(db.Pool, Config{Enabled: true, URL: srv.URL, Interval: 24 * time.Hour}, "0.3.0")
	c.Client = srv.Client()
	return c
}

func manifest(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }
}

func TestSuccessIsStored(t *testing.T) {
	db := openStore(t)
	srv := httptest.NewTLSServer(manifest(`{"version":"0.4.0","published_at":"2026-10-20T08:00:00Z","url":"ignored","extra":1}`))
	defer srv.Close()
	c := newChecker(db, srv)
	ctx := context.Background()
	if st, err := Load(ctx, db.Pool); err != nil || st != (State{}) {
		t.Fatalf("missing row must load as not checked yet: %+v %v", st, err)
	}
	if err := c.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := Load(ctx, db.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if st.LatestVersion != "0.4.0" || st.LastError != "" || st.CheckedAt.IsZero() || !st.PublishedAt.Equal(time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("stored state %+v", st)
	}
}

func TestFailuresKeepPreviousValueAndStoreOnlyCategories(t *testing.T) {
	db := openStore(t)
	var mu sync.Mutex
	status, body := 200, `{"version":"0.5.0","published_at":"2026-10-21T08:00:00Z"}`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := newChecker(db, srv)
	now := time.Now()
	c.Now = func() time.Time { return now }
	ctx := context.Background()
	if err := c.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"not semver", 200, `{"version":"latest"}`, "invalid manifest"},
		{"v prefix", 200, `{"version":"v0.6.0"}`, "invalid manifest"},
		{"not json", 200, `<html>secret-body</html>`, "invalid manifest"},
		{"bad published_at", 200, `{"version":"0.6.0","published_at":"yesterday"}`, "invalid manifest"},
		{"too large", 200, `{"version":"0.6.0","pad":"` + strings.Repeat("x", 64<<10) + `"}`, "response too large"},
		{"status", 503, `unavailable`, "unexpected HTTP status 503"},
	}
	for _, tc := range cases {
		mu.Lock()
		status, body = tc.status, tc.body
		mu.Unlock()
		now = now.Add(25 * time.Hour)
		if err := c.RunOnce(ctx); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		st, err := Load(ctx, db.Pool)
		if err != nil {
			t.Fatal(err)
		}
		if st.LatestVersion != "0.5.0" || !st.PublishedAt.Equal(time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)) {
			t.Fatalf("%s: previous value lost: %+v", tc.name, st)
		}
		if st.LastError != tc.want || !st.CheckedAt.Equal(now.Truncate(time.Microsecond)) {
			t.Fatalf("%s: last_error=%q checked_at=%v", tc.name, st.LastError, st.CheckedAt)
		}
	}
	// A later success clears the error.
	mu.Lock()
	status, body = 200, `{"version":"0.6.0"}`
	mu.Unlock()
	now = now.Add(25 * time.Hour)
	if err := c.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if st, _ := Load(ctx, db.Pool); st.LatestVersion != "0.6.0" || st.LastError != "" || !st.PublishedAt.IsZero() {
		t.Fatalf("success did not replace state: %+v", st)
	}
}

func TestBodyAtLimitIsAccepted(t *testing.T) {
	db := openStore(t)
	prefix, suffix := `{"version":"0.4.0","pad":"`, `"}`
	srv := httptest.NewTLSServer(manifest(prefix + strings.Repeat("x", 64<<10-len(prefix)-len(suffix)) + suffix))
	defer srv.Close()
	if err := newChecker(db, srv).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st, _ := Load(context.Background(), db.Pool); st.LatestVersion != "0.4.0" {
		t.Fatalf("64 KiB body rejected: %+v", st)
	}
}

func TestUnreachableManifestIsRequestFailed(t *testing.T) {
	db := openStore(t)
	srv := httptest.NewTLSServer(manifest(`{}`))
	c := newChecker(db, srv)
	srv.Close()
	if err := c.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, _ := Load(context.Background(), db.Pool)
	if st.LastError != "request failed" || st.LatestVersion != "" || st.CheckedAt.IsZero() {
		t.Fatalf("state %+v", st)
	}
}

func TestRequestCarriesOnlyUserAgent(t *testing.T) {
	db := openStore(t)
	var got http.Header
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{"version":"0.4.0"}`))
	}))
	defer srv.Close()
	if err := newChecker(db, srv).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.Get("User-Agent") != "allowops-gateway/0.3.0" {
		t.Fatalf("User-Agent=%q", got.Get("User-Agent"))
	}
	for name := range got {
		if name != "User-Agent" && name != "Accept-Encoding" {
			t.Fatalf("unexpected request header %s", name)
		}
	}
}

func TestRedirectPolicy(t *testing.T) {
	db := openStore(t)
	plain := httptest.NewServer(manifest(`{"version":"0.4.0"}`))
	defer plain.Close()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/3":
			http.Redirect(w, r, srv.URL+"/2", http.StatusFound)
		case "/4":
			http.Redirect(w, r, srv.URL+"/3", http.StatusFound)
		case "/2":
			http.Redirect(w, r, srv.URL+"/1", http.StatusFound)
		case "/1":
			http.Redirect(w, r, srv.URL+"/end", http.StatusFound)
		case "/plain":
			http.Redirect(w, r, plain.URL, http.StatusFound)
		default:
			_, _ = w.Write([]byte(`{"version":"0.4.0"}`))
		}
	}))
	defer srv.Close()
	for _, tc := range []struct{ path, want string }{{"/3", ""}, {"/4", "request failed"}, {"/plain", "request failed"}} {
		c := newChecker(db, srv)
		c.cfg.URL = srv.URL + tc.path
		if _, err := db.Pool.Exec(context.Background(), "DELETE FROM gateway_update_check"); err != nil {
			t.Fatal(err)
		}
		if err := c.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		if st, _ := Load(context.Background(), db.Pool); st.LastError != tc.want {
			t.Fatalf("%s: last_error=%q want %q", tc.path, st.LastError, tc.want)
		}
	}
}

func TestOneRequestPerIntervalAcrossCheckers(t *testing.T) {
	db := openStore(t)
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{"version":"0.4.0"}`))
	}))
	defer srv.Close()
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := newChecker(db, srv).RunOnce(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := newChecker(db, srv).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("requests=%d, want exactly 1", n)
	}
}

func TestRecentCheckIsSkippedAndStaleCheckIsNot(t *testing.T) {
	db := openStore(t)
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"version":"0.4.0"}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	set := func(age time.Duration) {
		if _, err := db.Pool.Exec(ctx, "INSERT INTO gateway_update_check(id,checked_at) VALUES (true,now()-$1::interval) ON CONFLICT (id) DO UPDATE SET checked_at=EXCLUDED.checked_at", age.String()); err != nil {
			t.Fatal(err)
		}
	}
	c := newChecker(db, srv)
	set(20 * time.Hour)
	if err := c.RunOnce(ctx); err != nil || requests.Load() != 0 {
		t.Fatalf("recent check not skipped: requests=%d err=%v", requests.Load(), err)
	}
	set(22 * time.Hour)
	if err := c.RunOnce(ctx); err != nil || requests.Load() != 1 {
		t.Fatalf("stale check skipped: requests=%d err=%v", requests.Load(), err)
	}
}

func TestLockHeldElsewhereSkipsRun(t *testing.T) {
	db := openStore(t)
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"version":"0.4.0"}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		t.Fatal(err)
	}
	if err = newChecker(db, srv).RunOnce(ctx); err != nil || requests.Load() != 0 {
		t.Fatalf("ran while lock held: requests=%d err=%v", requests.Load(), err)
	}
}

func TestRunStartsAfterDelayAndStopsWithContext(t *testing.T) {
	db := openStore(t)
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"version":"0.4.0"}`))
	}))
	defer srv.Close()
	c := newChecker(db, srv)
	var next atomic.Int32
	c.FirstDelay = func() time.Duration { return 20 * time.Millisecond }
	c.NextDelay = func() time.Duration { next.Add(1); return 20 * time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for next.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if next.Load() < 2 || requests.Load() != 1 {
		t.Fatalf("next=%d requests=%d", next.Load(), requests.Load())
	}
}

func TestDefaultDelays(t *testing.T) {
	c := New(nil, Config{Interval: 24 * time.Hour}, "dev")
	for i := 0; i < 1000; i++ {
		if d := c.FirstDelay(); d < 0 || d >= 10*time.Minute {
			t.Fatalf("first delay %v", d)
		}
		if d := c.NextDelay(); d < 24*time.Hour || d > 24*time.Hour+144*time.Minute {
			t.Fatalf("next delay %v", d)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	good := Config{Enabled: true, URL: "https://example.org/version.json", Interval: time.Hour}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if d := DefaultConfig(); d.Enabled || d.URL != "https://liubing0806.github.io/allowops/version.json" || d.Interval != 24*time.Hour || d.Validate() != nil {
		t.Fatalf("defaults %+v", d)
	}
	for name, mutate := range map[string]func(*Config){
		"http":         func(c *Config) { c.URL = "http://example.org/version.json" },
		"userinfo":     func(c *Config) { c.URL = "https://user:pw@example.org/version.json" },
		"user only":    func(c *Config) { c.URL = "https://user@example.org/version.json" },
		"no host":      func(c *Config) { c.URL = "https:///version.json" },
		"empty":        func(c *Config) { c.URL = "" },
		"short":        func(c *Config) { c.Interval = 59 * time.Minute },
		"zero":         func(c *Config) { c.Interval = 0 },
		"negative":     func(c *Config) { c.Interval = -time.Hour },
		"unparsable":   func(c *Config) { c.URL = "https://exa mple.org/" },
		"other scheme": func(c *Config) { c.URL = "file:///etc/passwd" },
	} {
		c := good
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
