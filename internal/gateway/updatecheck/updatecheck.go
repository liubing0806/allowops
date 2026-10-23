// Package updatecheck reads the opt-in release manifest and records the latest
// gateway version in PostgreSQL. It only informs; nothing is downloaded or run.
package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// lockKey is the advisory lock key; 418001-418010 are taken elsewhere.
const lockKey int64 = 418011
const (
	maxBody        = 64 << 10
	requestTimeout = 10 * time.Second
	maxRedirects   = 3
	maxFirstDelay  = 10 * time.Minute
	minInterval    = time.Hour
)

type Config struct {
	Enabled  bool          `yaml:"enabled"`
	URL      string        `yaml:"url"`
	Interval time.Duration `yaml:"interval"`
}

func DefaultConfig() Config {
	return Config{URL: "https://liubing0806.github.io/allowops/version.json", Interval: 24 * time.Hour}
}

func (c Config) Validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("update_check.url must be an HTTPS URL without credentials")
	}
	if c.Interval < minInterval {
		return errors.New("update_check.interval must be at least 1h")
	}
	return nil
}

// State is the stored check result; zero times mean unset.
type State struct {
	LatestVersion string
	PublishedAt   time.Time
	CheckedAt     time.Time
	LastError     string
}

type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Load returns the zero State when no check has been recorded yet.
func Load(ctx context.Context, q Querier) (State, error) {
	var st State
	var published, checked *time.Time
	err := q.QueryRow(ctx, "SELECT latest_version,published_at,checked_at,last_error FROM gateway_update_check WHERE id").Scan(&st.LatestVersion, &published, &checked, &st.LastError)
	if errors.Is(err, pgx.ErrNoRows) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	if published != nil {
		st.PublishedAt = *published
	}
	if checked != nil {
		st.CheckedAt = *checked
	}
	return st, nil
}

type Checker struct {
	Client *http.Client
	// Now, FirstDelay and NextDelay are replaceable for tests.
	Now        func() time.Time
	FirstDelay func() time.Duration
	NextDelay  func() time.Duration

	pool    *pgxpool.Pool
	cfg     Config
	version string
}

func New(pool *pgxpool.Pool, cfg Config, version string) *Checker {
	c := &Checker{
		Client: &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}},
		Now:    time.Now,
		pool:   pool, cfg: cfg, version: version,
	}
	c.FirstDelay = func() time.Duration { return rand.N(maxFirstDelay) }
	c.NextDelay = func() time.Duration {
		if jitter := cfg.Interval / 10; jitter > 0 {
			return cfg.Interval + rand.N(jitter)
		}
		return cfg.Interval
	}
	return c
}

// Run blocks until ctx ends.
func (c *Checker) Run(ctx context.Context) {
	timer := time.NewTimer(c.FirstDelay())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := c.RunOnce(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "gateway update check: database unavailable")
		}
		timer.Reset(c.NextDelay())
	}
}

// RunOnce fetches the manifest unless another instance did within the
// interval. A failed fetch is recorded, not returned; the error is for
// database failures.
func (c *Checker) RunOnce(ctx context.Context) error {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var locked bool
	if err = tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", lockKey).Scan(&locked); err != nil || !locked {
		return err
	}
	now := c.Now()
	st, err := Load(ctx, tx)
	if err != nil {
		return err
	}
	if !st.CheckedAt.IsZero() && st.CheckedAt.After(now.Add(-c.cfg.Interval*9/10)) {
		return nil
	}
	latest, published, failure := c.fetch(ctx)
	if failure != "" {
		_, err = tx.Exec(ctx, "INSERT INTO gateway_update_check(id,checked_at,last_error) VALUES (true,$1,$2) ON CONFLICT (id) DO UPDATE SET checked_at=EXCLUDED.checked_at,last_error=EXCLUDED.last_error", now, failure)
	} else {
		_, err = tx.Exec(ctx, "INSERT INTO gateway_update_check(id,latest_version,published_at,checked_at,last_error) VALUES (true,$1,$2,$3,'') ON CONFLICT (id) DO UPDATE SET latest_version=EXCLUDED.latest_version,published_at=EXCLUDED.published_at,checked_at=EXCLUDED.checked_at,last_error=''", latest, published, now)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// fetch returns a fixed failure category, never response content or the
// transport error text.
func (c *Checker) fetch(ctx context.Context) (latest string, published *time.Time, failure string) {
	client := *c.Client
	client.Timeout = requestTimeout
	client.Jar = nil
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects || r.URL.Scheme != "https" {
			return errors.New("redirect refused")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL, nil)
	if err != nil {
		return "", nil, "request failed"
	}
	req.Header.Set("User-Agent", "allowops-gateway/"+c.version)
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, "request failed"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Sprintf("unexpected HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return "", nil, "request failed"
	}
	if len(body) > maxBody {
		return "", nil, "response too large"
	}
	var m struct {
		Version     string     `json:"version"`
		PublishedAt *time.Time `json:"published_at"`
	}
	if json.Unmarshal(body, &m) != nil {
		return "", nil, "invalid manifest"
	}
	v, err := semver.StrictNewVersion(m.Version)
	if err != nil {
		return "", nil, "invalid manifest"
	}
	return v.String(), m.PublishedAt, ""
}
