package gitdocs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/knowledge"
	"github.com/liubing0806/allowops/plugin/plugintest"
	"golang.org/x/sys/unix"
)

type clockHost struct {
	*plugintest.TestHost
	mu  sync.Mutex
	now time.Time
}

func newClockHost(t *testing.T, start time.Time) *clockHost {
	t.Helper()
	return &clockHost{
		TestHost: plugintest.NewHost(t, plugintest.WithNow(start)),
		now:      start.UTC(),
	}
}

func (c *clockHost) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clockHost) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *clockHost) HTTPClient() *http.Client { return c.TestHost.HTTPClient() }
func (c *clockHost) Logger() *slog.Logger     { return c.TestHost.Logger() }

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDirModeStoreContractAndMarkdownParsing(t *testing.T) {
	repo := t.TempDir()
	// Simulate a git repository with .git metadata and hidden files that must be skipped.
	writeFile(t, filepath.Join(repo, ".git", "HEAD"), "ref: refs/heads/main\n")
	writeFile(t, filepath.Join(repo, ".git", "hooks", "ignored.md"), "# Must be ignored\n")
	writeFile(t, filepath.Join(repo, ".hidden.md"), "# Hidden\n")
	writeFile(t, filepath.Join(repo, "notes.txt"), "non-markdown file")
	writeFile(t, filepath.Join(repo, "ops", "restart.md"), strings.Join([]string{
		"---",
		"title: Restart API Service",
		"summary: Safe rolling restart procedure",
		"tags:",
		"  - ops",
		"  - api",
		"  - ops",
		"extra_ignored_key: ok",
		"---",
		"# Overview",
		"```sh",
		"# Not a heading inside backtick fence",
		"```",
		"~~~markdown",
		"## Not a heading inside tilde fence",
		"~~~",
		"## Drain Traffic ##",
		"### Verify Health",
		"#### Rollback",
		"##### Level 5 Excluded From Headings",
	}, "\n")+"\n")
	writeFile(t, filepath.Join(repo, "db", "failover.md"), strings.Join([]string{
		"---",
		"description: Primary failover playbook",
		"tags: [db]",
		"---",
		"# Database Failover",
		"Steps here.",
	}, "\n")+"\n")
	writeFile(t, filepath.Join(repo, "plain.md"), "No frontmatter or heading.\n")

	cfg := fmt.Sprintf("dir: %q\nrefresh_ttl: 1m\n", repo)
	plugintest.RunStoreContract(t, Module{}, cfg)

	h := newClockHost(t, time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC))
	m := &Module{Dir: repo}
	if err := m.Provision(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	docs, err := m.Search(t.Context(), knowledge.SearchQuery{MaxDocs: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 3 {
		t.Fatalf("got %d docs, want 3: %+v", len(docs), docs)
	}
	// Sorted by ID.
	if docs[0].ID != "db/failover.md" || docs[1].ID != "ops/restart.md" || docs[2].ID != "plain.md" {
		t.Fatalf("unexpected doc IDs: %+v", docs)
	}
	// Check description fallback & heading fallback for title.
	if docs[0].Title != "Database Failover" || docs[0].Summary != "Primary failover playbook" || !slices.Equal(docs[0].Tags, []string{"db"}) {
		t.Fatalf("unexpected db/failover.md metadata: %+v", docs[0])
	}
	// Check frontmatter + headings (#..####, fenced code skipped).
	wantHeadings := []string{"Overview", "Drain Traffic", "Verify Health", "Rollback"}
	if docs[1].Title != "Restart API Service" || docs[1].Summary != "Safe rolling restart procedure" ||
		!slices.Equal(docs[1].Tags, []string{"ops", "api"}) || !reflect.DeepEqual(docs[1].Headings, wantHeadings) {
		t.Fatalf("unexpected ops/restart.md metadata: %+v", docs[1])
	}
	// Filename fallback for title when neither frontmatter nor heading exists.
	if docs[2].Title != "plain" || len(docs[2].Headings) != 0 {
		t.Fatalf("unexpected plain.md metadata: %+v", docs[2])
	}
	// Read returns exact content + identical doc.
	read, err := m.Read(t.Context(), "ops/restart.md")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read.Doc, docs[1]) || !strings.Contains(read.Content, "#### Rollback") {
		t.Fatalf("unexpected read result: %+v", read)
	}
	// Subdir mode.
	subMod := &Module{Dir: repo, Subdir: "ops"}
	if err := subMod.Provision(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	subDocs, err := subMod.Search(t.Context(), knowledge.SearchQuery{MaxDocs: 100})
	if err != nil || len(subDocs) != 1 || subDocs[0].ID != "restart.md" {
		t.Fatalf("subdir search: %+v %v", subDocs, err)
	}
}

func TestDirModeHeadingLimitsAndUTF8Truncation(t *testing.T) {
	repo := t.TempDir()
	var b strings.Builder
	// 60 headings, first one > 128 bytes with multi-byte Chinese characters.
	b.WriteString("# " + strings.Repeat("排障手册", 20) + "\n")
	for i := 2; i <= 60; i++ {
		fmt.Fprintf(&b, "## Step %d\n", i)
	}
	writeFile(t, filepath.Join(repo, "many.md"), b.String())

	h := newClockHost(t, time.Now())
	m := &Module{Dir: repo}
	if err := m.Provision(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	docs, err := m.Search(t.Context(), knowledge.SearchQuery{})
	if err != nil || len(docs) != 1 {
		t.Fatalf("search: %+v %v", docs, err)
	}
	if len(docs[0].Headings) != maxHeadings {
		t.Fatalf("headings len = %d, want %d", len(docs[0].Headings), maxHeadings)
	}
	first := docs[0].Headings[0]
	if len(first) > maxHeadingBytes || !utf8.ValidString(first) || len(first) == 0 {
		t.Fatalf("invalid truncated heading: len=%d valid=%v %q", len(first), utf8.ValidString(first), first)
	}
}

func TestDirModeValidate(t *testing.T) {
	neg := -time.Second
	zero := time.Duration(0)
	tooLong := time.Hour + time.Second

	valid := []Module{
		{Dir: "/tmp/docs"},
		{Dir: "/tmp/docs", Subdir: "ops/runbooks", RefreshTTL: &zero, MaxFileBytes: maxFileBytesLimit, MaxTotalBytes: maxTotalBytesLimit, MaxFiles: maxFilesLimit, MaxEntries: maxEntriesLimit},
	}
	for i, m := range valid {
		if err := m.Validate(); err != nil {
			t.Errorf("valid[%d] failed: %v", i, err)
		}
	}

	invalid := []Module{
		{},
		{Dir: "   "},
		{Dir: "/tmp/docs\x00"},
		{Dir: "/tmp/docs", Subdir: "../escape"},
		{Dir: "/tmp/docs", Subdir: "/abs"},
		{Dir: "/tmp/docs", Subdir: "a/../b"},
		{Dir: "/tmp/docs", Subdir: `a\b`},
		{Dir: "/tmp/docs", Subdir: ".git"},
		{Dir: "/tmp/docs", RefreshTTL: &neg},
		{Dir: "/tmp/docs", RefreshTTL: &tooLong},
		{Dir: "/tmp/docs", MaxFileBytes: -1},
		{Dir: "/tmp/docs", MaxFileBytes: maxFileBytesLimit + 1},
		{Dir: "/tmp/docs", MaxTotalBytes: -1},
		{Dir: "/tmp/docs", MaxTotalBytes: maxTotalBytesLimit + 1},
		{Dir: "/tmp/docs", MaxFiles: -1},
		{Dir: "/tmp/docs", MaxFiles: maxFilesLimit + 1},
		{Dir: "/tmp/docs", MaxEntries: -1},
		{Dir: "/tmp/docs", MaxEntries: maxEntriesLimit + 1},
	}
	for i, m := range invalid {
		if err := m.Validate(); err == nil {
			t.Errorf("invalid[%d] unexpectedly passed: %+v", i, m)
		}
	}
}

func TestDirModeRejectsSymlinksFIFOAndYAMLAlias(t *testing.T) {
	h := newClockHost(t, time.Now())

	t.Run("symlink escape file", func(t *testing.T) {
		outside := t.TempDir()
		writeFile(t, filepath.Join(outside, "secret.md"), "# Secret\n")
		repo := t.TempDir()
		writeFile(t, filepath.Join(repo, "good.md"), "# Good\n")
		if err := os.Symlink(filepath.Join(outside, "secret.md"), filepath.Join(repo, "escape.md")); err != nil {
			t.Fatal(err)
		}
		m := &Module{Dir: repo}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errSymlink) {
			t.Fatalf("expected errSymlink, got %v", err)
		}
	})

	t.Run("symlink escape dir", func(t *testing.T) {
		outside := t.TempDir()
		writeFile(t, filepath.Join(outside, "secret.md"), "# Secret\n")
		repo := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(repo, "escape_dir")); err != nil {
			t.Fatal(err)
		}
		m := &Module{Dir: repo}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errSymlink) {
			t.Fatalf("expected errSymlink, got %v", err)
		}
	})

	t.Run("subdir symlink escape", func(t *testing.T) {
		outside := t.TempDir()
		writeFile(t, filepath.Join(outside, "secret.md"), "# Secret\n")
		repo := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(repo, "sub")); err != nil {
			t.Fatal(err)
		}
		m := &Module{Dir: repo, Subdir: "sub"}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errSymlink) {
			t.Fatalf("expected errSymlink, got %v", err)
		}
	})

	t.Run("in-root symlink", func(t *testing.T) {
		repo := t.TempDir()
		writeFile(t, filepath.Join(repo, "real.md"), "# Real\n")
		if err := os.Symlink(filepath.Join(repo, "real.md"), filepath.Join(repo, "alias.md")); err != nil {
			t.Fatal(err)
		}
		m := &Module{Dir: repo}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errSymlink) {
			t.Fatalf("expected errSymlink, got %v", err)
		}
	})

	t.Run("FIFO non-blocking rejected", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("linux FIFO test")
		}
		repo := t.TempDir()
		fifoPath := filepath.Join(repo, "trap.md")
		if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		m := &Module{Dir: repo}
		start := time.Now()
		err := m.Provision(ctx, h)
		if !errors.Is(err, errNonRegularFile) {
			t.Fatalf("expected errNonRegularFile, got %v", err)
		}
		if time.Since(start) > time.Second {
			t.Fatalf("FIFO check took too long: %v", time.Since(start))
		}
	})

	t.Run("yaml alias rejected", func(t *testing.T) {
		repo := t.TempDir()
		writeFile(t, filepath.Join(repo, "bomb.md"), "---\ntitle: &a Runbook\nsummary: *a\n---\n# Hi\n")
		m := &Module{Dir: repo}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errYAMLAlias) {
			t.Fatalf("expected errYAMLAlias, got %v", err)
		}
	})
}

func TestDirModeLimits(t *testing.T) {
	h := newClockHost(t, time.Now())

	t.Run("max_file_bytes", func(t *testing.T) {
		repo := t.TempDir()
		writeFile(t, filepath.Join(repo, "big.md"), strings.Repeat("a", 200))
		m := &Module{Dir: repo, MaxFileBytes: 100}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errFileSizeLimit) {
			t.Fatalf("expected errFileSizeLimit, got %v", err)
		}
	})

	t.Run("max_total_bytes", func(t *testing.T) {
		repo := t.TempDir()
		writeFile(t, filepath.Join(repo, "a.md"), strings.Repeat("a", 60))
		writeFile(t, filepath.Join(repo, "b.md"), strings.Repeat("b", 60))
		m := &Module{Dir: repo, MaxTotalBytes: 100}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errTotalBytes) {
			t.Fatalf("expected errTotalBytes, got %v", err)
		}
	})

	t.Run("max_files", func(t *testing.T) {
		repo := t.TempDir()
		writeFile(t, filepath.Join(repo, "a.md"), "# A\n")
		writeFile(t, filepath.Join(repo, "b.md"), "# B\n")
		m := &Module{Dir: repo, MaxFiles: 1}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errFileLimit) {
			t.Fatalf("expected errFileLimit, got %v", err)
		}
	})

	t.Run("max_entries counts dirs and non-md", func(t *testing.T) {
		repo := t.TempDir()
		writeFile(t, filepath.Join(repo, "dir1", "a.txt"), "x")
		writeFile(t, filepath.Join(repo, "dir1", "b.txt"), "x")
		writeFile(t, filepath.Join(repo, "c.md"), "# C\n")
		// Entries: dir1, c.md, a.txt, b.txt = 4 entries.
		m := &Module{Dir: repo, MaxEntries: 3}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errEntryLimit) {
			t.Fatalf("expected errEntryLimit, got %v", err)
		}
	})

	t.Run("max_depth", func(t *testing.T) {
		repo := t.TempDir()
		parts := make([]string, 0, maxWalkDepth+3)
		parts = append(parts, repo)
		for i := 0; i <= maxWalkDepth; i++ {
			parts = append(parts, fmt.Sprintf("d%d", i))
		}
		parts = append(parts, "deep.md")
		writeFile(t, filepath.Join(parts...), "# Deep\n")
		m := &Module{Dir: repo}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errDepthLimit) {
			t.Fatalf("expected errDepthLimit, got %v", err)
		}
	})
}

func TestDirModeAtomicRefreshAndZeroTTL(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "guide.md"), "# Version 1\nbody v1\n")

	start := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	h := newClockHost(t, start)
	ttl := time.Minute
	m := &Module{Dir: repo, RefreshTTL: &ttl}
	if err := m.Provision(t.Context(), h); err != nil {
		t.Fatal(err)
	}

	res1, err := m.Read(t.Context(), "guide.md")
	if err != nil || res1.Doc.Title != "Version 1" || !strings.Contains(res1.Content, "body v1") {
		t.Fatalf("initial read: %+v %v", res1, err)
	}

	// Update file on disk before TTL expires: snapshot remains immutable.
	writeFile(t, filepath.Join(repo, "guide.md"), "# Version 2\nbody v2\n")
	writeFile(t, filepath.Join(repo, "new.md"), "# New Doc\n")
	h.Advance(30 * time.Second)
	resStill1, err := m.Read(t.Context(), "guide.md")
	if err != nil || resStill1.Doc.Title != "Version 1" {
		t.Fatalf("expected cached v1 before TTL, got %+v %v", resStill1, err)
	}
	if _, err := m.Read(t.Context(), "new.md"); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("expected ErrNotFound before TTL, got %v", err)
	}

	// Advance past TTL: snapshot atomically swaps to v2.
	h.Advance(31 * time.Second)
	res2, err := m.Read(t.Context(), "guide.md")
	if err != nil || res2.Doc.Title != "Version 2" || !strings.Contains(res2.Content, "body v2") {
		t.Fatalf("expected refreshed v2, got %+v %v", res2, err)
	}
	docs, err := m.Search(t.Context(), knowledge.SearchQuery{})
	if err != nil || len(docs) != 2 {
		t.Fatalf("expected 2 docs after refresh, got %+v %v", docs, err)
	}

	// refresh_ttl: 0 loads once at startup and never reloads.
	zero := time.Duration(0)
	once := &Module{Dir: repo, RefreshTTL: &zero}
	if err := once.Provision(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(repo, "guide.md"), "# Version 3\nbody v3\n")
	h.Advance(24 * time.Hour)
	resOnce, err := once.Read(t.Context(), "guide.md")
	if err != nil || resOnce.Doc.Title != "Version 2" {
		t.Fatalf("zero refresh_ttl unexpectedly reloaded: %+v %v", resOnce, err)
	}
}

var (
	_ plugin.Module      = (*Module)(nil)
	_ plugin.Validator   = (*Module)(nil)
	_ plugin.Provisioner = (*Module)(nil)
	_ knowledge.Store    = (*Module)(nil)
)
