package gitdocs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

type tarEntry struct {
	name     string
	typeflag byte
	body     []byte
	linkname string
}

func buildTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Size:     int64(len(e.body)),
			Typeflag: tf,
			Linkname: e.linkname,
		}
		if tf == tar.TypeDir {
			hdr.Mode = 0o755
			hdr.Size = 0
		}
		if tf == tar.TypeSymlink || tf == tar.TypeLink {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if len(e.body) > 0 && tf == tar.TypeReg {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestArchiveModeStoreContractAndAuth(t *testing.T) {
	archive := buildTarGz(t, []tarEntry{
		{name: "repo-main/", typeflag: tar.TypeDir},
		{name: "repo-main/.git/HEAD", body: []byte("ref: refs/heads/main\n")},
		{name: "repo-main/docs/", typeflag: tar.TypeDir},
		{name: "repo-main/docs/link.md", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		{name: "repo-main/docs/hardlink.md", typeflag: tar.TypeLink, linkname: "repo-main/docs/api.md"},
		{name: "repo-main/docs/api.md", body: []byte("---\ntitle: API Runbook\nsummary: Restart API\ntags: [api]\n---\n# API\n## Restart\n")},
		{name: "repo-main/docs/db.md", body: []byte("# DB Runbook\n## Failover\n")},
	})

	const bearerSecret = "super-secret-archive-token-123"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+bearerSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized response body secret-echo"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	cfg := fmt.Sprintf("archive_url: %q\ncredential_ref: tok\nsubdir: docs\n", srv.URL+"/archive.tar.gz")
	plugintest.RunStoreContract(
		t,
		Module{},
		cfg,
		plugintest.WithHTTPServer(srv),
		plugintest.WithCredential("tok", []byte(bearerSecret)),
		plugintest.WithExpectHTTP(),
	)

	// Verify symlinks and hardlinks were excluded and only regular .md files loaded.
	h := plugintest.NewHost(t, plugintest.WithHTTPServer(srv), plugintest.WithCredential("tok", []byte(bearerSecret)))
	m := &Module{ArchiveURL: srv.URL + "/archive.tar.gz", CredentialRef: "tok", Subdir: "docs"}
	if err := m.Provision(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	docs, err := m.Search(t.Context(), knowledge.SearchQuery{MaxDocs: 100})
	if err != nil || len(docs) != 2 || docs[0].ID != "api.md" || docs[1].ID != "db.md" {
		t.Fatalf("unexpected archive docs: %+v %v", docs, err)
	}
	if _, err := m.Read(t.Context(), "link.md"); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("symlink entry should not be readable: %v", err)
	}
	if _, err := m.Read(t.Context(), "hardlink.md"); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("hardlink entry should not be readable: %v", err)
	}

	// Verify JSON bearer_token and Basic auth credentials, and no credential/body leakage on error.
	t.Run("json bearer and basic auth", func(t *testing.T) {
		var gotAuth string
		authSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			_, _ = w.Write(archive)
		}))
		defer authSrv.Close()

		hBearer := plugintest.NewHost(t, plugintest.WithHTTPServer(authSrv), plugintest.WithCredential("c", []byte(`{"bearer_token":"json-tok"}`)))
		mb := &Module{ArchiveURL: authSrv.URL + "/a.tar.gz", CredentialRef: "c", Subdir: "docs"}
		if err := mb.Provision(t.Context(), hBearer); err != nil {
			t.Fatal(err)
		}
		if gotAuth != "Bearer json-tok" {
			t.Fatalf("got auth %q", gotAuth)
		}

		hBasic := plugintest.NewHost(t, plugintest.WithHTTPServer(authSrv), plugintest.WithCredential("c", []byte(`{"username":"bot","password":"pw"}`)))
		mu := &Module{ArchiveURL: authSrv.URL + "/a.tar.gz", CredentialRef: "c", Subdir: "docs"}
		if err := mu.Provision(t.Context(), hBasic); err != nil {
			t.Fatal(err)
		}
		wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("bot:pw"))
		if gotAuth != wantBasic {
			t.Fatalf("got auth %q, want %q", gotAuth, wantBasic)
		}
	})

	t.Run("errors never leak credential or response body", func(t *testing.T) {
		badSecret := "do-not-echo-this-secret"
		hBad := plugintest.NewHost(t, plugintest.WithHTTPServer(srv), plugintest.WithCredential("tok", []byte(badSecret)))
		mBad := &Module{ArchiveURL: srv.URL + "/archive.tar.gz", CredentialRef: "tok"}
		err := mBad.Provision(t.Context(), hBad)
		if err == nil {
			t.Fatal("expected 401 error")
		}
		if strings.Contains(err.Error(), badSecret) || strings.Contains(err.Error(), "secret-echo") {
			t.Fatalf("error leaked secret or response body: %v", err)
		}
	})
}

func TestArchiveModeValidation(t *testing.T) {
	neg := -1
	five := 5
	zero := 0

	valid := []Module{
		{ArchiveURL: "https://example.com/repo.tar.gz", CredentialRef: "tok", StripComponents: &zero},
		{ArchiveURL: "http://example.com/public.tar.gz"},
	}
	for i, m := range valid {
		if err := m.Validate(); err != nil {
			t.Errorf("valid[%d] failed: %v", i, err)
		}
	}

	invalid := []Module{
		{Dir: "/tmp/a", ArchiveURL: "https://example.com/a.tar.gz"},
		{Dir: "/tmp/a", CredentialRef: "tok"},
		{ArchiveURL: "http://example.com/repo.tar.gz", CredentialRef: "tok"},
		{ArchiveURL: "ftp://example.com/repo.tar.gz"},
		{ArchiveURL: "https://user:pass@example.com/repo.tar.gz"},
		{ArchiveURL: "https://example.com/repo.tar.gz", CredentialRef: "BadRef!"},
		{ArchiveURL: "https://example.com/repo.tar.gz", StripComponents: &neg},
		{ArchiveURL: "https://example.com/repo.tar.gz", StripComponents: &five},
		{ArchiveURL: "https://example.com/repo.tar.gz", MaxArchiveBytes: maxArchiveBytesLimit + 1},
		{ArchiveURL: "https://example.com/repo.tar.gz", MaxDecompressedBytes: maxDecompressedBytesLimit + 1},
	}
	for i, m := range invalid {
		if err := m.Validate(); err == nil {
			t.Errorf("invalid[%d] unexpectedly passed: %+v", i, m)
		}
	}
}

func TestArchiveModeSecurityAndLimits(t *testing.T) {
	serve := func(t *testing.T, payload []byte) (*httptest.Server, *plugintest.TestHost) {
		t.Helper()
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(payload)
		}))
		t.Cleanup(srv.Close)
		return srv, plugintest.NewHost(t, plugintest.WithHTTPServer(srv))
	}

	t.Run("full-stream decompression bomb rejected even in skipped non-md file", func(t *testing.T) {
		// 2 MiB of zeros compresses to ~2 KiB in gzip, well below max_archive_bytes,
		// but exceeds max_decompressed_bytes=64 KiB via countingReader between gz and tar.
		bomb := buildTarGz(t, []tarEntry{
			{name: "repo/filler.bin", body: make([]byte, 2<<20)},
			{name: "repo/ok.md", body: []byte("# OK\n")},
		})
		if len(bomb) > 64<<10 {
			t.Fatalf("expected highly compressed bomb, got %d bytes", len(bomb))
		}
		srv, h := serve(t, bomb)
		m := &Module{
			ArchiveURL:           srv.URL + "/bomb.tar.gz",
			MaxArchiveBytes:      1 << 20,
			MaxDecompressedBytes: 64 << 10,
		}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errDecompressedLimit) {
			t.Fatalf("expected errDecompressedLimit, got %v", err)
		}
	})

	t.Run("max_archive_bytes rejected", func(t *testing.T) {
		payload := buildTarGz(t, []tarEntry{{name: "repo/a.md", body: []byte(strings.Repeat("abcdef123456", 500))}})
		srv, h := serve(t, payload)
		m := &Module{ArchiveURL: srv.URL + "/a.tar.gz", MaxArchiveBytes: len(payload) - 1}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errArchiveSizeLimit) {
			t.Fatalf("expected errArchiveSizeLimit, got %v", err)
		}
	})

	t.Run("max_entries rejected", func(t *testing.T) {
		entries := make([]tarEntry, 0, 5)
		for i := range 5 {
			entries = append(entries, tarEntry{name: fmt.Sprintf("repo/f%d.txt", i), body: []byte("x")})
		}
		srv, h := serve(t, buildTarGz(t, entries))
		m := &Module{ArchiveURL: srv.URL + "/e.tar.gz", MaxEntries: 3}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errEntryLimit) {
			t.Fatalf("expected errEntryLimit, got %v", err)
		}
	})

	for _, badName := range []string{
		"../escape.md",
		"repo/../../escape.md",
		"/etc/passwd",
		`repo\evil.md`,
	} {
		t.Run("path traversal rejected "+badName, func(t *testing.T) {
			payload := buildTarGz(t, []tarEntry{{name: badName, body: []byte("# Evil\n")}})
			srv, h := serve(t, payload)
			m := &Module{ArchiveURL: srv.URL + "/evil.tar.gz"}
			if err := m.Provision(t.Context(), h); !errors.Is(err, errArchivePath) {
				t.Fatalf("badName=%q: expected errArchivePath, got %v", badName, err)
			}
		})
	}

	t.Run("path traversal on symlink rejected", func(t *testing.T) {
		payload := buildTarGz(t, []tarEntry{{name: "repo/../link.md", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}})
		srv, h := serve(t, payload)
		m := &Module{ArchiveURL: srv.URL + "/symlink-trav.tar.gz"}
		if err := m.Provision(t.Context(), h); !errors.Is(err, errArchivePath) {
			t.Fatalf("expected errArchivePath, got %v", err)
		}
	})

	t.Run("nul byte rejected in archive path", func(t *testing.T) {
		if _, err := validateArchivePath("repo/bad\x00name.md"); !errors.Is(err, errArchivePath) {
			t.Fatalf("expected errArchivePath for NUL byte, got %v", err)
		}
	})

	t.Run("invalid credential returns fixed error without echo", func(t *testing.T) {
		srv, _ := serve(t, buildTarGz(t, []tarEntry{{name: "repo/a.md", body: []byte("# A\n")}}))
		for _, badCred := range []string{
			"",
			"   ",
			"tok\r\nX-Injected: secret-val",
			`{"bearer_token":"secret-val","username":"u","password":"p"}`,
			`{"unknown":"secret-val"}`,
			`{"username":"u"}`,
		} {
			h := plugintest.NewHost(t, plugintest.WithHTTPServer(srv), plugintest.WithCredential("tok", []byte(badCred)))
			m := &Module{ArchiveURL: srv.URL + "/a.tar.gz", CredentialRef: "tok"}
			err := m.Provision(t.Context(), h)
			if !errors.Is(err, errInvalidCredential) || strings.Contains(err.Error(), "secret-val") {
				t.Fatalf("badCred=%q: got err=%v", badCred, err)
			}
		}
	})

	t.Run("strip_components and atomic refresh", func(t *testing.T) {
		v1 := buildTarGz(t, []tarEntry{{name: "guide.md", body: []byte("# V1\n")}})
		v2 := buildTarGz(t, []tarEntry{{name: "guide.md", body: []byte("# V2\n")}})
		var version atomic.Int32
		version.Store(1)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if version.Load() == 1 {
				_, _ = w.Write(v1)
			} else {
				_, _ = w.Write(v2)
			}
		}))
		defer srv.Close()

		start := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
		h := &clockHost{
			TestHost: plugintest.NewHost(t, plugintest.WithHTTPServer(srv), plugintest.WithNow(start)),
			now:      start,
		}
		zero := 0
		ttl := time.Minute
		m := &Module{ArchiveURL: srv.URL + "/docs.tar.gz", StripComponents: &zero, RefreshTTL: &ttl}
		if err := m.Provision(t.Context(), h); err != nil {
			t.Fatal(err)
		}
		res, err := m.Read(t.Context(), "guide.md")
		if err != nil || res.Doc.Title != "V1" {
			t.Fatalf("v1 read: %+v %v", res, err)
		}
		version.Store(2)
		h.Advance(2 * time.Minute)
		res, err = m.Read(t.Context(), "guide.md")
		if err != nil || res.Doc.Title != "V2" {
			t.Fatalf("v2 read after refresh: %+v %v", res, err)
		}
	})
}
