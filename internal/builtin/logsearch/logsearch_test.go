package logsearch

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeLog(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeLog(t, path, "before\nerror first\nignore error\nafter\n")
	cfg := Config{AllowedRoots: []string{dir}}
	p := Params{PathGlob: path, Pattern: "error", Fixed: true, Exclude: "ignore", Context: 1}
	r, err := Run(context.Background(), cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	want := path + ":1:before\n" + path + ":2:error first\n"
	if r.Stdout != want || r.ExitCode != 0 || r.Truncated {
		t.Fatalf("got %#v; want stdout %q, success, untruncated", r, want)
	}
	p.Pattern, p.Fixed, p.Exclude, p.Context = "^error [a-z]+$", false, "", 0
	r, err = Run(context.Background(), cfg, p)
	if err != nil || r.Stdout != path+":2:error first\n" {
		t.Fatalf("regex: %#v, %v", r, err)
	}
	p.Pattern = "absent"
	r, err = Run(context.Background(), cfg, p)
	if err != nil || r.Stdout != "" || r.ExitCode != 0 {
		t.Fatalf("no matches: %#v, %v", r, err)
	}
}

func TestGzipAndContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	if _, err := z.Write([]byte("before\nmatch\nmatch\nafter\n")); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := Run(context.Background(), Config{AllowedRoots: []string{dir}}, Params{PathGlob: path, Pattern: "match", Context: 1})
	want := path + ":1:before\n" + path + ":2:match\n" + path + ":3:match\n" + path + ":4:after\n"
	if err != nil || r.Stdout != want {
		t.Fatalf("got %#v, %v; want %q", r, err, want)
	}
}

func TestLimits(t *testing.T) {
	for _, kind := range []string{"matches", "files", "scan", "long-line", "gzip-scan"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "a.log")
			writeLog(t, path, "hit\nhit\nhit\n")
			cfg := Config{AllowedRoots: []string{dir}}
			p := Params{PathGlob: path, Pattern: "hit"}
			switch kind {
			case "matches":
				p.MaxMatches = 1
			case "files":
				cfg.MaxFiles = 1
				writeLog(t, filepath.Join(dir, "b.log"), "hit\n")
				p.PathGlob = filepath.Join(dir, "*.log")
			case "scan":
				cfg.MaxScan = 5
			case "long-line":
				cfg.MaxScan = 128
				writeLog(t, path, strings.Repeat("x", 1<<20)+"hit\n")
			case "gzip-scan":
				cfg.MaxScan = 64
				path += ".gz"
				f, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				z := gzip.NewWriter(f)
				_, err = z.Write([]byte(strings.Repeat("hit\n", 1<<18)))
				if err != nil {
					t.Fatal(err)
				}
				if err = z.Close(); err != nil {
					t.Fatal(err)
				}
				if err = f.Close(); err != nil {
					t.Fatal(err)
				}
				p.PathGlob = path
			}
			r, err := Run(context.Background(), cfg, p)
			if err != nil || !r.Truncated || r.ExitCode != 0 {
				t.Fatalf("got %#v, %v; want truncated success", r, err)
			}
			if kind == "matches" && strings.Count(r.Stdout, "hit") != 1 {
				t.Fatalf("match limit: %q", r.Stdout)
			}
		})
	}
}

func TestLargeLineDoesNotHideLaterMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeLog(t, path, strings.Repeat("x", 1<<20)+"\nhit\n")
	r, err := Run(context.Background(), Config{AllowedRoots: []string{dir}}, Params{PathGlob: path, Pattern: "hit"})
	want := path + ":2:hit\n"
	if err != nil || r.Stdout != want || r.Truncated {
		t.Fatalf("got %#v, %v; want %q without truncation", r, err, want)
	}
}

func TestRawTextIsNotOutputTruncated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	text := "password=" + strings.Repeat("x", 64<<10) + "secret-end"
	writeLog(t, path, text+"\n")
	r, err := Run(context.Background(), Config{AllowedRoots: []string{dir}}, Params{PathGlob: path, Pattern: "password=", Fixed: true})
	want := path + ":1:" + text + "\n"
	if err != nil || r.Stdout != want || r.Truncated {
		t.Fatalf("raw text: length=%d want=%d truncated=%v error=%v", len(r.Stdout), len(want), r.Truncated, err)
	}
}

func TestReject(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeLog(t, path, "hit\n")
	secret := filepath.Join(outside, "secret.log")
	writeLog(t, secret, "secret\n")
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]Params{
		"outside":          {PathGlob: secret, Pattern: "secret"},
		"dotdot":           {PathGlob: dir + "/../" + filepath.Base(outside) + "/secret.log", Pattern: "secret"},
		"symlink":          {PathGlob: link, Pattern: "secret"},
		"mixed-glob":       {PathGlob: filepath.Join(dir, "*.log"), Pattern: "hit"},
		"option-pattern":   {PathGlob: path, Pattern: "--help"},
		"option-path":      {PathGlob: "-test", Pattern: "hit"},
		"option-exclude":   {PathGlob: path, Pattern: "hit", Exclude: "-test"},
		"bad-regex":        {PathGlob: path, Pattern: "["},
		"bad-exclude":      {PathGlob: path, Pattern: "hit", Exclude: "["},
		"negative-context": {PathGlob: path, Pattern: "hit", Context: -1},
		"large-context":    {PathGlob: path, Pattern: "hit", Context: 101},
		"large-matches":    {PathGlob: path, Pattern: "hit", MaxMatches: 10001},
		"empty-pattern":    {PathGlob: path},
		"bad-glob":         {PathGlob: dir + "/[", Pattern: "hit"},
		"directory":        {PathGlob: dir, Pattern: "hit"},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := Run(context.Background(), Config{AllowedRoots: []string{dir}}, p)
			if err == nil || r.ExitCode == 0 || r.Stdout != "" {
				t.Fatalf("got %#v, %v; want rejection without output", r, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := Run(ctx, Config{AllowedRoots: []string{dir}}, Params{PathGlob: path, Pattern: "hit"})
	if err == nil || r.ExitCode == 0 {
		t.Fatalf("cancelled: %#v %v", r, err)
	}
}

func logNames(files []logFile) []string {
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = f.name
	}
	return names
}

// Wildcard segments must not walk through symlinked directories: two
// self-links would otherwise multiply every wildcard level.
func TestGlobDoesNotTraverseSymlinkedDirectories(t *testing.T) {
	dir := t.TempDir()
	writeLog(t, filepath.Join(dir, "app.log"), "hit\n")
	for _, name := range []string{"a", "b"} {
		if err := os.Symlink(".", filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := files(context.Background(), Config{AllowedRoots: []string{dir}, MaxFiles: 50}, dir+strings.Repeat("/*", 11)+"/*.log")
	if err != nil || len(got) != 0 {
		t.Fatalf("symlink loop: %d matches (first %v), error %v; want no matches", len(got), logNames(got[:min(len(got), 1)]), err)
	}
	// The same file is still found when the directories on the way are real.
	got, err = files(context.Background(), Config{AllowedRoots: []string{dir}, MaxFiles: 50}, dir+"/*.log")
	if err != nil || len(got) != 1 {
		t.Fatalf("direct match: %v, %v", got, err)
	}
}

// Walking a directory tree is bounded by the number of entries examined, not
// by how many of them match.
func TestGlobStopsAtDirectoryEntryLimit(t *testing.T) {
	dir := t.TempDir()
	for i := range maxGlobEntries {
		writeLog(t, filepath.Join(dir, fmt.Sprintf("f%05d.log", i)), "")
	}
	cfg := Config{AllowedRoots: []string{dir}, MaxFiles: 50}
	got, err := files(context.Background(), cfg, dir+"/*.log")
	if err != nil || len(got) != cfg.MaxFiles+1 {
		t.Fatalf("at the limit: %d matches, error %v", len(got), err)
	}
	writeLog(t, filepath.Join(dir, "extra.log"), "")
	got, err = files(context.Background(), cfg, dir+"/*.log")
	if !errors.Is(err, ErrGlobLimit) {
		t.Fatalf("over the limit: %d matches, error %v; want ErrGlobLimit", len(got), err)
	}
}

// The walk, not only the validation of its matches, observes cancellation.
func TestGlobHonorsCancelledContext(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"one", "two"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := files(ctx, Config{AllowedRoots: []string{dir}, MaxFiles: 50}, dir+"/*/absent*.log")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled walk: %v, error %v; want context.Canceled", got, err)
	}
}

// For trees without symlinks the walk returns exactly what filepath.Glob does,
// in the same order.
func TestGlobMatchesFilepathGlobOnPlainTrees(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"svc1/app.log", "svc1/sub/deep.log", "svc2/app.log", "svc2/App.LOG", "svc10/app.log", "s_x/app.log", "top.log", "Top.log", ".hidden.log", "svc1/.hidden.log", "svc1/sub/b1.log", "svc1/sub/a1.log"} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		writeLog(t, path, "hit\n")
	}
	for _, pattern := range []string{"/*.log", "/*/*.log", "/svc?/app.log", "/s*/app.log", "/*/sub/*.log", "/svc1/sub/[ab]1.log", "/svc[0-9]*/app.log", "/svc1/app.log", "/svc1/*/*.log", "/*/*/*.log", "/svc1/sub/a1.log", "/absent/*.log", "/svc1/absent*.log", `/svc1/ap\p.log`, "/*/[!a]pp.log"} {
		want, err := filepath.Glob(dir + pattern)
		if err != nil {
			t.Fatal(err)
		}
		got, err := files(context.Background(), Config{AllowedRoots: []string{dir}, MaxFiles: 50}, dir+pattern)
		if err != nil || !slices.Equal(logNames(got), want) {
			t.Errorf("%s: got %v, error %v; want %v", pattern, logNames(got), err, want)
		}
	}
}

func TestConfigAndSchema(t *testing.T) {
	for _, cfg := range []Config{{}, {AllowedRoots: []string{"relative"}}, {AllowedRoots: []string{t.TempDir()}, MaxScan: -1}} {
		if cfg.Validate() == nil {
			t.Fatalf("accepted %#v", cfg)
		}
	}
	s := ParamsSchema()
	if s["$schema"] != "https://json-schema.org/draft/2020-12/schema" || s["additionalProperties"] != false {
		t.Fatalf("schema %#v", s)
	}
}

func FuzzParams(f *testing.F) {
	dir := f.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte("hello\nerror\n"), 0600); err != nil {
		f.Fatal(err)
	}
	f.Add("app.log", "error", "", false, 0, 1)
	f.Add("../outside", "[", "-test", true, -1, 10001)
	f.Fuzz(func(t *testing.T, glob, pattern, exclude string, fixed bool, lines, matches int) {
		if len(glob) > 4096 || len(pattern) > 4096 || len(exclude) > 4096 {
			t.Skip()
		}
		p := Params{PathGlob: dir + "/" + glob, Pattern: pattern, Exclude: exclude, Fixed: fixed, Context: lines, MaxMatches: matches}
		r, err := Run(context.Background(), Config{AllowedRoots: []string{dir}, MaxScan: 1024}, p)
		if r.Stdout != "" && !strings.HasSuffix(r.Stdout, "\n") {
			t.Fatalf("incomplete emitted line: %q", r.Stdout)
		}
		if err != nil && r.ExitCode == 0 {
			t.Fatalf("error with success: %v", err)
		}
	})
}
