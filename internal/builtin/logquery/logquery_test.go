package logquery

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const logback = "2006-01-02 15:04:05.000"

var shanghai = mustLocation("Asia/Shanghai")
var base = time.Date(2026, 10, 23, 10, 0, 0, 0, shanghai)

func mustLocation(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		panic(err)
	}
	return loc
}

func line(at time.Time, message string) string {
	return at.In(shanghai).Format(logback) + " [main] INFO  c.y.App - " + message + "\n"
}

func writeLog(t *testing.T, path, content string, mtime time.Time) {
	t.Helper()
	data := []byte(content)
	if strings.HasSuffix(path, ".gz") {
		var buffer bytes.Buffer
		z := gzip.NewWriter(&buffer)
		if _, err := z.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		data = buffer.Bytes()
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func testConfig(root string) Config {
	return Config{
		Mode: ModeSearch,
		Sources: map[string]Source{"app": {
			Type:      TypeFile,
			Paths:     []string{root + "/app.log*"},
			Timestamp: Timestamp{Layouts: []string{logback}, Timezone: "Asia/Shanghai"},
			Multiline: MultilineTimestampStart,
		}},
		AllowedRoots: []string{root},
	}
}

func setNow(t *testing.T, at time.Time) {
	t.Helper()
	previous := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = previous })
}

// rotated writes records 0-29 one minute apart: 0-9 in app.log.2.gz, 10-19 in
// app.log.1 and 20-29 in app.log.
func rotated(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for i, name := range []string{"app.log.2.gz", "app.log.1", "app.log"} {
		var content strings.Builder
		for j := 0; j < 10; j++ {
			content.WriteString(line(base.Add(time.Duration(i*10+j)*time.Minute), fmt.Sprintf("record %d", i*10+j)))
		}
		writeLog(t, filepath.Join(root, name), content.String(), base.Add(time.Duration(i*10+9)*time.Minute))
	}
	setNow(t, base.Add(40*time.Minute))
	return root
}

func search(t *testing.T, cfg Config, p Params) (SearchOutput, error) {
	t.Helper()
	return searchBudget(t, cfg, p, nil, 0)
}

func searchBudget(t *testing.T, cfg Config, p Params, redact func(string) string, maxOutput int64) (SearchOutput, error) {
	t.Helper()
	r, err := Run(context.Background(), cfg, p, redact, maxOutput)
	var out SearchOutput
	if err != nil {
		return out, err
	}
	if maxOutput > 0 && int64(len(r.Stdout)) > maxOutput {
		t.Fatalf("output %d bytes exceeds max_output %d", len(r.Stdout), maxOutput)
	}
	if jsonErr := json.Unmarshal([]byte(r.Stdout), &out); jsonErr != nil {
		t.Fatalf("invalid JSON %q: %v", r.Stdout, jsonErr)
	}
	return out, nil
}

func reasonOf(err error) string {
	var coded interface{ Reason() string }
	if errors.As(err, &coded) {
		return coded.Reason()
	}
	return ""
}

func messages(records []Record) []string {
	result := make([]string, len(records))
	for i, r := range records {
		result[i] = r.Text[strings.Index(r.Text, " - ")+3:]
	}
	return result
}

func TestParseTimeRange(t *testing.T) {
	at := base
	cases := []struct {
		name, since, until   string
		wantSince, wantUntil time.Time
		reason               string
	}{
		{"defaults", "", "", at.Add(-time.Hour), at, ""},
		{"relative", "30m", "", at.Add(-30 * time.Minute), at, ""},
		{"relative both", "2h", "1h", at.Add(-2 * time.Hour), at.Add(-time.Hour), ""},
		{"rfc3339", "2026-10-23T09:00:00+08:00", "2026-10-23T09:30:00.5+08:00", at.Add(-time.Hour), at.Add(-30*time.Minute + 500*time.Millisecond), ""},
		{"until only", "", "2026-10-23T08:00:00Z", time.Date(2026, 10, 23, 7, 0, 0, 0, time.UTC), time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC), ""},
		{"garbage", "yesterday", "", time.Time{}, time.Time{}, CodeTimeInvalid},
		{"negative", "-5m", "", time.Time{}, time.Time{}, CodeTimeInvalid},
		{"since after until", "1h", "2h", time.Time{}, time.Time{}, CodeTimeInvalid},
		{"equal", "1h", "1h", time.Time{}, time.Time{}, CodeTimeInvalid},
		{"too large", "25h", "", time.Time{}, time.Time{}, CodeWindowTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			since, until, err := parseTimeRange(tc.since, tc.until, at, 24*time.Hour)
			if tc.reason != "" {
				if reasonOf(err) != tc.reason {
					t.Fatalf("err=%v, want %s", err, tc.reason)
				}
				return
			}
			if err != nil || !since.Equal(tc.wantSince) || !until.Equal(tc.wantUntil) {
				t.Fatalf("got %v %v %v, want %v %v", since, until, err, tc.wantSince, tc.wantUntil)
			}
		})
	}
}

func TestTimestampParsing(t *testing.T) {
	cases := []struct {
		name string
		ts   Timestamp
		line string
		want time.Time
		ok   bool
	}{
		{"logback zone", Timestamp{Layouts: []string{logback}, Timezone: "Asia/Shanghai"}, "2026-10-23 10:00:01.250 [main] INFO x", base.Add(1250 * time.Millisecond), true},
		{"second layout", Timestamp{Layouts: []string{logback, "2006/01/02 15:04:05"}, Timezone: "Asia/Shanghai"}, "2026/10/23 10:00:02 x", base.Add(2 * time.Second), true},
		{"variable length rfc3339", Timestamp{Layouts: []string{time.RFC3339Nano}}, "2026-10-23T02:00:00.5Z level=info", time.Date(2026, 10, 23, 2, 0, 0, 5e8, time.UTC), true},
		{"variable length offset", Timestamp{Layouts: []string{time.RFC3339Nano}}, "2026-10-23T10:00:00+08:00 x", base, true},
		{"bracketed", Timestamp{Layouts: []string{"02/Jan/2006:15:04:05 -0700"}, Bracketed: true}, `1.2.3.4 - - [23/Oct/2026:10:00:00 +0800] "GET / HTTP/1.1" 200`, base, true},
		{"stack line", Timestamp{Layouts: []string{logback}}, "\tat com.example.Foo.bar(Foo.java:10)", time.Time{}, false},
		{"empty", Timestamp{Layouts: []string{logback}}, "", time.Time{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parser, err := newTimeParser(tc.ts)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := parser.parse(tc.line)
			if ok != tc.ok || (ok && !got.Equal(tc.want)) {
				t.Fatalf("parse(%q)=%v %v, want %v %v", tc.line, got, ok, tc.want, tc.ok)
			}
		})
	}
	local, err := newTimeParser(Timestamp{Layouts: []string{logback}})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := local.parse("2026-10-23 10:00:00.000 x"); got.Location() != time.Local {
		t.Fatalf("omitted timezone must use host local time, got %v", got.Location())
	}
}

func TestSeekSinceBisects(t *testing.T) {
	var content strings.Builder
	for i := 0; i < 20000; i++ {
		content.WriteString(line(base.Add(time.Duration(i)*time.Second), fmt.Sprintf("record %d", i)))
	}
	data := []byte(content.String())
	parser, err := newTimeParser(Timestamp{Layouts: []string{logback}, Timezone: "Asia/Shanghai"})
	if err != nil {
		t.Fatal(err)
	}
	since := base.Add(15000 * time.Second)
	offset, bisected, err := seekSince(bytes.NewReader(data), int64(len(data)), parser, since)
	if err != nil || !bisected {
		t.Fatalf("offset=%d bisected=%v err=%v", offset, bisected, err)
	}
	target := int64(bytes.Index(data, []byte("record 15000\n")))
	target = int64(bytes.LastIndexByte(data[:target], '\n') + 1)
	if offset > target || target-offset > 2*bisectBlock || (offset > 0 && data[offset-1] != '\n') {
		t.Fatalf("offset=%d, first record at %d", offset, target)
	}
}

func TestSeekSinceFallsBackWithoutTimestamps(t *testing.T) {
	var content strings.Builder
	content.WriteString(line(base, "first"))
	for i := 0; i < 5000; i++ {
		content.WriteString("\tat com.example.Foo.bar(Foo.java:10)\n")
	}
	content.WriteString(line(base.Add(time.Minute), "last"))
	data := []byte(content.String())
	parser, err := newTimeParser(Timestamp{Layouts: []string{logback}, Timezone: "Asia/Shanghai"})
	if err != nil {
		t.Fatal(err)
	}
	offset, bisected, err := seekSince(bytes.NewReader(data), int64(len(data)), parser, base.Add(30*time.Second))
	if err != nil || bisected || offset != 0 {
		t.Fatalf("want sequential scan from 0, got offset=%d bisected=%v err=%v", offset, bisected, err)
	}
	// The search itself still returns the record after the unparsed region.
	root := t.TempDir()
	writeLog(t, filepath.Join(root, "app.log"), content.String(), base.Add(time.Minute))
	setNow(t, base.Add(10*time.Minute))
	out, err := search(t, testConfig(root), Params{Source: "app", Since: "2026-10-23T10:00:30+08:00", Pattern: "last"})
	if err != nil || len(out.Records) != 1 || out.Records[0].Line != 5002 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestSearchUsesBisectedStart(t *testing.T) {
	root := t.TempDir()
	var content strings.Builder
	for i := 0; i < 20000; i++ {
		content.WriteString(line(base.Add(time.Duration(i)*time.Second), fmt.Sprintf("record %d", i)))
	}
	writeLog(t, filepath.Join(root, "app.log"), content.String(), base.Add(20000*time.Second))
	setNow(t, base.Add(20000*time.Second))
	out, err := search(t, testConfig(root), Params{Source: "app", Since: "2026-10-23T15:20:00+08:00", Until: "2026-10-23T15:20:04+08:00", Order: "asc"})
	if err != nil {
		t.Fatal(err)
	}
	got := messages(out.Records)
	want := []string{"record 19200", "record 19201", "record 19202", "record 19203", "record 19204"}
	if fmt.Sprint(got) != fmt.Sprint(want) || out.ScannedBytes > int64(content.Len())/4 {
		t.Fatalf("records=%v scanned=%d of %d", got, out.ScannedBytes, content.Len())
	}
}

const stackLog = "2026-10-23 10:00:00.000 [main] ERROR c.y.App - update failed\n" +
	"java.lang.IllegalStateException: boom\n" +
	"\tat com.example.Foo.bar(Foo.java:10)\n" +
	"\tat com.example.Foo.main(Foo.java:5)\n" +
	"2026-10-23 10:01:00.000 [main] INFO  c.y.App - ok\n"

func TestMultilineRecords(t *testing.T) {
	root := t.TempDir()
	writeLog(t, filepath.Join(root, "app.log"), stackLog, base.Add(time.Minute))
	setNow(t, base.Add(10*time.Minute))
	cfg := testConfig(root)
	out, err := search(t, cfg, Params{Source: "app", Pattern: "Foo.java:10", Fixed: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Records) != 1 || out.Records[0].Text != strings.Join(strings.Split(stackLog, "\n")[:4], "\n") || out.Records[0].Line != 1 || out.Records[0].RecordTruncated {
		t.Fatalf("records=%+v", out.Records)
	}
	if out.Records[0].Time != "2026-10-23T10:00:00+08:00" {
		t.Fatalf("time=%s", out.Records[0].Time)
	}

	none := cfg.Sources["app"]
	none.Multiline = MultilineNone
	cfg.Sources = map[string]Source{"app": none}
	out, err = search(t, cfg, Params{Source: "app", Pattern: "Foo.java:10", Fixed: true})
	if err != nil || len(out.Records) != 1 || out.Records[0].Text != "\tat com.example.Foo.bar(Foo.java:10)" || out.Records[0].Line != 3 || out.Records[0].Time != "2026-10-23T10:00:00+08:00" {
		t.Fatalf("none records=%+v err=%v", out.Records, err)
	}

	cfg = testConfig(root)
	cfg.MaxRecordBytes = 100
	out, err = search(t, cfg, Params{Source: "app", Pattern: "update failed"})
	if err != nil || len(out.Records) != 1 || !out.Records[0].RecordTruncated || len(out.Records[0].Text) > 100 {
		t.Fatalf("truncated records=%+v err=%v", out.Records, err)
	}
}

func TestMatchingOptions(t *testing.T) {
	root := rotated(t)
	cfg := testConfig(root)
	out, err := search(t, cfg, Params{Source: "app", Pattern: "RECORD 2[0-9]", IgnoreCase: true, Exclude: "record 2[5-9]", Order: "asc"})
	if err != nil || fmt.Sprint(messages(out.Records)) != "[record 20 record 21 record 22 record 23 record 24]" || out.Matched != 5 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	out, err = search(t, cfg, Params{Source: "app", Pattern: "record 1[", Fixed: true})
	if err != nil || out.Matched != 0 || len(out.Records) != 0 || out.HasMore {
		t.Fatalf("literal pattern without hits must succeed with matched=0: %+v %v", out, err)
	}
}

func pages(t *testing.T, cfg Config, p Params) [][]string {
	t.Helper()
	var result [][]string
	for i := 0; i < 20; i++ {
		out, err := search(t, cfg, p)
		if err != nil {
			t.Fatalf("page %d: %v", i, err)
		}
		result = append(result, messages(out.Records))
		if !out.HasMore {
			if out.NextCursor != "" {
				t.Fatal("cursor without has_more")
			}
			return result
		}
		p.Cursor = out.NextCursor
	}
	t.Fatal("too many pages")
	return nil
}

func numbered(from, to int) []string {
	var result []string
	step := 1
	if to < from {
		step = -1
	}
	for i := from; ; i += step {
		result = append(result, fmt.Sprintf("record %d", i))
		if i == to {
			return result
		}
	}
}

func TestPaginationDesc(t *testing.T) {
	cfg := testConfig(rotated(t))
	first, err := search(t, cfg, Params{Source: "app", Limit: 7})
	if err != nil || first.Matched != 30 || !first.HasMore || first.Order != "desc" || first.Files.Searched != 3 {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	got := pages(t, cfg, Params{Source: "app", Limit: 7})
	want := [][]string{numbered(29, 23), numbered(22, 16), numbered(15, 9), numbered(8, 2), numbered(1, 0)}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("pages=%v", got)
	}
}

func TestPaginationAsc(t *testing.T) {
	cfg := testConfig(rotated(t))
	got := pages(t, cfg, Params{Source: "app", Limit: 7, Order: "asc"})
	want := [][]string{numbered(0, 6), numbered(7, 13), numbered(14, 20), numbered(21, 27), numbered(28, 29)}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("pages=%v", got)
	}
	out, err := search(t, cfg, Params{Source: "app", Since: "2026-10-23T10:05:00+08:00", Until: "2026-10-23T10:12:00+08:00", Order: "asc"})
	if err != nil || fmt.Sprint(messages(out.Records)) != fmt.Sprint(numbered(5, 12)) || out.Files.SkippedOutOfRange != 1 {
		t.Fatalf("range out=%+v err=%v", out, err)
	}
}

func TestCursorValidation(t *testing.T) {
	cfg := testConfig(rotated(t))
	p := Params{Source: "app", Limit: 12, Order: "asc"}
	first, err := search(t, cfg, p)
	if err != nil || !first.HasMore {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	for name, mutate := range map[string]func(*Params){
		"not base64":        func(p *Params) { p.Cursor = "%%%" },
		"not json":          func(p *Params) { p.Cursor = "bm90LWpzb24" },
		"changed pattern":   func(p *Params) { p.Pattern = "record" },
		"changed order":     func(p *Params) { p.Order = "desc" },
		"offset past size":  func(p *Params) { p.Cursor = tamper(t, p.Cursor, func(c *cursor) { c.Offset = 1 << 40 }) },
		"offset mid line":   func(p *Params) { p.Cursor = tamper(t, p.Cursor, func(c *cursor) { c.Offset += 3 }) },
		"other source":      func(p *Params) { p.Cursor = tamper(t, p.Cursor, func(c *cursor) { c.Source = "other" }) },
		"window too large":  func(p *Params) { p.Cursor = tamper(t, p.Cursor, func(c *cursor) { c.Since = "2026-10-01T00:00:00Z" }) },
		"time outside page": func(p *Params) { p.Cursor = tamper(t, p.Cursor, func(c *cursor) { c.Time = "2026-10-24T00:00:00Z" }) },
	} {
		t.Run(name, func(t *testing.T) {
			next := p
			next.Cursor = first.NextCursor
			mutate(&next)
			_, err := search(t, cfg, next)
			if reasonOf(err) != CodeCursorInvalid {
				t.Fatalf("err=%v, want %s", err, CodeCursorInvalid)
			}
		})
	}
}

func tamper(t *testing.T, encoded string, change func(*cursor)) string {
	t.Helper()
	c, err := decodeCursor(encoded)
	if err != nil {
		t.Fatal(err)
	}
	change(&c)
	return c.encode()
}

func TestCursorFollowsRotation(t *testing.T) {
	root := rotated(t)
	cfg := testConfig(root)
	p := Params{Source: "app", Limit: 12, Order: "asc"}
	first, err := search(t, cfg, p)
	if err != nil || fmt.Sprint(messages(first.Records)) != fmt.Sprint(numbered(0, 11)) {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	// Rotate by rename: app.log.1 -> app.log.2, app.log -> app.log.1, new app.log.
	if err := os.Rename(filepath.Join(root, "app.log.1"), filepath.Join(root, "app.log.2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "app.log"), filepath.Join(root, "app.log.1")); err != nil {
		t.Fatal(err)
	}
	writeLog(t, filepath.Join(root, "app.log"), line(base.Add(30*time.Minute), "record 30")+line(base.Add(31*time.Minute), "record 31"), base.Add(31*time.Minute))
	p.Cursor = first.NextCursor
	second, err := search(t, cfg, p)
	if err != nil || fmt.Sprint(messages(second.Records)) != fmt.Sprint(numbered(12, 23)) || second.Records[0].File != filepath.Join(root, "app.log.2") {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	p.Cursor = second.NextCursor
	third, err := search(t, cfg, p)
	if err != nil || fmt.Sprint(messages(third.Records)) != fmt.Sprint(numbered(24, 31)) || third.HasMore {
		t.Fatalf("third=%+v err=%v", third, err)
	}
}

func TestCursorExpired(t *testing.T) {
	root := rotated(t)
	cfg := testConfig(root)
	p := Params{Source: "app", Limit: 12, Order: "asc"}
	first, err := search(t, cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	// Compressing app.log.1 replaces its inode.
	data, err := os.ReadFile(filepath.Join(root, "app.log.1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "app.log.1")); err != nil {
		t.Fatal(err)
	}
	writeLog(t, filepath.Join(root, "app.log.1.gz"), string(data), base.Add(19*time.Minute))
	p.Cursor = first.NextCursor
	_, err = search(t, cfg, p)
	if reasonOf(err) != CodeCursorExpired || !strings.Contains(err.Error(), "2026-10-23T10:12:00") {
		t.Fatalf("err=%v, want %s with the cursor time", err, CodeCursorExpired)
	}
}

func TestErrorCodes(t *testing.T) {
	root := rotated(t)
	outside := t.TempDir()
	writeLog(t, filepath.Join(outside, "secret.log"), line(base, "secret"), base)
	if err := os.Symlink(filepath.Join(outside, "secret.log"), filepath.Join(root, "link.log")); err != nil {
		t.Fatal(err)
	}
	writeLog(t, filepath.Join(root, "plain.txt"), "no timestamp here\n", base.Add(20*time.Minute))
	cfg := testConfig(root)
	cfg.Sources["empty"] = Source{Type: TypeFile, Paths: []string{root + "/missing*.log"}, Timestamp: Timestamp{Layouts: []string{logback}}}
	cfg.Sources["linked"] = Source{Type: TypeFile, Paths: []string{root + "/link.log"}, Timestamp: Timestamp{Layouts: []string{logback}}}
	cfg.Sources["unparsed"] = Source{Type: TypeFile, Paths: []string{root + "/plain.txt"}, Timestamp: Timestamp{Layouts: []string{logback}}}
	cases := []struct {
		name string
		p    Params
		code string
	}{
		{"unknown source", Params{Source: "nope"}, CodeSourceUnknown},
		{"no files", Params{Source: "empty"}, CodeSourceNoFiles},
		{"outside roots", Params{Source: "linked"}, CodePathOutsideRoots},
		{"window", Params{Source: "app", Since: "48h"}, CodeWindowTooLarge},
		{"time", Params{Source: "app", Since: "soon"}, CodeTimeInvalid},
		{"unparsed", Params{Source: "unparsed"}, CodeTimestampUnparsed},
		{"pattern", Params{Source: "app", Pattern: "("}, CodePatternInvalid},
		{"exclude", Params{Source: "app", Exclude: "[a"}, CodePatternInvalid},
		{"cursor invalid", Params{Source: "app", Cursor: "x"}, CodeCursorInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := search(t, cfg, tc.p)
			if reasonOf(err) != tc.code {
				t.Fatalf("err=%v, want %s", err, tc.code)
			}
		})
	}
	// CURSOR_EXPIRED is covered by TestCursorExpired.
}

func TestSkipsNonRegularFiles(t *testing.T) {
	root := rotated(t)
	if err := os.Mkdir(filepath.Join(root, "app.log.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "app.log.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := search(t, testConfig(root), Params{Source: "app", Limit: 1})
	if err != nil || out.Files.SkippedNotRegular != 2 || out.Matched != 30 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	cfg := testConfig(root)
	cfg.Mode = ModeSources
	r, err := Run(context.Background(), cfg, Params{}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var sources SourcesOutput
	if err := json.Unmarshal([]byte(r.Stdout), &sources); err != nil || len(sources.Sources) != 1 || sources.Sources[0].SkippedNotRegular != 2 || sources.Sources[0].Files != 3 {
		t.Fatalf("sources=%s err=%v", r.Stdout, err)
	}
}

func TestSourcesMode(t *testing.T) {
	root := rotated(t)
	writeLog(t, filepath.Join(root, "plain.txt"), "no timestamp here\n", base)
	cfg := testConfig(root)
	cfg.Mode = ModeSources
	cfg.Sources["empty"] = Source{Type: TypeFile, Paths: []string{root + "/missing*.log"}, Timestamp: Timestamp{Layouts: []string{logback}}}
	cfg.Sources["unparsed"] = Source{Type: TypeFile, Paths: []string{root + "/plain.txt"}, Timestamp: Timestamp{Layouts: []string{logback}, Timezone: "Asia/Shanghai"}}
	r, err := Run(context.Background(), cfg, Params{}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out SourcesOutput
	if err := json.Unmarshal([]byte(r.Stdout), &out); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, name := range []string{"app.log.2.gz", "app.log.1", "app.log"} {
		info, _ := os.Stat(filepath.Join(root, name))
		total += info.Size()
	}
	want := []SourceSummary{
		{Name: "app", Type: "file", Files: 3, Bytes: total, Earliest: "2026-10-23T10:00:00+08:00", Latest: "2026-10-23T10:29:00+08:00", TimestampParsed: true, Status: "ok"},
		{Name: "empty", Type: "file", Status: "no_files"},
		{Name: "unparsed", Type: "file", Files: 1, Bytes: 18, Latest: "2026-10-23T10:00:00+08:00", Status: "timestamp_unparsed"},
	}
	if fmt.Sprint(out.Sources) != fmt.Sprint(want) {
		t.Fatalf("sources=%+v\nwant    %+v", out.Sources, want)
	}
}

func TestScanLimitDesc(t *testing.T) {
	root := rotated(t)
	info, err := os.Stat(filepath.Join(root, "app.log"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(root)
	cfg.MaxScan = info.Size() + 10
	out, err := search(t, cfg, Params{Source: "app", Limit: 50})
	if err != nil || !out.ScanLimitReached || out.Matched != 10 || fmt.Sprint(messages(out.Records)) != fmt.Sprint(numbered(29, 20)) || out.ScannedSince != "2026-10-23T10:20:00+08:00" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	full, err := search(t, testConfig(root), Params{Source: "app"})
	if err != nil || full.ScanLimitReached || full.ScannedSince != full.Since {
		t.Fatalf("full=%+v err=%v", full, err)
	}
}

func TestGzipCountsDecompressedBytes(t *testing.T) {
	root := rotated(t)
	out, err := search(t, testConfig(root), Params{Source: "app", Since: "2026-10-23T10:00:00+08:00", Until: "2026-10-23T10:09:00+08:00", Order: "asc"})
	if err != nil {
		t.Fatal(err)
	}
	var content int64
	for j := 0; j < 10; j++ {
		content += int64(len(line(base, fmt.Sprintf("record %d", j))))
	}
	if out.Matched != 10 || out.ScannedBytes < content {
		t.Fatalf("matched=%d scanned=%d, want >= %d", out.Matched, out.ScannedBytes, content)
	}
}

func TestOutputBudgetAndRedaction(t *testing.T) {
	root := t.TempDir()
	var content strings.Builder
	for i := 0; i < 30; i++ {
		content.WriteString(line(base.Add(time.Duration(i)*time.Minute), fmt.Sprintf("record %d password=hunter2", i)))
	}
	writeLog(t, filepath.Join(root, "app.log"), content.String(), base.Add(29*time.Minute))
	setNow(t, base.Add(40*time.Minute))
	cfg := testConfig(root)
	redact := func(s string) string { return strings.ReplaceAll(s, "hunter2", "[REDACTED:credential]") }
	p := Params{Source: "app", Pattern: "hunter2", Limit: 30, Order: "asc"}
	var seen []string
	for page := 0; page < 30; page++ {
		out, err := searchBudget(t, cfg, p, redact, 1500)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Records) == 0 || len(out.Records) >= 30 {
			t.Fatalf("page %d records=%d", page, len(out.Records))
		}
		for _, r := range out.Records {
			if strings.Contains(r.Text, "hunter2") || !strings.Contains(r.Text, "[REDACTED:credential]") {
				t.Fatalf("unredacted %q", r.Text)
			}
			seen = append(seen, r.Text[strings.Index(r.Text, " - ")+3:strings.Index(r.Text, " password")])
		}
		if !out.HasMore {
			break
		}
		p.Cursor = out.NextCursor
	}
	if fmt.Sprint(seen) != fmt.Sprint(numbered(0, 29)) {
		t.Fatalf("seen=%v", seen)
	}

	big := t.TempDir()
	writeLog(t, filepath.Join(big, "app.log"), line(base, strings.Repeat("x", 10000)), base)
	out, err := searchBudget(t, testConfig(big), Params{Source: "app"}, nil, 2048)
	if err != nil || len(out.Records) != 1 || !out.Records[0].RecordTruncated || out.HasMore {
		t.Fatalf("big=%+v err=%v", out, err)
	}
}

func TestConfigValidate(t *testing.T) {
	root := t.TempDir()
	valid := testConfig(root)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	cases := map[string]func(*Config){
		"mode":             func(c *Config) { c.Mode = "stats" },
		"no sources":       func(c *Config) { c.Sources = nil },
		"no roots":         func(c *Config) { c.AllowedRoots = nil },
		"source name":      func(c *Config) { c.Sources = map[string]Source{"Bad Name": c.Sources["app"]} },
		"type":             func(c *Config) { s := c.Sources["app"]; s.Type = "k8s_pod"; c.Sources["app"] = s },
		"outside prefix":   func(c *Config) { s := c.Sources["app"]; s.Paths = []string{"/etc/*.log"}; c.Sources["app"] = s },
		"sibling prefix":   func(c *Config) { s := c.Sources["app"]; s.Paths = []string{root + "x/*.log"}; c.Sources["app"] = s },
		"relative":         func(c *Config) { s := c.Sources["app"]; s.Paths = []string{"logs/*.log"}; c.Sources["app"] = s },
		"parent segment":   func(c *Config) { s := c.Sources["app"]; s.Paths = []string{root + "/../*.log"}; c.Sources["app"] = s },
		"bad glob":         func(c *Config) { s := c.Sources["app"]; s.Paths = []string{root + "/[.log"}; c.Sources["app"] = s },
		"no layouts":       func(c *Config) { s := c.Sources["app"]; s.Timestamp.Layouts = nil; c.Sources["app"] = s },
		"timezone":         func(c *Config) { s := c.Sources["app"]; s.Timestamp.Timezone = "Mars/Base"; c.Sources["app"] = s },
		"multiline":        func(c *Config) { s := c.Sources["app"]; s.Multiline = "indent"; c.Sources["app"] = s },
		"max_files":        func(c *Config) { c.MaxFiles = DefaultMaxFiles + 1 },
		"max_scan":         func(c *Config) { c.MaxScan = DefaultMaxScan + 1 },
		"max_window":       func(c *Config) { c.MaxWindow = DefaultMaxWindow + time.Second },
		"max_page_records": func(c *Config) { c.MaxPageRecords = DefaultMaxPageRecords + 1 },
		"max_record_bytes": func(c *Config) { c.MaxRecordBytes = DefaultMaxRecordBytes + 1 },
		"timeout":          func(c *Config) { c.Timeout = 11 * time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := testConfig(root)
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
