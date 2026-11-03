package logquery

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func exportConfig(root string) Config {
	cfg := testConfig(root)
	cfg.Mode = ModeExport
	return cfg
}

func export(t *testing.T, cfg Config, p Params, redact func(string) string, maxOutput int64) string {
	t.Helper()
	r, err := Run(context.Background(), cfg, p, redact, maxOutput)
	if err != nil {
		t.Fatal(err)
	}
	if maxOutput > 0 && int64(len(r.Stdout)) > maxOutput {
		t.Fatalf("output %d bytes exceeds max_output %d", len(r.Stdout), maxOutput)
	}
	return r.Stdout
}

// exportLines splits an export into record lines and the trailer line.
func exportLines(t *testing.T, output string) ([]string, string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	trailer := lines[len(lines)-1]
	if !strings.HasPrefix(trailer, "# ") {
		t.Fatalf("export must end with a trailer line: %q", output)
	}
	return lines[:len(lines)-1], trailer
}

func TestExportWritesOneLinePerRecord(t *testing.T) {
	root := rotated(t)
	cfg := exportConfig(root)
	output := export(t, cfg, Params{Source: "app", Since: "1h"}, nil, 0)
	lines, trailer := exportLines(t, output)
	if len(lines) != 30 {
		t.Fatalf("lines %d: %q", len(lines), output)
	}
	if want := "2026-10-23T10:00:00+08:00 " + strings.TrimSuffix(line(base, "record 0"), "\n"); lines[0] != want {
		t.Fatalf("first line %q, want %q", lines[0], want)
	}
	if !strings.HasSuffix(lines[29], "record 29") || trailer != "# matched=30 scanned_bytes="+trailerField(trailer, "scanned_bytes")+" scan_limit_reached=false" {
		t.Fatalf("last line %q trailer %q", lines[29], trailer)
	}
}

func trailerField(trailer, name string) string {
	for _, field := range strings.Fields(trailer) {
		if value, ok := strings.CutPrefix(field, name+"="); ok {
			return value
		}
	}
	return ""
}

func TestExportEscapesMultilineAndRedacts(t *testing.T) {
	root := t.TempDir()
	writeLog(t, root+"/app.log", line(base, "boom password=hunter2")+"java.lang.IllegalStateException: a\\b\n\tat Foo\n", base)
	setNow(t, base.Add(10*time.Minute))
	redact := func(s string) string { return strings.ReplaceAll(s, "hunter2", "[REDACTED]") }
	output := export(t, exportConfig(root), Params{Source: "app", Since: "1h"}, redact, 0)
	lines, _ := exportLines(t, output)
	want := "2026-10-23T10:00:00+08:00 " + strings.TrimSuffix(line(base, "boom password=[REDACTED]"), "\n") + `\njava.lang.IllegalStateException: a\\b\n` + "\tat Foo"
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("lines %q, want %q", lines, want)
	}
}

func TestExportPagesByMaxOutput(t *testing.T) {
	root := rotated(t)
	cfg := exportConfig(root)
	p := Params{Source: "app", Since: "1h", Pattern: "record"}
	var got []string
	pages := 0
	for ; pages < 20; pages++ {
		lines, trailer := exportLines(t, export(t, cfg, p, nil, 1200))
		for _, l := range lines {
			_, message, _ := strings.Cut(l, " - ")
			got = append(got, message)
		}
		next := trailerField(trailer, "next_cursor")
		if next == "" {
			break
		}
		p.Cursor = next
	}
	if pages < 2 || fmt.Sprint(got) != fmt.Sprint(numbered(0, 29)) {
		t.Fatalf("pages %d records %q", pages, got)
	}
}

func TestExportParameters(t *testing.T) {
	defs := Parameters(exportConfig("/var/log"))
	if _, ok := defs["order"]; ok {
		t.Fatal("export order is fixed to asc")
	}
	for _, name := range []string{"source", "since", "until", "pattern", "fixed", "exclude", "ignore_case", "limit", "cursor"} {
		if _, ok := defs[name]; !ok {
			t.Fatalf("missing parameter %s", name)
		}
	}
}
