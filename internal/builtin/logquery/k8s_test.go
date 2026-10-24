package logquery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// criLine formats one CRI log line: <RFC3339Nano> <stream> <P|F> <content>.
func criLine(at time.Time, stream, tag, content string) string {
	return at.UTC().Format(time.RFC3339Nano) + " " + stream + " " + tag + " " + content + "\n"
}

func podRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	previous := podLogRoot
	podLogRoot = root
	t.Cleanup(func() { podLogRoot = previous })
	return root
}

func podConfig() Config {
	return Config{Mode: ModeSearch, Sources: map[string]Source{"pod": {
		Type: TypeK8sPod, Namespace: "shop", Pod: "web-app-", Container: "app",
		Timestamp: Timestamp{Timezone: "Asia/Shanghai"}, Multiline: MultilineNone,
	}}}
}

// writePodLog writes lines to <root>/<namespace>_<pod>_<uid>/<container>/<name>.
func writePodLog(t *testing.T, root, dir, container, name, content string, mtime time.Time) string {
	t.Helper()
	path := filepath.Join(root, dir, container, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	writeLog(t, path, content, mtime)
	return path
}

func TestK8sPodCRILines(t *testing.T) {
	root := podRoot(t)
	at := func(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }
	content := criLine(at(0), "stdout", "F", "hello") +
		criLine(at(1), "stdout", "P", "first part, ") +
		criLine(at(2), "stdout", "P", "second part, ") +
		criLine(at(3), "stdout", "F", "last part") +
		criLine(at(4), "stderr", "F", "") +
		criLine(at(5), "stderr", "F", "warn")
	writePodLog(t, root, "shop_web-app-7d9f8-x2k4p_0f2c", "app", "0.log", content, at(5))
	// Same prefix in another namespace, another container and another pod
	// name are not part of the source.
	writePodLog(t, root, "other_web-app-7d9f8-zzzzz_9a1b", "app", "0.log", criLine(at(0), "stdout", "F", "other namespace"), at(0))
	writePodLog(t, root, "shop_web-app-7d9f8-x2k4p_0f2c", "sidecar", "0.log", criLine(at(0), "stdout", "F", "sidecar"), at(0))
	writePodLog(t, root, "shop_db-0_77aa", "app", "0.log", criLine(at(0), "stdout", "F", "db"), at(0))
	setNow(t, base.Add(time.Minute))
	out, err := search(t, podConfig(), Params{Source: "pod", Since: "10m", Order: "asc"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"hello", "first part, second part, last part", "", "warn"}
	if fmt.Sprint(texts(out.Records)) != fmt.Sprint(want) {
		t.Fatalf("records %q, want %q", texts(out.Records), want)
	}
	r := out.Records[1]
	if r.Time != formatTime(at(1), shanghai) || r.Stream != "stdout" || out.Records[3].Stream != "stderr" ||
		r.File != filepath.Join(root, "shop_web-app-7d9f8-x2k4p_0f2c", "app", "0.log") || out.Files.Searched != 1 {
		t.Fatalf("record %+v files %+v", r, out.Files)
	}
}

// Rotated CRI files (kubelet names them 0.log.<time> and compresses older
// ones) form one timeline; cursors work across them.
func TestK8sPodRotationAndPaging(t *testing.T) {
	root := podRoot(t)
	dir := "shop_web-app-7d9f8-x2k4p_0f2c"
	var all []string
	write := func(name string, from, to int) {
		var content strings.Builder
		for i := from; i <= to; i++ {
			text := fmt.Sprintf("line %d", i)
			all = append(all, text)
			content.WriteString(criLine(base.Add(time.Duration(i)*time.Second), "stdout", "F", text))
		}
		writePodLog(t, root, dir, "app", name, content.String(), base.Add(time.Duration(to)*time.Second))
	}
	write("0.log.20261023-100010.gz", 0, 9)
	write("0.log.20261023-100020", 10, 19)
	write("0.log", 20, 29)
	setNow(t, base.Add(time.Minute))
	for _, order := range []string{"asc", "desc"} {
		p := Params{Source: "pod", Since: "1h", Order: order, Limit: 7}
		var got []string
		for page := 0; page < 10; page++ {
			out, err := search(t, podConfig(), p)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, texts(out.Records)...)
			if !out.HasMore {
				break
			}
			p.Cursor = out.NextCursor
		}
		want := series("line ", 0, 29)
		if order == "desc" {
			want = series("line ", 29, 0)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s: %q", order, got)
		}
	}
	// since in the middle of the plain file bisects to the first line.
	out, err := search(t, podConfig(), Params{Source: "pod", Since: base.Add(25 * time.Second).Format(time.RFC3339), Order: "asc"})
	if err != nil || fmt.Sprint(texts(out.Records)) != fmt.Sprint(series("line ", 25, 29)) {
		t.Fatalf("since inside a file: %v %q", err, texts(out.Records))
	}
}

func TestK8sPodMultiline(t *testing.T) {
	root := podRoot(t)
	at := func(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }
	content := criLine(at(0), "stdout", "F", "2026-10-23 10:00:00.000 [main] ERROR c.y.App - boom") +
		criLine(at(1), "stdout", "F", "java.lang.IllegalStateException: bad") +
		criLine(at(2), "stdout", "F", "\tat com.example.Foo.bar(Foo.java:10)") +
		criLine(at(3), "stdout", "F", "2026-10-23 10:00:00.003 [main] INFO  c.y.App - ok")
	writePodLog(t, root, "shop_web-app-1_u", "app", "0.log", content, at(3))
	setNow(t, base.Add(time.Minute))
	cfg := podConfig()
	source := cfg.Sources["pod"]
	source.Multiline, source.Timestamp.Layouts = MultilineTimestampStart, []string{logback}
	cfg.Sources["pod"] = source
	out, err := search(t, cfg, Params{Source: "pod", Since: "10m", Pattern: "Foo.java", Fixed: true})
	if err != nil || out.Matched != 1 || !strings.HasPrefix(out.Records[0].Text, "2026-10-23 10:00:00.000 [main] ERROR") || out.Records[0].Time != formatTime(base, shanghai) {
		t.Fatalf("multiline: %v %+v", err, out.Records)
	}
	// Bisection or a since inside the record must not return its tail as a
	// record of its own.
	out, err = search(t, cfg, Params{Source: "pod", Since: at(1).Format(time.RFC3339Nano), Order: "asc"})
	if err != nil || len(out.Records) != 1 || !strings.HasSuffix(out.Records[0].Text, "- ok") {
		t.Fatalf("since inside a record: %v %q", err, texts(out.Records))
	}
}

func TestK8sPodNoMatch(t *testing.T) {
	root := podRoot(t)
	writePodLog(t, root, "shop_db-0_77aa", "app", "0.log", criLine(base, "stdout", "F", "db"), base)
	setNow(t, base.Add(time.Minute))
	if _, err := search(t, podConfig(), Params{Source: "pod", Since: "10m"}); reasonOf(err) != CodeSourceNoFiles {
		t.Fatalf("no matching Pod: %v", err)
	}
}
