package logquery

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// entry is one write of a container's output as Docker stores it.
type entry struct {
	at     time.Time
	stderr bool
	text   string // a write without a trailing newline is a partial line
}

// fakeDocker serves the parts of the Docker Engine API that log_query uses on
// a unix socket and points dockerSocket at it.
type fakeDocker struct {
	inspect    map[string]any // container name -> /json response
	entries    map[string][]entry
	logsStatus int // non-zero: /logs fails with this status
	requests   []string
}

func startDocker(t *testing.T, d *fakeDocker) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(d.serve)}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	previous := dockerSocket
	dockerSocket = socket
	t.Cleanup(func() { dockerSocket = previous })
}

func (d *fakeDocker) serve(w http.ResponseWriter, r *http.Request) {
	d.requests = append(d.requests, r.URL.RequestURI())
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) >= 1 && strings.HasPrefix(parts[0], "v1.") {
		parts = parts[1:]
	}
	if len(parts) != 3 || parts[0] != "containers" {
		http.NotFound(w, r)
		return
	}
	inspect, ok := d.inspect[parts[1]]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"message":"No such container: %s"}`, parts[1])
		return
	}
	switch parts[2] {
	case "json":
		json.NewEncoder(w).Encode(inspect)
	case "logs":
		if d.logsStatus != 0 {
			w.WriteHeader(d.logsStatus)
			fmt.Fprint(w, `{"message":"configured logging driver does not support reading"}`)
			return
		}
		q := r.URL.Query()
		if q.Get("timestamps") != "1" && q.Get("timestamps") != "true" {
			http.Error(w, "log_query must request timestamps", http.StatusBadRequest)
			return
		}
		since := parseDockerTime(q.Get("since"))
		until := parseDockerTime(q.Get("until"))
		tty, _ := inspect.(map[string]any)["Config"].(map[string]any)["Tty"].(bool)
		entries := d.entries[parts[1]]
		if tail := q.Get("tail"); tail != "" && tail != "all" {
			n, _ := strconv.Atoi(tail)
			entries = entries[max(0, len(entries)-n):]
		}
		for _, e := range entries {
			if !since.IsZero() && e.at.Before(since) || !until.IsZero() && e.at.After(until) {
				continue
			}
			payload := e.at.UTC().Format(time.RFC3339Nano) + " " + e.text
			if tty {
				fmt.Fprint(w, payload)
				continue
			}
			header := make([]byte, 8)
			header[0] = 1
			if e.stderr {
				header[0] = 2
			}
			binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
			w.Write(header)
			w.Write([]byte(payload))
		}
	default:
		http.NotFound(w, r)
	}
}

// parseDockerTime reads the since/until value: seconds with optional
// fractional nanoseconds.
func parseDockerTime(text string) time.Time {
	if text == "" || text == "0" {
		return time.Time{}
	}
	seconds, fraction, _ := strings.Cut(text, ".")
	s, _ := strconv.ParseInt(seconds, 10, 64)
	n := int64(0)
	if fraction != "" {
		n, _ = strconv.ParseInt((fraction + "000000000")[:9], 10, 64)
	}
	return time.Unix(s, n)
}

func stdoutConfig(container string) Config {
	return Config{Mode: ModeSearch, Sources: map[string]Source{
		"web": {Type: TypeContainerStdout, Container: container, Timestamp: Timestamp{Timezone: "Asia/Shanghai"}, Multiline: MultilineNone},
	}}
}

func running(tty bool) map[string]any {
	return map[string]any{"State": map[string]any{"Running": true}, "Config": map[string]any{"Tty": tty}, "Mounts": []any{}}
}

// texts returns the record texts.
func texts(records []Record) []string {
	result := make([]string, len(records))
	for i, r := range records {
		result[i] = r.Text
	}
	return result
}

func series(prefix string, from, to int) []string {
	var result []string
	step := 1
	if from > to {
		step = -1
	}
	for i := from; ; i += step {
		result = append(result, fmt.Sprintf("%s%d", prefix, i))
		if i == to {
			return result
		}
	}
}

// burst writes A1..A1000 one millisecond apart, pauses 4 seconds, then writes
// B1..B1000 (design 1.3). It returns the time of A1000.
func burst() ([]entry, time.Time) {
	var entries []entry
	at := base
	for i := 1; i <= 1000; i++ {
		entries = append(entries, entry{at: at, text: fmt.Sprintf("A%d\n", i)})
		at = at.Add(time.Millisecond)
	}
	last := at.Add(-time.Millisecond)
	at = at.Add(4 * time.Second)
	for i := 1; i <= 1000; i++ {
		entries = append(entries, entry{at: at, text: fmt.Sprintf("B%d\n", i)})
		at = at.Add(time.Millisecond)
	}
	return entries, last
}

func TestContainerStdoutUntilWithLimit(t *testing.T) {
	entries, a1000 := burst()
	d := &fakeDocker{inspect: map[string]any{"web-app": running(false)}, entries: map[string][]entry{"web-app": entries}}
	startDocker(t, d)
	setNow(t, base.Add(time.Hour))
	cfg := stdoutConfig("web-app")
	mid2 := a1000.Add(2 * time.Second).Format(time.RFC3339Nano)
	p := Params{Source: "web", Since: base.Add(-time.Minute).Format(time.RFC3339Nano), Until: mid2, Limit: 500}
	out, err := search(t, cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	if got := texts(out.Records); fmt.Sprint(got) != fmt.Sprint(series("A", 1000, 501)) || !out.HasMore || out.Matched != 1000 || out.Files != nil {
		t.Fatalf("desc page: matched=%d has_more=%v files=%v first=%v last=%v", out.Matched, out.HasMore, out.Files, got[:1], got[len(got)-1:])
	}
	if out.Records[0].Stream != "stdout" || out.Records[0].File != "" || out.Records[0].Offset != nil {
		t.Fatalf("record fields: %+v", out.Records[0])
	}
	if want := a1000.In(shanghai).Format(time.RFC3339Nano); out.Records[0].Time != want {
		t.Fatalf("record time %s, want Docker time %s", out.Records[0].Time, want)
	}
	for _, request := range d.requests {
		if strings.Contains(request, "tail=") && !strings.Contains(request, "tail=all") {
			t.Fatalf("request passes tail: %s", request)
		}
	}
	p.Cursor = out.NextCursor
	out, err = search(t, cfg, p)
	if err != nil || fmt.Sprint(texts(out.Records)) != fmt.Sprint(series("A", 500, 1)) || out.HasMore {
		t.Fatalf("second desc page: %v %v has_more=%v", err, texts(out.Records), out.HasMore)
	}
	asc := Params{Source: "web", Since: mid2, Until: base.Add(time.Minute).Format(time.RFC3339Nano), Limit: 500, Order: "asc"}
	out, err = search(t, cfg, asc)
	if err != nil || fmt.Sprint(texts(out.Records)) != fmt.Sprint(series("B", 1, 500)) || !out.HasMore {
		t.Fatalf("asc page: %v %v", err, out.HasMore)
	}
	asc.Cursor = out.NextCursor
	out, err = search(t, cfg, asc)
	if err != nil || fmt.Sprint(texts(out.Records)) != fmt.Sprint(series("B", 501, 1000)) || out.HasMore {
		t.Fatalf("second asc page: %v %v", err, out.HasMore)
	}
}

// Records with the same Docker time are paged by their index among them.
func TestContainerStdoutSameTimestampPaging(t *testing.T) {
	var entries []entry
	for i := 1; i <= 7; i++ {
		at := base.Add(time.Second)
		if i == 1 {
			at = base
		} else if i == 7 {
			at = base.Add(2 * time.Second)
		}
		entries = append(entries, entry{at: at, text: fmt.Sprintf("S%d\n", i)})
	}
	startDocker(t, &fakeDocker{inspect: map[string]any{"web-app": running(false)}, entries: map[string][]entry{"web-app": entries}})
	cfg := stdoutConfig("web-app")
	for _, order := range []string{"desc", "asc"} {
		p := Params{Source: "web", Since: base.Add(-time.Minute).Format(time.RFC3339), Until: base.Add(time.Minute).Format(time.RFC3339), Limit: 2, Order: order}
		var got []string
		for page := 0; page < 10; page++ {
			out, err := search(t, cfg, p)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, texts(out.Records)...)
			if !out.HasMore {
				break
			}
			p.Cursor = out.NextCursor
		}
		want := series("S", 1, 7)
		if order == "desc" {
			want = series("S", 7, 1)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s pages %v, want %v", order, got, want)
		}
	}
}

func TestContainerStdoutMultilineAndFrames(t *testing.T) {
	at := func(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }
	entries := []entry{
		{at: at(0), text: "2026-10-23 10:00:00.000 [main] ERROR c.y.App - boom\n"},
		{at: at(1), stderr: true, text: "java.lang.IllegalStateException: bad\n"},
		{at: at(2), stderr: true, text: "\tat com.example.Foo.bar(Foo.java:10)\n"},
		{at: at(3), text: "2026-10-23 10:00:00.003 [main] INFO  c.y.App - long "},
		{at: at(3), text: "line\n"},
		{at: at(4), text: "2026-10-23 10:00:00.004 [main] INFO  c.y.App - done\r\n"},
	}
	for _, tty := range []bool{false, true} {
		t.Run(fmt.Sprintf("tty=%v", tty), func(t *testing.T) {
			entries := entries
			if tty {
				// A terminal stream has no frames, so no partial writes.
				entries = append(append([]entry{}, entries[:3]...), entry{at: at(3), text: "2026-10-23 10:00:00.003 [main] INFO  c.y.App - long line\n"}, entries[5])
			}
			startDocker(t, &fakeDocker{inspect: map[string]any{"web-app": running(tty)}, entries: map[string][]entry{"web-app": entries}})
			cfg := stdoutConfig("web-app")
			source := cfg.Sources["web"]
			source.Multiline, source.Timestamp.Layouts = MultilineTimestampStart, []string{logback}
			cfg.Sources["web"] = source
			out, err := search(t, cfg, Params{Source: "web", Since: base.Add(-time.Minute).Format(time.RFC3339), Until: base.Add(time.Minute).Format(time.RFC3339), Order: "asc"})
			if err != nil {
				t.Fatal(err)
			}
			want := []string{
				"2026-10-23 10:00:00.000 [main] ERROR c.y.App - boom\njava.lang.IllegalStateException: bad\n\tat com.example.Foo.bar(Foo.java:10)",
				"2026-10-23 10:00:00.003 [main] INFO  c.y.App - long line",
				"2026-10-23 10:00:00.004 [main] INFO  c.y.App - done",
			}
			if fmt.Sprint(texts(out.Records)) != fmt.Sprint(want) {
				t.Fatalf("records %q, want %q", texts(out.Records), want)
			}
			if out.Records[0].Time != formatTime(base, shanghai) {
				t.Fatalf("record time %s", out.Records[0].Time)
			}
		})
	}
}

// A record that starts before since is not returned partly: its
// continuation lines inside the range are dropped.
func TestContainerStdoutDropsContinuationBeforeStart(t *testing.T) {
	entries := []entry{
		{at: base, text: "2026-10-23 10:00:00.000 [main] ERROR c.y.App - boom\n"},
		{at: base.Add(2 * time.Second), text: "\tat com.example.Foo.bar(Foo.java:10)\n"},
		{at: base.Add(3 * time.Second), text: "2026-10-23 10:00:03.000 [main] INFO  c.y.App - next\n"},
	}
	startDocker(t, &fakeDocker{inspect: map[string]any{"web-app": running(false)}, entries: map[string][]entry{"web-app": entries}})
	cfg := stdoutConfig("web-app")
	source := cfg.Sources["web"]
	source.Multiline, source.Timestamp.Layouts = MultilineTimestampStart, []string{logback}
	cfg.Sources["web"] = source
	for _, order := range []string{"asc", "desc"} {
		out, err := search(t, cfg, Params{Source: "web", Since: base.Add(time.Second).Format(time.RFC3339), Until: base.Add(time.Minute).Format(time.RFC3339), Order: order})
		if err != nil || out.Matched != 1 || !strings.HasSuffix(out.Records[0].Text, "next") {
			t.Fatalf("%s: %v %+v", order, err, out.Records)
		}
	}
}

func TestContainerStdoutScanLimit(t *testing.T) {
	entries, _ := burst()
	startDocker(t, &fakeDocker{inspect: map[string]any{"web-app": running(false)}, entries: map[string][]entry{"web-app": entries}})
	cfg := stdoutConfig("web-app")
	cfg.MaxScan = 20 << 10
	since, until := base.Add(-time.Minute), base.Add(time.Minute)
	out, err := search(t, cfg, Params{Source: "web", Since: since.Format(time.RFC3339), Until: until.Format(time.RFC3339), Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !out.ScanLimitReached || out.ScannedBytes > cfg.MaxScan+1<<10 || len(out.Records) == 0 || out.Records[0].Text != "B1000" {
		t.Fatalf("desc with scan limit: limited=%v scanned=%d records=%v", out.ScanLimitReached, out.ScannedBytes, texts(out.Records))
	}
	if scanned, _ := time.Parse(time.RFC3339Nano, out.ScannedSince); !scanned.After(since) || out.Matched >= 2000 {
		// matched counts only the scanned suffix of the range.
		t.Fatalf("scanned_since %s should be inside the range, matched %d below 2000", out.ScannedSince, out.Matched)
	}
	out, err = search(t, cfg, Params{Source: "web", Since: since.Format(time.RFC3339), Until: until.Format(time.RFC3339), Limit: 10, Order: "asc"})
	if err != nil || !out.ScanLimitReached || out.Records[0].Text != "A1" {
		t.Fatalf("asc with scan limit: %v %+v", err, out)
	}
}

func TestContainerStdoutErrors(t *testing.T) {
	cfg := stdoutConfig("web-app")
	p := Params{Source: "web", Since: "1h"}
	previous := dockerSocket
	dockerSocket = filepath.Join(t.TempDir(), "missing.sock")
	_, err := search(t, cfg, p)
	dockerSocket = previous
	if reasonOf(err) != CodeSourceUnavailable {
		t.Fatalf("missing socket: %v", err)
	}
	d := &fakeDocker{inspect: map[string]any{"other": running(false)}}
	startDocker(t, d)
	if _, err := search(t, cfg, p); reasonOf(err) != CodeSourceUnavailable {
		t.Fatalf("missing container: %v", err)
	}
	d.inspect["web-app"] = running(false)
	d.logsStatus = http.StatusNotImplemented
	if _, err := search(t, cfg, p); reasonOf(err) != CodeSourceUnsupported {
		t.Fatalf("driver without read support: %v", err)
	}
}

func TestContainerStdoutSources(t *testing.T) {
	entries, _ := burst()
	startDocker(t, &fakeDocker{inspect: map[string]any{"web-app": running(false)}, entries: map[string][]entry{"web-app": entries}})
	cfg := stdoutConfig("web-app")
	cfg.Mode = ModeSources
	cfg.Sources["gone"] = Source{Type: TypeContainerStdout, Container: "gone", Timestamp: Timestamp{Timezone: "Asia/Shanghai"}}
	r, err := Run(context.Background(), cfg, Params{}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out SourcesOutput
	if err := json.Unmarshal([]byte(r.Stdout), &out); err != nil {
		t.Fatal(err)
	}
	last := entries[len(entries)-1].at
	want := []SourceSummary{
		{Name: "gone", Type: TypeContainerStdout, Status: "unavailable", Reason: CodeSourceUnavailable},
		{Name: "web", Type: TypeContainerStdout, Earliest: formatTime(base, shanghai), Latest: formatTime(last, shanghai), TimestampParsed: true, Status: "ok"},
	}
	if fmt.Sprint(out.Sources) != fmt.Sprint(want) {
		t.Fatalf("sources %+v, want %+v", out.Sources, want)
	}
}

func TestContainerSourceValidation(t *testing.T) {
	file := Source{Type: TypeFile, Paths: []string{"/var/log/a.log"}, Timestamp: Timestamp{Layouts: []string{logback}}}
	cases := map[string]Source{
		"stdout without container":     {Type: TypeContainerStdout},
		"stdout bad container name":    {Type: TypeContainerStdout, Container: "web/../x"},
		"stdout with paths":            {Type: TypeContainerStdout, Container: "web", Paths: []string{"/x"}},
		"stdout multiline no layouts":  {Type: TypeContainerStdout, Container: "web", Multiline: MultilineTimestampStart},
		"file with container":          {Type: TypeFile, Container: "web", Paths: file.Paths, Timestamp: file.Timestamp},
		"container_file outside roots": {Type: TypeContainerFile, Container: "web", Paths: []string{"/etc/*.log"}, AllowedRoots: []string{"/opt/app/logs"}, Timestamp: file.Timestamp},
		"container_file without roots": {Type: TypeContainerFile, Container: "web", Paths: []string{"/opt/app/logs/*.log"}, Timestamp: file.Timestamp},
		"k8s_pod without namespace":    {Type: TypeK8sPod, Pod: "web-", Container: "app"},
		"k8s_pod bad pod prefix":       {Type: TypeK8sPod, Namespace: "default", Pod: "web_x", Container: "app"},
	}
	for name, source := range cases {
		cfg := Config{Mode: ModeSearch, Sources: map[string]Source{"s": source}, AllowedRoots: []string{"/var/log"}}
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
	valid := Config{Mode: ModeSearch, Sources: map[string]Source{
		"stdout": {Type: TypeContainerStdout, Container: "web-app"},
		"files":  {Type: TypeContainerFile, Container: "web-app", Paths: []string{"/opt/app/logs/*.log*"}, AllowedRoots: []string{"/opt/app/logs"}, Timestamp: file.Timestamp},
		"pod":    {Type: TypeK8sPod, Namespace: "default", Pod: "web-app-", Container: "app"},
	}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("container sources without file sources need no allowed_roots: %v", err)
	}
}

// containerFileConfig reads /opt/app/logs/*.log* inside container web-app.
func containerFileConfig() Config {
	return Config{Mode: ModeSearch, Sources: map[string]Source{"files": {
		Type: TypeContainerFile, Container: "web-app", Paths: []string{"/opt/app/logs/*.log*"}, AllowedRoots: []string{"/opt/app/logs"},
		Timestamp: Timestamp{Layouts: []string{logback}, Timezone: "Asia/Shanghai"}, Multiline: MultilineTimestampStart,
	}}}
}

func writeRecords(t *testing.T, path string, from, to int) {
	t.Helper()
	var content strings.Builder
	for i := from; i <= to; i++ {
		content.WriteString(line(base.Add(time.Duration(i)*time.Minute), fmt.Sprintf("record %d", i)))
	}
	writeLog(t, path, content.String(), base.Add(time.Duration(to)*time.Minute))
}

func TestContainerFileBindMount(t *testing.T) {
	host := t.TempDir()
	writeRecords(t, filepath.Join(host, "app.log"), 0, 9)
	inspect := running(false)
	inspect["Mounts"] = []any{map[string]any{"Type": "bind", "Source": host, "Destination": "/opt/app/logs"}}
	inspect["GraphDriver"] = map[string]any{"Name": "overlay2", "Data": map[string]any{"MergedDir": t.TempDir()}}
	startDocker(t, &fakeDocker{inspect: map[string]any{"web-app": inspect}})
	setNow(t, base.Add(20*time.Minute))
	cfg := containerFileConfig()
	out, err := search(t, cfg, Params{Source: "files", Since: "30m", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if out.Matched != 10 || out.Records[0].File != "/opt/app/logs/app.log" || fmt.Sprint(messages(out.Records)) != "[record 9 record 8 record 7]" {
		t.Fatalf("bind mount: %+v", out)
	}
	next := Params{Source: "files", Since: "30m", Limit: 3, Cursor: out.NextCursor}
	if out, err = search(t, cfg, next); err != nil || fmt.Sprint(messages(out.Records)) != "[record 6 record 5 record 4]" {
		t.Fatalf("bind mount next page: %v %+v", err, out)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(host, "passwd.log")); err != nil {
		t.Fatal(err)
	}
	if _, err := search(t, cfg, Params{Source: "files", Since: "30m"}); reasonOf(err) != CodePathOutsideRoots {
		t.Fatalf("symlink to /etc/passwd in a bind mount: %v", err)
	}
}

func TestContainerFileOverlay(t *testing.T) {
	merged := t.TempDir()
	logs := filepath.Join(merged, "opt", "app", "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRecords(t, filepath.Join(logs, "app.log"), 0, 9)
	inspect := running(false)
	inspect["GraphDriver"] = map[string]any{"Name": "overlay2", "Data": map[string]any{"MergedDir": merged}}
	d := &fakeDocker{inspect: map[string]any{"web-app": inspect}}
	startDocker(t, d)
	setNow(t, base.Add(20*time.Minute))
	cfg := containerFileConfig()
	out, err := search(t, cfg, Params{Source: "files", Since: "30m", Order: "asc", Limit: 2})
	if err != nil || out.Matched != 10 || out.Records[0].File != "/opt/app/logs/app.log" || fmt.Sprint(messages(out.Records)) != "[record 0 record 1]" {
		t.Fatalf("overlay2: %v %+v", err, out)
	}
	// A symlink inside the container resolves inside the container's root:
	// relative targets in the root are read, absolute ones are rejected.
	if err := os.Symlink("app.log", filepath.Join(logs, "current.log")); err != nil {
		t.Fatal(err)
	}
	if out, err = search(t, cfg, Params{Source: "files", Since: "30m"}); err != nil || out.Matched != 10 {
		t.Fatalf("relative symlink in the root is the same file: %v %+v", err, out)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(logs, "passwd.log")); err != nil {
		t.Fatal(err)
	}
	if _, err := search(t, cfg, Params{Source: "files", Since: "30m"}); reasonOf(err) != CodePathOutsideRoots {
		t.Fatalf("symlink to /etc/passwd inside the container: %v", err)
	}
	os.Remove(filepath.Join(logs, "passwd.log"))
	if err := os.Symlink("../../../../../../../../etc/passwd", filepath.Join(logs, "escape.log")); err != nil {
		t.Fatal(err)
	}
	if _, err := search(t, cfg, Params{Source: "files", Since: "30m"}); reasonOf(err) != CodePathOutsideRoots {
		t.Fatalf("relative symlink leaving the container root: %v", err)
	}
	os.Remove(filepath.Join(logs, "escape.log"))
	// The allowed root itself may not be a symlink out of the container.
	if err := os.RemoveAll(filepath.Join(merged, "opt", "app")); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(merged, "opt", "app"), 0o755)
	if err := os.Symlink("/var/log", filepath.Join(merged, "opt", "app", "logs")); err != nil {
		t.Fatal(err)
	}
	if _, err := search(t, cfg, Params{Source: "files", Since: "30m"}); reasonOf(err) != CodePathOutsideRoots {
		t.Fatalf("allowed root symlinked out of the container: %v", err)
	}
	inspect["GraphDriver"] = map[string]any{"Name": "btrfs", "Data": map[string]any{}}
	if _, err := search(t, cfg, Params{Source: "files", Since: "30m"}); reasonOf(err) != CodeSourceUnsupported {
		t.Fatalf("other storage driver: %v", err)
	}
	delete(inspect, "GraphDriver")
	if _, err := search(t, cfg, Params{Source: "files", Since: "30m"}); reasonOf(err) != CodeSourceUnsupported {
		t.Fatalf("no storage driver data (containerd snapshotter): %v", err)
	}
}
