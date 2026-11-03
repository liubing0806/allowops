package arthas

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The responses in testdata/<jdk> were recorded from Arthas 4.3.5 by
// TestRealArthas. testdata/golden/<jdk> holds the text Render makes of them;
// ALLOWOPS_ARTHAS_UPDATE_GOLDEN=1 go test -run TestRenderGolden rewrites it,
// and the diff must be read before it is committed.

var renderJDKs = []string{"jdk8", "jdk17"}

// renderCases lists the recorded responses and the command each one answers.
// failure is the message of the status result when the command failed.
var renderCases = []struct {
	name    string
	kind    Kind
	failure string
}{
	{name: "version", kind: KindVersion},
	{name: "dashboard", kind: KindDashboard},
	{name: "dashboard_interrupted", kind: KindDashboard},
	{name: "thread_top", kind: KindThreadTop},
	{name: "thread_info", kind: KindThreadInfo},
	{name: "thread_info_missing", kind: KindThreadInfo, failure: "thread do not exist! id: 987654"},
	{name: "thread_blocking", kind: KindThreadBlocking},
	{name: "thread_blocking_none", kind: KindThreadBlocking, failure: "No most blocking thread found!"},
	{name: "memory", kind: KindMemory},
	{name: "jvm", kind: KindJVM},
	{name: "class_info", kind: KindClassInfo},
	{name: "class_info_nested", kind: KindClassInfo},
	{name: "class_info_missing", kind: KindClassInfo},
	{name: "method_info", kind: KindMethodInfo},
	{name: "method_info_all", kind: KindMethodInfo},
	{name: "classloader_tree", kind: KindClassLoaderTree},
	{name: "classloader_list", kind: KindClassLoaderList},
	{name: "logger", kind: KindLogger},
	{name: "sysprop", kind: KindSysprop},
	{name: "sysprop_missing", kind: KindSysprop, failure: "There is no property with the key no.such.key"},
}

// loadResponse reads a recorded envelope the way Client.Exec decodes it.
func loadResponse(t *testing.T, jdk, name string) *ExecResponse {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", jdk, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var env apiResponse
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("%s/%s: %v", jdk, name, err)
	}
	resp, err := decodeExec(&env)
	if err != nil {
		t.Fatalf("%s/%s: %v", jdk, name, err)
	}
	return resp
}

// resultsOf builds a response from result objects and adds a successful status.
func resultsOf(t *testing.T, results ...string) *ExecResponse {
	t.Helper()
	return rawResultsOf(t, append(results, `{"type":"status","statusCode":0}`)...)
}

// rawResultsOf builds a response from result objects only.
func rawResultsOf(t *testing.T, results ...string) *ExecResponse {
	t.Helper()
	resp := &ExecResponse{JobStatus: "TERMINATED"}
	for _, s := range results {
		var r Result
		if err := json.Unmarshal([]byte(s), &r); err != nil {
			t.Fatalf("result %s: %v", s, err)
		}
		resp.Results = append(resp.Results, r)
	}
	return resp
}

func mustRender(t *testing.T, kind Kind, resp *ExecResponse) string {
	t.Helper()
	out, err := Render(kind, resp)
	if err != nil {
		t.Fatalf("Render(%s): %v", kind, err)
	}
	return out
}

// sectionLines returns the lines under header up to the next blank line.
func sectionLines(t *testing.T, out, header string) []string {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if l != header {
			continue
		}
		end := i + 1
		for end < len(lines) && lines[end] != "" {
			end++
		}
		return lines[i+1 : end]
	}
	t.Fatalf("no section %q in:\n%s", header, out)
	return nil
}

func column(lines []string, i int) []string {
	var col []string
	for _, l := range lines {
		cells := strings.Split(l, "\t")
		if i < len(cells) {
			col = append(col, cells[i])
		}
	}
	return col
}

func firstDifference(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < max(len(g), len(w)); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl || i >= len(g) || i >= len(w) {
			return fmt.Sprintf("line %d:\n got  %q\n want %q", i+1, gl, wl)
		}
	}
	return "no difference"
}

func TestRenderGolden(t *testing.T) {
	update := os.Getenv("ALLOWOPS_ARTHAS_UPDATE_GOLDEN") == "1"
	for _, jdk := range renderJDKs {
		for _, c := range renderCases {
			if c.failure != "" {
				continue
			}
			t.Run(jdk+"/"+c.name, func(t *testing.T) {
				got := mustRender(t, c.kind, loadResponse(t, jdk, c.name))
				path := filepath.Join("testdata", "golden", jdk, c.name+".txt")
				if update {
					if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
						t.Fatal(err)
					}
					return
				}
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("%v (ALLOWOPS_ARTHAS_UPDATE_GOLDEN=1 writes the file)", err)
				}
				if got != string(want) {
					t.Errorf("%s differs from the output of Render:\n%s", path, firstDifference(got, string(want)))
				}
			})
		}
	}
}

func TestRenderCoversEveryKind(t *testing.T) {
	covered := map[Kind]bool{}
	for _, c := range renderCases {
		covered[c.kind] = true
	}
	for _, k := range Kinds() {
		if !covered[k] {
			t.Errorf("no recorded response for kind %s", k)
		}
	}
}

// TestRenderShape checks what every output has in common.
func TestRenderShape(t *testing.T) {
	for _, jdk := range renderJDKs {
		for _, c := range renderCases {
			if c.failure != "" {
				continue
			}
			t.Run(jdk+"/"+c.name, func(t *testing.T) {
				out := mustRender(t, c.kind, loadResponse(t, jdk, c.name))
				if !strings.HasPrefix(out, "# ") {
					t.Errorf("output does not start with a section header: %.40q", out)
				}
				if !strings.HasSuffix(out, "\n") || strings.HasSuffix(out, "\n\n") {
					t.Errorf("output must end with exactly one newline: %.40q", out[max(0, len(out)-40):])
				}
				if strings.Contains(out, "\n\n\n") {
					t.Error("output has two blank lines in a row")
				}
				for i, r := range out {
					if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
						t.Fatalf("output has the control character %q at byte %d", r, i)
					}
				}
				again := mustRender(t, c.kind, loadResponse(t, jdk, c.name))
				if again != out {
					t.Error("two renderings of the same response differ")
				}
			})
		}
	}
}

func TestRenderCommandError(t *testing.T) {
	for _, jdk := range renderJDKs {
		for _, c := range renderCases {
			if c.failure == "" {
				continue
			}
			t.Run(jdk+"/"+c.name, func(t *testing.T) {
				out, err := Render(c.kind, loadResponse(t, jdk, c.name))
				var ce *CommandError
				if !errors.As(err, &ce) {
					t.Fatalf("Render = %q, %v; want a *CommandError", out, err)
				}
				if out != "" {
					t.Errorf("output with an error = %q, want empty", out)
				}
				if ce.Kind != c.kind || ce.Code != 1 || ce.Message != c.failure {
					t.Errorf("CommandError = %+v, want kind %s code 1 message %q", ce, c.kind, c.failure)
				}
				if !strings.Contains(err.Error(), c.failure) {
					t.Errorf("error text %q does not hold the message", err)
				}
			})
		}
	}
}

func TestRenderCommandErrorWinsOverResults(t *testing.T) {
	resp := rawResultsOf(t,
		`{"type":"version","version":"4.3.5"}`,
		`{"type":"status","statusCode":-1,"message":"bad\nkey\u001b[0m"}`)
	_, err := Render(KindVersion, resp)
	var ce *CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("Render error = %v, want a *CommandError", err)
	}
	if ce.Code != -1 {
		t.Errorf("code = %d, want -1", ce.Code)
	}
	if want := `bad\nkey\x1b[0m`; ce.Message != want {
		t.Errorf("message = %q, want control characters escaped: %q", ce.Message, want)
	}
}

func TestRenderVersion(t *testing.T) {
	got := mustRender(t, KindVersion, loadResponse(t, "jdk17", "version"))
	if want := "# version\nversion\t4.3.5\n"; got != want {
		t.Errorf("version = %q, want %q", got, want)
	}
}

func TestRenderSysprop(t *testing.T) {
	for jdk, version := range map[string]string{"jdk8": "1.8.0_504", "jdk17": "17.0.20.1"} {
		got := mustRender(t, KindSysprop, loadResponse(t, jdk, "sysprop"))
		if want := "# sysprop\nkey\tvalue\njava.version\t" + version + "\n"; got != want {
			t.Errorf("%s sysprop = %q, want %q", jdk, got, want)
		}
	}
}

func TestRenderThreadInfo(t *testing.T) {
	got := mustRender(t, KindThreadInfo, loadResponse(t, "jdk17", "thread_info"))
	want := "# thread\n" +
		"id\t2\n" +
		"name\tReference Handler\n" +
		"state\tRUNNABLE\n" +
		"daemon\ttrue\n" +
		"priority\t10\n" +
		"in_native\tfalse\n" +
		"suspended\tfalse\n" +
		"blocked_count\t0\n" +
		"blocked_time_ms\t-1\n" +
		"waited_count\t0\n" +
		"waited_time_ms\t-1\n" +
		"lock_owner_id\t-1\n" +
		"\n" +
		"# stack 2 Reference Handler\n" +
		"at java.lang.ref.Reference.waitForReferencePendingList(Native Method)\n" +
		"at java.lang.ref.Reference.processPendingReferences(Reference.java:253)\n" +
		"at java.lang.ref.Reference$ReferenceHandler.run(Reference.java:215)\n"
	if got != want {
		t.Errorf("thread_info differs:\n%s", firstDifference(got, want))
	}
}

func TestRenderStackFrames(t *testing.T) {
	frame := func(file string, line int) string {
		b, _ := json.Marshal(map[string]any{"className": "a.B", "methodName": "m", "fileName": file, "lineNumber": line})
		return string(b)
	}
	resp := resultsOf(t, `{"type":"thread","threadInfo":{"threadId":7,"threadName":"t","threadState":"RUNNABLE","stackTrace":[`+
		strings.Join([]string{frame("B.java", 12), frame("B.java", -2), frame("B.java", -1), frame("", -1)}, ",")+
		`],"lockedMonitors":[{"className":"java.lang.Object","identityHashCode":255,"lockedStackDepth":1,"lockedStackFrame":{}}],`+
		`"lockedSynchronizers":[{"className":"java.util.concurrent.locks.ReentrantLock$NonfairSync","identityHashCode":4096}]}}`)
	lines := sectionLines(t, mustRender(t, KindThreadInfo, resp), "# stack 7 t")
	want := []string{
		"at a.B.m(B.java:12)",
		"at a.B.m(Native Method)",
		"at a.B.m(B.java)",
		"at a.B.m(Unknown Source)",
		"locked monitor java.lang.Object@ff at frame 1",
		"locked synchronizer java.util.concurrent.locks.ReentrantLock$NonfairSync@1000",
	}
	if !slices.Equal(lines, want) {
		t.Errorf("stack lines = %q\nwant %q", lines, want)
	}
}

func TestRenderMemory(t *testing.T) {
	out := mustRender(t, KindMemory, loadResponse(t, "jdk17", "memory"))
	lines := sectionLines(t, out, "# memory")
	if want := "type\tname\tused\ttotal\tmax"; lines[0] != want {
		t.Errorf("header = %q, want %q", lines[0], want)
	}
	if want := "heap\theap\t255303680\t536870912\t536870912"; lines[1] != want {
		t.Errorf("first row = %q, want %q", lines[1], want)
	}
	// Arthas reports an undefined maximum as -1 for memory pools and as the
	// smallest long for buffer pools; both are written as -1.
	for _, want := range []string{
		"heap\tg1_eden_space\t220200960\t318767104\t-1",
		"buffer_pool\tdirect\t100761741\t100761738\t-1",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("memory table has no row %q:\n%s", want, strings.Join(lines, "\n"))
		}
	}
	if strings.Contains(out, "-9223372036854775808") {
		t.Error("output holds the smallest long")
	}
}

func dashboardOf(t *testing.T, threads ...string) *ExecResponse {
	t.Helper()
	return resultsOf(t, `{"type":"dashboard","gcInfos":[],"memoryInfo":{"heap":[],"nonheap":[],"buffer_pool":[]},`+
		`"runtimeInfo":{"javaVersion":"17"},"threads":[`+strings.Join(threads, ",")+`]}`)
}

func threadRow(id int, name string, cpu float64, time int) string {
	b, _ := json.Marshal(map[string]any{"id": id, "name": name, "cpu": cpu, "time": time, "state": "RUNNABLE", "group": "main", "priority": 5})
	return string(b)
}

func TestRenderDashboardOrdersThreads(t *testing.T) {
	rows := []string{
		threadRow(3, "a", 1.5, 5),
		threadRow(1, "b", 0, 9),
		threadRow(2, "c", 0, 9),
		threadRow(4, "d", 20, 1),
		threadRow(5, "e", 0, 100),
	}
	want := []string{"4", "3", "5", "1", "2"} // cpu descending, then time descending, then id
	for _, perm := range [][]int{{0, 1, 2, 3, 4}, {4, 3, 2, 1, 0}, {2, 0, 4, 1, 3}} {
		var in []string
		for _, i := range perm {
			in = append(in, rows[i])
		}
		lines := sectionLines(t, mustRender(t, KindDashboard, dashboardOf(t, in...)), "# threads")
		if got := column(lines[1:], 0); !slices.Equal(got, want) {
			t.Errorf("thread order for input %v = %v, want %v", perm, got, want)
		}
	}
}

func TestRenderDashboardPartial(t *testing.T) {
	// A dashboard that hit execTimeout comes back as an INTERRUPTED state with
	// the data it had; the caller may render it.
	for _, jdk := range renderJDKs {
		out := mustRender(t, KindDashboard, loadResponse(t, jdk, "dashboard_interrupted"))
		for _, header := range []string{"# runtime", "# memory", "# gc", "# threads"} {
			if !strings.Contains(out, "\n"+header+"\n") && !strings.HasPrefix(out, header+"\n") {
				t.Errorf("%s: no section %q", jdk, header)
			}
		}
	}
}

func TestRenderEscapesControlCharacters(t *testing.T) {
	name := "x\ty\nz\x1b[0m\r\u2028\u0085"
	out := mustRender(t, KindDashboard, dashboardOf(t, threadRow(1, name, 0, 0)))
	lines := sectionLines(t, out, "# threads")
	if len(lines) != 2 {
		t.Fatalf("threads section has %d lines, want a header and one row:\n%s", len(lines), out)
	}
	cells := strings.Split(lines[1], "\t")
	if want := len(strings.Split(lines[0], "\t")); len(cells) != want {
		t.Fatalf("row has %d cells, want %d: %q", len(cells), want, lines[1])
	}
	if want := `x\ty\nz\x1b[0m\r\u2028\x85`; cells[1] != want {
		t.Errorf("name cell = %q, want %q", cells[1], want)
	}
	if strings.ContainsAny(out, "\r\x1b\u2028\u0085") {
		t.Error("output still holds a raw control character")
	}
}

func TestRenderCutsLongCells(t *testing.T) {
	name := strings.Repeat("é", maxCellRunes+100)
	out := mustRender(t, KindDashboard, dashboardOf(t, threadRow(1, name, 0, 0)))
	cell := strings.Split(sectionLines(t, out, "# threads")[1], "\t")[1]
	want := strings.Repeat("é", maxCellRunes) + "...[+100 characters]"
	if cell != want {
		t.Errorf("cell = %.40q... (%d bytes), want %d characters and the marker", cell, len(cell), maxCellRunes)
	}
	exact := strings.Repeat("é", maxCellRunes)
	out = mustRender(t, KindDashboard, dashboardOf(t, threadRow(1, exact, 0, 0)))
	if cell := strings.Split(sectionLines(t, out, "# threads")[1], "\t")[1]; cell != exact {
		t.Errorf("a cell of exactly %d characters was changed", maxCellRunes)
	}
}

func TestRenderLimitsRows(t *testing.T) {
	var loaders []string
	for i := 0; i < maxTableRows+100; i++ {
		loaders = append(loaders, fmt.Sprintf(`{"hash":"%08x","loadedCount":%d,"name":"loader%04d"}`, i, i, i))
	}
	out := mustRender(t, KindClassLoaderList, resultsOf(t, `{"type":"classloader","tree":false,"classLoaders":[`+strings.Join(loaders, ",")+`]}`))
	lines := sectionLines(t, out, "# classloaders")
	// header, the rows, and the note
	if len(lines) != 1+maxTableRows+1 {
		t.Fatalf("section has %d lines, want %d", len(lines), 1+maxTableRows+1)
	}
	if !strings.Contains(lines[1], "loader0000") || !strings.Contains(lines[maxTableRows], fmt.Sprintf("loader%04d", maxTableRows-1)) {
		t.Errorf("rows are not the first %d in name order: %q ... %q", maxTableRows, lines[1], lines[maxTableRows])
	}
	if want := "# truncated: 100 more rows"; lines[len(lines)-1] != want {
		t.Errorf("last line = %q, want %q", lines[len(lines)-1], want)
	}
}

func TestRenderLimitsStackFrames(t *testing.T) {
	var frames []string
	for i := 0; i < maxStackFrames+172; i++ {
		frames = append(frames, fmt.Sprintf(`{"className":"a.B","methodName":"m%d","fileName":"B.java","lineNumber":%d}`, i, i+1))
	}
	resp := resultsOf(t, `{"type":"thread","threadInfo":{"threadId":7,"threadName":"t","threadState":"RUNNABLE","stackTrace":[`+strings.Join(frames, ",")+`]}}`)
	lines := sectionLines(t, mustRender(t, KindThreadInfo, resp), "# stack 7 t")
	if len(lines) != maxStackFrames+1 {
		t.Fatalf("stack has %d lines, want %d frames and a note", len(lines), maxStackFrames)
	}
	if want := fmt.Sprintf("at a.B.m%d(B.java:%d)", maxStackFrames-1, maxStackFrames); lines[maxStackFrames-1] != want {
		t.Errorf("last frame = %q, want %q", lines[maxStackFrames-1], want)
	}
	if want := "# truncated: 172 more frames"; lines[maxStackFrames] != want {
		t.Errorf("note = %q, want %q", lines[maxStackFrames], want)
	}
}

// TestRenderSortsMaps checks that the order of keys in a JSON object, which
// the server does not fix, does not reach the text.
func TestRenderSortsMaps(t *testing.T) {
	a := mustRender(t, KindSysprop, resultsOf(t, `{"type":"sysprop","props":{"b":"2","a":"1","c":"3"}}`))
	b := mustRender(t, KindSysprop, resultsOf(t, `{"type":"sysprop","props":{"c":"3","a":"1","b":"2"}}`))
	if want := "# sysprop\nkey\tvalue\na\t1\nb\t2\nc\t3\n"; a != want || b != want {
		t.Errorf("sysprop = %q and %q, want %q", a, b, want)
	}

	logger := func(first, second string) string {
		info := func(name string) string {
			return fmt.Sprintf(`"%s":{"name":"%s","class":"c.L","level":"INFO","effectiveLevel":"INFO","additivity":true,`+
				`"appenders":[{"name":"A%s","class":"c.A","target":"System.out"}]}`, name, name, name)
		}
		return mustRender(t, KindLogger, resultsOf(t, `{"type":"logger","loggerInfoMap":{`+info(first)+`,`+info(second)+`}}`))
	}
	if x, y := logger("ROOT", "app"), logger("app", "ROOT"); x != y {
		t.Errorf("logger output depends on the key order:\n%s\n---\n%s", x, y)
	}
}

func TestRenderClassLoaderOrder(t *testing.T) {
	tree := `{"type":"classloader","tree":true,"classLoaders":[` +
		`{"hash":"2","loadedCount":1,"name":"z.Loader@2","children":[` +
		`{"hash":"6","loadedCount":1,"name":"m.Child@6","parent":"z.Loader@2"},` +
		`{"hash":"5","loadedCount":1,"name":"a.Child@5","parent":"z.Loader@2"}]},` +
		`{"hash":"null","loadedCount":9,"name":"BootstrapClassLoader"}]}`
	lines := sectionLines(t, mustRender(t, KindClassLoaderTree, resultsOf(t, tree)), "# classloaders")
	// Root loaders by name, children under their parent by name, depth first.
	if got, want := column(lines[1:], 3), []string{"BootstrapClassLoader", "z.Loader@2", "a.Child@5", "m.Child@6"}; !slices.Equal(got, want) {
		t.Errorf("names = %v, want %v", got, want)
	}
	if got, want := column(lines[1:], 0), []string{"0", "0", "1", "1"}; !slices.Equal(got, want) {
		t.Errorf("depths = %v, want %v", got, want)
	}
}

// TestRenderJVMOmitsLaunchData checks that the JVM start-up arguments, the
// class paths and the library path of the recorded responses do not reach the
// text. The start-up arguments can carry -D options with secrets.
func TestRenderJVMOmitsLaunchData(t *testing.T) {
	forbidden := []string{"INPUT-ARGUMENTS", "CLASS-PATH", "BOOT-CLASS-PATH", "LIBRARY-PATH"}
	for _, jdk := range renderJDKs {
		resp := loadResponse(t, jdk, "jvm")
		out := mustRender(t, KindJVM, resp)
		var jvm struct {
			Info map[string][]struct {
				Name  string          `json:"name"`
				Value json.RawMessage `json:"value"`
			} `json:"jvmInfo"`
		}
		if err := json.Unmarshal(resp.Results[0].Raw, &jvm); err != nil {
			t.Fatal(err)
		}
		var secrets []string
		for _, e := range jvm.Info["RUNTIME"] {
			if !slices.Contains(forbidden, e.Name) {
				continue
			}
			var list []string
			if json.Unmarshal(e.Value, &list) != nil {
				var s string
				if err := json.Unmarshal(e.Value, &s); err != nil {
					t.Fatal(err)
				}
				list = []string{s}
			}
			for _, s := range list {
				if s != "" {
					secrets = append(secrets, s)
				}
			}
		}
		if len(secrets) < 4 {
			t.Fatalf("%s: only %d launch values in the recording, the test would prove little", jdk, len(secrets))
		}
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("%s: output holds %q", jdk, s)
			}
		}
		for _, name := range forbidden {
			if strings.Contains(out, name) {
				t.Errorf("%s: output holds the entry name %q", jdk, name)
			}
		}
	}
}

// TestRenderJVMAllowsKnownEntries checks the other direction on made-up data:
// only the known groups and entries are written, so a field a later release
// adds does not leak.
func TestRenderJVMAllowsKnownEntries(t *testing.T) {
	jvm := `{"type":"jvm","jvmInfo":{` +
		`"RUNTIME":[{"name":"VM-NAME","value":"X VM"},{"name":"INPUT-ARGUMENTS","value":["-Dpassword=hunter2"]},` +
		`{"name":"CLASS-PATH","value":"/secret/a.jar"},{"name":"BOOT-CLASS-PATH","value":"/secret/b"},` +
		`{"name":"LIBRARY-PATH","value":"/secret/lib"},{"name":"NEW-ENTRY","value":"hunter2"}],` +
		`"SYSTEM-PROPERTIES":[{"name":"db.password","value":"hunter2"}],` +
		`"THREAD":[{"name":"COUNT","value":3}]}}`
	out := mustRender(t, KindJVM, resultsOf(t, jvm))
	for _, want := range []string{"VM-NAME\tX VM", "COUNT\t3"} {
		if !strings.Contains(out, want) {
			t.Errorf("output has no %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"hunter2", "/secret", "INPUT-ARGUMENTS", "SYSTEM-PROPERTIES", "NEW-ENTRY"} {
		if strings.Contains(out, bad) {
			t.Errorf("output holds %q:\n%s", bad, out)
		}
	}
}

func TestRenderRejectsWrongInput(t *testing.T) {
	version := `{"type":"version","version":"4.3.5"}`
	tests := []struct {
		name string
		kind Kind
		resp *ExecResponse
	}{
		{"nil response", KindVersion, nil},
		{"unknown kind", Kind("trace"), resultsOf(t, version)},
		{"empty kind", Kind(""), resultsOf(t, version)},
		{"no results", KindVersion, &ExecResponse{}},
		{"only a status", KindVersion, rawResultsOf(t, `{"type":"status","statusCode":0}`)},
		{"result of another command", KindVersion, resultsOf(t, `{"type":"sysprop","props":{"a":"b"}}`)},
		{"thread result without the wanted part", KindThreadInfo, resultsOf(t, `{"type":"thread","busyThreads":[]}`)},
		{"thread result without busyThreads", KindThreadTop, resultsOf(t, `{"type":"thread","threadInfo":{"threadId":1}}`)},
		{"thread result without blockingLockInfo", KindThreadBlocking, resultsOf(t, `{"type":"thread","threadInfo":{"threadId":1}}`)},
		{"malformed result", KindMemory, resultsOf(t, `{"type":"memory","memoryInfo":"text"}`)},
		{"malformed number", KindDashboard, resultsOf(t, `{"type":"dashboard","threads":[{"id":"x"}]}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := Render(tt.kind, tt.resp)
			if err == nil {
				t.Fatalf("Render = %q, nil; want an error", out)
			}
			var ce *CommandError
			if errors.As(err, &ce) {
				t.Errorf("error is a *CommandError: %v", err)
			}
			if out != "" {
				t.Errorf("output with an error = %q, want empty", out)
			}
		})
	}
}

func TestRenderIgnoresOtherResultTypes(t *testing.T) {
	plain := mustRender(t, KindVersion, resultsOf(t, `{"type":"version","version":"4.3.5"}`))
	extra := mustRender(t, KindVersion, resultsOf(t,
		`{"type":"row_affect","rowCount":1}`, `{"type":"version","version":"4.3.5"}`, `{"type":"welcome","version":"x"}`))
	if extra != plain {
		t.Errorf("extra result types changed the output:\n%q\n%q", extra, plain)
	}
}
