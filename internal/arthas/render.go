package arthas

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits of the text Render writes.
const (
	// maxCellRunes is the longest cell, in characters; a longer one is cut.
	maxCellRunes = 1024
	// maxTableRows is the largest number of rows in one table.
	maxTableRows = 500
	// maxStackFrames is the largest number of frames written for one thread.
	maxStackFrames = 128
)

// CommandError is returned by Render when the command ran but reported a
// failure: a status result whose code is not zero, for example "thread do not
// exist! id: 42".
type CommandError struct {
	Kind    Kind
	Code    int
	Message string
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("arthas %s: status %d: %s", e.Kind, e.Code, e.Message)
}

// Render turns the results of an exec response into plain text.
//
// The text is a list of sections. A section starts with a "# title" line and
// ends at the next blank line. It holds either key/value lines or a table with
// a header row; cells are separated by one tab. Stack sections hold "at"
// lines instead. When a table or a stack is longer than its limit, the last
// line of the section is "# truncated: N more rows" (or "frames").
//
// Only the fields named in this file are written. Everything else in the
// result, and every result of another type, is dropped. For jvm that leaves
// out the start-up arguments, the class paths and the library path.
//
// Control characters and other invisible characters in names and values are
// written as escape sequences (\t, \n, \xNN, \uNNNN), so that a thread or
// class name cannot add lines or cells. A cell longer than maxCellRunes
// characters is cut and ends with "...[+N characters]". Maps are written in
// key order and thread lists in a fixed order, so the same data always gives
// the same text.
//
// A command that failed returns a *CommandError. A partial response, such as
// the one a *StateError holds for an interrupted dashboard, can be rendered
// as well.
func Render(kind Kind, resp *ExecResponse) (string, error) {
	if resp == nil {
		return "", errors.New("arthas: Render needs a response")
	}
	render, ok := renderers[kind]
	if !ok {
		return "", fmt.Errorf("arthas: no rendering for command kind %q", kind)
	}
	if code, msg, found := resp.Status(); found && code != 0 {
		return "", &CommandError{Kind: kind, Code: code, Message: cell(msg)}
	}
	var w textWriter
	if err := render(&w, resp); err != nil {
		return "", fmt.Errorf("arthas: render %s: %w", kind, err)
	}
	return w.b.String(), nil
}

var renderers = map[Kind]func(*textWriter, *ExecResponse) error{
	KindDashboard:       renderDashboard,
	KindThreadTop:       renderThreadTop,
	KindThreadBlocking:  renderThreadBlocking,
	KindThreadInfo:      renderThreadInfo,
	KindMemory:          renderMemory,
	KindJVM:             renderJVM,
	KindClassInfo:       renderClassInfo,
	KindMethodInfo:      renderMethodInfo,
	KindClassLoaderTree: func(w *textWriter, r *ExecResponse) error { return renderClassLoaders(w, r, true) },
	KindClassLoaderList: func(w *textWriter, r *ExecResponse) error { return renderClassLoaders(w, r, false) },
	KindLogger:          renderLogger,
	KindSysprop:         renderSysprop,
	KindVersion:         renderVersion,
}

// textWriter builds the output.
type textWriter struct {
	b strings.Builder
}

// section starts a section; sections are separated by one blank line.
func (w *textWriter) section(title string) {
	if w.b.Len() > 0 {
		w.b.WriteByte('\n')
	}
	w.b.WriteString("# ")
	w.b.WriteString(cell(title))
	w.b.WriteByte('\n')
}

func (w *textWriter) row(cells ...string) {
	for i, c := range cells {
		if i > 0 {
			w.b.WriteByte('\t')
		}
		w.b.WriteString(cell(c))
	}
	w.b.WriteByte('\n')
}

func (w *textWriter) line(s string) {
	w.b.WriteString(cell(s))
	w.b.WriteByte('\n')
}

func (w *textWriter) truncated(n int, what string) {
	fmt.Fprintf(&w.b, "# truncated: %d more %s\n", n, what)
}

// table writes the header and at most maxTableRows rows.
func (w *textWriter) table(header []string, rows [][]string) {
	w.row(header...)
	for i, r := range rows {
		if i == maxTableRows {
			w.truncated(len(rows)-maxTableRows, "rows")
			return
		}
		w.row(r...)
	}
}

// cell cuts s to maxCellRunes characters and escapes the characters that
// could end the cell or the line, or that are not visible.
func cell(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxCellRunes {
			fmt.Fprintf(&b, "...[+%d characters]", utf8.RuneCountInString(s)-maxCellRunes)
			break
		}
		n++
		switch {
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case !unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	return b.String()
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', 2, 64) }

func btoa(b bool) string { return strconv.FormatBool(b) }

func joinList(l []string) string { return strings.Join(l, ", ") }

// undefinedAsMinusOne writes the maximum of a memory area. Arthas reports an
// area without a maximum as -1, and a buffer pool as the smallest long.
func undefinedAsMinusOne(n int64) string {
	if n < 0 {
		n = -1
	}
	return itoa(n)
}

// result returns the first result of the given type.
func result(resp *ExecResponse, typ string) (Result, error) {
	for _, r := range resp.Results {
		if r.Type == typ {
			return r, nil
		}
	}
	return Result{}, fmt.Errorf("response has no %s result", typ)
}

// decode reads the first result of the given type into v.
func decode(resp *ExecResponse, typ string, v any) error {
	r, err := result(resp, typ)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(r.Raw, v); err != nil {
		return fmt.Errorf("decode %s result: %w", typ, err)
	}
	return nil
}

func renderVersion(w *textWriter, resp *ExecResponse) error {
	var v struct {
		Version string `json:"version"`
	}
	if err := decode(resp, "version", &v); err != nil {
		return err
	}
	w.section("version")
	w.row("version", v.Version)
	return nil
}

// memory areas

type memoryArea struct {
	Name  string `json:"name"`
	Used  int64  `json:"used"`
	Total int64  `json:"total"`
	Max   int64  `json:"max"`
}

type memoryInfo struct {
	Heap       []memoryArea `json:"heap"`
	NonHeap    []memoryArea `json:"nonheap"`
	BufferPool []memoryArea `json:"buffer_pool"`
}

func (w *textWriter) memory(m memoryInfo) {
	var rows [][]string
	for _, g := range []struct {
		typ   string
		areas []memoryArea
	}{{"heap", m.Heap}, {"nonheap", m.NonHeap}, {"buffer_pool", m.BufferPool}} {
		for _, a := range g.areas {
			rows = append(rows, []string{g.typ, a.Name, itoa(a.Used), itoa(a.Total), undefinedAsMinusOne(a.Max)})
		}
	}
	w.section("memory")
	w.table([]string{"type", "name", "used", "total", "max"}, rows)
}

func renderMemory(w *textWriter, resp *ExecResponse) error {
	var m struct {
		MemoryInfo memoryInfo `json:"memoryInfo"`
	}
	if err := decode(resp, "memory", &m); err != nil {
		return err
	}
	w.memory(m.MemoryInfo)
	return nil
}

// threads

type frame struct {
	FileName   string `json:"fileName"`
	LineNumber int    `json:"lineNumber"`
	ClassName  string `json:"className"`
	MethodName string `json:"methodName"`
}

// String writes the frame the way StackTraceElement.toString does without the
// module and class loader parts.
func (f frame) String() string {
	loc := "Unknown Source"
	switch {
	case f.LineNumber == -2:
		loc = "Native Method"
	case f.FileName != "" && f.LineNumber >= 0:
		loc = f.FileName + ":" + strconv.Itoa(f.LineNumber)
	case f.FileName != "":
		loc = f.FileName
	}
	return f.ClassName + "." + f.MethodName + "(" + loc + ")"
}

type lockRef struct {
	ClassName        string `json:"className"`
	IdentityHashCode int64  `json:"identityHashCode"`
}

func (l lockRef) String() string {
	return fmt.Sprintf("%s@%x", l.ClassName, uint32(l.IdentityHashCode))
}

type lockedMonitor struct {
	lockRef
	LockedStackDepth int `json:"lockedStackDepth"`
}

// threadEntry is an element of the threads of dashboard and of the
// busyThreads of thread -n.
type threadEntry struct {
	ID                  int64           `json:"id"`
	Name                string          `json:"name"`
	Group               string          `json:"group"`
	State               string          `json:"state"`
	Priority            int             `json:"priority"`
	Daemon              bool            `json:"daemon"`
	Interrupted         bool            `json:"interrupted"`
	CPU                 float64         `json:"cpu"`
	DeltaTime           int64           `json:"deltaTime"`
	Time                int64           `json:"time"`
	InNative            bool            `json:"inNative"`
	Suspended           bool            `json:"suspended"`
	BlockedCount        int64           `json:"blockedCount"`
	WaitedCount         int64           `json:"waitedCount"`
	LockName            string          `json:"lockName"`
	LockOwnerID         int64           `json:"lockOwnerId"`
	StackTrace          []frame         `json:"stackTrace"`
	LockedMonitors      []lockedMonitor `json:"lockedMonitors"`
	LockedSynchronizers []lockRef       `json:"lockedSynchronizers"`
}

// threadDetail is the threadInfo of thread <id> and the lock holder of thread -b.
type threadDetail struct {
	ThreadID            int64           `json:"threadId"`
	ThreadName          string          `json:"threadName"`
	ThreadState         string          `json:"threadState"`
	Daemon              bool            `json:"daemon"`
	Priority            int             `json:"priority"`
	InNative            bool            `json:"inNative"`
	Suspended           bool            `json:"suspended"`
	BlockedCount        int64           `json:"blockedCount"`
	BlockedTime         int64           `json:"blockedTime"`
	WaitedCount         int64           `json:"waitedCount"`
	WaitedTime          int64           `json:"waitedTime"`
	LockName            string          `json:"lockName"`
	LockOwnerID         int64           `json:"lockOwnerId"`
	LockOwnerName       string          `json:"lockOwnerName"`
	StackTrace          []frame         `json:"stackTrace"`
	LockedMonitors      []lockedMonitor `json:"lockedMonitors"`
	LockedSynchronizers []lockRef       `json:"lockedSynchronizers"`
}

// stack writes the frames and the locks of one thread.
func (w *textWriter) stack(id int64, name string, frames []frame, monitors []lockedMonitor, synchronizers []lockRef) {
	w.section("stack " + itoa(id) + " " + name)
	for i, f := range frames {
		if i == maxStackFrames {
			w.truncated(len(frames)-maxStackFrames, "frames")
			break
		}
		w.line("at " + f.String())
	}
	var locks []string
	for _, m := range monitors {
		locks = append(locks, fmt.Sprintf("locked monitor %s at frame %d", m.lockRef, m.LockedStackDepth))
	}
	for _, s := range synchronizers {
		locks = append(locks, "locked synchronizer "+s.String())
	}
	for i, l := range locks {
		if i == maxStackFrames {
			w.truncated(len(locks)-maxStackFrames, "locks")
			break
		}
		w.line(l)
	}
}

func (w *textWriter) threadDetail(title string, d threadDetail) {
	w.section(title)
	w.row("id", itoa(d.ThreadID))
	w.row("name", d.ThreadName)
	w.row("state", d.ThreadState)
	w.row("daemon", btoa(d.Daemon))
	w.row("priority", strconv.Itoa(d.Priority))
	w.row("in_native", btoa(d.InNative))
	w.row("suspended", btoa(d.Suspended))
	w.row("blocked_count", itoa(d.BlockedCount))
	w.row("blocked_time_ms", itoa(d.BlockedTime))
	w.row("waited_count", itoa(d.WaitedCount))
	w.row("waited_time_ms", itoa(d.WaitedTime))
	if d.LockName != "" {
		w.row("lock_name", d.LockName)
	}
	w.row("lock_owner_id", itoa(d.LockOwnerID))
	if d.LockOwnerName != "" {
		w.row("lock_owner_name", d.LockOwnerName)
	}
	w.stack(d.ThreadID, d.ThreadName, d.StackTrace, d.LockedMonitors, d.LockedSynchronizers)
}

// threadResult holds the parts of a thread result that the three thread
// commands use. A pointer tells a missing part from an empty one.
type threadResult struct {
	BusyThreads      *[]threadEntry `json:"busyThreads"`
	ThreadInfo       *threadDetail  `json:"threadInfo"`
	BlockingLockInfo *struct {
		BlockingThreadCount  int64         `json:"blockingThreadCount"`
		LockIdentityHashCode int64         `json:"lockIdentityHashCode"`
		ThreadInfo           *threadDetail `json:"threadInfo"`
	} `json:"blockingLockInfo"`
}

func renderThreadTop(w *textWriter, resp *ExecResponse) error {
	var t threadResult
	if err := decode(resp, "thread", &t); err != nil {
		return err
	}
	if t.BusyThreads == nil {
		return errors.New("thread result has no busyThreads")
	}
	threads := *t.BusyThreads
	rows := make([][]string, len(threads))
	for i, th := range threads {
		rows[i] = []string{
			itoa(th.ID), th.Name, th.Group, th.State, ftoa(th.CPU), itoa(th.DeltaTime), itoa(th.Time),
			strconv.Itoa(th.Priority), btoa(th.Daemon), btoa(th.Interrupted), btoa(th.InNative), btoa(th.Suspended),
			itoa(th.BlockedCount), itoa(th.WaitedCount), th.LockName, itoa(th.LockOwnerID),
		}
	}
	w.section("busy threads")
	w.table([]string{
		"id", "name", "group", "state", "cpu_percent", "delta_time_ms", "time_ms", "priority", "daemon", "interrupted",
		"in_native", "suspended", "blocked_count", "waited_count", "lock_name", "lock_owner_id",
	}, rows)
	for i, th := range threads {
		if i == maxTableRows {
			break
		}
		w.stack(th.ID, th.Name, th.StackTrace, th.LockedMonitors, th.LockedSynchronizers)
	}
	return nil
}

func renderThreadInfo(w *textWriter, resp *ExecResponse) error {
	var t threadResult
	if err := decode(resp, "thread", &t); err != nil {
		return err
	}
	if t.ThreadInfo == nil {
		return errors.New("thread result has no threadInfo")
	}
	w.threadDetail("thread", *t.ThreadInfo)
	return nil
}

func renderThreadBlocking(w *textWriter, resp *ExecResponse) error {
	var t threadResult
	if err := decode(resp, "thread", &t); err != nil {
		return err
	}
	b := t.BlockingLockInfo
	if b == nil || b.ThreadInfo == nil {
		return errors.New("thread result has no blockingLockInfo")
	}
	w.section("blocking lock")
	w.row("lock_identity_hash", strconv.FormatUint(uint64(uint32(b.LockIdentityHashCode)), 16))
	w.row("blocked_thread_count", itoa(b.BlockingThreadCount))
	w.threadDetail("lock holder thread", *b.ThreadInfo)
	return nil
}

// dashboard

func renderDashboard(w *textWriter, resp *ExecResponse) error {
	var d struct {
		RuntimeInfo struct {
			JavaHome          string  `json:"javaHome"`
			JavaVersion       string  `json:"javaVersion"`
			OSName            string  `json:"osName"`
			OSVersion         string  `json:"osVersion"`
			Processors        int     `json:"processors"`
			SystemLoadAverage float64 `json:"systemLoadAverage"`
			Uptime            int64   `json:"uptime"`
		} `json:"runtimeInfo"`
		MemoryInfo memoryInfo `json:"memoryInfo"`
		GCInfos    []struct {
			Name            string `json:"name"`
			CollectionCount int64  `json:"collectionCount"`
			CollectionTime  int64  `json:"collectionTime"`
		} `json:"gcInfos"`
		Threads []threadEntry `json:"threads"`
	}
	if err := decode(resp, "dashboard", &d); err != nil {
		return err
	}
	rt := d.RuntimeInfo
	w.section("runtime")
	w.row("java_version", rt.JavaVersion)
	w.row("java_home", rt.JavaHome)
	w.row("os_name", rt.OSName)
	w.row("os_version", rt.OSVersion)
	w.row("processors", strconv.Itoa(rt.Processors))
	w.row("system_load_average", ftoa(rt.SystemLoadAverage))
	w.row("uptime_seconds", itoa(rt.Uptime))

	w.memory(d.MemoryInfo)

	gc := make([][]string, len(d.GCInfos))
	for i, g := range d.GCInfos {
		gc[i] = []string{g.Name, itoa(g.CollectionCount), itoa(g.CollectionTime)}
	}
	w.section("gc")
	w.table([]string{"name", "collection_count", "collection_time_ms"}, gc)

	// The server lists the threads in no particular order.
	threads := d.Threads
	slices.SortStableFunc(threads, func(a, b threadEntry) int {
		return cmp.Or(cmp.Compare(b.CPU, a.CPU), cmp.Compare(b.Time, a.Time), cmp.Compare(a.ID, b.ID))
	})
	rows := make([][]string, len(threads))
	for i, t := range threads {
		rows[i] = []string{
			itoa(t.ID), t.Name, t.Group, t.State, ftoa(t.CPU), itoa(t.DeltaTime), itoa(t.Time),
			strconv.Itoa(t.Priority), btoa(t.Daemon), btoa(t.Interrupted),
		}
	}
	w.section("threads")
	w.table([]string{"id", "name", "group", "state", "cpu_percent", "delta_time_ms", "time_ms", "priority", "daemon", "interrupted"}, rows)
	return nil
}

// jvm

// jvmScalars lists, per group, the entries that are written. A group or entry
// that is not listed is dropped; RUNTIME also holds INPUT-ARGUMENTS,
// CLASS-PATH, BOOT-CLASS-PATH and LIBRARY-PATH, which can carry secrets.
var jvmScalars = map[string][]string{
	"RUNTIME": {
		"MACHINE-NAME", "JVM-START-TIME", "MANAGEMENT-SPEC-VERSION", "SPEC-NAME", "SPEC-VENDOR", "SPEC-VERSION",
		"VM-NAME", "VM-VENDOR", "VM-VERSION",
	},
	"CLASS-LOADING":    {"LOADED-CLASS-COUNT", "TOTAL-LOADED-CLASS-COUNT", "UNLOADED-CLASS-COUNT", "IS-VERBOSE"},
	"COMPILATION":      {"NAME", "TOTAL-COMPILE-TIME"},
	"OPERATING-SYSTEM": {"OS", "ARCH", "PROCESSORS-COUNT", "LOAD-AVERAGE", "VERSION"},
	"THREAD":           {"COUNT", "DAEMON-COUNT", "PEAK-COUNT", "STARTED-COUNT", "DEADLOCK-COUNT"},
	"FILE-DESCRIPTOR":  {"MAX-FILE-DESCRIPTOR-COUNT", "OPEN-FILE-DESCRIPTOR-COUNT"},
}

// jvmGroups is the order of the sections.
var jvmGroups = []string{
	"RUNTIME", "CLASS-LOADING", "COMPILATION", "GARBAGE-COLLECTORS", "MEMORY-MANAGERS", "MEMORY",
	"OPERATING-SYSTEM", "THREAD", "FILE-DESCRIPTOR",
}

type jvmEntry struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

// scalar reads a JSON string, number or boolean. A number with a fraction is
// written with two decimals.
func scalar(raw json.RawMessage) (string, bool) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return "", false
	}
	switch v := v.(type) {
	case string:
		return v, true
	case bool:
		return btoa(v), true
	case json.Number:
		if strings.ContainsAny(string(v), ".eE") {
			f, err := v.Float64()
			if err != nil {
				return "", false
			}
			return ftoa(f), true
		}
		return string(v), true
	}
	return "", false
}

func renderJVM(w *textWriter, resp *ExecResponse) error {
	var j struct {
		Info map[string][]jvmEntry `json:"jvmInfo"`
	}
	if err := decode(resp, "jvm", &j); err != nil {
		return err
	}
	for _, group := range jvmGroups {
		entries, ok := j.Info[group]
		if !ok {
			continue
		}
		w.section(group)
		switch group {
		case "GARBAGE-COLLECTORS":
			rows := make([][]string, 0, len(entries))
			for _, e := range entries {
				var gc struct {
					CollectionCount int64 `json:"collectionCount"`
					CollectionTime  int64 `json:"collectionTime"`
				}
				if err := json.Unmarshal(e.Value, &gc); err != nil {
					return fmt.Errorf("decode jvm %s %s: %w", group, e.Name, err)
				}
				rows = append(rows, []string{e.Name, itoa(gc.CollectionCount), itoa(gc.CollectionTime)})
			}
			w.table([]string{"name", "collection_count", "collection_time_ms"}, rows)
		case "MEMORY-MANAGERS":
			var rows [][]string
			for _, e := range entries {
				var pools []string
				if err := json.Unmarshal(e.Value, &pools); err != nil {
					return fmt.Errorf("decode jvm %s %s: %w", group, e.Name, err)
				}
				for _, p := range pools {
					rows = append(rows, []string{e.Name, p})
				}
			}
			w.table([]string{"manager", "pool"}, rows)
		case "MEMORY":
			for _, e := range entries {
				switch e.Name {
				case "HEAP-MEMORY-USAGE", "NO-HEAP-MEMORY-USAGE":
					var u struct {
						Init      int64 `json:"init"`
						Used      int64 `json:"used"`
						Committed int64 `json:"committed"`
						Max       int64 `json:"max"`
					}
					if err := json.Unmarshal(e.Value, &u); err != nil {
						return fmt.Errorf("decode jvm %s %s: %w", group, e.Name, err)
					}
					w.row(e.Name+".init", itoa(u.Init))
					w.row(e.Name+".used", itoa(u.Used))
					w.row(e.Name+".committed", itoa(u.Committed))
					w.row(e.Name+".max", undefinedAsMinusOne(u.Max))
				case "PENDING-FINALIZE-COUNT":
					if s, ok := scalar(e.Value); ok {
						w.row(e.Name, s)
					}
				}
			}
		default:
			for _, e := range entries {
				if !slices.Contains(jvmScalars[group], e.Name) {
					continue
				}
				if s, ok := scalar(e.Value); ok {
					w.row(e.Name, s)
				}
			}
		}
	}
	return nil
}

// classes and methods

type classInfo struct {
	Name            string   `json:"name"`
	Modifier        string   `json:"modifier"`
	CodeSource      string   `json:"codeSource"`
	ClassLoaderHash string   `json:"classLoaderHash"`
	ClassLoader     []string `json:"classloader"`
	SuperClass      []string `json:"superClass"`
	Interfaces      []string `json:"interfaces"`
	Annotations     []string `json:"annotations"`
	Annotation      bool     `json:"annotation"`
	AnonymousClass  bool     `json:"anonymousClass"`
	Array           bool     `json:"array"`
	Enum            bool     `json:"enum"`
	Interface       bool     `json:"interface"`
	LocalClass      bool     `json:"localClass"`
	MemberClass     bool     `json:"memberClass"`
	Primitive       bool     `json:"primitive"`
	Synthetic       bool     `json:"synthetic"`
}

func (c classInfo) flags() string {
	var flags []string
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"annotation", c.Annotation}, {"anonymous", c.AnonymousClass}, {"array", c.Array}, {"enum", c.Enum},
		{"interface", c.Interface}, {"local", c.LocalClass}, {"member", c.MemberClass},
		{"primitive", c.Primitive}, {"synthetic", c.Synthetic},
	} {
		if f.set {
			flags = append(flags, f.name)
		}
	}
	return strings.Join(flags, ",")
}

// results returns every result of the given type.
func results(resp *ExecResponse, typ string) []Result {
	var out []Result
	for _, r := range resp.Results {
		if r.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

func renderClassInfo(w *textWriter, resp *ExecResponse) error {
	var classes []classInfo
	for _, r := range results(resp, "sc") {
		var sc struct {
			ClassInfo *classInfo `json:"classInfo"`
		}
		if err := json.Unmarshal(r.Raw, &sc); err != nil {
			return fmt.Errorf("decode sc result: %w", err)
		}
		if sc.ClassInfo == nil {
			return errors.New("sc result has no classInfo")
		}
		classes = append(classes, *sc.ClassInfo)
	}
	w.section("classes")
	w.row("count", strconv.Itoa(len(classes)))
	for i, c := range classes {
		if i == maxTableRows {
			w.truncated(len(classes)-maxTableRows, "classes")
			break
		}
		w.section("class " + c.Name)
		w.row("name", c.Name)
		w.row("modifier", c.Modifier)
		w.row("flags", c.flags())
		w.row("code_source", c.CodeSource)
		w.row("class_loader_hash", c.ClassLoaderHash)
		w.row("class_loaders", joinList(c.ClassLoader))
		w.row("super_classes", joinList(c.SuperClass))
		w.row("interfaces", joinList(c.Interfaces))
		w.row("annotations", joinList(c.Annotations))
	}
	return nil
}

func renderMethodInfo(w *textWriter, resp *ExecResponse) error {
	var rows [][]string
	for _, r := range results(resp, "sm") {
		var sm struct {
			MethodInfo *struct {
				DeclaringClass  string   `json:"declaringClass"`
				MethodName      string   `json:"methodName"`
				Descriptor      string   `json:"descriptor"`
				Modifier        string   `json:"modifier"`
				Constructor     bool     `json:"constructor"`
				ReturnType      string   `json:"returnType"`
				Parameters      []string `json:"parameters"`
				Exceptions      []string `json:"exceptions"`
				Annotations     []string `json:"annotations"`
				ClassLoaderHash string   `json:"classLoaderHash"`
			} `json:"methodInfo"`
		}
		if err := json.Unmarshal(r.Raw, &sm); err != nil {
			return fmt.Errorf("decode sm result: %w", err)
		}
		m := sm.MethodInfo
		if m == nil {
			return errors.New("sm result has no methodInfo")
		}
		rows = append(rows, []string{
			m.DeclaringClass, m.MethodName, m.Descriptor, m.Modifier, btoa(m.Constructor), m.ReturnType,
			joinList(m.Parameters), joinList(m.Exceptions), joinList(m.Annotations), m.ClassLoaderHash,
		})
	}
	w.section("methods")
	w.table([]string{
		"class", "method", "descriptor", "modifier", "constructor", "return_type",
		"parameters", "exceptions", "annotations", "class_loader_hash",
	}, rows)
	return nil
}

// class loaders

type loaderNode struct {
	Hash        string       `json:"hash"`
	LoadedCount int64        `json:"loadedCount"`
	Name        string       `json:"name"`
	Parent      string       `json:"parent"`
	Children    []loaderNode `json:"children"`
}

// flatten appends one row per loader, children after their parent. Loaders
// are ordered by name and hash, because the server does not fix the order.
func flatten(nodes []loaderNode, depth int, tree bool, rows *[][]string) {
	slices.SortStableFunc(nodes, func(a, b loaderNode) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Hash, b.Hash))
	})
	for _, n := range nodes {
		row := []string{n.Hash, itoa(n.LoadedCount), n.Name, n.Parent}
		if tree {
			row = append([]string{strconv.Itoa(depth)}, row...)
		}
		*rows = append(*rows, row)
		if tree {
			flatten(n.Children, depth+1, tree, rows)
		}
	}
}

func renderClassLoaders(w *textWriter, resp *ExecResponse, tree bool) error {
	var c struct {
		ClassLoaders []loaderNode `json:"classLoaders"`
	}
	if err := decode(resp, "classloader", &c); err != nil {
		return err
	}
	var rows [][]string
	flatten(c.ClassLoaders, 0, tree, &rows)
	header := []string{"hash", "loaded_count", "name", "parent"}
	if tree {
		header = append([]string{"depth"}, header...)
	}
	w.section("classloaders")
	w.table(header, rows)
	return nil
}

// logger and sysprop

func renderLogger(w *textWriter, resp *ExecResponse) error {
	var l struct {
		Loggers map[string]struct {
			Class          string `json:"class"`
			Level          string `json:"level"`
			EffectiveLevel string `json:"effectiveLevel"`
			Additivity     bool   `json:"additivity"`
			Appenders      []struct {
				Name   string `json:"name"`
				Class  string `json:"class"`
				Target string `json:"target"`
			} `json:"appenders"`
		} `json:"loggerInfoMap"`
	}
	if err := decode(resp, "logger", &l); err != nil {
		return err
	}
	var loggers, appenders [][]string
	for _, name := range slices.Sorted(maps.Keys(l.Loggers)) {
		info := l.Loggers[name]
		loggers = append(loggers, []string{name, info.Level, info.EffectiveLevel, btoa(info.Additivity), info.Class})
		for _, a := range info.Appenders {
			appenders = append(appenders, []string{name, a.Name, a.Class, a.Target})
		}
	}
	w.section("loggers")
	w.table([]string{"name", "level", "effective_level", "additivity", "class"}, loggers)
	w.section("appenders")
	w.table([]string{"logger", "name", "class", "target"}, appenders)
	return nil
}

func renderSysprop(w *textWriter, resp *ExecResponse) error {
	var s struct {
		Props map[string]string `json:"props"`
	}
	if err := decode(resp, "sysprop", &s); err != nil {
		return err
	}
	var rows [][]string
	for _, k := range slices.Sorted(maps.Keys(s.Props)) {
		rows = append(rows, []string{k, s.Props[k]})
	}
	w.section("sysprop")
	w.table([]string{"key", "value"}, rows)
	return nil
}
