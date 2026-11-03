package arthas

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// maxBlockLines is the largest number of lines written for one watch value or one jad source.
const maxBlockLines = 2000

// block writes text as indented lines: every line starts with two spaces, so that no line of
// the text can start a section. Long lines are cut like cells.
func (w *textWriter) block(text string) {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	for i, l := range lines {
		if i == maxBlockLines {
			w.truncated(len(lines)-maxBlockLines, "lines")
			return
		}
		w.b.WriteString("  ")
		w.b.WriteString(cell(strings.TrimSuffix(l, "\r")))
		w.b.WriteByte('\n')
	}
}

func unmarshalResult(r Result, v any) error {
	if err := json.Unmarshal(r.Raw, v); err != nil {
		return fmt.Errorf("decode %s result: %w", r.Type, err)
	}
	return nil
}

// looseID is a thread ID, which Arthas writes as a number in some results and as a string in
// others (the stack result).
type looseID string

func (l *looseID) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*l = looseID(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*l = looseID(n.String())
	return nil
}

// msec writes milliseconds with three decimals.
func msec(f float64) string { return strconv.FormatFloat(f, 'f', 3, 64) }

// nsec writes nanoseconds as milliseconds with three decimals.
func nsec(n int64) string { return msec(float64(n) / 1e6) }

// eachResult decodes every result of the given type with decodeOne, in order.
func eachResult(resp *ExecResponse, typ string, decodeOne func(Result) error) (int, error) {
	n := 0
	for _, r := range resp.Results {
		if r.Type != typ {
			continue
		}
		n++
		if err := decodeOne(r); err != nil {
			return n, err
		}
	}
	return n, nil
}

// noResults writes the section of an enhancing command that saw no matching invocation.
func (w *textWriter) noResults(kind string) {
	w.section(kind)
	w.row("results", "0")
}

func renderWatch(w *textWriter, resp *ExecResponse) error {
	n, err := eachResult(resp, "watch", func(r Result) error {
		var v struct {
			TS          string  `json:"ts"`
			Cost        float64 `json:"cost"`
			ClassName   string  `json:"className"`
			MethodName  string  `json:"methodName"`
			AccessPoint string  `json:"accessPoint"`
			Value       *string `json:"value"`
		}
		if err := unmarshalResult(r, &v); err != nil {
			return err
		}
		w.section("watch")
		w.row("time", v.TS)
		w.row("class", v.ClassName)
		w.row("method", v.MethodName)
		w.row("access_point", v.AccessPoint)
		w.row("cost_ms", msec(v.Cost))
		w.line("value")
		if v.Value != nil {
			w.block(*v.Value)
		}
		return nil
	})
	if err == nil && n == 0 {
		w.noResults("watch")
	}
	return err
}

// traceNode is a node of the tree of a trace result: the thread at the root, then methods,
// calls inside them and thrown exceptions.
type traceNode struct {
	Type       string      `json:"type"`
	ClassName  string      `json:"className"`
	MethodName string      `json:"methodName"`
	LineNumber int         `json:"lineNumber"`
	Invoking   bool        `json:"invoking"`
	Throw      bool        `json:"isThrow"`
	ThrowExp   string      `json:"throwExp"`
	Times      int64       `json:"times"`
	TotalCost  int64       `json:"totalCost"`
	MinCost    int64       `json:"minCost"`
	MaxCost    int64       `json:"maxCost"`
	Exception  string      `json:"exception"`
	Message    string      `json:"message"`
	Children   []traceNode `json:"children"`
}

func renderTrace(w *textWriter, resp *ExecResponse) error {
	n, err := eachResult(resp, "trace", func(r Result) error {
		var t struct {
			NodeCount int `json:"nodeCount"`
			Root      *struct {
				ThreadName  string      `json:"threadName"`
				ThreadID    int64       `json:"threadId"`
				Daemon      bool        `json:"daemon"`
				Priority    int         `json:"priority"`
				ClassLoader string      `json:"classloader"`
				Timestamp   string      `json:"timestamp"`
				Children    []traceNode `json:"children"`
			} `json:"root"`
		}
		if err := unmarshalResult(r, &t); err != nil {
			return err
		}
		if t.Root == nil {
			return errors.New("trace result has no root")
		}
		w.section("trace")
		w.row("time", t.Root.Timestamp)
		w.row("thread", t.Root.ThreadName)
		w.row("thread_id", itoa(t.Root.ThreadID))
		w.row("daemon", btoa(t.Root.Daemon))
		w.row("priority", strconv.Itoa(t.Root.Priority))
		w.row("classloader", t.Root.ClassLoader)
		w.row("node_count", strconv.Itoa(t.NodeCount))
		var rows [][]string
		var walk func(nodes []traceNode, depth int)
		walk = func(nodes []traceNode, depth int) {
			for _, nd := range nodes {
				rows = append(rows, nd.row(depth))
				walk(nd.Children, depth+1)
			}
		}
		walk(t.Root.Children, 0)
		w.section("trace tree")
		w.table([]string{"depth", "type", "name", "line", "times", "total_ms", "min_ms", "max_ms", "exception"}, rows)
		return nil
	})
	if err == nil && n == 0 {
		w.noResults("trace")
	}
	return err
}

// row is the table row of a trace node. type is method for the traced method, call for a
// method called from it, and throw for an exception thrown at a line.
func (nd traceNode) row(depth int) []string {
	line := ""
	if nd.LineNumber >= 0 {
		line = strconv.Itoa(nd.LineNumber)
	}
	if nd.Type == "throw" {
		return []string{strconv.Itoa(depth), "throw", nd.Exception, line, "", "", "", "", nd.Message}
	}
	kind := "method"
	if nd.Invoking {
		kind = "call"
	}
	exception := ""
	if nd.Throw {
		exception = nd.ThrowExp
	}
	return []string{
		strconv.Itoa(depth), kind, nd.ClassName + "." + nd.MethodName, line, itoa(nd.Times),
		nsec(nd.TotalCost), nsec(nd.MinCost), nsec(nd.MaxCost), exception,
	}
}

func renderStack(w *textWriter, resp *ExecResponse) error {
	n, err := eachResult(resp, "stack", func(r Result) error {
		var s struct {
			TS          string  `json:"ts"`
			Cost        float64 `json:"cost"`
			ThreadName  string  `json:"threadName"`
			ThreadID    looseID `json:"threadId"`
			Daemon      bool    `json:"daemon"`
			Priority    int     `json:"priority"`
			ClassLoader string  `json:"classloader"`
			StackTrace  []frame `json:"stackTrace"`
		}
		if err := unmarshalResult(r, &s); err != nil {
			return err
		}
		w.section("stack")
		w.row("time", s.TS)
		w.row("thread", s.ThreadName)
		w.row("thread_id", string(s.ThreadID))
		w.row("daemon", btoa(s.Daemon))
		w.row("priority", strconv.Itoa(s.Priority))
		w.row("classloader", s.ClassLoader)
		for i, f := range s.StackTrace {
			if i == maxStackFrames {
				w.truncated(len(s.StackTrace)-maxStackFrames, "frames")
				break
			}
			w.line("at " + f.String())
		}
		return nil
	})
	if err == nil && n == 0 {
		w.noResults("stack")
	}
	return err
}

func renderMonitor(w *textWriter, resp *ExecResponse) error {
	var rows [][]string
	_, err := eachResult(resp, "monitor", func(r Result) error {
		var m struct {
			MonitorDataList []struct {
				Timestamp  string  `json:"timestamp"`
				ClassName  string  `json:"className"`
				MethodName string  `json:"methodName"`
				Total      int64   `json:"total"`
				Success    int64   `json:"success"`
				Failed     int64   `json:"failed"`
				Cost       float64 `json:"cost"`
			} `json:"monitorDataList"`
		}
		if err := unmarshalResult(r, &m); err != nil {
			return err
		}
		for _, d := range m.MonitorDataList {
			avg := 0.0
			if d.Total > 0 {
				avg = d.Cost / float64(d.Total)
			}
			rows = append(rows, []string{d.Timestamp, d.ClassName, d.MethodName, itoa(d.Total), itoa(d.Success), itoa(d.Failed), msec(d.Cost), msec(avg)})
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		w.noResults("monitor")
		return nil
	}
	w.section("monitor")
	w.table([]string{"time", "class", "method", "total", "success", "failed", "total_ms", "average_ms"}, rows)
	return nil
}

func renderJad(w *textWriter, resp *ExecResponse) error {
	var j struct {
		ClassInfo *struct {
			Name        string   `json:"name"`
			ClassLoader []string `json:"classloader"`
		} `json:"classInfo"`
		Location string  `json:"location"`
		Source   *string `json:"source"`
	}
	if err := decode(resp, "jad", &j); err != nil {
		return err
	}
	if j.Source == nil {
		return errors.New("jad result has no source")
	}
	w.section("jad")
	if j.ClassInfo != nil {
		w.row("class", j.ClassInfo.Name)
		w.row("classloader", joinList(j.ClassInfo.ClassLoader))
	}
	if j.Location != "" {
		w.row("location", j.Location)
	}
	w.line("source")
	w.block(*j.Source)
	return nil
}
